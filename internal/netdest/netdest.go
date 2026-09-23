// Package netdest extracts network destinations from agent-invoked shell
// commands so timeline, exports and detections can reason about where an
// agent reached out to. Deterministic regex extraction; never resolves
// or contacts anything.
package netdest

import (
	"github.com/efij/AgentDFIR/v2/internal/shellshape"
	"regexp"
	"strconv"
	"strings"
)

var (
	urlRe = regexp.MustCompile(`(?i)\bhttps?://([A-Za-z0-9._-]+(?::\d+)?)`)
	sshRe = regexp.MustCompile(`\b(?:scp|rsync|ssh|sftp)\b[^|;&]*?\b[A-Za-z0-9._-]+@([A-Za-z0-9._-]+)`)
	// Flags that take a value: without consuming the value, `nc -w 3 host`
	// reported "3" as the destination.
	ncRe    = regexp.MustCompile(`\b(?:nc|ncat|netcat)\s+(?:-[a-zA-Z]+(?:\s+\d+)?\s+)*([A-Za-z0-9._-]+)\s+\d+`)
	ipRe    = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?\b`)
	uploadR = regexp.MustCompile(`(?i)\b(curl\b[^|;&]*\s(-F|-d|--data|--data-binary|-T|--upload-file|-X\s*P(OST|UT))\b|scp\s+[^|;&]*\s\S+@\S+:|rsync\s+[^|;&]*\s\S+@|wget\s+[^|;&]*--post)`)
)

// DefaultAllowlist: destinations routinely contacted by legitimate
// development tooling. Rules treat anything else as "unexpected".
var DefaultAllowlist = []string{
	"github.com", "api.github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
	"gitlab.com", "bitbucket.org",
	"pypi.org", "files.pythonhosted.org", "registry.npmjs.org", "npmjs.com", "yarnpkg.com",
	"proxy.golang.org", "sum.golang.org", "golang.org", "go.dev", "pkg.go.dev",
	"crates.io", "static.crates.io", "rubygems.org", "packagist.org",
	"docker.io", "registry-1.docker.io", "hub.docker.com", "ghcr.io", "quay.io",
	"localhost", "127.0.0.1", "0.0.0.0", "::1",
	"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com",
	"deb.debian.org", "archive.ubuntu.com", "security.ubuntu.com", "dl.fedoraproject.org",
	"brew.sh", "formulae.brew.sh", "nodejs.org", "deno.land", "bun.sh",
}

// Extract returns unique destinations (host or host:port) referenced by a
// command line, in order of first appearance.
func Extract(cmd string) []string {
	if cmd == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] {
			return
		}
		seen[h] = true
		out = append(out, h)
	}
	for _, m := range urlRe.FindAllStringSubmatch(cmd, -1) {
		add(m[1])
	}
	for _, m := range sshRe.FindAllStringSubmatch(cmd, -1) {
		add(m[1])
	}
	for _, m := range ncRe.FindAllStringSubmatch(cmd, -1) {
		if !plausibleHost(m[1]) {
			continue
		}
		add(m[1])
	}
	for _, m := range ipRe.FindAllStringSubmatch(cmd, -1) {
		add(m[1])
	}
	return out
}

// Host strips a port suffix.
func Host(dest string) string {
	if i := strings.LastIndex(dest, ":"); i > 0 && !strings.Contains(dest[i:], "]") {
		return dest[:i]
	}
	return dest
}

// IsAllowed reports whether a destination (or its parent domain) is in
// the allowlist.
func IsAllowed(dest string, extra []string) bool {
	h := Host(dest)
	check := func(list []string) bool {
		for _, a := range list {
			a = strings.ToLower(a)
			if h == a || strings.HasSuffix(h, "."+a) {
				return true
			}
		}
		return false
	}
	return check(DefaultAllowlist) || check(extra)
}

// IsUpload reports whether a command has upload/egress semantics, judged
// on what the shell runs: heredoc bodies and quoted text do not count, and
// `nc` only counts when data is fed into it (`… | nc host port`, `nc host
// port < file`). `nc -z host port` is a reachability probe; on a real
// machine 7 of 11 HIGH exfiltration findings were probes.
func IsUpload(cmd string) bool {
	stripped := shellshape.Strip(shellshape.ExpandVars(cmd))
	if uploadR.MatchString(stripped) {
		return true
	}
	for _, st := range shellshape.Stages(stripped) {
		if v := shellshape.Verb(st.Text); v != "nc" && v != "ncat" {
			continue
		}
		f := strings.Fields(st.Text)
		probe := false
		for _, a := range f {
			if strings.HasPrefix(a, "-") && strings.Contains(a, "z") && !strings.HasPrefix(a, "--") {
				probe = true
			}
		}
		if probe {
			continue
		}
		if st.Piped || strings.Contains(st.Text, "<") {
			return true
		}
	}
	return false
}

// outboundVerbs are the programs whose presence as a stage's verb means the
// command talks to the network. A URL inside a heredoc or a quoted string is
// text, not a connection.
var outboundVerbs = map[string]bool{"curl": true, "wget": true, "scp": true, "rsync": true, "sftp": true, "ssh": true, "ncat": true}

// IsOutbound reports whether a stage of the command opens a network
// connection: a network verb, `git push`, `aws s3 cp`/`gsutil cp`, or a
// non-probe `nc`. Chain rules use it as their "data left the host" step.
func IsOutbound(cmd string) bool {
	stripped := shellshape.Strip(shellshape.ExpandVars(cmd))
	for _, st := range shellshape.Stages(stripped) {
		f := strings.Fields(st.Text)
		v := shellshape.Verb(st.Text)
		switch {
		case outboundVerbs[v]:
			if v == "curl" || v == "wget" {
				// The destination has to be visible: a health check against
				// the agent's own dev server is not data leaving the host,
				// and a `curl` whose URL the 300-character command trim cut
				// off is not evidence of anything.
				dest, ok := destinationOf(f)
				if !ok || dest == "loopback" {
					continue
				}
			}
			return true
		case v == "git" && len(f) >= 2 && f[1] == "push":
			return true
		case (v == "aws" || v == "gsutil") && len(f) >= 3 && f[2] == "cp":
			return true
		case v == "nc":
			probe := false
			for _, a := range f {
				if strings.HasPrefix(a, "-") && strings.Contains(a, "z") && !strings.HasPrefix(a, "--") {
					probe = true
				}
			}
			if !probe {
				return true
			}
		}
	}
	return false
}

// destinationOf classifies where a curl/wget stage points: "loopback" when
// every visible URL or host is the local machine, "remote" otherwise, and
// ok=false when no destination is visible at all.
func destinationOf(fields []string) (string, bool) {
	if !onlyLoopback(fields) {
		for _, a := range fields[1:] {
			a = strings.Trim(a, `"'`)
			if strings.Contains(a, "://") || (!strings.HasPrefix(a, "-") && strings.Contains(a, ".") && !strings.Contains(a, "/") && !strings.HasSuffix(a, "…")) {
				return "remote", true
			}
		}
		return "", false
	}
	return "loopback", true
}

// onlyLoopback reports whether every URL or host:port in the fields points
// at the local machine.
func onlyLoopback(fields []string) bool {
	seen := false
	for _, a := range fields {
		a = strings.Trim(a, `"'`)
		var h string
		switch {
		case strings.Contains(a, "://"):
			h = a[strings.Index(a, "://")+3:]
		case strings.HasPrefix(a, "localhost") || strings.HasPrefix(a, "127.") || strings.HasPrefix(a, "[::1]") || strings.HasPrefix(a, "0.0.0.0"):
			h = a
		default:
			continue
		}
		if i := strings.IndexAny(h, "/?#"); i >= 0 {
			h = h[:i]
		}
		h = Host(strings.ToLower(h))
		seen = true
		if h != "localhost" && !strings.HasPrefix(h, "127.") && h != "[::1]" && h != "::1" && h != "0.0.0.0" {
			return false
		}
	}
	return seen
}

// IsCloudMetadata flags the cloud instance-metadata endpoint — a classic
// credential-theft pivot inside cloud workloads.
func IsCloudMetadata(dest string) bool {
	h := Host(dest)
	return h == "169.254.169.254" || h == "metadata.google.internal" || h == "fd00:ec2::254"
}

// plausibleHost rejects things that are syntactically a word but cannot be
// a destination: bare numbers (a flag's value), flags themselves, and
// single labels that are not a known local name.
func plausibleHost(h string) bool {
	if h == "" || strings.HasPrefix(h, "-") {
		return false
	}
	if _, err := strconv.Atoi(h); err == nil {
		return false
	}
	if strings.Contains(h, ".") {
		return true
	}
	switch strings.ToLower(h) {
	case "localhost", "127.0.0.1", "::1":
		return true
	}
	return false
}
