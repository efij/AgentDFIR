// Package netdest extracts network destinations from agent-invoked shell
// commands so timeline, exports and detections can reason about where an
// agent reached out to. Deterministic regex extraction; never resolves
// or contacts anything.
package netdest

import (
	"regexp"
	"strings"
)

var (
	urlRe   = regexp.MustCompile(`(?i)\bhttps?://([A-Za-z0-9._-]+(?::\d+)?)`)
	sshRe   = regexp.MustCompile(`\b(?:scp|rsync|ssh|sftp)\b[^|;&]*?\b[A-Za-z0-9._-]+@([A-Za-z0-9._-]+)`)
	ncRe    = regexp.MustCompile(`\b(?:nc|ncat|netcat)\s+(?:-\w+\s+)*([A-Za-z0-9._-]+)\s+\d+`)
	ipRe    = regexp.MustCompile(`\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?\b`)
	uploadR = regexp.MustCompile(`(?i)\b(curl\b[^|;&]*\s(-F|-d|--data|--data-binary|-T|--upload-file|-X\s*P(OST|UT))\b|scp\s+[^|;&]*\s\S+@\S+:|rsync\s+[^|;&]*\s\S+@|\bnc\s|wget\s+[^|;&]*--post)`)
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

// IsUpload reports whether a command has upload/egress semantics.
func IsUpload(cmd string) bool { return uploadR.MatchString(cmd) }

// IsCloudMetadata flags the cloud instance-metadata endpoint — a classic
// credential-theft pivot inside cloud workloads.
func IsCloudMetadata(dest string) bool {
	h := Host(dest)
	return h == "169.254.169.254" || h == "metadata.google.internal" || h == "fd00:ec2::254"
}
