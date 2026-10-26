package correlate

import (
	"fmt"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/netdest"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// Sightings: DNS query logs, web proxy logs, auth.log/secure and the
// journal. Each can confirm an action, none sees everything:
//
//   - proxy (Squid, Zeek http/ssl, proxy exports): a request to the host
//     the tool call contacted, within sightingWindow → CORROBORATED, the
//     same as a host network record; when both sides carry a path and the
//     paths differ → PARTIALLY_CORROBORATED
//   - sudo COMMAND= lines and journal _CMDLINE entries: the same command
//     within the match window → CORROBORATED
//   - Falco and bpftrace process records, and docker exec events (the
//     command run inside the container): the same, like a process record
//   - DNS: a lookup of exactly the host the tool call contacted, within
//     sightingWindow → PARTIALLY_CORROBORATED. A lookup shows intent to
//     connect, not a connection, and it names a client IP, not a process.
//   - sshd Accepted for the user an `ssh user@host` command named →
//     PARTIALLY_CORROBORATED (the log does not say which host it is)
//
// A miss changes nothing and nothing is ever contradicted: resolver
// caches, hard-coded IPs, direct connections around the proxy and logs
// from another machine all leave honest gaps. The records do not widen
// telemetry coverage, and since they carry no process lineage they never
// raise UNLOGGED_* findings either.

const sightingWindow = 2 * time.Minute

// cmdURLRe finds URL candidates; the host is taken from net/url, never
// from the regex, so userinfo (https://trusted.com@evil.com/) cannot pose
// as the host.
var cmdURLRe = regexp.MustCompile(`(?i)\bhttps?://[^\s"'<>|;&()` + "`" + `]+`)

// urlDest parses one URL candidate into the host a client would contact
// and its path. Candidates that do not parse, have no host, or carry a
// percent-encoded host (clients disagree on decoding it) are dropped.
func urlDest(raw string) (dest, bool) {
	u, err := url.Parse(strings.TrimRight(raw, ".,"))
	if err != nil || u.Host == "" || strings.Contains(u.Host, "%") {
		return dest{}, false
	}
	h := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if h == "" {
		return dest{}, false
	}
	return dest{h, strings.TrimSuffix(u.EscapedPath(), "/")}, true
}

type dest struct{ host, path string }

func sightingPass(events []schema.Event, records []endpoint.Record, opts EndpointOptions, res *EndpointResult) {
	res.WitnessRecords = len(records)
	if len(records) == 0 {
		return
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].Time.Before(records[j].Time) })
	used := make([]bool, len(records)) // proxy requests and commands explain one action each
	for i := range events {
		ev := &events[i]
		if ev.EventType != schema.EventToolCall || (ev.Command == "" && ev.NetworkDest == "") {
			continue
		}
		t, ok := parseEventTime(ev.Timestamp)
		if !ok {
			continue
		}
		dests := eventDests(ev)
		sshUser := sshLoginUser(ev.Command)
		full, part := -1, -1
		fullScore, partRank := 0, 0
		lo := t.Add(-sightingWindow)
		if opts.Window > sightingWindow {
			lo = t.Add(-opts.Window)
		}
		for j := lowerBound(records, lo); j < len(records) && !records[j].Time.After(t.Add(sightingWindow)); j++ {
			r := records[j]
			near := absDur(r.Time.Sub(t)) <= opts.Window
			switch r.Kind {
			case "process", "container":
				if !near || used[j] || r.Cmdline == "" {
					continue
				}
				// A container-runtime exec event names the command run
				// inside the container; it is compared like a process.
				r.Kind = "process"
				s := score(ev, r)
				if s < 100 && ev.Command != "" {
					// sudo logs the command it was asked to run, not "sudo …";
					// the inner command is the better comparison when it scores higher.
					if inner := stripSudo(ev.Command); inner != ev.Command {
						cp := *ev
						cp.Command = inner
						if s2 := score(&cp, r); s2 > s {
							s = s2
						}
					}
				}
				if s >= 60 && s > fullScore {
					full, fullScore = j, s
				}
			case "network":
				if used[j] {
					continue
				}
				for _, d := range dests {
					if !proxyHostMatch(d.host, r.DestHost) {
						continue
					}
					if pathsDiffer(d.path, recordPath(r.URL)) {
						if partRank < 3 {
							part, partRank = j, 3
						}
					} else if fullScore < 80 {
						full, fullScore = j, 80
					}
				}
			case "dns":
				for _, d := range dests {
					if d.host == r.DestHost && partRank < 2 {
						part, partRank = j, 2
					}
				}
			case "auth":
				if sshUser != "" && strings.HasPrefix(r.Operation, "ssh-accept") && r.User == sshUser && partRank < 1 {
					part, partRank = j, 1
				}
			}
		}
		switch {
		case full >= 0:
			used[full] = true
			r := records[full]
			switch ev.Corroboration {
			case schema.StateObserved, schema.StateReported, schema.StateUnknown, schema.StatePartial:
				ev.Corroboration = schema.StateCorroborated
			}
			ev.Summary = appendNote(ev.Summary, fmt.Sprintf("corroborated by %s %s: %s (%s)", r.Source, r.Kind, sightingWhat(r), r.Ref))
			res.WitnessCorroborated++
			basis, conf, win := sightingBasis(dests, r, fullScore, false, opts.Window)
			addMatchBasis(res, WitnessSighting, ev, r, fullScore, basis, conf, win, nil)
		case part >= 0:
			r := records[part]
			if r.Kind == "network" {
				used[part] = true
			}
			switch ev.Corroboration {
			case schema.StateObserved, schema.StateReported, schema.StateUnknown:
				ev.Corroboration = schema.StatePartial
			}
			ev.Summary = appendNote(ev.Summary, fmt.Sprintf("partly corroborated by %s %s: %s (%s)", r.Source, r.Kind, sightingWhat(r), r.Ref))
			res.WitnessPartial++
			// The score only ranks the partial rungs: proxy request to
			// another path 50, DNS lookup 40, ssh login 30.
			pscore := 20 + 10*partRank
			basis, conf, win := sightingBasis(dests, r, pscore, true, opts.Window)
			addMatchBasis(res, WitnessSighting, ev, r, pscore, basis, conf, win, nil)
		}
	}
}

// sightingBasis states what a sighting match compared, its confidence
// and the window it was searched in. Process records (sudo COMMAND=,
// journal _CMDLINE) were matched like host process telemetry inside the
// match window; everything else inside sightingWindow.
func sightingBasis(dests []dest, r endpoint.Record, score int, partial bool, window time.Duration) (string, string, time.Duration) {
	wide := sightingWindow
	if window > wide {
		wide = window
	}
	src := r.Source
	switch r.Kind {
	case "process", "container":
		b, conf := MatchBasis("process", score)
		return src + " command line: " + b, conf, window
	case "network":
		if partial {
			return "proxy request to " + r.DestHost + " (another path) within ±" + wide.String(), "LOW", wide
		}
		for _, d := range dests {
			if proxyHostMatch(d.host, r.DestHost) && d.path != "" && d.path == recordPath(r.URL) {
				return "proxy request host+path " + r.DestHost + d.path + " within ±" + wide.String(), "MEDIUM", wide
			}
		}
		return "proxy request host " + r.DestHost + " within ±" + wide.String(), "MEDIUM", wide
	case "dns":
		return "DNS lookup of " + r.DestHost + " within ±" + wide.String(), "LOW", wide
	case "auth":
		return "sshd login accepted for " + r.User + " within ±" + wide.String() + " (the log does not name the host)", "LOW", wide
	}
	return src + " record", "LOW", wide
}

// eventDests: the hosts (and URL paths) a tool call reached for, from
// its network destination and the URLs and hosts in its command.
func eventDests(ev *schema.Event) []dest {
	var out []dest
	seen := map[dest]bool{}
	add := func(h, p string) {
		h = strings.TrimSuffix(strings.ToLower(strings.Trim(h, "[]")), ".")
		if h == "" || isLoopback(h) {
			return
		}
		d := dest{h, strings.TrimSuffix(p, "/")}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	urls := func(s string) {
		for _, m := range cmdURLRe.FindAllString(s, -1) {
			if d, ok := urlDest(m); ok {
				add(d.host, d.path)
			}
		}
	}
	if ev.Command != "" {
		// Everything comes from the command itself (NetworkDest holds only
		// its first destination); URLs go through net/url, and they are
		// removed before the non-URL extractor
		// (ssh/scp/nc targets, bare IPs) runs.
		urls(ev.Command)
		for _, d := range netdest.Extract(cmdURLRe.ReplaceAllString(ev.Command, " ")) {
			add(netdest.Host(d), "")
		}
	} else if ev.NetworkDest != "" {
		// MCP and fetch tools: the destination is the tool's own URL or domain.
		if strings.Contains(ev.NetworkDest, "://") {
			urls(ev.NetworkDest)
		} else if d, ok := urlDest("https://" + ev.NetworkDest); ok {
			add(d.host, "")
		}
	}
	// A host seen with a path is not also matched without one, or the
	// path check would never bite.
	withPath := map[string]bool{}
	for _, d := range out {
		if d.path != "" {
			withPath[d.host] = true
		}
	}
	kept := out[:0]
	for _, d := range out {
		if d.path != "" || !withPath[d.host] {
			kept = append(kept, d)
		}
	}
	return kept
}

// sudoValued are sudo flags that take a value.
var sudoValued = map[string]bool{"-u": true, "-g": true, "-C": true, "-h": true, "-p": true, "-U": true, "-r": true, "-t": true, "-D": true, "-R": true, "-T": true}

// stripSudo drops a leading `sudo [flags]` from a command.
func stripSudo(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) < 2 || exeName(f[0]) != "sudo" {
		return cmd
	}
	i := 1
	for i < len(f) && strings.HasPrefix(f[i], "-") {
		if f[i] == "--" {
			i++
			break
		}
		if sudoValued[f[i]] {
			i++
		}
		i++
	}
	if i >= len(f) {
		return cmd
	}
	return strings.Join(f[i:], " ")
}

// proxyHostMatch follows the host network matching: the same host, or a
// subdomain of it.
func proxyHostMatch(want, got string) bool {
	got = strings.ToLower(got)
	return got != "" && (want == got || strings.HasSuffix(got, "."+want))
}

// recordPath is the path of a proxy record's URL (absolute or not).
func recordPath(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
		if j := strings.IndexByte(u, '/'); j >= 0 {
			u = u[j:]
		} else {
			u = ""
		}
	} else if !strings.HasPrefix(u, "/") {
		return "" // CONNECT host:port
	}
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	return strings.TrimSuffix(u, "/")
}

func pathsDiffer(a, b string) bool { return a != "" && b != "" && a != b }

// sshLoginUser: the user an `ssh user@host` command logs in as.
func sshLoginUser(cmd string) string {
	for _, seg := range splitCompound(cmd) {
		f := strings.Fields(seg)
		if len(f) < 2 || exeName(f[0]) != "ssh" {
			continue
		}
		for _, a := range f[1:] {
			if u, _, ok := strings.Cut(a, "@"); ok && !strings.HasPrefix(a, "-") && u != "" {
				return u
			}
		}
	}
	return ""
}

func sightingWhat(r endpoint.Record) string {
	switch r.Kind {
	case "dns":
		s := "lookup of " + r.DestHost
		if r.SourceIP != "" {
			s += " from " + r.SourceIP
		}
		return s
	case "network":
		s := strings.TrimSpace(r.Operation + " " + firstNonBlank(r.URL, r.DestHost))
		if r.Failed != "" {
			s += " (" + r.Failed + ")"
		}
		return s
	case "auth":
		return r.Operation + " for " + r.User + " from " + r.SourceIP
	}
	s := trim(r.Cmdline, 120)
	if r.Failed != "" {
		s += " (" + r.Failed + ")"
	}
	return s
}

func firstNonBlank(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func absDur(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}
