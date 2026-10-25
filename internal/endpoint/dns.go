package endpoint

import (
	"fmt"
	"regexp"
	"strings"
	"time"
)

// DNS query logs: which client asked for which name, and when. A lookup
// is evidence that something on that client was about to contact the
// name; it is not evidence of a connection, so DNS records only ever
// partly corroborate an action. Five line formats, mixed freely:
//
//   - BIND query log:  client @0x… 10.0.0.5#53514 (example.com): query: example.com IN A +E(0)K (10.0.0.1)
//   - dnsmasq / Pi-hole pihole.log:  query[A] example.com from 10.0.0.5 ; reply example.com is 93.184.216.34
//   - Unbound log-queries:  [1698228000] unbound[123:0] info: 10.0.0.5 example.com. A IN
//   - Windows DNS Server debug log:  … PACKET 0000… UDP Rcv 10.0.0.5 0002   Q [0001   D   NOERROR] A (7)example(3)com(0)
//
// Pi-hole's FTL.log is diagnostics, not queries; its query log is
// pihole.log (dnsmasq format), which is what this adapter reads.

var (
	bindQueryRe    = regexp.MustCompile(`client (?:@\S+ )?([0-9A-Fa-f.:]+)#\d+.*?: query: (\S+) IN (\S+)`)
	dnsmasqQueryRe = regexp.MustCompile(`query\[(\w+)\] (\S+) from ([0-9A-Fa-f.:]+)`)
	dnsmasqReplyRe = regexp.MustCompile(`(?:reply|cached|/\S+|gravity blocked|exactly blocked|regex blacklisted|special domain|config) (\S+) is (\S+)`)
	unboundQueryRe = regexp.MustCompile(`info: ([0-9A-Fa-f.:]+) (\S+?)\.? ([A-Z0-9]+) IN\b`)
	winDNSRe       = regexp.MustCompile(`^(\d{1,2}/\d{1,2}/\d{4} \d{1,2}:\d{2}:\d{2}(?: [AP]M)?) +\S+ +PACKET +\S+ +(UDP|TCP) +(Snd|Rcv) +(\S+) +\S+ +(R)? *(\w) +\[[^\]]*\] +(\S+) +(\S+)`)
	winQnameRe     = regexp.MustCompile(`\((\d+)\)`)
)

// dnsLineKind names the DNS format a line is in, or "".
func dnsLineKind(l string) string {
	switch {
	case winDNSRe.MatchString(l):
		return "windows-dns"
	case bindQueryRe.MatchString(l):
		return "bind"
	case dnsmasqQueryRe.MatchString(l):
		return "dnsmasq"
	case strings.Contains(l, "unbound") && unboundQueryRe.MatchString(l):
		return "unbound"
	}
	return ""
}

func loadDNSLog(path string) (*LoadResult, error) {
	res := &LoadResult{}
	ref := modTime(path)
	base := baseName(path)
	// dnsmasq logs the answer on a later line: attach it to the latest
	// query for that name.
	pending := map[string]int{}
	err := scanLines(path, func(line string, n int) {
		if strings.TrimSpace(line) == "" {
			return
		}
		at := fmt.Sprintf("%s:%d", base, n)
		if m := winDNSRe.FindStringSubmatch(line); m != nil {
			if m[3] != "Rcv" || m[5] == "R" || m[6] != "Q" {
				res.ignore() // responses and our own recursion, not a client asking
				return
			}
			t, ok := parseWinDNSTime(m[1])
			if !ok {
				res.problem(at + ": unreadable timestamp " + m[1])
				return
			}
			name := decodeWinQname(m[8])
			if name == "" {
				res.problem(at + ": empty query name")
				return
			}
			res.Records = append(res.Records, Record{Time: t, Kind: "dns", DestHost: name, SourceIP: m[4], Operation: m[7], Source: "windows-dns", Ref: at})
			return
		}
		t, rest, ok := lineTime(line, ref)
		if !ok {
			res.problem(at + ": no recognizable timestamp")
			return
		}
		prog := ""
		if pm := syslogProgRe.FindStringSubmatch(rest); pm != nil {
			prog = strings.ToLower(pm[2])
		}
		switch {
		case bindQueryRe.MatchString(rest):
			m := bindQueryRe.FindStringSubmatch(rest)
			res.Records = append(res.Records, Record{Time: t, Kind: "dns", DestHost: normName(m[2]), SourceIP: m[1], Operation: m[3], Source: "bind", Ref: at})
		case dnsmasqQueryRe.MatchString(rest):
			m := dnsmasqQueryRe.FindStringSubmatch(rest)
			src := "dnsmasq"
			if strings.HasPrefix(prog, "pihole") {
				src = "pihole"
			}
			name := normName(m[2])
			pending[name] = len(res.Records)
			res.Records = append(res.Records, Record{Time: t, Kind: "dns", DestHost: name, SourceIP: m[3], Operation: m[1], Source: src, Ref: at})
		case dnsmasqReplyRe.MatchString(rest):
			m := dnsmasqReplyRe.FindStringSubmatch(rest)
			if strings.Contains(rest, "gravity blocked") {
				if i, ok := pending[normName(m[1])]; ok {
					res.Records[i].Source = "pihole"
				}
			}
			if i, ok := pending[normName(m[1])]; ok && len(strings.Fields(res.Records[i].Answers)) < 16 {
				res.Records[i].Answers = strings.TrimSpace(res.Records[i].Answers + " " + m[2])
			} else {
				res.ignore()
			}
		case unboundQueryRe.MatchString(rest):
			m := unboundQueryRe.FindStringSubmatch(rest)
			res.Records = append(res.Records, Record{Time: t, Kind: "dns", DestHost: normName(m[2]), SourceIP: m[1], Operation: m[3], Source: "unbound", Ref: at})
		default:
			res.ignore() // forwarded, config, cache statistics …
		}
	})
	return res, err
}

func normName(s string) string { return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".") }

// decodeWinQname turns (7)example(3)com(0) into example.com.
func decodeWinQname(s string) string {
	parts := winQnameRe.Split(s, -1)
	var labels []string
	for _, p := range parts {
		if p != "" {
			labels = append(labels, p)
		}
	}
	return normName(strings.Join(labels, "."))
}

// parseWinDNSTime reads the debug log's locale date (US month/day order,
// 12- or 24-hour clock). Local time without a zone, read as UTC.
func parseWinDNSTime(s string) (time.Time, bool) {
	for _, layout := range []string{"1/2/2006 3:04:05 PM", "1/2/2006 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}
