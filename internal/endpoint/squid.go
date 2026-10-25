package endpoint

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Squid access.log, the forward proxy's record of every request it
// handled, in the two stock formats:
//
//	native: 1698228000.123    180 10.0.0.5 TCP_MISS/200 411 GET http://example.com/x - HIER_DIRECT/93.184.216.34 text/html
//	common: 10.0.0.5 - dev [25/Oct/2026:10:00:00 +0000] "CONNECT example.com:443 HTTP/1.1" 200 5120 TCP_TUNNEL:HIER_DIRECT
//
// HTTPS through a proxy is a CONNECT host:port: the host is known, the
// path is not.

var (
	squidNativeRe = regexp.MustCompile(`^\d{9,10}\.\d{3}\s+-?\d+\s+\S+\s+[A-Z_]+/\d{3}\s+\d+\s+[A-Z_]+\s+\S+`)
	squidCommonRe = regexp.MustCompile(`^(\S+) \S+ (\S+) \[([^\]]+)\] "([A-Z_]+) (\S+)(?: [^"]*)?" (\d{3}) (-|\d+)(?: (\S+))?`)
)

// isSquidCommon accepts a common-format line only when it looks like a
// proxy's (absolute URL, CONNECT, or a Squid result code), not a web
// server's access log.
func isSquidCommon(l string) bool {
	m := squidCommonRe.FindStringSubmatch(l)
	if m == nil {
		return false
	}
	return m[4] == "CONNECT" || strings.Contains(m[5], "://") || strings.Contains(m[8], "TCP_") || strings.Contains(m[8], "HIER_")
}

func loadSquid(path string) (*LoadResult, error) {
	res := &LoadResult{}
	base := baseName(path)
	err := scanLines(path, func(line string, n int) {
		if strings.TrimSpace(line) == "" {
			return
		}
		at := fmt.Sprintf("%s:%d", base, n)
		var r Record
		switch {
		case squidNativeRe.MatchString(line):
			f := strings.Fields(line)
			t, ok := parseTime(f[0])
			if !ok {
				res.problem(at + ": unreadable timestamp")
				return
			}
			code, status, _ := strings.Cut(f[3], "/")
			r = Record{Time: t, SourceIP: f[2], Operation: f[5], URL: f[6]}
			if len(f) > 7 && f[7] != "-" {
				r.User = f[7]
			}
			if len(f) > 8 {
				if _, ip, ok := strings.Cut(f[8], "/"); ok && ip != "-" && ip != "" {
					r.DestIP = ip
				}
			}
			r.Failed = squidFailure(code, status)
		case squidCommonRe.MatchString(line):
			m := squidCommonRe.FindStringSubmatch(line)
			t, err := time.Parse("02/Jan/2006:15:04:05 -0700", m[3])
			if err != nil {
				res.problem(at + ": unreadable timestamp " + m[3])
				return
			}
			r = Record{Time: t.UTC(), SourceIP: m[1], Operation: m[4], URL: m[5]}
			if m[2] != "-" {
				r.User = m[2]
			}
			code, _, _ := strings.Cut(m[8], ":")
			r.Failed = squidFailure(code, m[6])
		default:
			res.problem(at + ": not a Squid access.log line")
			return
		}
		host, port, _ := hostOfURL(r.URL)
		if host == "" || host == "-" {
			res.problem(at + ": request without a host")
			return
		}
		r.Kind, r.DestHost, r.DestPort, r.Source, r.Ref = "network", host, port, "squid", at
		if r.Operation == "CONNECT" && r.DestPort == 0 {
			r.DestPort = 443
		}
		res.Records = append(res.Records, r)
	})
	return res, err
}

// squidFailure: denied requests and HTTP errors are recorded, not dropped.
func squidFailure(code, status string) string {
	if strings.Contains(code, "DENIED") {
		return code
	}
	if s, _ := strconv.Atoi(status); s >= 400 {
		return "HTTP " + status
	}
	return ""
}
