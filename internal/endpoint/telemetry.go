package endpoint

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/parsers/plaso"
)

// Second-witness telemetry beyond process auditing: DNS query logs, web
// proxy logs, Linux authentication logs and the journal, Kubernetes audit
// logs, Git hosting audit exports and cloud object-storage access logs.
//
// None of these sources sees everything an agent does: a DNS log misses
// cached and hard-coded lookups, a proxy misses direct connections, an
// audit export may be for another cluster or organization. The records
// they yield can corroborate an action; they never contradict one, and
// they never count as process coverage. IsSighting tells the correlation
// engine which records those are.

const (
	FormatZeek    Format = "zeek"           // Zeek dns.log / http.log / ssl.log, TSV or JSON
	FormatDNSLog  Format = "dns-log"        // BIND, dnsmasq, Pi-hole, Unbound, Windows DNS Server debug log
	FormatSquid   Format = "squid"          // Squid access.log, native or common format
	FormatAuthLog Format = "authlog"        // /var/log/auth.log, /var/log/secure
	FormatJournal Format = "journald"       // journalctl -o json
	FormatK8s     Format = "k8s-audit"      // Kubernetes audit.k8s.io/v1 Event lines
	FormatGitAud  Format = "git-audit"      // GitHub audit log export (JSON/CSV), GitLab audit events JSON
	FormatStorage Format = "storage-access" // S3 server access, GCS usage CSV, Azure Storage analytics

	telemetryFormatList = "zeek|dns-log|squid|authlog|journald|k8s-audit|git-audit|storage-access|plaso"
)

// sightingSources are the adapters whose records corroborate but never
// give coverage (see the package comment above).
var sightingSources = map[string]bool{
	"zeek-dns": true, "zeek-http": true, "zeek-ssl": true,
	"bind": true, "dnsmasq": true, "pihole": true, "unbound": true, "windows-dns": true,
	"squid": true, "proxy-export": true,
	"authlog": true, "journald": true,
	"plaso": true,
}

// IsSighting reports whether a record comes from a partial-coverage
// witness: it may corroborate a matching action but must never widen
// telemetry coverage or contradict anything.
func IsSighting(r Record) bool { return sightingSources[r.Source] }

// IsWitnessCloud reports whether a kind-cloud record comes from one of the
// cloud-like audit sources added beside CloudTrail/Azure/GCP.
func IsWitnessCloud(r Record) bool {
	switch r.Provider {
	case "k8s", "github", "gitlab", "s3", "gcs", "azure-storage":
		return r.Kind == "cloud"
	}
	return false
}

func loadTelemetry(path string, f Format) (*LoadResult, bool, error) {
	var res *LoadResult
	var err error
	switch f {
	case FormatZeek:
		res, err = loadZeek(path)
	case FormatDNSLog:
		res, err = loadDNSLog(path)
	case FormatSquid:
		res, err = loadSquid(path)
	case FormatAuthLog:
		res, err = loadAuthLog(path)
	case FormatJournal:
		res, err = loadJournal(path)
	case FormatK8s:
		res, err = loadK8sAudit(path)
	case FormatGitAud:
		res, err = loadGitAudit(path)
	case FormatStorage:
		res, err = loadStorageLog(path)
	case FormatPlaso:
		res, err = loadPlaso(path)
	default:
		return nil, false, nil
	}
	return res, true, err
}

var (
	githubActionRe = regexp.MustCompile(`"action"\s*:\s*"[a-z_]+\.[a-z_.]+"`)
	s3AccessRe     = regexp.MustCompile(`^(?:[0-9a-f]{64}|-) \S+ \[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}\] `)
	azureStorRe    = regexp.MustCompile(`^[12]\.0;\d{4}-\d{2}-\d{2}T[^;]*;[A-Za-z]+;`)
)

// sniffTelemetry recognizes the formats above by content. It runs before
// the generic JSON/CSV fallbacks and must not claim their files.
func sniffTelemetry(head []byte) Format {
	if plaso.Sniff(head) != "" {
		return FormatPlaso
	}
	has := func(k string) bool { return bytes.Contains(head, []byte(`"`+k+`"`)) }
	if bytes.HasPrefix(head, []byte("{")) || (bytes.HasPrefix(head, []byte("[")) && !epochBrRe.Match(head)) {
		switch {
		case has("auditID") && has("verb") && (has("objectRef") || bytes.Contains(head, []byte("audit.k8s.io"))):
			return FormatK8s
		case has("__REALTIME_TIMESTAMP"):
			return FormatJournal
		case has("id.orig_h") && (has("query") || has("uri") || has("server_name")):
			return FormatZeek
		case githubActionRe.Match(head) && has("actor"):
			return FormatGitAud
		case has("entity_type") && (has("author_id") || has("author_name")) && has("details"):
			return FormatGitAud
		}
		return ""
	}
	lines := headLines(head, 40)
	if len(lines) == 0 {
		return ""
	}
	first := lines[0]
	switch {
	case strings.HasPrefix(first, "#separator") || strings.HasPrefix(first, "#fields\t") || (strings.HasPrefix(first, "#") && strings.Contains(string(head), "\n#path\t")):
		return FormatZeek
	case s3AccessRe.MatchString(first) || azureStorRe.MatchString(first):
		return FormatStorage
	case strings.Contains(first, "time_micros") && strings.Contains(first, "cs_method"):
		return FormatStorage
	case isGitHubCSVHeader(first):
		return FormatGitAud
	}
	dns, squid, auth := 0, 0, 0
	for _, l := range lines {
		switch {
		case dnsLineKind(l) != "":
			dns++
		case squidNativeRe.MatchString(l) || isSquidCommon(l):
			squid++
		case isAuthLine(l):
			auth++
		}
	}
	switch {
	case dns > 0 && dns >= squid:
		return FormatDNSLog
	case squid > 0:
		return FormatSquid
	case auth > 0:
		return FormatAuthLog
	}
	return ""
}

// headLines splits the sniff buffer into at most n non-empty lines,
// dropping a possibly truncated last line when there are others.
func headLines(head []byte, n int) []string {
	parts := strings.Split(string(head), "\n")
	if len(parts) > 1 && !bytes.HasSuffix(head, []byte("\n")) {
		parts = parts[:len(parts)-1]
	}
	var out []string
	for _, p := range parts {
		if p = strings.TrimRight(p, "\r"); strings.TrimSpace(p) != "" {
			out = append(out, p)
			if len(out) == n {
				break
			}
		}
	}
	return out
}

// ignore counts a well-formed line that carries nothing these adapters
// read (a cron session, a forwarded-query line): skipped, not a problem.
func (r *LoadResult) ignore() { r.Skipped++ }

// ---- line timestamps ----

var (
	syslogTimeRe = regexp.MustCompile(`^([A-Z][a-z]{2}) +(\d{1,2}) (\d{2}:\d{2}:\d{2})(?:\.\d+)? `)
	isoTimeRe    = regexp.MustCompile(`^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?) `)
	bindTimeRe   = regexp.MustCompile(`^(\d{2}-[A-Z][a-z]{2}-\d{4} \d{2}:\d{2}:\d{2}(?:\.\d+)?) `)
	epochBrRe    = regexp.MustCompile(`^\[(\d{9,10})(?:\.\d+)?\] `)
)

// lineTime reads the timestamp a syslog-style line starts with and returns
// the rest. Classic syslog has no year and no zone: the year comes from
// yearRef (the file's modification time) and the zone is UTC, the same
// convention parseTime applies to zone-less timestamps.
func lineTime(line string, yearRef time.Time) (time.Time, string, bool) {
	if m := isoTimeRe.FindStringSubmatch(line); m != nil {
		s := strings.Replace(m[1], " ", "T", 1)
		if len(s) >= 5 && (s[len(s)-5] == '+' || s[len(s)-5] == '-') && !strings.Contains(s[len(s)-5:], ":") {
			s = s[:len(s)-2] + ":" + s[len(s)-2:] // +0000 → +00:00
		}
		if t, ok := parseTime(s); ok {
			return t, line[len(m[0]):], true
		}
	}
	if m := syslogTimeRe.FindStringSubmatch(line); m != nil {
		year := yearRef.Year()
		if yearRef.IsZero() {
			year = time.Now().UTC().Year()
		}
		t, err := time.Parse("2006 Jan 2 15:04:05", fmt.Sprintf("%d %s %s %s", year, m[1], m[2], m[3]))
		if err == nil {
			// A December line in a file written in January belongs to last year.
			if !yearRef.IsZero() && t.After(yearRef.Add(48*time.Hour)) {
				t = t.AddDate(-1, 0, 0)
			}
			return t.UTC(), line[len(m[0]):], true
		}
	}
	if m := bindTimeRe.FindStringSubmatch(line); m != nil {
		for _, layout := range []string{"02-Jan-2006 15:04:05.000", "02-Jan-2006 15:04:05"} {
			if t, err := time.Parse(layout, m[1]); err == nil {
				return t.UTC(), line[len(m[0]):], true
			}
		}
	}
	if m := epochBrRe.FindStringSubmatch(line); m != nil {
		if t, ok := parseTime(m[1]); ok {
			return t, line[len(m[0]):], true
		}
	}
	return time.Time{}, line, false
}

// modTime is the year reference for zone-less, year-less logs.
func modTime(path string) time.Time {
	if fi, err := os.Stat(path); err == nil {
		return fi.ModTime().UTC()
	}
	return time.Time{}
}

// syslogProgRe splits "[host ]prog[pid]: msg" after the timestamp. The
// host is optional (pihole.log and journal-forwarded files omit it).
var syslogProgRe = regexp.MustCompile(`^(?:(\S+) )?([A-Za-z0-9_.()/-]+?)(?:\[(\d+)(?::\d+)?\])?: (.*)$`)

// ---- JSON documents ----

// forEachJSONDoc calls fn for every JSON object in a JSON Lines file, a
// JSON array, or a single object that wraps an array under one of
// wrapKeys. JSON Lines are read line by line so one malformed line costs
// one record, not the rest of the file.
func forEachJSONDoc(path string, res *LoadResult, wrapKeys []string, fn func(doc map[string]any, ref string)) error {
	base := baseName(path)
	lineMode := false
	if f, err := os.Open(path); err == nil {
		br := bufio.NewReader(f)
		first, _ := br.ReadBytes('\n')
		for len(bytes.TrimSpace(first)) == 0 {
			next, err := br.ReadBytes('\n')
			first = next
			if err != nil {
				break
			}
		}
		first = bytes.TrimSpace(bytes.TrimPrefix(first, []byte("\xef\xbb\xbf")))
		var probe map[string]json.RawMessage
		lineMode = len(first) > 0 && first[0] == '{' && json.Unmarshal(first, &probe) == nil
		if lineMode {
			for _, k := range wrapKeys { // {"items":[...]} on one line is a wrapper, not a record
				if v, ok := probe[k]; ok && len(bytes.TrimSpace(v)) > 0 && bytes.TrimSpace(v)[0] == '[' {
					lineMode = false
				}
			}
		}
		f.Close()
	}
	if lineMode {
		return scanLines(path, func(line string, n int) {
			line = strings.TrimSpace(strings.TrimPrefix(line, "\xef\xbb\xbf"))
			if line == "" {
				return
			}
			var doc map[string]any
			if err := json.Unmarshal([]byte(line), &doc); err != nil {
				res.problem(fmt.Sprintf("line %d: %v", n, err))
				return
			}
			fn(doc, fmt.Sprintf("%s:%d", base, n))
		})
	}
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	n := 0
	var visit func(raw json.RawMessage, depth int)
	visit = func(raw json.RawMessage, depth int) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 || depth > 4 {
			return
		}
		if raw[0] == '[' {
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err != nil {
				res.problem("json array: " + err.Error())
				return
			}
			for _, e := range arr {
				visit(e, depth+1)
			}
			return
		}
		var wrap map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrap); err != nil {
			res.problem("json: " + err.Error())
			return
		}
		for _, k := range wrapKeys {
			if inner, ok := wrap[k]; ok && len(bytes.TrimSpace(inner)) > 0 && bytes.TrimSpace(inner)[0] == '[' {
				visit(inner, depth+1)
				return
			}
		}
		n++
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			res.problem(fmt.Sprintf("record %d: %v", n, err))
			return
		}
		fn(doc, fmt.Sprintf("%s record %d", base, n))
	}
	dec := json.NewDecoder(bufio.NewReader(f))
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if !errors.Is(err, io.EOF) {
				res.problem("json: " + err.Error())
			}
			return nil
		}
		visit(raw, 0)
	}
}

// anyStr renders a JSON leaf as text (numbers without exponent).
func anyStr(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%f", t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	}
	return ""
}

// leaf digs a dotted path and renders it as text.
func leaf(doc map[string]any, path string) string { return anyStr(dig(doc, path)) }

// ---- delimited fields ----

// splitQuoted splits a line on sep, keeping "quoted" and [bracketed]
// fields whole (S3 access logs, Azure Storage logs, Squid common format).
func splitQuoted(line string, sep byte, brackets bool) []string {
	var out []string
	var cur strings.Builder
	inQ, inB := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case inQ:
			if c == '\\' && i+1 < len(line) {
				cur.WriteByte(line[i+1])
				i++
				continue
			}
			if c == '"' {
				inQ = false
				continue
			}
			cur.WriteByte(c)
		case inB:
			if c == ']' {
				inB = false
				continue
			}
			cur.WriteByte(c)
		case c == '"':
			inQ = true
		case brackets && c == '[' && cur.Len() == 0:
			inB = true
		case c == sep:
			if sep == ' ' && cur.Len() == 0 && i > 0 && line[i-1] == ' ' {
				continue // runs of spaces
			}
			out = append(out, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(out, cur.String())
}

// hostOfURL returns the host of an absolute URL or a CONNECT host:port.
func hostOfURL(u string) (host string, port int, path string) {
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		path = rest[i:]
		rest = rest[:i]
	}
	if i := strings.LastIndexByte(rest, '@'); i >= 0 {
		rest = rest[i+1:]
	}
	host = rest
	if strings.HasPrefix(host, "[") { // [v6]:port
		if j := strings.Index(host, "]"); j > 0 {
			if strings.HasPrefix(host[j+1:], ":") {
				fmt.Sscanf(host[j+2:], "%d", &port)
			}
			return strings.ToLower(host[1:j]), port, path
		}
	}
	if i := strings.LastIndexByte(host, ':'); i >= 0 && strings.Count(host, ":") == 1 {
		fmt.Sscanf(host[i+1:], "%d", &port)
		host = host[:i]
	}
	return strings.ToLower(host), port, path
}
