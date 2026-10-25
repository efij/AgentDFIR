package endpoint

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Zeek network-monitor logs, as TSV (with the #separator/#fields header)
// or as JSON lines (LogAscii::use_json): dns.log (client, query, answers),
// http.log (host, URI) and ssl.log (TLS SNI server_name). Other Zeek logs
// are reported as unsupported rather than guessed at.

func loadZeek(path string) (*LoadResult, error) {
	res := &LoadResult{}
	base := baseName(path)
	sep := "\t"
	unset, empty := "-", "(empty)"
	var fields []string
	logPath := ""
	unsupported := false
	err := scanLines(path, func(line string, n int) {
		line = strings.TrimRight(line, "\r")
		if strings.TrimSpace(line) == "" {
			return
		}
		at := fmt.Sprintf("%s:%d", base, n)
		if strings.HasPrefix(line, "{") {
			var doc map[string]any
			if err := json.Unmarshal([]byte(line), &doc); err != nil {
				res.problem(fmt.Sprintf("line %d: %v", n, err))
				return
			}
			flat := map[string]string{}
			for k, v := range doc {
				if l, ok := v.([]any); ok {
					var parts []string
					for _, x := range l {
						parts = append(parts, anyStr(x))
					}
					flat[k] = strings.Join(parts, ",")
				} else {
					flat[k] = anyStr(v)
				}
			}
			p := logPath
			if p == "" {
				p = zeekPathOf(flat)
			}
			zeekRecord(res, p, flat, at)
			return
		}
		if strings.HasPrefix(line, "#") {
			key, val, _ := strings.Cut(line[1:], sep)
			if key == "separator" || strings.HasPrefix(line, "#separator ") {
				v := strings.TrimSpace(strings.TrimPrefix(line, "#separator"))
				if s, err := strconv.Unquote(`"` + v + `"`); err == nil && s != "" {
					sep = s
				}
				return
			}
			switch key {
			case "path":
				logPath = val
				unsupported = logPath != "dns" && logPath != "http" && logPath != "ssl"
				if unsupported {
					res.problem("UNSUPPORTED: Zeek " + logPath + ".log is not read (dns, http and ssl are)")
				}
			case "fields":
				fields = strings.Split(val, sep)
			case "unset_field":
				unset = val
			case "empty_field":
				empty = val
			}
			return
		}
		if unsupported {
			res.ignore()
			return
		}
		if fields == nil {
			res.problem(at + ": data line before the #fields header")
			return
		}
		vals := strings.Split(line, sep)
		if len(vals) != len(fields) {
			res.problem(fmt.Sprintf("%s: %d fields, header has %d", at, len(vals), len(fields)))
			return
		}
		flat := map[string]string{}
		for i, f := range fields {
			if v := vals[i]; v != unset && v != empty {
				flat[f] = v
			}
		}
		p := logPath
		if p == "" {
			p = zeekPathOf(flat)
		}
		zeekRecord(res, p, flat, at)
	})
	return res, err
}

// zeekPathOf infers which log a JSON line came from.
func zeekPathOf(f map[string]string) string {
	switch {
	case f["query"] != "" || f["qtype_name"] != "":
		return "dns"
	case f["uri"] != "" || f["method"] != "":
		return "http"
	case f["server_name"] != "" || f["ssl_history"] != "" || f["cipher"] != "":
		return "ssl"
	}
	return ""
}

func zeekRecord(res *LoadResult, logPath string, f map[string]string, at string) {
	t, ok := parseTime(f["ts"])
	if !ok {
		res.problem(at + ": no recognizable timestamp")
		return
	}
	port, _ := strconv.Atoi(f["id.resp_p"])
	switch logPath {
	case "dns":
		if f["query"] == "" {
			res.ignore() // a response without a question (or an empty query)
			return
		}
		res.Records = append(res.Records, Record{Time: t, Kind: "dns", DestHost: normName(f["query"]), SourceIP: f["id.orig_h"],
			Operation: f["qtype_name"], Answers: strings.ReplaceAll(f["answers"], ",", " "), Source: "zeek-dns", Ref: at})
	case "http":
		host := f["host"]
		if h, _, _ := hostOfURL(host); h != "" {
			host = h
		}
		if host == "" {
			host = f["id.resp_h"]
		}
		if host == "" {
			res.problem(at + ": http record without host")
			return
		}
		r := Record{Time: t, Kind: "network", DestHost: strings.ToLower(host), DestIP: f["id.resp_h"], DestPort: port, SourceIP: f["id.orig_h"],
			Operation: f["method"], URL: f["uri"], Source: "zeek-http", Ref: at}
		if c, _ := strconv.Atoi(f["status_code"]); c >= 400 {
			r.Failed = "HTTP " + f["status_code"]
		}
		res.Records = append(res.Records, r)
	case "ssl":
		if f["server_name"] == "" {
			res.ignore() // no SNI: nothing to match a hostname against
			return
		}
		res.Records = append(res.Records, Record{Time: t, Kind: "network", DestHost: normName(f["server_name"]), DestIP: f["id.resp_h"], DestPort: port,
			SourceIP: f["id.orig_h"], Operation: "TLS", Source: "zeek-ssl", Ref: at})
	default:
		res.problem(at + ": UNSUPPORTED Zeek record (not dns, http or ssl)")
	}
}
