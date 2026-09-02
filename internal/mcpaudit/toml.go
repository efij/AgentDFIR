package mcpaudit

import (
	"fmt"
	"sort"
	"strings"
)

// parseCodexTOML reads the [mcp_servers.<name>] tables of a Codex
// config.toml with a deliberately small TOML subset: string, boolean,
// string arrays, inline tables and dotted sub-tables ([mcp_servers.x.env]).
// Anything outside mcp_servers is ignored; malformed lines are reported.
func parseCodexTOML(data []byte) ([]Server, error) {
	type raw struct {
		kv  map[string]string
		arr map[string][]string
		env map[string]string
		hdr map[string]string
	}
	servers := map[string]*raw{}
	get := func(name string) *raw {
		if r, ok := servers[name]; ok {
			return r
		}
		r := &raw{kv: map[string]string{}, arr: map[string][]string{}, env: map[string]string{}, hdr: map[string]string{}}
		servers[name] = r
		return r
	}
	var curName, curSub string
	inServers := false
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(stripTOMLComment(line))
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "[") {
			hdr := strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			hdr = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(hdr, "["), "]")) // arrays of tables too
			parts := splitDotted(hdr)
			if len(parts) >= 2 && parts[0] == "mcp_servers" {
				inServers = true
				curName = parts[1]
				curSub = ""
				if len(parts) >= 3 {
					curSub = parts[2]
				}
				get(curName)
			} else {
				inServers = false
			}
			continue
		}
		if !inServers {
			continue
		}
		eq := strings.Index(line, "=")
		if eq < 0 {
			return nil, fmt.Errorf("config.toml line %d: expected key = value", n+1)
		}
		key := unquote(strings.TrimSpace(line[:eq]))
		val := strings.TrimSpace(line[eq+1:])
		r := get(curName)
		switch curSub {
		case "env":
			r.env[key] = unquote(val)
			continue
		case "http_headers", "headers":
			r.hdr[key] = unquote(val)
			continue
		}
		switch {
		case strings.HasPrefix(val, "["):
			r.arr[key] = parseStringArray(val)
		case strings.HasPrefix(val, "{"):
			m := parseInlineTable(val)
			if key == "env" {
				for k, v := range m {
					r.env[k] = v
				}
			} else if key == "http_headers" || key == "headers" {
				for k, v := range m {
					r.hdr[k] = v
				}
			}
		default:
			r.kv[key] = unquote(val)
		}
	}
	names := make([]string, 0, len(servers))
	for n := range servers {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []Server
	for _, n := range names {
		r := servers[n]
		s := Server{Name: n, Command: r.kv["command"], Args: r.arr["args"], URL: r.kv["url"]}
		s.Disabled = strings.EqualFold(r.kv["enabled"], "false")
		s.EnvKeys, s.SecretEnv = envKeys(r.env)
		s.HeaderKeys = sortedKeys(r.hdr)
		out = append(out, s)
	}
	return out, nil
}

func stripTOMLComment(line string) string {
	inStr := false
	for i := 0; i < len(line); i++ {
		switch line[i] {
		case '"':
			if i == 0 || line[i-1] != '\\' {
				inStr = !inStr
			}
		case '#':
			if !inStr {
				return line[:i]
			}
		}
	}
	return line
}

func splitDotted(s string) []string {
	var parts []string
	cur, inStr := "", false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			inStr = !inStr
		case c == '.' && !inStr:
			parts = append(parts, strings.TrimSpace(cur))
			cur = ""
		default:
			cur += string(c)
		}
	}
	parts = append(parts, strings.TrimSpace(cur))
	return parts
}

func unquote(v string) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
		inner := v[1 : len(v)-1]
		if v[0] == '"' {
			inner = strings.NewReplacer(`\"`, `"`, `\\`, `\`, `\n`, "\n", `\t`, "\t").Replace(inner)
		}
		return inner
	}
	return v
}

func parseStringArray(v string) []string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(strings.TrimPrefix(v, "["), "]")
	var out []string
	for _, item := range splitTopLevel(v, ',') {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, unquote(item))
	}
	return out
}

func parseInlineTable(v string) map[string]string {
	v = strings.TrimSpace(v)
	v = strings.TrimSuffix(strings.TrimPrefix(v, "{"), "}")
	out := map[string]string{}
	for _, pair := range splitTopLevel(v, ',') {
		eq := strings.Index(pair, "=")
		if eq < 0 {
			continue
		}
		out[unquote(strings.TrimSpace(pair[:eq]))] = unquote(strings.TrimSpace(pair[eq+1:]))
	}
	return out
}

// splitTopLevel splits on sep outside quotes.
func splitTopLevel(s string, sep byte) []string {
	var parts []string
	cur, inStr := "", false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' && (i == 0 || s[i-1] != '\\') {
			inStr = !inStr
		}
		if c == sep && !inStr {
			parts = append(parts, cur)
			cur = ""
			continue
		}
		cur += string(c)
	}
	parts = append(parts, cur)
	return parts
}
