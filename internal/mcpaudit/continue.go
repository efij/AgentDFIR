package mcpaudit

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Continue (continue.dev) MCP dialects.
//
//	~/.continue/config.json          {"experimental":{"modelContextProtocolServers":[{"transport":{"type","command","args","env","url"}}]}}
//	                                 and, in later builds, "mcpServers" as a list or a name-keyed map
//	~/.continue/config.yaml          mcpServers: [ {name, command, args, env, type, url} | {uses: owner/block} ]
//	~/.continue/mcpServers/*.yaml    one block per file, same mcpServers list
//	~/.continue/mcpServers/*.json    Claude-style {"mcpServers":{…}} copied from another tool
const (
	fmtContinueJSON format = 101
	fmtContinueYAML format = 102
)

type continueServer struct {
	Name      string            `json:"name"`
	Command   string            `json:"command"`
	Args      []string          `json:"args"`
	Env       map[string]string `json:"env"`
	URL       string            `json:"url"`
	Type      string            `json:"type"`
	Uses      string            `json:"uses"`
	Transport *continueServer   `json:"transport"`
}

// parseContinueJSON adds the servers of a Continue config.json.
func parseContinueJSON(inv *Inventory, doc map[string]json.RawMessage, host, scope, display string) {
	var exp struct {
		Servers []continueServer `json:"modelContextProtocolServers"`
	}
	if raw, ok := doc["experimental"]; ok {
		if err := json.Unmarshal(raw, &exp); err != nil {
			inv.Problems = append(inv.Problems, display+": experimental.modelContextProtocolServers: "+err.Error())
		}
	}
	list := exp.Servers
	if raw, ok := doc["mcpServers"]; ok {
		var l []continueServer
		if json.Unmarshal(raw, &l) == nil {
			list = append(list, l...)
		} else {
			addServerMap(inv, raw, host, scope, display, "")
		}
	}
	for i, cs := range list {
		addContinueServer(inv, cs, i, host, scope, display)
	}
}

func addContinueServer(inv *Inventory, cs continueServer, i int, host, scope, display string) {
	t := cs
	if cs.Transport != nil {
		t = *cs.Transport
		if t.Name == "" {
			t.Name = cs.Name
		}
	}
	name := t.Name
	if name == "" {
		name = fmt.Sprintf("server-%d", i+1)
	}
	s := Server{Name: name, Host: host, Scope: scope, ConfigPath: display,
		Command: t.Command, Args: t.Args, URL: t.URL, Transport: strings.ToLower(t.Type)}
	s.EnvKeys, s.SecretEnv = envKeys(t.Env)
	s.EnvSHA256 = envHash(t.Env)
	enrich(&s, inv.Mode == "live")
	if t.Uses != "" && s.Command == "" && s.URL == "" {
		// A hub reference names a published block; its launch line is not
		// in this file, so it cannot be judged pinned.
		s.Package, s.PackageMgr, s.Pinned = t.Uses, "continue-hub", false
	}
	inv.Servers = append(inv.Servers, s)
}

// parseContinueYAML reads the mcpServers list of a Continue YAML config
// with a deliberately small YAML subset: block mappings and sequences,
// flow lists ([a, "b"]) and flow maps ({K: v}), plain and quoted scalars.
// Anything outside mcpServers is ignored; a server it cannot read is
// reported in Problems, never dropped silently.
func parseContinueYAML(data []byte) ([]continueServer, []string, error) {
	lines := yamlLines(string(data))
	start := -1
	for i, l := range lines {
		if l.indent == 0 && (l.text == "mcpServers:" || strings.HasPrefix(l.text, "mcpServers:")) {
			start = i
			if rest := strings.TrimSpace(strings.TrimPrefix(l.text, "mcpServers:")); rest != "" {
				if rest == "[]" {
					return nil, nil, nil
				}
				return nil, nil, fmt.Errorf("mcpServers: inline value not supported")
			}
			break
		}
	}
	if start < 0 {
		return nil, nil, nil
	}
	var block []yamlLine
	for _, l := range lines[start+1:] {
		if l.indent == 0 {
			break
		}
		block = append(block, l)
	}
	var out []continueServer
	var problems []string
	// Split into sequence items.
	var items [][]yamlLine
	itemIndent := -1
	for _, l := range block {
		if strings.HasPrefix(l.text, "- ") || l.text == "-" {
			if itemIndent < 0 {
				itemIndent = l.indent
			}
			if l.indent == itemIndent {
				items = append(items, nil)
				rest := strings.TrimSpace(strings.TrimPrefix(l.text, "-"))
				if rest != "" {
					// The first key sits after "- ", two columns in.
					items[len(items)-1] = append(items[len(items)-1], yamlLine{indent: l.indent + 2, text: rest})
				}
				continue
			}
		}
		if len(items) == 0 {
			problems = append(problems, "mcpServers is not a list")
			return nil, problems, nil
		}
		items[len(items)-1] = append(items[len(items)-1], l)
	}
	for i, it := range items {
		cs, err := yamlServer(it)
		if err != nil {
			problems = append(problems, fmt.Sprintf("mcpServers[%d]: %v", i, err))
			continue
		}
		out = append(out, cs)
	}
	return out, problems, nil
}

type yamlLine struct {
	indent int
	text   string
}

// yamlLines drops blank lines, comments and document markers, and records
// each line's indentation.
func yamlLines(s string) []yamlLine {
	var out []yamlLine
	for _, raw := range strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n") {
		line := stripYAMLComment(raw)
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || trimmed == "---" || trimmed == "..." {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " \t"))
		out = append(out, yamlLine{indent: indent, text: strings.TrimRight(trimmed, " \t")})
	}
	return out
}

// stripYAMLComment cuts a " #" comment that is not inside quotes.
func stripYAMLComment(s string) string {
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#' && (i == 0 || s[i-1] == ' ' || s[i-1] == '\t'):
			return s[:i]
		}
	}
	return s
}

// yamlServer reads one sequence item's mapping.
func yamlServer(lines []yamlLine) (continueServer, error) {
	var cs continueServer
	if len(lines) == 0 {
		return cs, fmt.Errorf("empty item")
	}
	base := lines[0].indent
	for i := 0; i < len(lines); i++ {
		l := lines[i]
		if l.indent != base {
			continue // nested content of a key handled below
		}
		key, val, ok := splitKV(l.text)
		if !ok {
			return cs, fmt.Errorf("line %q is not a key: value pair", trimTo(l.text, 40))
		}
		// Nested block for an empty value.
		var nested []yamlLine
		for j := i + 1; j < len(lines) && lines[j].indent > base; j++ {
			nested = append(nested, lines[j])
		}
		switch key {
		case "name":
			cs.Name = unquote(val)
		case "uses":
			cs.Uses = unquote(val)
			if cs.Name == "" {
				cs.Name = cs.Uses
			}
		case "command":
			cs.Command = unquote(val)
		case "url":
			cs.URL = unquote(val)
		case "type":
			cs.Type = unquote(val)
		case "args":
			if val != "" {
				cs.Args = flowList(val)
			} else {
				for _, n := range nested {
					if strings.HasPrefix(n.text, "- ") || n.text == "-" {
						cs.Args = append(cs.Args, unquote(strings.TrimSpace(strings.TrimPrefix(n.text, "-"))))
					}
				}
			}
		case "env":
			cs.Env = map[string]string{}
			if val != "" {
				for k, v := range flowMap(val) {
					cs.Env[k] = v
				}
			} else {
				for _, n := range nested {
					if k, v, ok := splitKV(n.text); ok {
						cs.Env[unquote(k)] = unquote(v)
					}
				}
			}
		}
	}
	return cs, nil
}

// splitKV splits "key: value" (value may be empty).
func splitKV(s string) (string, string, bool) {
	i := strings.Index(s, ":")
	if i <= 0 {
		return "", "", false
	}
	if i+1 < len(s) && s[i+1] != ' ' && s[i+1] != '\t' {
		// "https://x" style colons inside a scalar are not a key separator.
		j := strings.Index(s[i+1:], ": ")
		if j < 0 {
			return "", "", false
		}
		i = i + 1 + j
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:]), true
}

// flowList reads [a, "b c", 'd'].
func flowList(s string) []string {
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "[") || !strings.HasSuffix(s, "]") {
		return []string{unquote(s)}
	}
	var out []string
	for _, part := range splitFlow(s[1 : len(s)-1]) {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, unquote(p))
		}
	}
	return out
}

// flowMap reads {A: b, "C": 'd'}.
func flowMap(s string) map[string]string {
	out := map[string]string{}
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
		return out
	}
	for _, part := range splitFlow(s[1 : len(s)-1]) {
		if k, v, ok := splitKV(strings.TrimSpace(part)); ok {
			out[unquote(k)] = unquote(v)
		}
	}
	return out
}

// splitFlow splits on commas outside quotes.
func splitFlow(s string) []string {
	var out []string
	var q byte
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == ',':
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func trimTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
