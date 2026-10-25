package mcpaudit

import (
	"encoding/json"
	"sort"
)

// Entry points for the supply-chain timeline (internal/supplychain): one
// historical copy of a config or a cached tool manifest is parsed the same
// way the audit parses the current one, so a round-by-round comparison
// never runs through a second parser.

// ParseArtifact parses one copy of the file at a package logical path.
// ok is false when the path is not an MCP configuration this package
// knows. Problems land in the returned inventory, never silently.
func ParseArtifact(logical string, data []byte) (inv *Inventory, ok bool) {
	host, scope, f, ok := classify(logical)
	if !ok {
		return nil, false
	}
	inv = &Inventory{Source: logical, Mode: "package"}
	if int64(len(data)) > MaxConfigBytes {
		inv.Problems = append(inv.Problems, logical+": exceeds size bound, not parsed")
		return inv, true
	}
	parseInto(inv, host, scope, logical, logical, f, data)
	finish(inv)
	return inv, true
}

// IsConfigPath reports whether a logical path is an MCP configuration.
func IsConfigPath(logical string) bool {
	_, _, _, ok := classify(logical)
	return ok
}

// ServerTools reads a cached tool manifest and returns the tool
// declarations it holds, grouped by the server they are filed under: the
// key of the object holding a "tools" array, or that object's own
// "name"/"serverName". Declarations found outside any such object are
// filed under "". Depth and count are bounded.
func ServerTools(data []byte) map[string][]Tool {
	if int64(len(data)) > MaxConfigBytes {
		return nil
	}
	var doc any
	if err := json.Unmarshal(stripJSONC(data), &doc); err != nil {
		return nil
	}
	out := map[string][]Tool{}
	count := 0
	var walk func(v any, key string, depth int)
	walk = func(v any, key string, depth int) {
		if depth > 12 || count > 10000 {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			if arr, ok := t["tools"].([]any); ok {
				server := key
				if n, ok := t["serverName"].(string); ok && n != "" {
					server = n
				} else if n, ok := t["name"].(string); ok && n != "" {
					if _, isTool := t["inputSchema"]; !isTool {
						server = n
					}
				}
				for _, e := range arr {
					if m, ok := e.(map[string]any); ok {
						if name, _ := m["name"].(string); name != "" {
							out[server] = append(out[server], toolFromMap(m))
							count++
						}
					}
				}
			} else if name, _ := t["name"].(string); name != "" {
				if _, has := t["inputSchema"]; has {
					out[key] = append(out[key], toolFromMap(t))
					count++
					return
				}
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				if k != "tools" {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k], k, depth+1)
			}
		case []any:
			for _, e := range t {
				walk(e, key, depth+1)
			}
		}
	}
	walk(doc, "", 0)
	return out
}
