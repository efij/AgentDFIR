package genericchat

import (
	"encoding/json"
	"strconv"
	"strings"
)

// canonicalize rewrites one raw message using the pack's FieldMap into the
// canonical shape the tolerant engine already understands:
//
//	{"role","text","timestamp","sessionID","tool_calls":[{"function":{"name","arguments"}}]}
//
// Unmapped fields are dropped; the original bytes stay in the sealed
// artifact, so nothing is lost — only normalized.
func (fm *FieldMap) canonicalize(raw json.RawMessage) (json.RawMessage, bool) {
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, false
	}
	out := map[string]any{}
	role := asString(lookupPath(doc, fm.Role))
	switch {
	case containsFold(fm.ModelRoles, role):
		role = "assistant"
	case containsFold(fm.HumanRoles, role):
		role = "user"
	}
	if role != "" {
		out["role"] = role
	}
	if t := asString(lookupPath(doc, fm.Text)); t != "" {
		out["text"] = t
	}
	switch ts := lookupPath(doc, fm.Timestamp).(type) {
	case string:
		if ts != "" {
			out["timestamp"] = ts
		}
	case float64: // epoch seconds or milliseconds
		ms := int64(ts)
		if ts < 1e11 {
			ms = int64(ts * 1000)
		}
		if s := msToRFC3339(ms); s != "" {
			out["timestamp"] = s
		}
	}
	if sid := asString(lookupPath(doc, fm.SessionID)); sid != "" {
		out["sessionID"] = sid
	}
	if name := asString(lookupPath(doc, fm.ToolName)); name != "" {
		args := "{}"
		if a := lookupPath(doc, fm.ToolArgs); a != nil {
			switch v := a.(type) {
			case string:
				args = v
			default:
				if b, err := json.Marshal(v); err == nil {
					args = string(b)
				}
			}
		}
		if _, isModel := out["role"]; !isModel {
			out["role"] = "assistant"
		}
		out["tool_calls"] = []any{map[string]any{
			"function": map[string]any{"name": name, "arguments": args},
		}}
	}
	if len(out) == 0 {
		return nil, false
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, false
	}
	return b, true
}

// lookupPath resolves a dot-path with optional [n] indexes against a
// decoded JSON value. Empty path → nil.
func lookupPath(doc any, path string) any {
	if path == "" {
		return nil
	}
	cur := doc
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			return nil
		}
		key, idx := seg, -1
		if i := strings.IndexByte(seg, '['); i >= 0 && strings.HasSuffix(seg, "]") {
			key = seg[:i]
			n, err := strconv.Atoi(seg[i+1 : len(seg)-1])
			if err != nil {
				return nil
			}
			idx = n
		}
		if key != "" {
			m, ok := cur.(map[string]any)
			if !ok {
				return nil
			}
			cur, ok = m[key]
			if !ok {
				return nil
			}
		}
		if idx >= 0 {
			arr, ok := cur.([]any)
			if !ok || idx >= len(arr) {
				return nil
			}
			cur = arr[idx]
		}
	}
	return cur
}

func asString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		b, err := json.Marshal(t)
		if err != nil {
			return ""
		}
		return string(b)
	}
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}
