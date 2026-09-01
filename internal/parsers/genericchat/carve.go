package genericchat

import (
	"encoding/json"
	"time"
)

// carved is one JSON message fragment recovered from a binary store.
type carved struct {
	msg    json.RawMessage
	offset int64
}

// maxFragment bounds one carved object (hostile input).
const maxFragment = 256 << 10

// CarveMessages string-carves JSON message objects out of a binary blob
// (e.g. Cursor's SQLite store.db) — the classic forensic technique of
// recovering structured fragments without a format driver. Only objects
// that parse as JSON AND look like chat messages (role/text/content
// present) are returned. Carved evidence is marked as such downstream;
// it proves presence of content, not database-level ordering.
func CarveMessages(data []byte) []carved {
	var out []carved
	seen := map[string]bool{}
	for i := 0; i+2 < len(data); i++ {
		if data[i] != '{' || data[i+1] != '"' {
			continue
		}
		frag, ok := balancedObject(data[i:])
		if !ok {
			continue
		}
		if !looksLikeMessage(frag) {
			continue
		}
		key := string(frag)
		if seen[key] {
			i += len(frag) - 1
			continue
		}
		seen[key] = true
		out = append(out, carved{msg: json.RawMessage(frag), offset: int64(i)})
		i += len(frag) - 1
	}
	return out
}

// balancedObject returns the shortest balanced {...} starting at b[0],
// respecting JSON string quoting and escapes, bounded by maxFragment.
func balancedObject(b []byte) ([]byte, bool) {
	depth := 0
	inStr := false
	esc := false
	limit := len(b)
	if limit > maxFragment {
		limit = maxFragment
	}
	for i := 0; i < limit; i++ {
		c := b[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				frag := b[:i+1]
				if json.Valid(frag) {
					return frag, true
				}
				return nil, false
			}
		}
	}
	return nil, false
}

// looksLikeMessage keeps carving high-precision: the object must have a
// role plus some content-bearing field.
func looksLikeMessage(frag []byte) bool {
	var probe struct {
		Role    string          `json:"role"`
		Text    string          `json:"text"`
		Content json.RawMessage `json:"content"`
		Parts   json.RawMessage `json:"parts"`
	}
	if err := json.Unmarshal(frag, &probe); err != nil {
		return false
	}
	if probe.Role == "" {
		return false
	}
	return probe.Text != "" || len(probe.Content) > 0 || len(probe.Parts) > 0
}

func timeUnixMilli(ms int64) string {
	return time.UnixMilli(ms).UTC().Format(time.RFC3339)
}
