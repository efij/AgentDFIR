package mitigate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The agents' config files are hand-edited by people and rewritten by the
// agents themselves, and ~/.claude.json alone carries hundreds of keys
// agentdfir knows nothing about. Round-tripping them through a Go map
// would reorder every key and turn every number into a float, so a
// one-line deny rule would show up as a thousand-line diff. This is a
// minimal ordered JSON tree: key order, number text and unknown values
// all survive; only the nodes a control touches change.

// Obj is a JSON object with its key order.
type Obj struct {
	Keys []string
	Vals map[string]any // *Obj, []any, json.Number, string, bool, nil
}

// NewObj returns an empty object.
func NewObj() *Obj { return &Obj{Vals: map[string]any{}} }

// Get returns the value under k.
func (o *Obj) Get(k string) (any, bool) {
	v, ok := o.Vals[k]
	return v, ok
}

// Set replaces or appends k.
func (o *Obj) Set(k string, v any) {
	if _, ok := o.Vals[k]; !ok {
		o.Keys = append(o.Keys, k)
	}
	o.Vals[k] = v
}

// Delete removes k.
func (o *Obj) Delete(k string) {
	if _, ok := o.Vals[k]; !ok {
		return
	}
	delete(o.Vals, k)
	for i, x := range o.Keys {
		if x == k {
			o.Keys = append(o.Keys[:i], o.Keys[i+1:]...)
			break
		}
	}
}

// Child returns the object under k, creating it when absent. It fails
// when k holds something that is not an object: overwriting a value we do
// not understand is how a config file gets broken.
func (o *Obj) Child(k string) (*Obj, error) {
	v, ok := o.Vals[k]
	if !ok || v == nil {
		c := NewObj()
		o.Set(k, c)
		return c, nil
	}
	c, ok := v.(*Obj)
	if !ok {
		return nil, fmt.Errorf("%q is not an object", k)
	}
	return c, nil
}

// List returns the array under k, or nil when absent.
func (o *Obj) List(k string) ([]any, error) {
	v, ok := o.Vals[k]
	if !ok || v == nil {
		return nil, nil
	}
	l, ok := v.([]any)
	if !ok {
		return nil, fmt.Errorf("%q is not an array", k)
	}
	return l, nil
}

// ParseJSON reads one JSON document into the ordered tree.
func ParseJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	v, err := parseValue(dec)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("trailing data after the JSON document")
	}
	return v, nil
}

func parseValue(dec *json.Decoder) (any, error) {
	t, err := dec.Token()
	if err != nil {
		return nil, err
	}
	switch x := t.(type) {
	case json.Delim:
		switch x {
		case '{':
			o := NewObj()
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, err
				}
				k, ok := kt.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				o.Set(k, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return o, nil
		case '[':
			l := []any{}
			for dec.More() {
				v, err := parseValue(dec)
				if err != nil {
					return nil, err
				}
				l = append(l, v)
			}
			if _, err := dec.Token(); err != nil {
				return nil, err
			}
			return l, nil
		}
		return nil, fmt.Errorf("unexpected %v", x)
	default:
		return t, nil // string, json.Number, bool, nil
	}
}

// Style is the indentation a file already uses, so a rewrite matches it.
type Style struct {
	Indent   string
	TrailNL  bool
	HadInput bool
}

// DetectStyle reads the indentation of an existing document.
func DetectStyle(b []byte) Style {
	st := Style{Indent: "  ", TrailNL: true}
	if len(bytes.TrimSpace(b)) == 0 {
		return st
	}
	st.HadInput = true
	st.TrailNL = bytes.HasSuffix(b, []byte("\n"))
	for _, line := range strings.Split(string(b), "\n")[1:] {
		trimmed := strings.TrimLeft(line, " \t")
		if trimmed == "" || len(trimmed) == len(line) {
			continue
		}
		st.Indent = line[:len(line)-len(trimmed)]
		break
	}
	return st
}

// MarshalJSON renders the tree with the given style.
func MarshalJSON(v any, st Style) ([]byte, error) {
	var b bytes.Buffer
	if err := writeValue(&b, v, st.Indent, 0); err != nil {
		return nil, err
	}
	if st.TrailNL {
		b.WriteByte('\n')
	}
	return b.Bytes(), nil
}

func writeValue(b *bytes.Buffer, v any, ind string, depth int) error {
	switch x := v.(type) {
	case *Obj:
		if len(x.Keys) == 0 {
			b.WriteString("{}")
			return nil
		}
		b.WriteString("{\n")
		for i, k := range x.Keys {
			b.WriteString(strings.Repeat(ind, depth+1))
			writeString(b, k)
			b.WriteString(": ")
			if err := writeValue(b, x.Vals[k], ind, depth+1); err != nil {
				return err
			}
			if i < len(x.Keys)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat(ind, depth))
		b.WriteByte('}')
	case []any:
		if len(x) == 0 {
			b.WriteString("[]")
			return nil
		}
		b.WriteString("[\n")
		for i, e := range x {
			b.WriteString(strings.Repeat(ind, depth+1))
			if err := writeValue(b, e, ind, depth+1); err != nil {
				return err
			}
			if i < len(x)-1 {
				b.WriteByte(',')
			}
			b.WriteByte('\n')
		}
		b.WriteString(strings.Repeat(ind, depth))
		b.WriteByte(']')
	case string:
		writeString(b, x)
	case json.Number:
		b.WriteString(x.String())
	case bool:
		if x {
			b.WriteString("true")
		} else {
			b.WriteString("false")
		}
	case nil:
		b.WriteString("null")
	default:
		return fmt.Errorf("unsupported JSON value %T", v)
	}
	return nil
}

func writeString(b *bytes.Buffer, s string) {
	var tmp bytes.Buffer
	enc := json.NewEncoder(&tmp)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	b.Write(bytes.TrimRight(tmp.Bytes(), "\n"))
}

// stringsIn returns the string members of a JSON array.
func stringsIn(l []any) []string {
	out := make([]string, 0, len(l))
	for _, v := range l {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}
