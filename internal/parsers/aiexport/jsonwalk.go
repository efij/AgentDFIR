package aiexport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Account exports are single JSON documents, often one line and often
// hundreds of megabytes. They are never decoded whole: the top-level array
// is walked with the json.Decoder token API and one element (one
// conversation) is held at a time, bounded by MaxElementBytes. Every
// element is located by its byte offset and line in the sealed artifact so
// an event can point at the exact place it was read from.

// errElementTooLarge stops a walk whose current element exceeds the bound.
var errElementTooLarge = errors.New("element exceeds the per-element bound")

// countingReader counts the bytes and newlines read from the artifact and
// refuses to keep reading once the element being decoded has grown past
// maxSpan bytes, so a hostile single element cannot exhaust memory.
type countingReader struct {
	r       io.Reader
	n       int64 // bytes read from r
	lines   int64 // newlines among them
	mark    int64 // offset where the current element starts
	maxSpan int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.maxSpan > 0 && c.n-c.mark > c.maxSpan {
		return 0, errElementTooLarge
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	c.lines += int64(bytes.Count(p[:n], []byte{'\n'}))
	return n, err
}

// element is one value of a top-level JSON array.
type element struct {
	Index  int
	Raw    json.RawMessage
	Offset int64 // byte offset of the element's first byte
	Line   int   // 1-based line of that byte
}

// walkError describes where a walk stopped and why.
type walkError struct {
	Index  int   // elements fully read before the failure
	Offset int64 // byte offset reached
	Line   int
	Reason string
}

func (e *walkError) Error() string {
	return fmt.Sprintf("%s at byte %d (line %d) after %d element(s)", e.Reason, e.Offset, e.Line, e.Index)
}

// walkArray streams the top-level array in r and calls fn per element.
// A document that is not an array, is truncated or holds an element over
// maxElem bytes returns a *walkError; elements already delivered stay
// delivered.
func walkArray(r io.Reader, maxElem int64, fn func(el element) error) error {
	cr := &countingReader{r: r}
	dec := json.NewDecoder(cr)
	lineAt := func() int {
		buffered, _ := io.ReadAll(dec.Buffered())
		return int(1 + cr.lines - int64(bytes.Count(buffered, []byte{'\n'})))
	}
	tok, err := dec.Token()
	if err != nil {
		return &walkError{Offset: dec.InputOffset(), Line: lineAt(), Reason: "not a JSON document"}
	}
	if d, ok := tok.(json.Delim); !ok || d != '[' {
		return &walkError{Offset: dec.InputOffset(), Line: lineAt(), Reason: "top-level value is not an array"}
	}
	i := 0
	for dec.More() {
		cr.mark, cr.maxSpan = dec.InputOffset(), maxElem
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			reason := "truncated or malformed JSON"
			if errors.Is(err, errElementTooLarge) {
				reason = fmt.Sprintf("element exceeds the %d-byte bound", maxElem)
			}
			return &walkError{Index: i, Offset: cr.mark, Line: lineAt(), Reason: reason}
		}
		cr.maxSpan = 0
		end := dec.InputOffset()
		line := lineAt() - bytes.Count(raw, []byte{'\n'})
		if err := fn(element{Index: i, Raw: raw, Offset: end - int64(len(raw)), Line: line}); err != nil {
			return err
		}
		i++
	}
	if _, err := dec.Token(); err != nil {
		return &walkError{Index: i, Offset: dec.InputOffset(), Line: lineAt(), Reason: "array is not terminated (truncated export)"}
	}
	return nil
}

// member is one key/value of an in-memory JSON object or one element of
// an in-memory JSON array, located relative to the start of its parent.
type member struct {
	Key    string // object key; "" for array elements
	Index  int    // array index; position for object members
	Raw    json.RawMessage
	RelOff int64
}

// membersOf iterates an object's members (or an array's elements) in
// document order. limit bounds how many are delivered; the second return
// reports whether the value had more than that.
func membersOf(raw json.RawMessage, limit int, fn func(m member)) (truncated bool, err error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return false, err
	}
	d, ok := tok.(json.Delim)
	if !ok || (d != '{' && d != '[') {
		return false, errors.New("not an object or array")
	}
	for i := 0; dec.More(); i++ {
		if i >= limit {
			return true, nil
		}
		var key string
		if d == '{' {
			kt, err := dec.Token()
			if err != nil {
				return false, err
			}
			key, _ = kt.(string)
		}
		var v json.RawMessage
		if err := dec.Decode(&v); err != nil {
			return false, err
		}
		fn(member{Key: key, Index: i, Raw: v, RelOff: dec.InputOffset() - int64(len(v))})
	}
	return false, nil
}

// pointer builds an RFC 6901 JSON Pointer from path tokens.
func pointer(tokens ...any) string {
	var b strings.Builder
	for _, t := range tokens {
		b.WriteByte('/')
		switch v := t.(type) {
		case int:
			b.WriteString(strconv.Itoa(v))
		case string:
			b.WriteString(strings.NewReplacer("~", "~0", "/", "~1").Replace(v))
		}
	}
	return b.String()
}

// lineOf returns the 1-based line of byte rel inside raw, given the line
// raw starts on.
func lineOf(raw []byte, startLine int, rel int64) int {
	if rel < 0 || rel > int64(len(raw)) {
		return startLine
	}
	return startLine + bytes.Count(raw[:rel], []byte{'\n'})
}
