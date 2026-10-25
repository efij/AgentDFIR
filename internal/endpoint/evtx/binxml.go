package evtx

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Binary XML (BinXml) as stored in EVTX chunks. Names and template
// definitions are referenced by chunk-relative offsets, so every cursor
// works on the whole 64 KiB chunk buffer and is bounded by an end offset.

// Token values. The 0x40 bit on element, value, attribute, CDATA, char-ref
// and entity-ref tokens means "more data follows"; it is masked off.
const (
	tokEOF           = 0x00
	tokOpenStart     = 0x01
	tokCloseStart    = 0x02
	tokCloseEmpty    = 0x03
	tokEndElement    = 0x04
	tokValue         = 0x05
	tokAttribute     = 0x06
	tokCDATA         = 0x07
	tokCharRef       = 0x08
	tokEntityRef     = 0x09
	tokPITarget      = 0x0a
	tokPIData        = 0x0b
	tokTemplate      = 0x0c
	tokNormalSub     = 0x0d
	tokOptionalSub   = 0x0e
	tokFragmentHdr   = 0x0f
	tokHasMore       = 0x40
	maxDepth         = 32      // element / nested-BinXml / template nesting
	maxNodesPerChunk = 1 << 18 // parsed-node budget shared by one chunk
	maxRenderNodes   = 1 << 16 // rendered nodes per record
	maxRenderText    = 4 << 20 // rendered text bytes per record
	// A chunk holds at most ~2300 records; these cap the total work one
	// hostile chunk can cause through shared templates and nested values.
	maxChunkRenderNodes = 1 << 20
	maxChunkRenderText  = 32 << 20
)

// Value types.
const (
	vtNull       = 0x00
	vtString     = 0x01
	vtAnsi       = 0x02
	vtInt8       = 0x03
	vtUint8      = 0x04
	vtInt16      = 0x05
	vtUint16     = 0x06
	vtInt32      = 0x07
	vtUint32     = 0x08
	vtInt64      = 0x09
	vtUint64     = 0x0a
	vtReal32     = 0x0b
	vtReal64     = 0x0c
	vtBool       = 0x0d
	vtBinary     = 0x0e
	vtGUID       = 0x0f
	vtSizeT      = 0x10
	vtFileTime   = 0x11
	vtSysTime    = 0x12
	vtSID        = 0x13
	vtHexInt32   = 0x14
	vtHexInt64   = 0x15
	vtEvtHandle  = 0x20
	vtBinXML     = 0x21
	vtEvtXML     = 0x23
	vtArrayFlag  = 0x80
	filetimeUnix = 116444736000000000 // 1601-01-01 → 1970-01-01 in 100 ns ticks
)

var (
	errTruncated = errors.New("binxml: truncated")
	errDepth     = errors.New("binxml: nesting too deep")
	errBudget    = errors.New("binxml: node budget exhausted")
)

// cursor is a bounds-checked little-endian reader over a chunk buffer.
// Errors are sticky: after the first out-of-range read every read
// returns zero and err is set.
type cursor struct {
	b        []byte
	pos, end int
	err      error
}

func (c *cursor) need(n int) bool {
	if c.err != nil {
		return false
	}
	if n < 0 || c.pos+n > c.end || c.pos+n > len(c.b) {
		c.err = errTruncated
		return false
	}
	return true
}

func (c *cursor) u8() byte {
	if !c.need(1) {
		return 0
	}
	v := c.b[c.pos]
	c.pos++
	return v
}

func (c *cursor) u16() uint16 {
	if !c.need(2) {
		return 0
	}
	v := binary.LittleEndian.Uint16(c.b[c.pos:])
	c.pos += 2
	return v
}

func (c *cursor) u32() uint32 {
	if !c.need(4) {
		return 0
	}
	v := binary.LittleEndian.Uint32(c.b[c.pos:])
	c.pos += 4
	return v
}

func (c *cursor) peek() (byte, bool) {
	if c.err != nil || c.pos >= c.end || c.pos >= len(c.b) {
		return 0, false
	}
	return c.b[c.pos], true
}

func (c *cursor) utf16(chars int) string {
	if !c.need(chars * 2) {
		return ""
	}
	s := decodeUTF16(c.b[c.pos : c.pos+chars*2])
	c.pos += chars * 2
	return s
}

// node is one parsed BinXml item. A template body is parsed once per
// chunk into nodes that still contain substitution placeholders.
type node struct {
	kind     byte // a token value (tokOpenStart, tokValue, tokNormalSub, …)
	name     string
	text     string
	attrs    []attr
	children []*node
	sub      uint16 // substitution index
	char     uint16 // char-ref code unit
	tmpl     *template
	values   []value
}

type attr struct {
	name  string
	parts []*node
}

type template struct {
	nodes []*node
}

// value is one substitution value; data stays in the chunk buffer
// because a nested BinXml value can reference chunk offsets.
type value struct {
	typ       byte
	off, size int
}

// chunkParser holds the per-chunk caches: name strings and template
// definitions by offset.
type chunkParser struct {
	b         []byte
	names     map[int]string
	templates map[int]*template
	building  map[int]bool
	budget    int
	// rendering work across all records of the chunk
	rendered, renderedText int
}

func newChunkParser(b []byte) *chunkParser {
	return &chunkParser{b: b, names: map[int]string{}, templates: map[int]*template{}, building: map[int]bool{}, budget: maxNodesPerChunk}
}

func (p *chunkParser) newNode(kind byte) (*node, error) {
	p.budget--
	if p.budget < 0 {
		return nil, errBudget
	}
	return &node{kind: kind}, nil
}

// nameAt parses a name structure at a chunk offset: next-string offset
// (4), hash (2), character count (2), UTF-16 characters, NUL (2).
// It returns the name and the offset just past it.
func (p *chunkParser) nameAt(off int) (string, int, error) {
	if off < 0 || off+8 > len(p.b) {
		return "", 0, fmt.Errorf("binxml: name offset %d out of range", off)
	}
	n := int(binary.LittleEndian.Uint16(p.b[off+6:]))
	endOff := off + 8 + 2*n + 2
	if endOff > len(p.b) {
		return "", 0, fmt.Errorf("binxml: name at %d overruns chunk", off)
	}
	if s, ok := p.names[off]; ok {
		return s, endOff, nil
	}
	s := decodeUTF16(p.b[off+8 : off+8+2*n])
	p.names[off] = s
	return s, endOff, nil
}

// readName reads a 4-byte name offset. When the offset is the current
// position the name is stored inline and the cursor moves past it;
// otherwise it refers to a name defined earlier in the chunk.
func (p *chunkParser) readName(c *cursor) (string, error) {
	off := int(c.u32())
	if c.err != nil {
		return "", c.err
	}
	if off == c.pos {
		s, next, err := p.nameAt(off)
		if err != nil {
			return "", err
		}
		if next > c.end {
			return "", errTruncated
		}
		c.pos = next
		return s, nil
	}
	if off >= c.pos {
		return "", fmt.Errorf("binxml: forward name reference %d", off)
	}
	s, _, err := p.nameAt(off)
	return s, err
}

// validNameRef reports whether a name offset read at position at (the
// offset field's own position) is plausible: inline right after the
// field, or an earlier offset in the chunk holding a well-formed name.
func (p *chunkParser) validNameRef(off, at int) bool {
	if off == at+4 {
		return off+8 <= len(p.b)
	}
	if off < chunkHeaderSize || off+10 > at { // names live in the record area
		return false
	}
	n := int(binary.LittleEndian.Uint16(p.b[off+6:]))
	return n < 0x4000 && off+8+2*n+2 <= at
}

// parseFragment reads tokens until EOF or the cursor end, returning the
// top-level nodes (normally one element or one template instance).
func (p *chunkParser) parseFragment(c *cursor, depth int) ([]*node, error) {
	if depth > maxDepth {
		return nil, errDepth
	}
	var out []*node
	for {
		tok, ok := c.peek()
		if !ok {
			return out, c.err
		}
		switch tok &^ tokHasMore {
		case tokEOF:
			c.pos++
			return out, nil
		case tokFragmentHdr:
			c.pos++
			c.u8() // major
			c.u8() // minor
			c.u8() // flags
		case tokTemplate:
			c.pos++
			n, err := p.parseTemplateInstance(c, depth+1)
			if err != nil {
				return out, err
			}
			out = append(out, n)
		case tokOpenStart:
			n, err := p.parseElement(c, depth+1)
			if err != nil {
				return out, err
			}
			out = append(out, n)
		default:
			n, err := p.parseContent(c, depth+1)
			if err != nil {
				return out, err
			}
			out = append(out, n)
		}
		if c.err != nil {
			return out, c.err
		}
	}
}

// parseElement reads an open-start-element token through its end tag.
// The 2-byte dependency identifier is absent in some nested fragments,
// so both layouts are tried and the one whose name reference is
// plausible wins.
func (p *chunkParser) parseElement(c *cursor, depth int) (*node, error) {
	if depth > maxDepth {
		return nil, errDepth
	}
	tok := c.u8()
	if c.err != nil {
		return nil, c.err
	}
	start := c.pos
	lim := c.end
	if len(c.b) < lim {
		lim = len(c.b)
	}
	switch {
	case start+10 <= lim && p.validNameRef(int(binary.LittleEndian.Uint32(c.b[start+6:])), start+6):
		c.pos = start + 2 // skip the dependency identifier
	case start+8 <= lim && p.validNameRef(int(binary.LittleEndian.Uint32(c.b[start+4:])), start+4):
	default:
		return nil, fmt.Errorf("binxml: element at %d has no valid name reference", start-1)
	}
	c.u32() // data size
	el, err := p.newNode(tokOpenStart)
	if err != nil {
		return nil, err
	}
	if el.name, err = p.readName(c); err != nil {
		return nil, err
	}
	if tok&tokHasMore != 0 {
		c.u32() // attribute list size
	}
	// Attributes.
	for {
		t, ok := c.peek()
		if !ok {
			return nil, errTruncated
		}
		if t&^tokHasMore != tokAttribute {
			break
		}
		c.pos++
		name, err := p.readName(c)
		if err != nil {
			return nil, err
		}
		a := attr{name: name}
		for {
			t, ok := c.peek()
			if !ok {
				return nil, errTruncated
			}
			if !isContentToken(t &^ tokHasMore) {
				break
			}
			n, err := p.parseContent(c, depth+1)
			if err != nil {
				return nil, err
			}
			a.parts = append(a.parts, n)
		}
		el.attrs = append(el.attrs, a)
	}
	switch t := c.u8(); t {
	case tokCloseEmpty:
		return el, nil
	case tokCloseStart:
	default:
		if c.err != nil {
			return nil, c.err
		}
		return nil, fmt.Errorf("binxml: unexpected token 0x%02x closing start element %q", t, el.name)
	}
	// Content.
	for {
		t, ok := c.peek()
		if !ok {
			return nil, errTruncated
		}
		switch t &^ tokHasMore {
		case tokEndElement:
			c.pos++
			return el, nil
		case tokOpenStart:
			ch, err := p.parseElement(c, depth+1)
			if err != nil {
				return nil, err
			}
			el.children = append(el.children, ch)
		case tokTemplate:
			c.pos++
			ch, err := p.parseTemplateInstance(c, depth+1)
			if err != nil {
				return nil, err
			}
			el.children = append(el.children, ch)
		case tokEOF:
			return nil, fmt.Errorf("binxml: end of fragment inside element %q", el.name)
		default:
			ch, err := p.parseContent(c, depth+1)
			if err != nil {
				return nil, err
			}
			el.children = append(el.children, ch)
		}
	}
}

func isContentToken(t byte) bool {
	switch t {
	case tokValue, tokCDATA, tokCharRef, tokEntityRef, tokPITarget, tokPIData, tokNormalSub, tokOptionalSub:
		return true
	}
	return false
}

// parseContent reads one text-like token.
func (p *chunkParser) parseContent(c *cursor, depth int) (*node, error) {
	if depth > maxDepth {
		return nil, errDepth
	}
	t := c.u8() &^ tokHasMore
	n, err := p.newNode(t)
	if err != nil {
		return nil, err
	}
	switch t {
	case tokValue:
		vt := c.u8()
		if vt != vtString {
			if c.err != nil {
				return nil, c.err
			}
			return nil, fmt.Errorf("binxml: value text of type 0x%02x", vt)
		}
		n.text = c.utf16(int(c.u16()))
	case tokCDATA, tokPIData:
		n.text = c.utf16(int(c.u16()))
	case tokCharRef:
		n.char = c.u16()
	case tokEntityRef, tokPITarget:
		if n.name, err = p.readName(c); err != nil {
			return nil, err
		}
	case tokNormalSub, tokOptionalSub:
		n.sub = c.u16()
		c.u8() // declared value type; the substitution array carries the real one
	default:
		if c.err != nil {
			return nil, c.err
		}
		return nil, fmt.Errorf("binxml: unexpected token 0x%02x at %d", t, c.pos-1)
	}
	return n, c.err
}

// parseTemplateInstance reads a template instance (the token byte is
// already consumed): unknown byte, template id, definition offset, an
// inline definition when the offset is the current position, then the
// substitution array.
func (p *chunkParser) parseTemplateInstance(c *cursor, depth int) (*node, error) {
	if depth > maxDepth {
		return nil, errDepth
	}
	c.u8()  // unknown
	c.u32() // template id
	defOff := int(c.u32())
	if c.err != nil {
		return nil, c.err
	}
	var tmpl *template
	var err error
	switch {
	case defOff == c.pos:
		var next int
		tmpl, next, err = p.templateAt(defOff, depth)
		if err != nil {
			return nil, err
		}
		if next > c.end {
			return nil, errTruncated
		}
		c.pos = next
	case defOff < c.pos:
		if tmpl, _, err = p.templateAt(defOff, depth); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("binxml: forward template reference %d", defOff)
	}
	count := int(c.u32())
	if c.err != nil {
		return nil, c.err
	}
	if count < 0 || count > (c.end-c.pos)/4 {
		return nil, fmt.Errorf("binxml: %d substitution values do not fit", count)
	}
	vals := make([]value, count)
	for i := range vals {
		vals[i].size = int(c.u16())
		vals[i].typ = c.u8()
		c.u8()
	}
	for i := range vals {
		if !c.need(vals[i].size) {
			return nil, c.err
		}
		vals[i].off = c.pos
		c.pos += vals[i].size
	}
	n, err := p.newNode(tokTemplate)
	if err != nil {
		return nil, err
	}
	n.tmpl, n.values = tmpl, vals
	return n, nil
}

// templateAt parses (or returns the cached) template definition at a
// chunk offset: next-definition offset (4), GUID (16), data size (4),
// body. It returns the template and the offset past the body.
func (p *chunkParser) templateAt(off, depth int) (*template, int, error) {
	if off < 0 || off+24 > len(p.b) {
		return nil, 0, fmt.Errorf("binxml: template offset %d out of range", off)
	}
	size := int(binary.LittleEndian.Uint32(p.b[off+20:]))
	end := off + 24 + size
	if size < 0 || end > len(p.b) {
		return nil, 0, fmt.Errorf("binxml: template at %d overruns chunk", off)
	}
	if t, ok := p.templates[off]; ok {
		return t, end, nil
	}
	if p.building[off] {
		return nil, 0, fmt.Errorf("binxml: template at %d references itself", off)
	}
	p.building[off] = true
	defer delete(p.building, off)
	body := &cursor{b: p.b, pos: off + 24, end: end}
	nodes, err := p.parseFragment(body, depth+1)
	if err != nil {
		return nil, 0, err
	}
	t := &template{nodes: nodes}
	p.templates[off] = t
	return t, end, nil
}

// Elem is a rendered XML element.
type Elem struct {
	Name     string
	Attrs    []Attr
	Children []*Elem
	Text     string
}

// Attr is a rendered attribute.
type Attr struct{ Name, Value string }

// Attr returns an attribute value by name.
func (e *Elem) Attr(name string) string {
	if e == nil {
		return ""
	}
	for _, a := range e.Attrs {
		if a.Name == name {
			return a.Value
		}
	}
	return ""
}

// Child returns the first child element with the given name.
func (e *Elem) Child(name string) *Elem {
	if e == nil {
		return nil
	}
	for _, c := range e.Children {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// renderer turns parsed nodes plus substitution values into Elems.
type renderer struct {
	p         *chunkParser
	nodes     int
	textBytes int
}

func (r *renderer) render(nodes []*node, vals []value, depth int) ([]*Elem, string, error) {
	if depth > maxDepth {
		return nil, "", errDepth
	}
	var elems []*Elem
	var text strings.Builder
	for _, n := range nodes {
		r.nodes++
		r.p.rendered++
		if r.nodes > maxRenderNodes || r.textBytes+text.Len() > maxRenderText ||
			r.p.rendered > maxChunkRenderNodes || r.p.renderedText+text.Len() > maxChunkRenderText {
			return nil, "", errBudget
		}
		switch n.kind {
		case tokOpenStart:
			e, err := r.element(n, vals, depth+1)
			if err != nil {
				return nil, "", err
			}
			if e != nil {
				elems = append(elems, e)
			}
		case tokTemplate:
			es, t, err := r.render(n.tmpl.nodes, n.values, depth+1)
			if err != nil {
				return nil, "", err
			}
			elems = append(elems, es...)
			text.WriteString(t)
		case tokNormalSub, tokOptionalSub:
			if int(n.sub) >= len(vals) {
				continue
			}
			v := vals[n.sub]
			if v.typ == vtBinXML {
				es, t, err := r.nested(v, depth+1)
				if err != nil {
					return nil, "", err
				}
				elems = append(elems, es...)
				text.WriteString(t)
				continue
			}
			text.WriteString(r.p.format(v))
		default:
			text.WriteString(literal(n))
		}
	}
	r.textBytes += text.Len()
	r.p.renderedText += text.Len()
	return elems, text.String(), nil
}

// spend charges one node and n text bytes to the per-record and
// per-chunk render budgets, failing once any of them is exceeded.
func (r *renderer) spend(n int) error {
	r.nodes++
	r.p.rendered++
	r.textBytes += n
	r.p.renderedText += n
	if r.nodes > maxRenderNodes || r.textBytes > maxRenderText ||
		r.p.rendered > maxChunkRenderNodes || r.p.renderedText > maxChunkRenderText {
		return errBudget
	}
	return nil
}

func (r *renderer) element(n *node, vals []value, depth int) (*Elem, error) {
	if err := r.spend(0); err != nil {
		return nil, err
	}
	e := &Elem{Name: n.name}
	for _, a := range n.attrs {
		var sb strings.Builder
		omit := len(a.parts) > 0
		for _, part := range a.parts {
			var t string
			switch part.kind {
			case tokNormalSub, tokOptionalSub:
				if int(part.sub) >= len(vals) {
					if err := r.spend(0); err != nil {
						return nil, err
					}
					continue
				}
				v := vals[part.sub]
				if part.kind == tokNormalSub || (v.typ != vtNull && v.size > 0) {
					omit = false
				}
				if v.typ == vtBinXML {
					_, nt, err := r.nested(v, depth+1)
					if err != nil {
						return nil, err
					}
					t = nt
				} else {
					t = r.p.format(v)
				}
			default:
				omit = false
				t = literal(part)
			}
			// Attribute text counts against the same budgets as content.
			if err := r.spend(len(t)); err != nil {
				return nil, err
			}
			sb.WriteString(t)
		}
		if !omit {
			e.Attrs = append(e.Attrs, Attr{Name: a.name, Value: sb.String()})
		}
	}
	children, text, err := r.render(n.children, vals, depth+1)
	if err != nil {
		return nil, err
	}
	e.Children, e.Text = children, text
	return e, nil
}

// nested parses and renders a BinXml-typed substitution value.
func (r *renderer) nested(v value, depth int) ([]*Elem, string, error) {
	c := &cursor{b: r.p.b, pos: v.off, end: v.off + v.size}
	nodes, err := r.p.parseFragment(c, depth+1)
	if err != nil {
		return nil, "", err
	}
	return r.render(nodes, nil, depth+1)
}

func literal(n *node) string {
	switch n.kind {
	case tokValue, tokCDATA:
		return n.text
	case tokCharRef:
		return string(utf16.Decode([]uint16{n.char}))
	case tokEntityRef:
		switch n.name {
		case "amp":
			return "&"
		case "lt":
			return "<"
		case "gt":
			return ">"
		case "quot":
			return `"`
		case "apos":
			return "'"
		}
		return "&" + n.name + ";"
	}
	return "" // processing instructions are not content
}

// format renders a substitution value the way Windows renders it in XML.
func (p *chunkParser) format(v value) string {
	if v.off < 0 || v.size < 0 || v.off+v.size > len(p.b) {
		return ""
	}
	return formatValue(v.typ, p.b[v.off:v.off+v.size])
}

func formatValue(typ byte, d []byte) string {
	if typ&vtArrayFlag != 0 {
		base := typ &^ vtArrayFlag
		switch base {
		case vtString:
			parts := strings.Split(strings.TrimRight(decodeUTF16Raw(d), "\x00"), "\x00")
			return strings.Join(parts, ",")
		case vtAnsi:
			return strings.Join(strings.Split(strings.TrimRight(ansi(d), "\x00"), "\x00"), ",")
		}
		size := fixedSize(base, len(d))
		if size == 0 {
			return strings.ToUpper(hex.EncodeToString(d))
		}
		var parts []string
		for i := 0; i+size <= len(d) && len(parts) < 4096; i += size {
			parts = append(parts, formatValue(base, d[i:i+size]))
		}
		return strings.Join(parts, ",")
	}
	le := binary.LittleEndian
	switch typ {
	case vtNull:
		return ""
	case vtString:
		return strings.TrimRight(decodeUTF16(d), "\x00")
	case vtAnsi:
		return strings.TrimRight(ansi(d), "\x00")
	case vtInt8:
		if len(d) >= 1 {
			return strconv.Itoa(int(int8(d[0])))
		}
	case vtUint8:
		if len(d) >= 1 {
			return strconv.Itoa(int(d[0]))
		}
	case vtInt16:
		if len(d) >= 2 {
			return strconv.Itoa(int(int16(le.Uint16(d))))
		}
	case vtUint16:
		if len(d) >= 2 {
			return strconv.Itoa(int(le.Uint16(d)))
		}
	case vtInt32:
		if len(d) >= 4 {
			return strconv.FormatInt(int64(int32(le.Uint32(d))), 10)
		}
	case vtUint32:
		if len(d) >= 4 {
			return strconv.FormatUint(uint64(le.Uint32(d)), 10)
		}
	case vtInt64:
		if len(d) >= 8 {
			return strconv.FormatInt(int64(le.Uint64(d)), 10)
		}
	case vtUint64:
		if len(d) >= 8 {
			return strconv.FormatUint(le.Uint64(d), 10)
		}
	case vtReal32:
		if len(d) >= 4 {
			return strconv.FormatFloat(float64(math.Float32frombits(le.Uint32(d))), 'g', -1, 32)
		}
	case vtReal64:
		if len(d) >= 8 {
			return strconv.FormatFloat(math.Float64frombits(le.Uint64(d)), 'g', -1, 64)
		}
	case vtBool:
		if len(d) >= 1 {
			for _, b := range d {
				if b != 0 {
					return "true"
				}
			}
			return "false"
		}
	case vtGUID:
		if len(d) >= 16 {
			return formatGUID(d)
		}
	case vtSizeT, vtHexInt32, vtHexInt64:
		switch {
		case len(d) >= 8:
			return "0x" + strconv.FormatUint(le.Uint64(d), 16)
		case len(d) >= 4:
			return "0x" + strconv.FormatUint(uint64(le.Uint32(d)), 16)
		}
	case vtFileTime:
		if len(d) >= 8 {
			return formatTime(FileTime(le.Uint64(d)))
		}
	case vtSysTime:
		if len(d) >= 16 {
			return formatTime(systemTime(d))
		}
	case vtSID:
		if s, ok := formatSID(d); ok {
			return s
		}
	case vtEvtXML:
		return strings.TrimRight(decodeUTF16(d), "\x00")
	}
	return strings.ToUpper(hex.EncodeToString(d))
}

func fixedSize(typ byte, total int) int {
	switch typ {
	case vtInt8, vtUint8:
		return 1
	case vtInt16, vtUint16:
		return 2
	case vtInt32, vtUint32, vtReal32, vtBool, vtHexInt32:
		return 4
	case vtInt64, vtUint64, vtReal64, vtFileTime, vtHexInt64:
		return 8
	case vtGUID, vtSysTime:
		return 16
	case vtSizeT:
		if total%8 == 0 {
			return 8
		}
		return 4
	}
	return 0
}

// FileTime converts a Windows FILETIME to UTC; zero stays the zero time.
func FileTime(ft uint64) time.Time {
	if ft == 0 {
		return time.Time{}
	}
	return time.Unix(int64(ft/1e7)-filetimeUnix/1e7, int64(ft%1e7)*100).UTC()
}

func systemTime(d []byte) time.Time {
	le := binary.LittleEndian
	y, mo, day := int(le.Uint16(d)), int(le.Uint16(d[2:])), int(le.Uint16(d[6:]))
	h, mi, s, ms := int(le.Uint16(d[8:])), int(le.Uint16(d[10:])), int(le.Uint16(d[12:])), int(le.Uint16(d[14:]))
	return time.Date(y, time.Month(mo), day, h, mi, s, ms*int(time.Millisecond), time.UTC)
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05.0000000Z")
}

func formatGUID(d []byte) string {
	le := binary.LittleEndian
	return fmt.Sprintf("{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
		le.Uint32(d), le.Uint16(d[4:]), le.Uint16(d[6:]), d[8], d[9], d[10], d[11], d[12], d[13], d[14], d[15])
}

func formatSID(d []byte) (string, bool) {
	if len(d) < 8 {
		return "", false
	}
	n := int(d[1])
	if len(d) < 8+4*n {
		return "", false
	}
	var auth uint64
	for _, b := range d[2:8] {
		auth = auth<<8 | uint64(b)
	}
	var sb strings.Builder
	fmt.Fprintf(&sb, "S-%d-%d", d[0], auth)
	for i := 0; i < n; i++ {
		fmt.Fprintf(&sb, "-%d", binary.LittleEndian.Uint32(d[8+4*i:]))
	}
	return sb.String(), true
}

func decodeUTF16(b []byte) string {
	s := decodeUTF16Raw(b)
	if i := strings.IndexByte(s, 0); i >= 0 {
		return s[:i]
	}
	return s
}

func decodeUTF16Raw(b []byte) string {
	u := make([]uint16, len(b)/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2*i:])
	}
	return string(utf16.Decode(u))
}

// ansi maps single-byte text to runes (code page unknown; Latin-1 keeps
// every byte visible).
func ansi(b []byte) string {
	r := make([]rune, len(b))
	for i, c := range b {
		r[i] = rune(c)
	}
	return string(r)
}
