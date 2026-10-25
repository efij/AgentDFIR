// Package evtxtest writes synthetic .evtx files for tests: valid file
// headers, chunks with correct checksums and string/template tables, and
// Binary XML records built from templates with substitution arrays.
// Windows is not needed to produce fixtures, and every fixture is
// generated in the test that uses it.
package evtxtest

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
)

// Node is a template body item.
type Node interface{ node() }

// Elem is an element; Attrs values and Children are Nodes.
type Elem struct {
	Name     string
	Attrs    []Attr
	Children []Node
	NoDep    bool // omit the dependency identifier (seen in nested fragments)
}

// Attr is an attribute whose value is a sequence of Text/Sub/CharRef/EntityRef.
type Attr struct {
	Name  string
	Value []Node
}

type (
	Text      string // value text
	CDATA     string
	CharRef   uint16
	EntityRef string
	PI        struct{ Target, Data string }
	// Sub is a normal or optional substitution of value Type.
	Sub struct {
		ID       uint16
		Optional bool
		Type     byte
	}
	// Instance is a template instance inside a body (for nested BinXml values).
	Instance struct {
		Template *Template
		Values   []Value
	}
)

func (Elem) node()      {}
func (Text) node()      {}
func (CDATA) node()     {}
func (CharRef) node()   {}
func (EntityRef) node() {}
func (PI) node()        {}
func (Sub) node()       {}
func (Instance) node()  {}

// Value is one substitution value. Nested is used for type 0x21 (BinXml).
type Value struct {
	Type   byte
	Data   []byte
	Nested Node
}

// Value types.
const (
	TNull     = 0x00
	TString   = 0x01
	TAnsi     = 0x02
	TInt8     = 0x03
	TUint8    = 0x04
	TInt16    = 0x05
	TUint16   = 0x06
	TInt32    = 0x07
	TUint32   = 0x08
	TInt64    = 0x09
	TUint64   = 0x0a
	TReal32   = 0x0b
	TReal64   = 0x0c
	TBool     = 0x0d
	TBinary   = 0x0e
	TGUID     = 0x0f
	TSizeT    = 0x10
	TFileTime = 0x11
	TSysTime  = 0x12
	TSID      = 0x13
	THex32    = 0x14
	THex64    = 0x15
	TBinXML   = 0x21
	TArray    = 0x80
)

func le16(v uint16) []byte { return binary.LittleEndian.AppendUint16(nil, v) }
func le32(v uint32) []byte { return binary.LittleEndian.AppendUint32(nil, v) }
func le64(v uint64) []byte { return binary.LittleEndian.AppendUint64(nil, v) }

func utf16le(s string) []byte {
	var b []byte
	for _, u := range utf16.Encode([]rune(s)) {
		b = binary.LittleEndian.AppendUint16(b, u)
	}
	return b
}

func Null() Value                { return Value{Type: TNull} }
func String(s string) Value      { return Value{Type: TString, Data: utf16le(s)} }
func Ansi(s string) Value        { return Value{Type: TAnsi, Data: []byte(s)} }
func Int8(v int8) Value          { return Value{Type: TInt8, Data: []byte{byte(v)}} }
func Uint8(v uint8) Value        { return Value{Type: TUint8, Data: []byte{v}} }
func Int16(v int16) Value        { return Value{Type: TInt16, Data: le16(uint16(v))} }
func Uint16(v uint16) Value      { return Value{Type: TUint16, Data: le16(v)} }
func Int32(v int32) Value        { return Value{Type: TInt32, Data: le32(uint32(v))} }
func Uint32(v uint32) Value      { return Value{Type: TUint32, Data: le32(v)} }
func Int64(v int64) Value        { return Value{Type: TInt64, Data: le64(uint64(v))} }
func Uint64(v uint64) Value      { return Value{Type: TUint64, Data: le64(v)} }
func Real32(v float32) Value     { return Value{Type: TReal32, Data: le32(math.Float32bits(v))} }
func Real64(v float64) Value     { return Value{Type: TReal64, Data: le64(math.Float64bits(v))} }
func Binary(b []byte) Value      { return Value{Type: TBinary, Data: b} }
func SizeT(v uint64) Value       { return Value{Type: TSizeT, Data: le64(v)} }
func Hex32(v uint32) Value       { return Value{Type: THex32, Data: le32(v)} }
func Hex64(v uint64) Value       { return Value{Type: THex64, Data: le64(v)} }
func FileTime(t time.Time) Value { return Value{Type: TFileTime, Data: le64(filetime(t))} }
func BinXML(n Node) Value        { return Value{Type: TBinXML, Nested: n} }

func Bool(v bool) Value {
	if v {
		return Value{Type: TBool, Data: le32(1)}
	}
	return Value{Type: TBool, Data: le32(0)}
}

func filetime(t time.Time) uint64 {
	return uint64(t.UnixNano()/100) + 116444736000000000
}

// SystemTime encodes a SYSTEMTIME (millisecond precision).
func SystemTime(t time.Time) Value {
	t = t.UTC()
	var b []byte
	for _, v := range []int{t.Year(), int(t.Month()), int(t.Weekday()), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond() / 1e6} {
		b = append(b, le16(uint16(v))...)
	}
	return Value{Type: TSysTime, Data: b}
}

// GUID encodes "{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}".
func GUID(s string) Value { return Value{Type: TGUID, Data: guidBytes(s)} }

func guidBytes(s string) []byte {
	h := strings.NewReplacer("{", "", "}", "", "-", "").Replace(s)
	if len(h) != 32 {
		panic("evtxtest: bad guid " + s)
	}
	p := func(a, b int) uint64 { v, _ := strconv.ParseUint(h[a:b], 16, 64); return v }
	out := le32(uint32(p(0, 8)))
	out = append(out, le16(uint16(p(8, 12)))...)
	out = append(out, le16(uint16(p(12, 16)))...)
	for i := 16; i < 32; i += 2 {
		out = append(out, byte(p(i, i+2)))
	}
	return out
}

// SID encodes "S-1-5-21-…".
func SID(s string) Value {
	parts := strings.Split(s, "-")
	if len(parts) < 3 || parts[0] != "S" {
		panic("evtxtest: bad sid " + s)
	}
	rev, _ := strconv.Atoi(parts[1])
	auth, _ := strconv.ParseUint(parts[2], 10, 48)
	b := []byte{byte(rev), byte(len(parts) - 3)}
	for i := 5; i >= 0; i-- {
		b = append(b, byte(auth>>(8*i)))
	}
	for _, sub := range parts[3:] {
		v, _ := strconv.ParseUint(sub, 10, 32)
		b = append(b, le32(uint32(v))...)
	}
	return Value{Type: TSID, Data: b}
}

// StringArray encodes NUL-terminated UTF-16 strings back to back.
func StringArray(ss ...string) Value {
	var b []byte
	for _, s := range ss {
		b = append(b, utf16le(s)...)
		b = append(b, 0, 0)
	}
	return Value{Type: TString | TArray, Data: b}
}

// Uint16Array encodes a packed uint16 array.
func Uint16Array(vs ...uint16) Value {
	var b []byte
	for _, v := range vs {
		b = append(b, le16(v)...)
	}
	return Value{Type: TUint16 | TArray, Data: b}
}

// Template is a template definition.
type Template struct {
	ID   uint32
	GUID string
	Body Node
}

// Record is one event record.
type Record struct {
	ID       uint64
	Written  time.Time
	Template *Template
	Values   []Value
}

// Options tune file layout.
type Options struct {
	RecordsPerChunk int  // 0 fills chunks
	Dirty           bool // set the header dirty flag
	Slack           bool // copy each chunk's first record past its free-space offset
}

const chunkSize = 65536

// Build writes a complete .evtx image.
func Build(recs []Record, o Options) []byte {
	var chunks [][]byte
	var nextID uint64 = 1
	cw := newChunk()
	for _, r := range recs {
		if r.ID >= nextID {
			nextID = r.ID + 1
		}
		if o.RecordsPerChunk > 0 && cw.count >= o.RecordsPerChunk {
			chunks = append(chunks, cw.finish(o))
			cw = newChunk()
		}
		if !cw.add(r) {
			chunks = append(chunks, cw.finish(o))
			cw = newChunk()
			if !cw.add(r) {
				panic(fmt.Sprintf("evtxtest: record %d does not fit in an empty chunk", r.ID))
			}
		}
	}
	if cw.count > 0 || len(chunks) == 0 {
		chunks = append(chunks, cw.finish(o))
	}
	hdr := make([]byte, 4096)
	copy(hdr, "ElfFile\x00")
	binary.LittleEndian.PutUint64(hdr[8:], 0)
	binary.LittleEndian.PutUint64(hdr[16:], uint64(len(chunks)-1))
	binary.LittleEndian.PutUint64(hdr[24:], nextID)
	binary.LittleEndian.PutUint32(hdr[32:], 128)
	binary.LittleEndian.PutUint16(hdr[36:], 1)
	binary.LittleEndian.PutUint16(hdr[38:], 3)
	binary.LittleEndian.PutUint16(hdr[40:], 4096)
	binary.LittleEndian.PutUint16(hdr[42:], uint16(len(chunks)))
	if o.Dirty {
		binary.LittleEndian.PutUint32(hdr[120:], 1)
	}
	binary.LittleEndian.PutUint32(hdr[124:], crc32.ChecksumIEEE(hdr[:120]))
	out := hdr
	for _, c := range chunks {
		out = append(out, c...)
	}
	return out
}

type chunk struct {
	b          []byte
	pos        int
	overflow   bool
	names      map[string]int
	templates  map[*Template]int
	strTable   [64]uint32
	tmplTable  [32]uint32
	count      int
	firstID    uint64
	lastID     uint64
	lastRecOff int
}

func newChunk() *chunk {
	return &chunk{b: make([]byte, chunkSize), pos: 512, names: map[string]int{}, templates: map[*Template]int{}}
}

func (c *chunk) put(b ...byte) {
	if c.pos+len(b) > len(c.b) {
		c.overflow = true
		c.pos += len(b)
		return
	}
	copy(c.b[c.pos:], b)
	c.pos += len(b)
}

func (c *chunk) patch32(at int, v uint32) {
	if at+4 <= len(c.b) {
		binary.LittleEndian.PutUint32(c.b[at:], v)
	}
}

func (c *chunk) patch16(at int, v uint16) {
	if at+2 <= len(c.b) {
		binary.LittleEndian.PutUint16(c.b[at:], v)
	}
}

// add writes one record, or rolls back and reports false if it does not fit.
func (c *chunk) add(r Record) bool {
	pos := c.pos
	names := make(map[string]int, len(c.names))
	for k, v := range c.names {
		names[k] = v
	}
	tmpls := make(map[*Template]int, len(c.templates))
	for k, v := range c.templates {
		tmpls[k] = v
	}
	strTable, tmplTable := c.strTable, c.tmplTable

	start := c.pos
	c.put(0x2a, 0x2a, 0, 0)
	c.put(0, 0, 0, 0) // size
	c.put(le64(r.ID)...)
	c.put(le64(filetime(r.Written))...)
	c.put(0x0f, 1, 1, 0) // fragment header
	c.instance(r.Template, r.Values)
	c.put(0x00) // EOF
	size := c.pos - start + 4
	c.put(le32(uint32(size))...)
	if c.overflow {
		for i := pos; i < len(c.b); i++ {
			c.b[i] = 0
		}
		c.pos, c.names, c.templates, c.strTable, c.tmplTable, c.overflow = pos, names, tmpls, strTable, tmplTable, false
		return false
	}
	c.patch32(start+4, uint32(size))
	if c.count == 0 {
		c.firstID = r.ID
	}
	c.lastID, c.lastRecOff = r.ID, start
	c.count++
	return true
}

// instance writes a template instance: the definition inline on first use
// in the chunk, a back-reference afterwards, then the substitution array.
func (c *chunk) instance(t *Template, vals []Value) {
	c.put(0x0c, 0x01)
	c.put(le32(t.ID)...)
	if off, ok := c.templates[t]; ok {
		c.put(le32(uint32(off))...)
	} else {
		off := c.pos + 4
		c.put(le32(uint32(off))...)
		c.templates[t] = off
		c.tmplTable[t.ID%32] = uint32(off)
		c.put(0, 0, 0, 0) // next definition
		g := "{00000000-0000-0000-0000-000000000000}"
		if t.GUID != "" {
			g = t.GUID
		}
		c.put(guidBytes(g)...)
		sizeAt := c.pos
		c.put(0, 0, 0, 0)
		c.node(t.Body)
		c.put(0x00) // EOF
		c.patch32(sizeAt, uint32(c.pos-sizeAt-4))
	}
	c.put(le32(uint32(len(vals)))...)
	descAt := c.pos
	for range vals {
		c.put(0, 0, 0, 0)
	}
	for i, v := range vals {
		s := c.pos
		if v.Type == TBinXML && v.Nested != nil {
			c.put(0x0f, 1, 1, 0)
			c.node(v.Nested)
			c.put(0x00)
		} else {
			c.put(v.Data...)
		}
		c.patch16(descAt+4*i, uint16(c.pos-s))
		if descAt+4*i+2 < len(c.b) {
			c.b[descAt+4*i+2] = v.Type
		}
	}
}

// name writes a name reference: inline on first use, an offset afterwards.
func (c *chunk) name(s string) {
	if off, ok := c.names[s]; ok {
		c.put(le32(uint32(off))...)
		return
	}
	off := c.pos + 4
	c.put(le32(uint32(off))...)
	c.names[s] = off
	var h uint32
	for _, u := range utf16.Encode([]rune(s)) {
		h = h*65599 + uint32(u)
	}
	bucket := h % 64
	c.put(le32(c.strTable[bucket])...) // chain to the previous name in this bucket
	c.strTable[bucket] = uint32(off)
	c.put(le16(uint16(h))...)
	c.put(le16(uint16(len(utf16.Encode([]rune(s)))))...)
	c.put(utf16le(s)...)
	c.put(0, 0)
}

func (c *chunk) node(n Node) {
	switch t := n.(type) {
	case Elem:
		tok := byte(0x01)
		if len(t.Attrs) > 0 {
			tok = 0x41
		}
		c.put(tok)
		if !t.NoDep {
			c.put(0xff, 0xff)
		}
		sizeAt := c.pos
		c.put(0, 0, 0, 0)
		c.name(t.Name)
		if len(t.Attrs) > 0 {
			listAt := c.pos
			c.put(0, 0, 0, 0)
			for i, a := range t.Attrs {
				if i < len(t.Attrs)-1 {
					c.put(0x46)
				} else {
					c.put(0x06)
				}
				c.name(a.Name)
				for _, v := range a.Value {
					c.node(v)
				}
			}
			c.patch32(listAt, uint32(c.pos-listAt-4))
		}
		if len(t.Children) == 0 {
			c.put(0x03)
		} else {
			c.put(0x02)
			for _, ch := range t.Children {
				c.node(ch)
			}
			c.put(0x04)
		}
		c.patch32(sizeAt, uint32(c.pos-sizeAt-4))
	case Text:
		u := utf16le(string(t))
		c.put(0x05, 0x01)
		c.put(le16(uint16(len(u) / 2))...)
		c.put(u...)
	case CDATA:
		u := utf16le(string(t))
		c.put(0x07)
		c.put(le16(uint16(len(u) / 2))...)
		c.put(u...)
	case CharRef:
		c.put(0x08)
		c.put(le16(uint16(t))...)
	case EntityRef:
		c.put(0x09)
		c.name(string(t))
	case PI:
		c.put(0x0a)
		c.name(t.Target)
		u := utf16le(t.Data)
		c.put(0x0b)
		c.put(le16(uint16(len(u) / 2))...)
		c.put(u...)
	case Sub:
		if t.Optional {
			c.put(0x0e)
		} else {
			c.put(0x0d)
		}
		c.put(le16(t.ID)...)
		c.put(t.Type)
	case Instance:
		c.instance(t.Template, t.Values)
	default:
		panic(fmt.Sprintf("evtxtest: unknown node %T", n))
	}
}

func (c *chunk) finish(o Options) []byte {
	b := c.b
	le := binary.LittleEndian
	copy(b, "ElfChnk\x00")
	le.PutUint64(b[8:], c.firstID)
	le.PutUint64(b[16:], c.lastID)
	le.PutUint64(b[24:], c.firstID)
	le.PutUint64(b[32:], c.lastID)
	le.PutUint32(b[40:], 128)
	le.PutUint32(b[44:], uint32(c.lastRecOff))
	le.PutUint32(b[48:], uint32(c.pos))
	le.PutUint32(b[52:], crc32.ChecksumIEEE(b[512:c.pos]))
	for i, v := range c.strTable {
		le.PutUint32(b[128+4*i:], v)
	}
	for i, v := range c.tmplTable {
		le.PutUint32(b[384+4*i:], v)
	}
	if o.Slack && c.count > 0 {
		size := int(le.Uint32(b[512+4:]))
		at := (c.pos + 7) &^ 7
		if at+size <= len(b) {
			copy(b[at:], b[512:512+size])
		}
	}
	h := crc32.NewIEEE()
	h.Write(b[:120])
	h.Write(b[128:512])
	le.PutUint32(b[124:], h.Sum32())
	return b
}

// KV is one named EventData or UserData field.
type KV struct {
	Name  string
	Value Value
}

// Event describes a typical Windows event; Events turns a list of them
// into Records that share one template per event shape, the way Windows
// providers do.
type Event struct {
	Provider     string
	ProviderGUID string // optional
	EventID      uint16
	Qualifiers   int // -1 omits the attribute (optional substitution with a null value)
	Version      uint8
	Level        uint8
	Task         uint16
	Opcode       uint8
	Keywords     uint64
	Time         time.Time
	RecordID     uint64
	PID, TID     uint32
	Channel      string
	Computer     string
	UserSID      string // optional
	Data         []KV   // EventData
	// UserData, when set, is emitted as a nested BinXml substitution:
	// <UserData><Element xmlns=NS><Field>…</Field>…</Element></UserData>.
	UserDataElement string
	UserDataNS      string
	UserData        []KV
}

const eventNS = "http://schemas.microsoft.com/win/2004/08/events/event"

// Events converts Event descriptions to Records.
func Events(evs []Event) []Record {
	tmpls := map[string]*Template{}
	var out []Record
	for _, e := range evs {
		key := shapeKey(e)
		t := tmpls[key]
		if t == nil {
			t = &Template{ID: uint32(len(tmpls) + 1), GUID: fmt.Sprintf("{%08X-0000-4000-8000-%012X}", len(tmpls)+1, e.EventID), Body: shape(e)}
			tmpls[key] = t
		}
		vals := []Value{
			String(e.Provider), Null(), Null(), Uint16(e.EventID),
			Uint8(e.Version), Uint8(e.Level), Uint16(e.Task), Uint8(e.Opcode), Hex64(e.Keywords),
			FileTime(e.Time), Uint64(e.RecordID), Null(), Uint32(e.PID), Uint32(e.TID),
			String(e.Channel), String(e.Computer), Null(),
		}
		if e.ProviderGUID != "" {
			vals[1] = GUID(e.ProviderGUID)
		}
		if e.Qualifiers >= 0 {
			vals[2] = Uint16(uint16(e.Qualifiers))
		}
		if e.UserSID != "" {
			vals[16] = SID(e.UserSID)
		}
		for _, kv := range e.Data {
			vals = append(vals, kv.Value)
		}
		if e.UserDataElement != "" {
			var fields []Node
			for _, kv := range e.UserData {
				fields = append(fields, Elem{Name: kv.Name, Children: []Node{Text(valueText(kv.Value))}, NoDep: true})
			}
			vals = append(vals, BinXML(Elem{Name: e.UserDataElement, NoDep: true,
				Attrs: []Attr{{Name: "xmlns", Value: []Node{Text(e.UserDataNS)}}}, Children: fields}))
		}
		out = append(out, Record{ID: e.RecordID, Written: e.Time, Template: t, Values: vals})
	}
	return out
}

func valueText(v Value) string {
	if v.Type == TString {
		u := make([]uint16, len(v.Data)/2)
		for i := range u {
			u[i] = binary.LittleEndian.Uint16(v.Data[2*i:])
		}
		return string(utf16.Decode(u))
	}
	return fmt.Sprintf("%x", v.Data)
}

func shapeKey(e Event) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "%s|%d|%s|", e.Provider, e.EventID, e.UserDataElement)
	for _, kv := range e.Data {
		fmt.Fprintf(&sb, "%s:%d,", kv.Name, kv.Value.Type)
	}
	return sb.String()
}

func shape(e Event) Node {
	sub := func(id uint16, typ byte) Node { return Sub{ID: id, Type: typ} }
	opt := func(id uint16, typ byte) Node { return Sub{ID: id, Type: typ, Optional: true} }
	el := func(name string, children ...Node) Elem { return Elem{Name: name, Children: children} }
	system := Elem{Name: "System", Children: []Node{
		Elem{Name: "Provider", Attrs: []Attr{{Name: "Name", Value: []Node{sub(0, TString)}}, {Name: "Guid", Value: []Node{opt(1, TGUID)}}}},
		Elem{Name: "EventID", Attrs: []Attr{{Name: "Qualifiers", Value: []Node{opt(2, TUint16)}}}, Children: []Node{sub(3, TUint16)}},
		el("Version", sub(4, TUint8)), el("Level", sub(5, TUint8)), el("Task", sub(6, TUint16)),
		el("Opcode", sub(7, TUint8)), el("Keywords", sub(8, THex64)),
		Elem{Name: "TimeCreated", Attrs: []Attr{{Name: "SystemTime", Value: []Node{sub(9, TFileTime)}}}},
		el("EventRecordID", sub(10, TUint64)),
		Elem{Name: "Correlation", Attrs: []Attr{{Name: "ActivityID", Value: []Node{opt(11, TGUID)}}}},
		Elem{Name: "Execution", Attrs: []Attr{{Name: "ProcessID", Value: []Node{sub(12, TUint32)}}, {Name: "ThreadID", Value: []Node{sub(13, TUint32)}}}},
		el("Channel", sub(14, TString)), el("Computer", sub(15, TString)),
		Elem{Name: "Security", Attrs: []Attr{{Name: "UserID", Value: []Node{opt(16, TSID)}}}},
	}}
	root := Elem{Name: "Event", Attrs: []Attr{{Name: "xmlns", Value: []Node{Text(eventNS)}}}, Children: []Node{system}}
	next := uint16(17)
	if len(e.Data) > 0 {
		ed := Elem{Name: "EventData"}
		for _, kv := range e.Data {
			ed.Children = append(ed.Children, Elem{Name: "Data", Attrs: []Attr{{Name: "Name", Value: []Node{Text(kv.Name)}}}, Children: []Node{Sub{ID: next, Type: kv.Value.Type, Optional: true}}})
			next++
		}
		root.Children = append(root.Children, ed)
	}
	if e.UserDataElement != "" {
		root.Children = append(root.Children, el("UserData", Sub{ID: next, Type: TBinXML}))
	}
	return root
}

// F builds a KV.
func F(name string, v Value) KV { return KV{Name: name, Value: v} }
