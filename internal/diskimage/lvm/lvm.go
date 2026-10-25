// Package lvm reads LVM2 physical volume labels and the volume group
// metadata text stored in their metadata areas, read-only, in pure Go.
// It never activates anything; it only describes where each logical
// volume's extents live.
//
// Supported: the label (sectors 0-3), the PV header with its data and
// metadata area lists, the metadata area header (magic, checksum, the
// circular text buffer including wrap-around) and the text format itself
// (sections, numbers, strings, lists, comments). Logical volumes made of
// "striped" segments with stripe_count = 1 (linear, one or more segments)
// are mapped to physical extents; every other segment type (striped over
// several devices, thin, thin-pool, snapshot, raid*, mirror, cache, vdo,
// error, zero …) is reported with its type so the caller can mark the LV
// UNSUPPORTED.
package lvm

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"sort"
	"strconv"
	"strings"
)

var le = binary.LittleEndian

const (
	labelMagic   = "LABELONE"
	labelType    = "LVM2 001"
	mdaMagic     = " LVM2 x[5A%r0N*>"
	initialCRC   = 0xf597a6cf
	maxTextBytes = 16 << 20
	maxAreas     = 16
	maxDepth     = 16
	maxTokens    = 1 << 20
)

// ErrNoLabel means the volume carries no LVM2 label.
var ErrNoLabel = errors.New("lvm: no LVM2 label")

func corrupt(format string, a ...any) error {
	return fmt.Errorf("lvm: corrupt: %s", fmt.Sprintf(format, a...))
}

// Area is a byte range within the PV.
type Area struct{ Offset, Size uint64 }

// PV is a physical volume label.
type PV struct {
	UUID       string // 32 characters, no dashes
	DeviceSize uint64
	Data       []Area
	Metadata   []Area
}

// crc is LVM's calc_crc: CRC-32 (IEEE polynomial) seeded with 0xf597a6cf,
// without the usual pre/post inversion.
func crc(b []byte) uint32 { return ^crc32.Update(^uint32(initialCRC), crc32.IEEETable, b) }

// ReadLabel looks for the label in the first four sectors of a volume.
func ReadLabel(r io.ReaderAt, size int64) (*PV, error) {
	if size < 2048 {
		return nil, ErrNoLabel
	}
	head := make([]byte, 2048)
	if n, _ := r.ReadAt(head, 0); n < 2048 {
		return nil, ErrNoLabel
	}
	for s := 0; s < 4; s++ {
		sec := head[s*512 : (s+1)*512]
		if string(sec[:8]) != labelMagic || string(sec[24:32]) != labelType {
			continue
		}
		if le.Uint64(sec[8:]) != uint64(s) {
			return nil, corrupt("label in sector %d claims sector %d", s, le.Uint64(sec[8:]))
		}
		if crc(sec[20:]) != le.Uint32(sec[16:]) {
			return nil, corrupt("label checksum mismatch")
		}
		off := int(le.Uint32(sec[20:]))
		if off < 32 || off+40 > 512 {
			return nil, corrupt("PV header offset %d", off)
		}
		h := sec[off:]
		pv := &PV{UUID: string(h[:32]), DeviceSize: le.Uint64(h[32:])}
		pos := 40
		for list := 0; list < 2; list++ {
			for i := 0; ; i++ {
				if pos+16 > len(h) || i > maxAreas {
					return nil, corrupt("PV header area list overruns the label sector")
				}
				a := Area{le.Uint64(h[pos:]), le.Uint64(h[pos+8:])}
				pos += 16
				if a.Offset == 0 {
					break
				}
				if list == 0 {
					pv.Data = append(pv.Data, a)
				} else {
					pv.Metadata = append(pv.Metadata, a)
				}
			}
		}
		return pv, nil
	}
	return nil, ErrNoLabel
}

// ReadMetadata returns the current metadata text from the first usable
// metadata area of the PV.
func ReadMetadata(r io.ReaderAt, size int64, pv *PV) (string, error) {
	var firstErr error
	for _, a := range pv.Metadata {
		t, err := readArea(r, size, a)
		if err == nil {
			return t, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}
	if firstErr == nil {
		firstErr = corrupt("PV has no metadata area")
	}
	return "", firstErr
}

func readArea(r io.ReaderAt, size int64, a Area) (string, error) {
	if a.Size < 1024 || a.Offset > uint64(size) || a.Size > uint64(size)-a.Offset {
		return "", corrupt("metadata area %d+%d out of bounds", a.Offset, a.Size)
	}
	h := make([]byte, 512)
	if _, err := r.ReadAt(h, int64(a.Offset)); err != nil {
		return "", err
	}
	if string(h[4:20]) != mdaMagic {
		return "", corrupt("metadata area header magic missing")
	}
	if crc(h[4:]) != le.Uint32(h) {
		return "", corrupt("metadata area header checksum mismatch")
	}
	if le.Uint64(h[24:]) != a.Offset {
		return "", corrupt("metadata area header start %d, area at %d", le.Uint64(h[24:]), a.Offset)
	}
	off, n := le.Uint64(h[40:]), le.Uint64(h[48:])
	want := le.Uint32(h[56:])
	if n == 0 {
		return "", corrupt("metadata area holds no metadata")
	}
	if off < 512 || off >= a.Size || n > maxTextBytes || n > a.Size-512 {
		return "", corrupt("metadata text %d+%d outside its %d-byte area", off, n, a.Size)
	}
	text := make([]byte, n)
	first := min(n, a.Size-off)
	if _, err := r.ReadAt(text[:first], int64(a.Offset+off)); err != nil {
		return "", err
	}
	if first < n { // circular buffer: continues right after the header
		if _, err := r.ReadAt(text[first:], int64(a.Offset+512)); err != nil {
			return "", err
		}
	}
	if crc(text) != want {
		return "", corrupt("metadata text checksum mismatch")
	}
	if i := strings.IndexByte(string(text), 0); i >= 0 {
		text = text[:i]
	}
	return string(text), nil
}

// ---- text format ----

// Value is a parsed metadata value: int64, string, []Value or Section.
type Value any

// Section is a { … } block.
type Section map[string]Value

func (s Section) str(k string) string {
	v, _ := s[k].(string)
	return v
}

func (s Section) num(k string) (int64, bool) {
	v, ok := s[k].(int64)
	return v, ok
}

func (s Section) sec(k string) Section {
	v, _ := s[k].(Section)
	return v
}

type lexer struct {
	s    string
	pos  int
	toks int
}

func (l *lexer) skip() {
	for l.pos < len(l.s) {
		c := l.s[l.pos]
		switch {
		case c == '#':
			for l.pos < len(l.s) && l.s[l.pos] != '\n' {
				l.pos++
			}
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			l.pos++
		default:
			return
		}
	}
}

func (l *lexer) next() (string, error) {
	if l.toks++; l.toks > maxTokens {
		return "", corrupt("metadata text too complex")
	}
	l.skip()
	if l.pos >= len(l.s) {
		return "", io.EOF
	}
	c := l.s[l.pos]
	switch {
	case strings.IndexByte("{}[]=,", c) >= 0:
		l.pos++
		return string(c), nil
	case c == '"':
		var b strings.Builder
		b.WriteByte('"')
		for l.pos++; l.pos < len(l.s); l.pos++ {
			switch l.s[l.pos] {
			case '\\':
				if l.pos+1 < len(l.s) {
					l.pos++
					b.WriteByte(l.s[l.pos])
				}
			case '"':
				l.pos++
				return b.String(), nil
			default:
				b.WriteByte(l.s[l.pos])
			}
		}
		return "", corrupt("unterminated string")
	}
	start := l.pos
	for l.pos < len(l.s) && strings.IndexByte("{}[]=,\"# \t\r\n", l.s[l.pos]) < 0 {
		l.pos++
	}
	return l.s[start:l.pos], nil
}

// Parse parses LVM2 metadata text into its top-level section.
func Parse(text string) (Section, error) {
	l := &lexer{s: text}
	return parseSection(l, 0, true)
}

func parseSection(l *lexer, depth int, top bool) (Section, error) {
	if depth > maxDepth {
		return nil, corrupt("metadata nested too deeply")
	}
	s := Section{}
	for {
		tok, err := l.next()
		if err == io.EOF {
			if top {
				return s, nil
			}
			return nil, corrupt("unterminated section")
		}
		if err != nil {
			return nil, err
		}
		if tok == "}" {
			if top {
				return nil, corrupt("unbalanced }")
			}
			return s, nil
		}
		if strings.IndexByte("{}[]=,", tok[0]) >= 0 || tok[0] == '"' {
			return nil, corrupt("unexpected %q", tok)
		}
		op, err := l.next()
		if err != nil {
			return nil, corrupt("%s: truncated", tok)
		}
		switch op {
		case "{":
			sub, err := parseSection(l, depth+1, false)
			if err != nil {
				return nil, err
			}
			s[tok] = sub
		case "=":
			v, err := parseValue(l, depth)
			if err != nil {
				return nil, err
			}
			s[tok] = v
		default:
			return nil, corrupt("%s: expected = or {, got %q", tok, op)
		}
	}
}

func parseValue(l *lexer, depth int) (Value, error) {
	tok, err := l.next()
	if err != nil {
		return nil, corrupt("value truncated")
	}
	switch {
	case tok == "[":
		var out []Value
		for {
			t, err := l.next()
			if err != nil {
				return nil, corrupt("list truncated")
			}
			if t == "]" {
				return out, nil
			}
			if t == "," {
				continue
			}
			v, err := scalar(t)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
	case tok[0] == '"':
		return tok[1:], nil
	}
	return scalar(tok)
}

func scalar(t string) (Value, error) {
	if t != "" && t[0] == '"' {
		return t[1:], nil
	}
	if n, err := strconv.ParseInt(t, 10, 64); err == nil {
		return n, nil
	}
	if _, err := strconv.ParseFloat(t, 64); err == nil {
		return t, nil
	}
	return nil, corrupt("bad value %q", t)
}

// ---- volume group model ----

// VG is a volume group as the metadata describes it.
type VG struct {
	Name       string
	ID         string
	Seqno      int64
	ExtentSize uint64 // bytes
	PVs        map[string]PVInfo
	LVs        []LV
}

// PVInfo is one physical_volumes entry.
type PVInfo struct {
	Name    string // pv0, pv1 …
	UUID    string // 32 characters, no dashes
	PEStart uint64 // bytes
	PECount uint64
}

// LV is one logical volume.
type LV struct {
	Name     string
	Visible  bool
	Status   []string
	Extents  uint64 // total length in extents
	Segments []Segment
	// Unsupported is set when the LV cannot be read as linear extents.
	Unsupported string
}

// Segment is one LV segment. For linear segments PV and PE are set.
type Segment struct {
	StartExtent, ExtentCount uint64
	Type                     string
	StripeCount              int64
	PV                       string
	PE                       uint64
	Origin, COW              string // snapshot segments
}

func normUUID(s string) string { return strings.ReplaceAll(s, "-", "") }

// Model converts parsed metadata into a VG. The text holds exactly one
// volume group section next to a few top-level scalars.
func Model(top Section) (*VG, error) {
	var name string
	var vgs Section
	for k, v := range top {
		if s, ok := v.(Section); ok {
			if vgs != nil {
				return nil, corrupt("metadata holds more than one volume group")
			}
			name, vgs = k, s
		}
	}
	if vgs == nil {
		return nil, corrupt("metadata holds no volume group")
	}
	es, ok := vgs.num("extent_size")
	if !ok || es <= 0 || es > 1<<32 {
		return nil, corrupt("VG %s: extent_size %d", name, es)
	}
	vg := &VG{Name: name, ID: vgs.str("id"), ExtentSize: uint64(es) * 512, PVs: map[string]PVInfo{}}
	vg.Seqno, _ = vgs.num("seqno")
	for pn, v := range vgs.sec("physical_volumes") {
		p, ok := v.(Section)
		if !ok {
			continue
		}
		start, _ := p.num("pe_start")
		count, _ := p.num("pe_count")
		if start < 0 || count < 0 {
			return nil, corrupt("PV %s: pe_start %d pe_count %d", pn, start, count)
		}
		vg.PVs[pn] = PVInfo{Name: pn, UUID: normUUID(p.str("id")), PEStart: uint64(start) * 512, PECount: uint64(count)}
	}
	names := make([]string, 0)
	lvs := vgs.sec("logical_volumes")
	for ln := range lvs {
		names = append(names, ln)
	}
	sort.Strings(names)
	cow := map[string]string{} // cow store LV → origin
	for _, ln := range names {
		l, ok := lvs[ln].(Section)
		if !ok {
			continue
		}
		lv := LV{Name: ln}
		if st, ok := l["status"].([]Value); ok {
			for _, x := range st {
				if s, ok := x.(string); ok {
					lv.Status = append(lv.Status, s)
					if s == "VISIBLE" {
						lv.Visible = true
					}
				}
			}
		}
		nseg, _ := l.num("segment_count")
		if nseg <= 0 || nseg > 1<<16 {
			lv.Unsupported = fmt.Sprintf("segment_count %d", nseg)
			vg.LVs = append(vg.LVs, lv)
			continue
		}
		for i := int64(1); i <= nseg; i++ {
			s := l.sec("segment" + strconv.FormatInt(i, 10))
			if s == nil {
				lv.Unsupported = fmt.Sprintf("segment%d missing", i)
				break
			}
			start, _ := s.num("start_extent")
			cnt, _ := s.num("extent_count")
			if start < 0 || cnt <= 0 {
				lv.Unsupported = fmt.Sprintf("segment%d: start %d count %d", i, start, cnt)
				break
			}
			seg := Segment{StartExtent: uint64(start), ExtentCount: uint64(cnt), Type: s.str("type")}
			seg.StripeCount, _ = s.num("stripe_count")
			if st, ok := s["stripes"].([]Value); ok && len(st) >= 2 {
				seg.PV, _ = st[0].(string)
				if pe, ok := st[1].(int64); ok && pe >= 0 {
					seg.PE = uint64(pe)
				}
			}
			seg.Origin, seg.COW = s.str("origin"), s.str("cow_store")
			if seg.Type == "snapshot" && seg.COW != "" {
				cow[seg.COW] = seg.Origin
			}
			lv.Segments = append(lv.Segments, seg)
			lv.Extents = max(lv.Extents, seg.StartExtent+seg.ExtentCount)
		}
		vg.LVs = append(vg.LVs, lv)
	}
	for i := range vg.LVs {
		lv := &vg.LVs[i]
		if lv.Unsupported != "" {
			continue
		}
		if o, ok := cow[lv.Name]; ok {
			// On disk the exception store is not VISIBLE; LVM's tools
			// present it under its own name as the snapshot LV.
			lv.Visible = true
			lv.Unsupported = fmt.Sprintf("snapshot of %q: a copy-on-write exception store over the origin; snapshot LVs are not reconstructed", o)
			continue
		}
		lv.Unsupported = linearReason(vg, lv)
	}
	return vg, nil
}

// linearReason returns "" when every segment is linear on a known PV and
// the segments tile the LV in order; otherwise why not.
func linearReason(vg *VG, lv *LV) string {
	var next uint64
	for i, s := range lv.Segments {
		switch {
		case s.Type == "striped" && s.StripeCount == 1:
		case s.Type == "striped":
			return fmt.Sprintf("striped over %d devices (segment %d)", s.StripeCount, i+1)
		default:
			return fmt.Sprintf("segment type %q (segment %d); only linear LVs are read", s.Type, i+1)
		}
		if s.StartExtent != next {
			return fmt.Sprintf("segment %d starts at extent %d, expected %d", i+1, s.StartExtent, next)
		}
		pv, ok := vg.PVs[s.PV]
		if !ok {
			return fmt.Sprintf("segment %d names unknown PV %q", i+1, s.PV)
		}
		if s.PE+s.ExtentCount > pv.PECount || s.PE+s.ExtentCount < s.PE {
			return fmt.Sprintf("segment %d extents %d+%d exceed %s's %d extents", i+1, s.PE, s.ExtentCount, s.PV, pv.PECount)
		}
		next = s.StartExtent + s.ExtentCount
	}
	return ""
}
