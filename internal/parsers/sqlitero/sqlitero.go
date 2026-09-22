// Package sqlitero is a read-only SQLite file reader with no dependencies
// outside the standard library.
//
// Why not a driver: the collector core is stdlib-only by policy, so that a
// forensic tool can be audited in an afternoon and cross-compiled for every
// release target without cgo. What the parsers need from an agent's SQLite
// store is small — walk one table, hand back its rows — and the file
// format is documented and stable (https://sqlite.org/fileformat2.html).
// A few hundred lines of page walking cover it, and unlike a driver they
// never write, never take a lock, and never touch the file the evidence
// came from: the bytes are read out of the sealed package.
//
// What it does: table b-trees (rowid tables and WITHOUT ROWID tables),
// overflow chains, UTF-8 text, and the write-ahead log, so rows a product
// wrote but had not checkpointed yet are still seen. What it does not do:
// indexes, views, triggers, UTF-16 databases, or anything that would
// require interpreting SQL beyond a CREATE TABLE column list.
//
// Every read is bounds-checked and every page walk is cycle-checked. A
// database is evidence from a machine that may have been hostile, so a
// corrupt or crafted file must produce an error, never a panic or a loop.
package sqlitero

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// Limits on what a single database may ask of the reader.
const (
	maxDepth    = 64      // b-tree depth; real trees are < 10
	maxOverflow = 1 << 20 // overflow pages in one chain
	maxPayload  = 1 << 30 // one record
	MaxDBBytes  = 1 << 30 // Open refuses anything larger
	MaxWALBytes = 256 << 20
)

var errCorrupt = errors.New("sqlite: corrupt or unsupported database")

// DB is one opened database image.
type DB struct {
	data     []byte
	pageSize int
	usable   int // page size minus reserved bytes
	nPages   uint32
	wal      map[uint32][]byte // pages superseded by the WAL
	walPages uint32            // database size after the last commit in the WAL, 0 if none
}

// Table describes one table found in sqlite_master.
type Table struct {
	Name     string
	Columns  []string
	RootPage uint32
	SQL      string

	rowidAlias   int // column index that aliases the rowid, or -1
	withoutRowid bool
	pkOrder      []int // WITHOUT ROWID: record position → declared column index
}

// Open parses a database image and, when wal is non-empty, overlays the
// committed frames of its write-ahead log. Neither slice is copied; the
// caller must not modify them while the DB is in use.
func Open(db, wal []byte) (*DB, error) {
	if len(db) < 100 {
		return nil, fmt.Errorf("%w: header too short", errCorrupt)
	}
	if len(db) > MaxDBBytes {
		return nil, fmt.Errorf("sqlite: database is %d bytes, over the %d-byte bound", len(db), MaxDBBytes)
	}
	if string(db[:16]) != "SQLite format 3\x00" {
		return nil, fmt.Errorf("%w: bad magic", errCorrupt)
	}
	ps := int(binary.BigEndian.Uint16(db[16:18]))
	if ps == 1 {
		ps = 65536
	}
	if ps < 512 || ps > 65536 || ps&(ps-1) != 0 {
		return nil, fmt.Errorf("%w: page size %d", errCorrupt, ps)
	}
	reserved := int(db[20])
	if ps-reserved < 480 {
		return nil, fmt.Errorf("%w: reserved bytes %d", errCorrupt, reserved)
	}
	if enc := binary.BigEndian.Uint32(db[56:60]); enc != 1 && enc != 0 {
		return nil, fmt.Errorf("sqlite: text encoding %d is not UTF-8; unsupported", enc)
	}
	d := &DB{data: db, pageSize: ps, usable: ps - reserved}
	// The in-header page count is only valid when the change counter
	// matches version-valid-for; otherwise derive it from the file size.
	n := binary.BigEndian.Uint32(db[28:32])
	if n == 0 || binary.BigEndian.Uint32(db[24:28]) != binary.BigEndian.Uint32(db[92:96]) {
		n = uint32(len(db) / ps)
	}
	if uint64(n)*uint64(ps) > uint64(len(db)) {
		n = uint32(len(db) / ps)
	}
	d.nPages = n
	if len(wal) > 0 {
		if err := d.applyWAL(wal); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// PageSize reports the database page size.
func (d *DB) PageSize() int { return d.pageSize }

// Pages reports the number of pages the reader believes the database has,
// after any WAL commit.
func (d *DB) Pages() uint32 {
	if d.walPages > 0 {
		return d.walPages
	}
	return d.nPages
}

// page returns page n (1-based), preferring the WAL's copy.
func (d *DB) page(n uint32) ([]byte, error) {
	if n == 0 || n > d.Pages() {
		return nil, fmt.Errorf("%w: page %d out of range (%d pages)", errCorrupt, n, d.Pages())
	}
	if p, ok := d.wal[n]; ok {
		return p, nil
	}
	off := uint64(n-1) * uint64(d.pageSize)
	if off+uint64(d.pageSize) > uint64(len(d.data)) {
		return nil, fmt.Errorf("%w: page %d beyond end of file", errCorrupt, n)
	}
	return d.data[off : off+uint64(d.pageSize)], nil
}

// Tables lists the tables recorded in sqlite_master.
func (d *DB) Tables() ([]Table, error) {
	master := &Table{Name: "sqlite_master", RootPage: 1,
		Columns: []string{"type", "name", "tbl_name", "rootpage", "sql"}, rowidAlias: -1}
	var out []Table
	err := d.Each(master, func(_ int64, v []any) error {
		if Str(v[0]) != "table" {
			return nil
		}
		t := Table{Name: Str(v[1]), RootPage: uint32(Int(v[3])), SQL: Str(v[4]), rowidAlias: -1}
		if t.RootPage == 0 {
			return nil // virtual table
		}
		parseCreate(&t)
		out = append(out, t)
		return nil
	})
	return out, err
}

// Table finds one table by name (case-insensitive, as SQLite treats names).
func (d *DB) Table(name string) (*Table, error) {
	ts, err := d.Tables()
	if err != nil {
		return nil, err
	}
	for i := range ts {
		if strings.EqualFold(ts[i].Name, name) {
			return &ts[i], nil
		}
	}
	return nil, fmt.Errorf("sqlite: no table %q", name)
}

// Index returns the position of a column in the rows Each yields, or -1.
func (t *Table) Index(col string) int {
	for i, c := range t.Columns {
		if strings.EqualFold(c, col) {
			return i
		}
	}
	return -1
}

// Each walks every row of t in b-tree order. Values are nil, int64,
// float64, string or []byte, in declared column order (padded with nil
// when a row predates an ALTER TABLE ADD COLUMN). rowid is 0 for WITHOUT
// ROWID tables. Returning an error from fn stops the walk.
func (d *DB) Each(t *Table, fn func(rowid int64, values []any) error) error {
	seen := map[uint32]bool{}
	return d.walk(t, t.RootPage, 0, seen, fn)
}

func (d *DB) walk(t *Table, pg uint32, depth int, seen map[uint32]bool, fn func(int64, []any) error) error {
	if depth > maxDepth {
		return fmt.Errorf("%w: b-tree deeper than %d", errCorrupt, maxDepth)
	}
	if seen[pg] {
		return fmt.Errorf("%w: page %d appears twice in one b-tree", errCorrupt, pg)
	}
	seen[pg] = true
	p, err := d.page(pg)
	if err != nil {
		return err
	}
	hdr := 0
	if pg == 1 {
		hdr = 100
	}
	if len(p) < hdr+8 {
		return fmt.Errorf("%w: page %d too short", errCorrupt, pg)
	}
	typ := p[hdr]
	nCells := int(binary.BigEndian.Uint16(p[hdr+3 : hdr+5]))
	hdrLen := 8
	var right uint32
	switch typ {
	case 0x05, 0x02:
		hdrLen = 12
		if len(p) < hdr+12 {
			return fmt.Errorf("%w: interior page %d too short", errCorrupt, pg)
		}
		right = binary.BigEndian.Uint32(p[hdr+8 : hdr+12])
	case 0x0D, 0x0A:
	default:
		return fmt.Errorf("%w: page %d has b-tree type 0x%02x", errCorrupt, pg, typ)
	}
	ptrs := hdr + hdrLen
	if ptrs+2*nCells > len(p) {
		return fmt.Errorf("%w: page %d cell pointer array overruns page", errCorrupt, pg)
	}
	for i := 0; i < nCells; i++ {
		off := int(binary.BigEndian.Uint16(p[ptrs+2*i : ptrs+2*i+2]))
		if off < ptrs+2*nCells || off >= len(p) {
			return fmt.Errorf("%w: page %d cell %d offset %d", errCorrupt, pg, i, off)
		}
		cell := p[off:]
		switch typ {
		case 0x05: // table interior: left child, rowid key
			if len(cell) < 4 {
				return errCorrupt
			}
			if err := d.walk(t, binary.BigEndian.Uint32(cell[:4]), depth+1, seen, fn); err != nil {
				return err
			}
		case 0x02: // index interior: left child, payload
			if len(cell) < 4 {
				return errCorrupt
			}
			if err := d.walk(t, binary.BigEndian.Uint32(cell[:4]), depth+1, seen, fn); err != nil {
				return err
			}
			if err := d.indexCell(t, cell[4:], fn); err != nil {
				return err
			}
		case 0x0D: // table leaf: payload size, rowid, payload
			plen, n := varint(cell)
			if n == 0 {
				return errCorrupt
			}
			rowid, m := varint(cell[n:])
			if m == 0 {
				return errCorrupt
			}
			payload, err := d.payload(cell[n+m:], plen, d.usable-35)
			if err != nil {
				return err
			}
			vals, err := decodeRecord(payload)
			if err != nil {
				return err
			}
			if err := fn(rowid, t.shape(vals, rowid)); err != nil {
				return err
			}
		case 0x0A: // index leaf: payload size, payload
			if err := d.indexCell(t, cell, fn); err != nil {
				return err
			}
		}
	}
	if typ == 0x05 || typ == 0x02 {
		return d.walk(t, right, depth+1, seen, fn)
	}
	return nil
}

// indexCell decodes one index-b-tree cell, which is how WITHOUT ROWID
// tables store their rows.
func (d *DB) indexCell(t *Table, cell []byte, fn func(int64, []any) error) error {
	plen, n := varint(cell)
	if n == 0 {
		return errCorrupt
	}
	payload, err := d.payload(cell[n:], plen, (d.usable-12)*64/255-23)
	if err != nil {
		return err
	}
	vals, err := decodeRecord(payload)
	if err != nil {
		return err
	}
	return fn(0, t.shape(vals, 0))
}

// payload assembles a cell's payload, following the overflow chain when
// the record does not fit in the page. maxLocal is X in the file-format
// document: the most payload that is stored on the b-tree page itself.
func (d *DB) payload(local []byte, total int64, maxLocal int) ([]byte, error) {
	if total < 0 || total > maxPayload {
		return nil, fmt.Errorf("%w: payload size %d", errCorrupt, total)
	}
	P := int(total)
	if P <= maxLocal {
		if P > len(local) {
			return nil, fmt.Errorf("%w: payload overruns cell", errCorrupt)
		}
		return local[:P], nil
	}
	U := d.usable
	M := (U-12)*32/255 - 23
	K := M + (P-M)%(U-4)
	inPage := K
	if K > maxLocal {
		inPage = M
	}
	if inPage+4 > len(local) {
		return nil, fmt.Errorf("%w: overflow cell shorter than its local part", errCorrupt)
	}
	out := make([]byte, 0, P)
	out = append(out, local[:inPage]...)
	next := binary.BigEndian.Uint32(local[inPage : inPage+4])
	seen := map[uint32]bool{}
	for len(out) < P {
		if next == 0 {
			return nil, fmt.Errorf("%w: overflow chain ended %d bytes early", errCorrupt, P-len(out))
		}
		if seen[next] || len(seen) > maxOverflow {
			return nil, fmt.Errorf("%w: overflow chain loops", errCorrupt)
		}
		seen[next] = true
		pg, err := d.page(next)
		if err != nil {
			return nil, err
		}
		if len(pg) < 4 {
			return nil, errCorrupt
		}
		next = binary.BigEndian.Uint32(pg[:4])
		chunk := pg[4:U]
		if rem := P - len(out); rem < len(chunk) {
			chunk = chunk[:rem]
		}
		out = append(out, chunk...)
	}
	return out, nil
}

// shape lays a decoded record out in declared column order: substitutes
// the rowid for its alias column, reorders WITHOUT ROWID records, and pads
// short records (columns added later by ALTER TABLE) with nil.
func (t *Table) shape(vals []any, rowid int64) []any {
	if len(t.Columns) == 0 {
		return vals
	}
	out := make([]any, len(t.Columns))
	if t.withoutRowid && len(t.pkOrder) == len(t.Columns) {
		for pos, col := range t.pkOrder {
			if pos < len(vals) && col >= 0 && col < len(out) {
				out[col] = vals[pos]
			}
		}
	} else {
		copy(out, vals)
	}
	if t.rowidAlias >= 0 && t.rowidAlias < len(out) && out[t.rowidAlias] == nil {
		out[t.rowidAlias] = rowid
	}
	return out
}

// decodeRecord decodes the record format: a header of serial types, then
// the values.
func decodeRecord(b []byte) ([]any, error) {
	hlen, n := varint(b)
	if n == 0 || hlen < int64(n) || hlen > int64(len(b)) {
		return nil, fmt.Errorf("%w: record header", errCorrupt)
	}
	hdr := b[n:hlen]
	body := b[hlen:]
	var vals []any
	for len(hdr) > 0 {
		st, m := varint(hdr)
		if m == 0 {
			return nil, fmt.Errorf("%w: record serial type", errCorrupt)
		}
		hdr = hdr[m:]
		var v any
		var size int
		switch {
		case st == 0:
			v = nil
		case st >= 1 && st <= 6:
			size = []int{0, 1, 2, 3, 4, 6, 8}[st]
			if size > len(body) {
				return nil, fmt.Errorf("%w: record body", errCorrupt)
			}
			var x int64
			for _, c := range body[:size] {
				x = x<<8 | int64(c)
			}
			// sign-extend
			shift := uint(64 - 8*size)
			v = x << shift >> shift
		case st == 7:
			size = 8
			if size > len(body) {
				return nil, fmt.Errorf("%w: record body", errCorrupt)
			}
			v = float64FromBits(binary.BigEndian.Uint64(body[:8]))
		case st == 8:
			v = int64(0)
		case st == 9:
			v = int64(1)
		case st == 10 || st == 11:
			return nil, fmt.Errorf("%w: reserved serial type %d", errCorrupt, st)
		default:
			if st > int64(maxPayload) {
				return nil, fmt.Errorf("%w: serial type %d", errCorrupt, st)
			}
			size = int((st - 12) / 2)
			if size > len(body) {
				return nil, fmt.Errorf("%w: record body", errCorrupt)
			}
			if st%2 == 0 {
				v = append([]byte(nil), body[:size]...)
			} else {
				v = string(body[:size])
			}
		}
		body = body[size:]
		vals = append(vals, v)
	}
	return vals, nil
}

// varint decodes SQLite's big-endian 7-bit varint (up to 9 bytes). It
// returns the value and the number of bytes consumed, 0 on truncation.
func varint(b []byte) (int64, int) {
	var v uint64
	for i := 0; i < 8 && i < len(b); i++ {
		v = v<<7 | uint64(b[i]&0x7f)
		if b[i]&0x80 == 0 {
			return int64(v), i + 1
		}
	}
	if len(b) < 9 {
		return 0, 0
	}
	v = v<<8 | uint64(b[8])
	return int64(v), 9
}

// Str returns v as a string: text as-is, blobs as raw bytes, numbers
// formatted, nil as "".
func Str(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case []byte:
		return string(x)
	case int64:
		return fmt.Sprint(x)
	case float64:
		return fmt.Sprint(x)
	}
	return fmt.Sprint(v)
}

// Int returns v as an integer, 0 when it is not numeric.
func Int(v any) int64 {
	switch x := v.(type) {
	case int64:
		return x
	case float64:
		return int64(x)
	}
	return 0
}

// parseCreate reads the column list out of a CREATE TABLE statement. It
// is deliberately a tokenizer, not a SQL parser: it needs column names,
// the rowid alias and the WITHOUT ROWID primary key order, nothing else.
func parseCreate(t *Table) {
	sql := t.SQL
	open := strings.IndexByte(sql, '(')
	if open < 0 {
		return
	}
	// Find the matching close parenthesis of the column list.
	depth, close := 0, -1
	inQuote := byte(0)
	for i := open; i < len(sql); i++ {
		c := sql[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			inQuote = c
		case '[':
			inQuote = ']'
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				close = i
			}
		}
		if close >= 0 {
			break
		}
	}
	if close < 0 {
		return
	}
	t.withoutRowid = strings.Contains(strings.ToUpper(sql[close:]), "WITHOUT ROWID")
	var pkCols []string
	for _, def := range splitTopLevel(sql[open+1 : close]) {
		def = strings.TrimSpace(def)
		if def == "" {
			continue
		}
		upper := strings.ToUpper(def)
		if hasPrefixWord(upper, "PRIMARY") || hasPrefixWord(upper, "UNIQUE") ||
			hasPrefixWord(upper, "CHECK") || hasPrefixWord(upper, "FOREIGN") ||
			hasPrefixWord(upper, "CONSTRAINT") {
			if hasPrefixWord(upper, "PRIMARY") || strings.Contains(upper, "PRIMARY KEY") {
				pkCols = append(pkCols, parenList(def)...)
			}
			continue
		}
		name, rest := firstIdent(def)
		if name == "" {
			continue
		}
		t.Columns = append(t.Columns, name)
		restU := strings.ToUpper(rest)
		if strings.Contains(restU, "PRIMARY KEY") {
			pkCols = append(pkCols, name)
			typ := strings.Fields(restU)
			if len(typ) > 0 && typ[0] == "INTEGER" && !t.withoutRowid {
				t.rowidAlias = len(t.Columns) - 1
			}
		}
	}
	if t.withoutRowid && len(pkCols) > 0 {
		// Record layout: primary-key columns first (in key order), then the
		// remaining columns in declared order.
		used := map[int]bool{}
		for _, pk := range pkCols {
			if i := t.Index(pk); i >= 0 && !used[i] {
				t.pkOrder = append(t.pkOrder, i)
				used[i] = true
			}
		}
		for i := range t.Columns {
			if !used[i] {
				t.pkOrder = append(t.pkOrder, i)
			}
		}
	}
}

// splitTopLevel splits on commas that are not inside parentheses or
// quotes.
func splitTopLevel(s string) []string {
	var out []string
	depth := 0
	inQuote := byte(0)
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote != 0 {
			if c == inQuote {
				inQuote = 0
			}
			continue
		}
		switch c {
		case '\'', '"', '`':
			inQuote = c
		case '[':
			inQuote = ']'
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// firstIdent returns the leading identifier of a column definition,
// unquoted, and the remainder of the definition.
func firstIdent(def string) (string, string) {
	def = strings.TrimSpace(def)
	if def == "" {
		return "", ""
	}
	switch def[0] {
	case '"', '\'', '`', '[':
		end := byte(def[0])
		if end == '[' {
			end = ']'
		}
		if i := strings.IndexByte(def[1:], end); i >= 0 {
			return def[1 : 1+i], def[2+i:]
		}
		return "", ""
	}
	i := 0
	for i < len(def) && (def[i] == '_' || def[i] == '$' || isAlnum(def[i])) {
		i++
	}
	return def[:i], def[i:]
}

func parenList(def string) []string {
	open := strings.IndexByte(def, '(')
	close := strings.LastIndexByte(def, ')')
	if open < 0 || close <= open {
		return nil
	}
	var out []string
	for _, c := range strings.Split(def[open+1:close], ",") {
		name, _ := firstIdent(c)
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func hasPrefixWord(s, w string) bool {
	return strings.HasPrefix(s, w) && (len(s) == len(w) || !isAlnum(s[len(w)]))
}

func isAlnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}
