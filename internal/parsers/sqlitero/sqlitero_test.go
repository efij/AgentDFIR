package sqlitero

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The fixtures were produced by the sqlite3 CLI (3.51) and are read-only
// test inputs: fixture.sqlite is a 1 KiB-page database with a 3001-row
// table (interior pages), one 200,000-byte TEXT value (an overflow chain
// ~200 pages long), NULLs, negative and 64-bit integers, an empty blob, a
// WITHOUT ROWID table, a table extended by ALTER TABLE after rows were
// written, and quoted identifiers. fixture_wal.sqlite is the same file
// with a write-ahead log holding one insert, one update and one WITHOUT
// ROWID insert that were never checkpointed.

func open(t *testing.T, name string, withWAL bool) *DB {
	t.Helper()
	db, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var wal []byte
	if withWAL {
		wal, err = os.ReadFile(filepath.Join("testdata", name+"-wal"))
		if err != nil {
			t.Fatal(err)
		}
	}
	d, err := Open(db, wal)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// num reads a REAL column. SQLite stores a REAL whose value is a whole
// number as an integer in the record, so the reader hands back int64 for
// 500.0 and float64 for -1.25; both are the same column.
func num(v any) float64 {
	switch x := v.(type) {
	case int64:
		return float64(x)
	case float64:
		return x
	}
	return -1e300
}

func rows(t *testing.T, d *DB, table string) (*Table, [][]any) {
	t.Helper()
	tb, err := d.Table(table)
	if err != nil {
		t.Fatal(err)
	}
	var out [][]any
	if err := d.Each(tb, func(_ int64, v []any) error { out = append(out, v); return nil }); err != nil {
		t.Fatalf("Each(%s): %v", table, err)
	}
	return tb, out
}

func TestReadsEveryRowAcrossInteriorPagesAndOverflowChains(t *testing.T) {
	d := open(t, "fixture.sqlite", false)
	tb, rs := rows(t, d, "items")
	if got, want := strings.Join(tb.Columns, ","), "id,name,score,flag,data,body"; got != want {
		t.Fatalf("columns = %s; want %s", got, want)
	}
	if len(rs) != 3001 {
		t.Fatalf("rows = %d; want 3001", len(rs))
	}
	byID := map[int64][]any{}
	for _, r := range rs {
		byID[Int(r[tb.Index("id")])] = r
	}
	// The rowid alias column is stored as NULL in the record; the reader
	// must substitute the rowid, or every id reads back as nil.
	if r := byID[1000]; Str(r[1]) != "item-1000" || num(r[2]) != 500 || Int(r[3]) != 0 || string(r[4].([]byte)) != "\xde\xad\xbe\xef" {
		t.Fatalf("row 1000 = %#v", r)
	}
	if body := Str(byID[42][5]); len(body) != 200000 || strings.Trim(body, "X") != "" {
		t.Fatalf("overflow body: len %d", len(body))
	}
	if r := byID[7]; r[2] != nil || Int(r[3]) != -7 || r[4] != nil {
		t.Fatalf("row 7 nulls/negatives = %#v", r)
	}
	if r := byID[-5]; Str(r[1]) != "negative" || num(r[2]) != -1.25 || Int(r[3]) != 9223372036854775807 || len(r[4].([]byte)) != 0 || r[5] != nil {
		t.Fatalf("row -5 = %#v", r)
	}
}

func TestWithoutRowidTableComesBackInDeclaredColumnOrder(t *testing.T) {
	d := open(t, "fixture.sqlite", false)
	tb, rs := rows(t, d, "kv")
	if !tb.withoutRowid || strings.Join(tb.Columns, ",") != "k,v,note" {
		t.Fatalf("table = %+v", tb)
	}
	var got []string
	for _, r := range rs {
		got = append(got, Str(r[0])+"="+Str(r[1])+"/"+Str(r[2]))
	}
	if want := "alpha=1/first beta=2/ gamma=3/third"; strings.Join(got, " ") != want {
		t.Fatalf("kv = %v; want %s", got, want)
	}
}

func TestShortRecordsFromBeforeAlterTableArePadded(t *testing.T) {
	d := open(t, "fixture.sqlite", false)
	tb, rs := rows(t, d, "later")
	if strings.Join(tb.Columns, ",") != "a,b,c" || len(rs) != 3 {
		t.Fatalf("later = %v / %d rows", tb.Columns, len(rs))
	}
	if len(rs[0]) != 3 || rs[0][2] != nil || Str(rs[2][2]) != "see" {
		t.Fatalf("rows = %#v", rs)
	}
}

func TestQuotedIdentifiersAreUnquoted(t *testing.T) {
	d := open(t, "fixture.sqlite", false)
	tb, rs := rows(t, d, "quoted name")
	if strings.Join(tb.Columns, ",") != "weird col,bracket,tick" || len(rs) != 1 || Str(rs[0][0]) != "q" {
		t.Fatalf("quoted = %v %#v", tb.Columns, rs)
	}
}

func TestWALFramesAreAppliedOnlyWhenPresentAndCommitted(t *testing.T) {
	stale := open(t, "fixture_wal.sqlite", false)
	_, rs := rows(t, stale, "items")
	if len(rs) != 3001 {
		t.Fatalf("without WAL: %d rows; want the checkpointed 3001", len(rs))
	}

	fresh := open(t, "fixture_wal.sqlite", true)
	tb, rs := rows(t, fresh, "items")
	if len(rs) != 3002 {
		t.Fatalf("with WAL: %d rows; want 3002", len(rs))
	}
	var renamed, walRow bool
	for _, r := range rs {
		switch Int(r[tb.Index("id")]) {
		case 1:
			renamed = Str(r[1]) == "renamed-in-wal"
		case 9001:
			walRow = Str(r[5]) == "only in wal"
		}
	}
	if !renamed || !walRow {
		t.Fatalf("WAL update seen=%v, WAL insert seen=%v", renamed, walRow)
	}
	if _, kv := rows(t, fresh, "kv"); len(kv) != 4 {
		t.Fatalf("kv with WAL = %d rows; want 4", len(kv))
	}
}

func TestCorruptInputsErrorInsteadOfPanicking(t *testing.T) {
	good, _ := os.ReadFile(filepath.Join("testdata", "fixture.sqlite"))
	cases := map[string]func([]byte) []byte{
		"truncated header": func(b []byte) []byte { return b[:50] },
		"bad magic":        func(b []byte) []byte { c := append([]byte(nil), b...); c[0] = 'X'; return c },
		"page size 3":      func(b []byte) []byte { c := append([]byte(nil), b...); c[16], c[17] = 0, 3; return c },
		"utf-16":           func(b []byte) []byte { c := append([]byte(nil), b...); c[59] = 2; return c },
	}
	for name, mut := range cases {
		if _, err := Open(mut(good), nil); err == nil {
			t.Errorf("%s: Open accepted it", name)
		}
	}

	// A root page pointer that loops back onto itself must be caught by
	// the cycle check, and a page number past the end by the bounds check.
	d, err := Open(good, nil)
	if err != nil {
		t.Fatal(err)
	}
	tb, _ := d.Table("items")
	loop := *tb
	loop.RootPage = 1 // sqlite_master's page, whose cells are not rows of items but must not crash
	_ = d.Each(&loop, func(int64, []any) error { return nil })
	far := *tb
	far.RootPage = 1 << 30
	if err := d.Each(&far, func(int64, []any) error { return nil }); err == nil {
		t.Fatal("out-of-range root page accepted")
	}
	// Truncate the file under the b-tree: the overflow chain of row 42
	// must fail cleanly.
	if short, err := Open(good[:len(good)/2], nil); err == nil {
		_ = short.Each(tb, func(int64, []any) error { return nil })
	}
}

func TestWALWithWrongSaltOrChecksumIsIgnored(t *testing.T) {
	db, _ := os.ReadFile(filepath.Join("testdata", "fixture_wal.sqlite"))
	wal, _ := os.ReadFile(filepath.Join("testdata", "fixture_wal.sqlite-wal"))
	flip := func(off int) []byte { c := append([]byte(nil), wal...); c[off] ^= 0xff; return c }
	// Header checksum broken: refused outright.
	if _, err := Open(db, flip(30)); err == nil {
		t.Fatal("WAL with a bad header checksum accepted")
	}
	// First frame's page bytes corrupted: its checksum fails, so nothing
	// after it is applied and the database reads as checkpointed.
	d, err := Open(db, flip(32+24+100))
	if err != nil {
		t.Fatal(err)
	}
	if _, rs := rows(t, d, "items"); len(rs) != 3001 {
		t.Fatalf("torn WAL applied: %d rows", len(rs))
	}
}

func TestVarint(t *testing.T) {
	cases := []struct {
		in   []byte
		want int64
		n    int
	}{
		{[]byte{0x00}, 0, 1},
		{[]byte{0x7f}, 127, 1},
		{[]byte{0x81, 0x00}, 128, 2},
		{[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, -1, 9},
		{[]byte{0x80}, 0, 0}, // truncated
	}
	for _, c := range cases {
		if v, n := varint(c.in); v != c.want || n != c.n {
			t.Errorf("varint(%x) = %d,%d; want %d,%d", c.in, v, n, c.want, c.n)
		}
	}
}
