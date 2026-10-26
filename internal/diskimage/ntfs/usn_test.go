package ntfs

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestUSNJournalFixture(t *testing.T) {
	v := openUSNFixture(t)
	recs, st, err := v.USN()
	if err != nil {
		t.Fatal(err)
	}
	if st.Status != "read" || !st.Present || st.StreamSize != 73728 {
		t.Fatalf("stats %+v", st)
	}
	// The 64 KiB leading hole is skipped by run, never read.
	if st.SparseSkipped != 65536 || st.BytesScanned != 8192 {
		t.Fatalf("sparse %d scanned %d", st.SparseSkipped, st.BytesScanned)
	}
	if st.Records != 9 || st.V2 != 6 || st.V3 != 2 || st.V4Unsupported != 1 {
		t.Fatalf("counts %+v", st)
	}
	if st.GarbageSkipped != 24 || st.Resyncs != 1 {
		t.Fatalf("garbage %d resyncs %d", st.GarbageSkipped, st.Resyncs)
	}
	byName := map[string]USNRecord{}
	for _, r := range recs {
		if r.FileName != "" {
			byName[r.FileName+"@"+r.Timestamp.Format(time.TimeOnly)] = r
		}
	}
	first := recs[0]
	if first.Offset != 65536 || first.FileName != "keep.txt" || first.Path != "/Users/alice/proj/keep.txt" ||
		first.PathStatus != "resolved" || !slices.Equal(first.Reasons, []string{"FILE_CREATE"}) ||
		!slices.Equal(first.Attributes, []string{"ARCHIVE"}) || first.FileRecord != 67 || first.ParentRecord != 66 {
		t.Fatalf("first record %+v", first)
	}
	if !first.Timestamp.Equal(time.Date(2026, 8, 30, 10, 1, 0, 0, time.UTC)) {
		t.Fatalf("timestamp %v", first.Timestamp)
	}
	if r := recs[1]; !slices.Equal(r.Reasons, []string{"DATA_EXTEND", "FILE_CREATE", "CLOSE"}) {
		t.Fatalf("reasons %v", r.Reasons)
	}
	v3 := recs[2]
	if v3.MajorVersion != 3 || len(v3.FileRef) != 32 || v3.Path != "/Users/alice/proj/newcomer.txt" ||
		!slices.Equal(v3.SourceInfoText, []string{"AUXILIARY_DATA"}) {
		t.Fatalf("v3 %+v", v3)
	}
	// The delete record still resolves: its parent directory is intact.
	if d := recs[3]; d.Path != "/Users/alice/proj/deleted-big.txt" || !slices.Contains(d.Reasons, "FILE_DELETE") {
		t.Fatalf("delete %+v", d)
	}
	if r := recs[4]; r.Path != PathReusedEntry+"/renamed.txt" || r.PathStatus != "reused-mft-entry" {
		t.Fatalf("stale parent sequence not flagged: %+v", r)
	}
	if r := recs[5]; r.MajorVersion != 4 || r.Status != StatusUnsupported || r.Path != "" || r.FileRecord != 68 {
		t.Fatalf("v4 %+v", r)
	}
	if r := recs[6]; r.Path != "/Users" || r.Offset != 66104 {
		t.Fatalf("record after garbage %+v", r)
	}
	if r := recs[7]; r.PathStatus != "unresolved" || !strings.Contains(r.Path, "3000") {
		t.Fatalf("unknown parent %+v", r)
	}
	if r := recs[8]; r.Offset != 69632 || r.FileName != "kept-big.bin" {
		t.Fatalf("second page %+v", r)
	}
}

func TestUSNAbsent(t *testing.T) {
	v := openFixture(t)
	recs, st, err := v.USN()
	if err != nil || len(recs) != 0 || st.Status != "absent" || st.Present {
		t.Fatalf("absent journal: %v %d %+v", err, len(recs), st)
	}
}

func TestUSNWalkStops(t *testing.T) {
	v := openUSNFixture(t)
	stop := errors.New("enough")
	n := 0
	_, err := v.WalkUSN(func(USNRecord) error {
		n++
		if n == 2 {
			return stop
		}
		return nil
	})
	if !errors.Is(err, stop) || n != 2 {
		t.Fatalf("walk stop: %v after %d", err, n)
	}
}

func TestParseUSNRecord(t *testing.T) {
	ts := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	b := buildUSNv2(usnSpec{file: mkref(40, 3), parent: mkref(5, 5), usn: 4096, ts: ts, reason: 0x00000201 | 0x40000000, attrs: 0x2 | 0x1000000, name: "naïve.txt"})
	r, err := ParseUSNRecord(b)
	if err != nil {
		t.Fatal(err)
	}
	if r.FileName != "naïve.txt" || r.FileSeq != 3 || r.FileRecord != 40 || r.USN != 4096 || !r.Timestamp.Equal(ts) {
		t.Fatalf("%+v", r)
	}
	// Undocumented bits are kept as hex, never dropped.
	if !slices.Equal(r.Reasons, []string{"DATA_OVERWRITE", "FILE_DELETE", "0x40000000"}) ||
		!slices.Equal(r.Attributes, []string{"HIDDEN", "0x01000000"}) {
		t.Fatalf("flags %v %v", r.Reasons, r.Attributes)
	}
	bad := map[string][]byte{
		"short":         b[:7],
		"length>buffer": b[:len(b)-8],
		"name outside": func() []byte {
			c := slices.Clone(b)
			c[56] = 0xF0
			return c
		}(),
		"name offset in header": func() []byte {
			c := slices.Clone(b)
			c[58] = 8
			return c
		}(),
		"odd name length": func() []byte {
			c := slices.Clone(b)
			c[56] = 3
			return c
		}(),
		"version 9": func() []byte {
			c := slices.Clone(b)
			c[4] = 9
			return c
		}(),
		"v3 too short": func() []byte {
			c := slices.Clone(b)
			c[4] = 3
			return c[:64]
		}(),
		"negative usn": func() []byte {
			c := slices.Clone(b)
			c[31] = 0x80
			return c
		}(),
	}
	for name, c := range bad {
		if _, err := ParseUSNRecord(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// scanBytes runs the scanner over a raw $J image (no volume).
func scanBytes(t *testing.T, j []byte) ([]USNRecord, USNStats) {
	t.Helper()
	f := &Volume{nodes: map[uint64]*node{}}
	st := USNStats{}
	var out []USNRecord
	sc := &usnScanner{fsys: f, st: &st, fn: func(r USNRecord) error { out = append(out, r); return nil }, paths: map[uint64]pathResult{}}
	s := &stream{resident: j, size: int64(len(j)), initSize: int64(len(j)), cuIdx: -1}
	if err := sc.scanExtent(s, 0, int64(len(j))); err != nil {
		t.Fatal(err)
	}
	return out, st
}

func TestUSNScannerDamage(t *testing.T) {
	rec := buildUSNv2(usnSpec{file: mkref(70, 1), parent: mkref(5, 5), usn: 8, reason: 0x100, name: "a.txt"})
	// Garbage of every flavour between valid records: implausible lengths,
	// misaligned lengths, a length past the end, a bad version.
	var j []byte
	j = append(j, rec...)
	j = append(j, 0x13, 0, 0, 0, 2, 0, 0, 0) // length 19 (unaligned)
	j = append(j, 0, 0x20, 0, 0, 2, 0, 0, 0) // length 8192 (> page)
	j = append(j, 64, 0, 0, 0, 7, 0, 0, 0)   // version 7
	j = append(j, rec...)
	j = append(j, make([]byte, 40)...) // zero padding
	j = append(j, rec...)
	tail := slices.Clone(rec)
	j = append(j, tail[:len(tail)-16]...) // cut-off record at the end
	recs, st := scanBytes(t, j)
	if len(recs) != 3 || st.V2 != 3 {
		t.Fatalf("got %d records, stats %+v", len(recs), st)
	}
	if st.Resyncs < 2 || st.GarbageSkipped < 24+40 {
		t.Fatalf("resync accounting %+v", st)
	}
	for _, r := range recs {
		if r.Path != "(mft-record-5-not-in-use)" || r.PathStatus != "unresolved" {
			t.Fatalf("path without MFT: %+v", r)
		}
	}
}

func TestUSNScannerChunkBoundary(t *testing.T) {
	// Records straddling the 1 MiB read chunk must be carried over, not lost.
	rec := buildUSNv3(usnSpec{file: mkref(70, 1), parent: mkref(5, 5), usn: 8, reason: 0x2, name: "chunk-boundary.bin"})
	var j []byte
	for len(j) < 3*usnChunk {
		j = append(j, rec...)
	}
	want := len(j) / len(rec)
	recs, st := scanBytes(t, j)
	if len(recs) != want || st.GarbageSkipped != 0 || st.Resyncs != 0 {
		t.Fatalf("got %d/%d records, %+v", len(recs), want, st)
	}
}

func TestUSNDamagedVolume(t *testing.T) {
	b := usnFixtureBytes(t)
	v, err := OpenVolume(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	s, _ := v.usnStream()
	ex := s.extents()
	r, _ := s.lookup(ex[0][0] / v.v.clusterSize)
	phys := r.lcn * v.v.clusterSize
	// Scribble over the journal clusters: the walk must survive and
	// account for what it skipped.
	c := slices.Clone(b)
	for i := phys; i < phys+8192; i += 13 {
		c[i] ^= 0xA5
	}
	v2, err := OpenVolume(bytes.NewReader(c), int64(len(c)))
	if err != nil {
		t.Fatal(err)
	}
	_, st, err := v2.USN()
	if err != nil || st.Status != "read" || st.GarbageSkipped == 0 {
		t.Fatalf("damaged journal: %v %+v", err, st)
	}
	// A reader that fails mid-stream is reported, not fatal.
	v3, err := OpenVolume(&failAfter{r: bytes.NewReader(b), limit: phys}, int64(len(b)))
	if err != nil {
		t.Fatalf("journal clusters lie before the MFT in this fixture: %v", err)
	}
	_, st, err = v3.USN()
	if err != nil || len(st.Problems) == 0 {
		t.Fatalf("read error not reported: %v %+v", err, st)
	}
}

// failAfter fails every read that reaches past limit.
type failAfter struct {
	r     io.ReaderAt
	limit int64
}

func (f *failAfter) ReadAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > f.limit && off >= f.limit {
		return 0, errors.New("injected read error")
	}
	return f.r.ReadAt(p, off)
}
