package vss

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/diskimage/ntfs"
)

const (
	reportSize = 16384
	notesSize  = 8192 // head -c bound; the 256 rows are 7936 bytes
)

var (
	created1 = time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	created2 = time.Date(2026, 8, 15, 9, 0, 0, 0, time.UTC)
)

func lines(prefix string, n, size int) []byte {
	var b bytes.Buffer
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&b, prefix, i)
	}
	return b.Bytes()[:min(size, b.Len())]
}

func currentReport() []byte { return lines("CURRENT report %04d of 512 lines\n", 512, reportSize) }
func currentNotes() []byte  { return lines("CURRENT notes %04d of 256 rows\n", 256, notesSize) }
func reportV(n int) []byte {
	return lines(fmt.Sprintf("VERSION-%d report %%04d of 512 lines\n", n), 512, reportSize)
}

// oldBlocks returns, for every 16 KiB block the file range [at, at+len(old))
// touches, the current block with the file's bytes replaced by old.
func oldBlocks(vol []byte, at int64, old []byte) []synthBlock {
	var out []synthBlock
	end := at + int64(len(old))
	for base := at &^ (BlockSize - 1); base < end; base += BlockSize {
		b := slices.Clone(vol[base : base+BlockSize])
		lo, hi := max(at, base), min(end, base+BlockSize)
		copy(b[lo-base:hi-base], old[lo-at:hi-at])
		out = append(out, synthBlock{orig: base, data: b})
	}
	return out
}

// TestGenerateVSSFixture writes testdata/vss-synthetic.ntfs.gz from the
// base volume made by testdata/gen-vss.sh. Skipped unless ADFIR_GEN_VSS
// names that volume.
func TestGenerateVSSFixture(t *testing.T) {
	src := os.Getenv("ADFIR_GEN_VSS")
	if src == "" {
		t.Skip("set ADFIR_GEN_VSS=<base volume from gen-vss.sh> to regenerate")
	}
	vol, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(vol[HeaderOffset:HeaderOffset+512], make([]byte, 512)) {
		t.Fatal("0x1e00 is not free in the base volume")
	}
	rep := int64(bytes.Index(vol, currentReport()))
	notes := int64(bytes.Index(vol, currentNotes()))
	area := int64(bytes.Index(vol, bytes.Repeat([]byte("VSS-STORE-AREA!\n"), 262144/16)))
	if rep < 0 || notes < 0 || area < 0 || area%4096 != 0 {
		t.Fatalf("layout not found: report %d notes %d store area %d", rep, notes, area)
	}
	next := (area + BlockSize - 1) &^ (BlockSize - 1)
	alloc := func() int64 {
		off := next
		next += BlockSize
		if next > area+262144 {
			t.Fatal("store area exhausted")
		}
		return off
	}
	size := int64(len(vol))
	// Snapshot 2 overlays only the first sector of notes.txt.
	notesOld := slices.Clone(vol[notes&^(BlockSize-1) : notes&^(BlockSize-1)+BlockSize])
	sec := (notes % BlockSize) / 512
	copy(notesOld[sec*512:], bytes.Repeat([]byte("OLD-NOTES-SECTOR"), 32))
	snaps := []synthSnap{
		{id: 0xA1, created: created1, volSize: size, blocks: oldBlocks(vol, rep, reportV(1))},
		{id: 0xB2, created: created2, volSize: size, blocks: append(oldBlocks(vol, rep, reportV(2)),
			synthBlock{orig: notes &^ (BlockSize - 1), data: notesOld, flags: flagOverlay, bitmap: 1 << sec})},
	}
	// Written newest-first to prove the reader orders by creation time.
	slices.Reverse(snaps)
	writeStore(vol, alloc, snaps)
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	zw.Write(vol)
	zw.Close()
	if err := os.WriteFile(filepath.Join("testdata", "vss-synthetic.ntfs.gz"), gz.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d bytes", gz.Len())
}

func fixture(t testing.TB) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "vss-synthetic.ntfs.gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSyntheticFixtureSnapshots(t *testing.T) {
	vol := fixture(t)
	r := bytes.NewReader(vol)
	cur, err := ntfs.OpenVolume(r, int64(len(vol)))
	if err != nil {
		t.Fatal(err)
	}
	if cur.Stats().ShadowStore != 1 {
		t.Fatalf("store file not counted: %+v", cur.Stats())
	}
	if b, _ := fs.ReadFile(cur, "Users/alice/report.txt"); !bytes.Equal(b, currentReport()) {
		t.Fatal("current volume changed by the store")
	}
	st, err := Open(r, int64(len(vol)))
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Snapshots) != 2 || len(st.Problems) != 0 {
		t.Fatalf("snapshots %d problems %v", len(st.Snapshots), st.Problems)
	}
	s1, s2 := st.Snapshots[0], st.Snapshots[1]
	if !s1.Created.Equal(created1) || !s2.Created.Equal(created2) || s1.Index != 1 || s2.Index != 2 {
		t.Fatalf("order/creation: %+v %+v", s1, s2)
	}
	if s1.StoreID != "a1a1a1a1-a1a1-a1a1-a1a1-a1a1a1a1a1a1" || s1.ShadowCopyID != "b1b1b1b1-b1b1-b1b1-b1b1-b1b1b1b1b1b1" ||
		s1.Machine != "WS-01.example.test" || s1.Status != StatusOK || s1.BitmapBlocks != 8 {
		t.Fatalf("snapshot 1 metadata %+v", s1)
	}
	if s2.Overlays != 1 || s2.Blocks < 2 {
		t.Fatalf("snapshot 2 blocks %+v", s2)
	}
	for i, want := range [][]byte{reportV(1), reportV(2)} {
		sr, n, err := st.Volume(i + 1)
		if err != nil {
			t.Fatal(err)
		}
		v, err := ntfs.OpenVolume(sr, n)
		if err != nil {
			t.Fatalf("snapshot %d: %v", i+1, err)
		}
		got, err := fs.ReadFile(v, "Users/alice/report.txt")
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("snapshot %d report: %v %q", i+1, err, got[:min(len(got), 40)])
		}
		// notes.txt: overlay in store 2 only; snapshot 1 reads through it.
		nb, err := fs.ReadFile(v, "Users/alice/notes.txt")
		if err != nil || !bytes.HasPrefix(nb, []byte("OLD-NOTES-SECTOR")) || !bytes.Equal(nb[512:], currentNotes()[512:]) {
			t.Fatalf("snapshot %d notes: %v %q", i+1, err, nb[:min(len(nb), 40)])
		}
	}
	if _, _, err := st.Volume(3); err == nil {
		t.Fatal("snapshot 3 opened")
	}
}

// memVolume: a 512 KiB non-filesystem volume whose block k is filled with
// byte 'a'+k, plus a store area in its upper half.
func memVolume() ([]byte, func() int64) {
	vol := make([]byte, 512<<10)
	for k := 0; k < 16; k++ {
		for i := 0; i < BlockSize; i++ {
			vol[k*BlockSize+i] = byte('a' + k)
		}
	}
	clear(vol[HeaderOffset : HeaderOffset+512])
	next := int64(256 << 10)
	return vol, func() int64 { off := next; next += BlockSize; return off }
}

func filled(c byte) []byte { return bytes.Repeat([]byte{c}, BlockSize) }

func readBlockN(t *testing.T, st *Store, snap int, k int64) []byte {
	t.Helper()
	r, _, err := st.Volume(snap)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, BlockSize)
	if _, err := r.ReadAt(b, k*BlockSize); err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMemoryStoreSemantics(t *testing.T) {
	vol, alloc := memVolume()
	size := int64(len(vol))
	overlay := filled('o')
	writeStore(vol, alloc, []synthSnap{
		{id: 1, created: created1, volSize: size, blocks: []synthBlock{
			{orig: 1 * BlockSize, data: filled('1')},
			{orig: 4 * BlockSize, flags: flagNotUsed},
		}},
		{id: 2, created: created2, volSize: size, blocks: []synthBlock{
			{orig: 1 * BlockSize, data: filled('2')},
			{orig: 2 * BlockSize, data: filled('2')},
			{orig: 3 * BlockSize, data: overlay, flags: flagOverlay, bitmap: 0b101},
			{orig: 5 * BlockSize, flags: flagForwarder, rel: 6 * BlockSize},
		}},
	})
	st, err := Open(bytes.NewReader(vol), size)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		snap int
		blk  int64
		want func(b []byte) bool
		what string
	}{
		{1, 1, func(b []byte) bool { return bytes.Equal(b, filled('1')) }, "own store wins"},
		{2, 1, func(b []byte) bool { return bytes.Equal(b, filled('2')) }, "own store wins"},
		{1, 2, func(b []byte) bool { return bytes.Equal(b, filled('2')) }, "falls through to the newer store"},
		{1, 0, func(b []byte) bool { return bytes.Equal(b[:HeaderOffset], filled('a')[:HeaderOffset]) }, "falls through to the current volume"},
		{1, 4, func(b []byte) bool { return bytes.Equal(b, filled('e')) }, "not-used descriptor ignored"},
		{2, 3, func(b []byte) bool {
			return bytes.Equal(b[:512], overlay[:512]) && bytes.Equal(b[512:1024], filled('d')[:512]) &&
				bytes.Equal(b[1024:1536], overlay[:512]) && bytes.Equal(b[1536:], filled('d')[1536:])
		}, "overlay replaces only its sectors"},
		{2, 5, func(b []byte) bool { return bytes.Equal(b, filled('g')) }, "forwarder reads its target"},
	}
	for _, c := range cases {
		if b := readBlockN(t, st, c.snap, c.blk); !c.want(b) {
			t.Errorf("snapshot %d block %d: %s: got %q…", c.snap, c.blk, c.what, b[:8])
		}
	}
	// Reads that straddle blocks and the end of the volume.
	r, n, _ := st.Volume(1)
	b := make([]byte, 100)
	if _, err := r.ReadAt(b, BlockSize-50); err != nil || b[0] != 'a' || b[99] != '1' {
		t.Fatalf("straddling read %q %v", b, err)
	}
	if got, err := r.ReadAt(b, n-10); got != 10 || !errors.Is(err, io.EOF) {
		t.Fatalf("read at end: %d %v", got, err)
	}
}

// mutate builds a fresh two-snapshot store and applies f to the raw bytes.
func mutate(t *testing.T, f func(vol []byte, st *Store)) (*Store, error) {
	t.Helper()
	vol, alloc := memVolume()
	size := int64(len(vol))
	writeStore(vol, alloc, []synthSnap{
		{id: 1, created: created1, volSize: size, blocks: []synthBlock{{orig: BlockSize, data: filled('1')}}},
		{id: 2, created: created2, volSize: size, blocks: []synthBlock{{orig: BlockSize, data: filled('2')}}},
	})
	orig, err := Open(bytes.NewReader(vol), size)
	if err != nil {
		t.Fatal(err)
	}
	f(vol, orig)
	return Open(bytes.NewReader(vol), size)
}

func TestDamagedStores(t *testing.T) {
	le := binary.LittleEndian
	t.Run("no header", func(t *testing.T) {
		vol, _ := memVolume()
		if _, err := Open(bytes.NewReader(vol), int64(len(vol))); !errors.Is(err, ErrNoStore) {
			t.Fatalf("want ErrNoStore, got %v", err)
		}
	})
	t.Run("header version 2", func(t *testing.T) {
		_, err := mutate(t, func(vol []byte, _ *Store) { le.PutUint32(vol[HeaderOffset+16:], 2) })
		if !errors.Is(err, ErrUnsupported) {
			t.Fatalf("want unsupported, got %v", err)
		}
	})
	t.Run("no catalog", func(t *testing.T) {
		st, err := mutate(t, func(vol []byte, _ *Store) { le.PutUint64(vol[HeaderOffset+48:], 0) })
		if err != nil || len(st.Snapshots) != 0 {
			t.Fatalf("%v %v", err, st)
		}
	})
	t.Run("catalog outside volume", func(t *testing.T) {
		_, err := mutate(t, func(vol []byte, _ *Store) { le.PutUint64(vol[HeaderOffset+48:], 1<<40) })
		if err == nil {
			t.Fatal("accepted")
		}
	})
	t.Run("catalog loop", func(t *testing.T) {
		st, err := mutate(t, func(vol []byte, s *Store) { le.PutUint64(vol[s.Catalog+40:], uint64(s.Catalog)) })
		if err != nil || len(st.Snapshots) != 2 || !strings.Contains(strings.Join(st.Problems, " "), "loops") {
			t.Fatalf("%v %+v", err, st)
		}
	})
	t.Run("unknown catalog entry", func(t *testing.T) {
		st, err := mutate(t, func(vol []byte, s *Store) { le.PutUint64(vol[s.Catalog+128+4*128:], 9) })
		if err != nil || len(st.Problems) == 0 {
			t.Fatalf("%v %+v", err, st)
		}
	})
	t.Run("unknown descriptor flag", func(t *testing.T) {
		st, err := mutate(t, func(vol []byte, s *Store) {
			le.PutUint32(vol[s.Snapshots[1].blockList+128+24:], 0x80)
		})
		if err != nil {
			t.Fatal(err)
		}
		s2 := st.Snapshots[1]
		if s2.Status != StatusUnsupported || !strings.Contains(s2.Reason, "flags") {
			t.Fatalf("%+v", s2)
		}
		if _, _, err := st.Volume(2); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("unsupported snapshot opened: %v", err)
		}
		// Snapshot 1 is fine itself, but a read that falls through to the
		// unsupported newer store must fail rather than guess.
		r, _, err := st.Volume(1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := r.ReadAt(make([]byte, 16), 0); !errors.Is(err, ErrUnsupported) {
			t.Fatalf("read through an unsupported store: %v", err)
		}
		if _, err := r.ReadAt(make([]byte, 16), BlockSize); err != nil {
			t.Fatalf("own block: %v", err)
		}
	})
	t.Run("data offset outside volume", func(t *testing.T) {
		st, _ := mutate(t, func(vol []byte, s *Store) { le.PutUint64(vol[s.Snapshots[0].blockList+128+16:], 1<<40) })
		if st.Snapshots[0].Status != StatusUnsupported {
			t.Fatalf("%+v", st.Snapshots[0])
		}
	})
	t.Run("store header wrong type", func(t *testing.T) {
		st, _ := mutate(t, func(vol []byte, s *Store) { le.PutUint32(vol[s.Snapshots[0].storeHeader+20:], 7) })
		if st.Snapshots[0].Status != StatusUnsupported || !strings.Contains(st.Snapshots[0].Reason, "store header") {
			t.Fatalf("%+v", st.Snapshots[0])
		}
	})
	t.Run("block list loop", func(t *testing.T) {
		st, _ := mutate(t, func(vol []byte, s *Store) {
			bl := s.Snapshots[0].blockList
			le.PutUint64(vol[bl+40:], uint64(bl))
		})
		if st.Snapshots[0].Status != StatusUnsupported || !strings.Contains(st.Snapshots[0].Reason, "loops") {
			t.Fatalf("%+v", st.Snapshots[0])
		}
	})
	t.Run("volume size larger than volume", func(t *testing.T) {
		st, _ := mutate(t, func(vol []byte, s *Store) {
			le.PutUint64(vol[s.Catalog+128+8:], 1<<40)
		})
		if st.Snapshots[0].Status != StatusUnsupported && st.Snapshots[1].Status != StatusUnsupported {
			t.Fatalf("%+v %+v", st.Snapshots[0], st.Snapshots[1])
		}
	})
	t.Run("forwarder with one store", func(t *testing.T) {
		vol, alloc := memVolume()
		size := int64(len(vol))
		writeStore(vol, alloc, []synthSnap{{id: 1, created: created1, volSize: size, blocks: []synthBlock{
			{orig: BlockSize, flags: flagForwarder, rel: 2 * BlockSize},
		}}})
		st, err := Open(bytes.NewReader(vol), size)
		if err != nil {
			t.Fatal(err)
		}
		// One store: the forwarder target comes from the current volume.
		if b := readBlockN(t, st, 1, 1); b[0] != 'c' {
			t.Fatalf("forwarder: %q", b[:4])
		}
	})
	t.Run("truncated volume", func(t *testing.T) {
		vol, alloc := memVolume()
		size := int64(len(vol))
		writeStore(vol, alloc, []synthSnap{{id: 1, created: created1, volSize: size, blocks: []synthBlock{{orig: BlockSize, data: filled('1')}}}})
		for _, cut := range []int{HeaderOffset + 100, 260 << 10, 300 << 10} {
			c := vol[:cut]
			st, err := Open(bytes.NewReader(c), int64(len(c)))
			if err == nil {
				for _, sn := range st.Snapshots {
					if sn.Status == StatusOK {
						t.Fatalf("cut %d: snapshot usable on a truncated volume: %+v", cut, sn)
					}
				}
			}
		}
	})
}
