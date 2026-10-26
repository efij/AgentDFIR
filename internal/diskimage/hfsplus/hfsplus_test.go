package hfsplus

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

func loadImage(t testing.TB, name string) []byte {
	t.Helper()
	f, err := os.Open("testdata/" + name)
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

func openBytes(t testing.TB, b []byte) *FS {
	t.Helper()
	fsys, err := OpenFS(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return fsys
}

func expected(t *testing.T) map[string]string {
	f, err := os.Open("testdata/expected.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	m := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if p := strings.Fields(sc.Text()); len(p) == 2 {
			m[p[1]] = p[0]
		}
	}
	return m
}

func sum(t *testing.T, fsys fs.FS, p string) string {
	t.Helper()
	b, err := fs.ReadFile(fsys, p)
	if err != nil {
		t.Fatalf("%s: %v", p, err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

func TestProbe(t *testing.T) {
	b := loadImage(t, "hfsplus.img.gz")
	if !Probe(bytes.NewReader(b), int64(len(b))) {
		t.Fatal("probe failed")
	}
	if Probe(bytes.NewReader(make([]byte, 8192)), 8192) || Probe(nil, 0) {
		t.Fatal("probe accepted zeros")
	}
}

func TestFixture(t *testing.T) {
	fsys := openBytes(t, loadImage(t, "hfsplus.img.gz"))
	want := expected(t)
	h := "Users/alice/"
	for p, name := range map[string]string{
		h + ".claude/projects/-Users-alice-proj/session.jsonl": "session.jsonl",
		h + "known.bin":            "known.bin",
		h + "fragmented.bin":       "fragmented.bin",
		h + "small-compressed.txt": "small-compressed.txt",
	} {
		if got := sum(t, fsys, p); got != want[name] {
			t.Errorf("%s sha256 %s, want %s", p, got, want[name])
		}
	}
	// fragmented.bin needs the extents-overflow B-tree.
	l, err := fsys.lookup("stat", h+"fragmented.bin")
	if err != nil {
		t.Fatal(err)
	}
	k, err := fsys.forkReader(l.node.id, 0, l.node.data, true)
	if err != nil || len(k.runs) <= 8 {
		t.Fatalf("fragmented runs %d %v", len(k.runs), err)
	}
	// Hard link: both names resolve to the indirect node.
	a, _ := fs.Stat(fsys, h+"notes.txt")
	b, _ := fs.Stat(fsys, h+"hardlink.txt")
	if a.Sys().(map[string]any)["inode"] != b.Sys().(map[string]any)["inode"] || b.Sys().(map[string]any)["hard_link"] != true {
		t.Errorf("hard link %v / %v", a.Sys(), b.Sys())
	}
	if sum(t, fsys, h+"notes.txt") != sum(t, fsys, h+"hardlink.txt") {
		t.Error("hard link content differs")
	}
	if tgt, err := fsys.ReadLink(h + "link"); err != nil || tgt != "docs/sub/nested.txt" {
		t.Errorf("readlink %q %v", tgt, err)
	}
	if xs := a.Sys().(map[string]any)["xattrs"].([]string); !strings.Contains(strings.Join(xs, ","), "com.example.zone") {
		t.Errorf("xattrs %v", xs)
	}
	if !a.ModTime().Equal(time.Date(2024, 8, 30, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("mtime %v", a.ModTime())
	}
	ents, err := fs.ReadDir(fsys, "many")
	if err != nil || len(ents) != 600 {
		t.Errorf("many: %d %v", len(ents), err)
	}
	root, _ := fs.ReadDir(fsys, ".")
	for _, e := range root {
		if strings.Contains(e.Name(), "Private") {
			t.Errorf("private folder listed: %q", e.Name())
		}
	}
	if _, err := fs.Stat(fsys, "users/ALICE/notes.txt"); err != nil {
		t.Errorf("case-insensitive lookup: %v", err)
	}
	// LZVN (what ditto writes): listed with its size, read is UNSUPPORTED.
	fi, err := fs.Stat(fsys, h+"compressed.txt")
	if err != nil || fi.Size() != 200000 {
		t.Fatalf("compressed stat %v %v", fi, err)
	}
	if _, err := fs.ReadFile(fsys, h+"compressed.txt"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("lzvn read: %v", err)
	}
	walkAll(t, fsys)
}

func TestHFSX(t *testing.T) {
	fsys := openBytes(t, loadImage(t, "hfsx.img.gz"))
	if fsys.Metadata()["fs"] != "hfsx" {
		t.Fatal(fsys.Metadata())
	}
	a, _ := fs.ReadFile(fsys, "Users/alice/CASE.txt")
	b, _ := fs.ReadFile(fsys, "Users/alice/case.txt")
	if string(a) != "upper\n" || string(b) != "lower\n" {
		t.Errorf("case-sensitive names %q %q", a, b)
	}
	if _, err := fs.Stat(fsys, "users/alice"); err == nil {
		t.Error("HFSX lookup ignored case")
	}
}

// TestDirtyJournal marks the volume journaled with a journal whose start
// and end differ: it is read as is and reported, never replayed.
func TestDirtyJournal(t *testing.T) {
	b := loadImage(t, "hfsplus.img.gz")
	vh := b[1024:]
	be.PutUint32(vh[4:], be.Uint32(vh[4:])|attrJournaled)
	jib := uint32(be.Uint32(vh[44:]) - 2) // a block near the end, unused by data
	be.PutUint32(vh[12:], jib)
	blk := b[int(jib)*4096:]
	clear(blk[:8192])
	be.PutUint32(blk, 1)                          // in-FS journal
	be.PutUint64(blk[36:], uint64(jib)*4096+4096) // journal header in the next block
	jh := blk[4096:]
	be.PutUint32(jh, 0x4a4e4c78)
	be.PutUint32(jh[4:], 0x12345678)
	be.PutUint64(jh[8:], 512)
	be.PutUint64(jh[16:], 4096)
	fsys := openBytes(t, b)
	if fsys.Metadata()["journal"] != "dirty (not replayed)" || !strings.Contains(strings.Join(fsys.Problems(), ";"), "not replayed") {
		t.Errorf("journal %v problems %v", fsys.Metadata()["journal"], fsys.Problems())
	}
	if _, err := fs.ReadFile(fsys, "Users/alice/known.bin"); err != nil {
		t.Error(err)
	}
}

func TestDamaged(t *testing.T) {
	b := loadImage(t, "hfsplus.img.gz")
	for _, n := range []int{600, 2048, len(b) / 3} {
		if _, err := OpenFS(bytes.NewReader(b[:n]), int64(n)); err == nil {
			t.Errorf("truncated to %d opened", n)
		}
	}
	fsys := openBytes(t, b)
	cat := fsys.catalog
	// Every catalog leaf links to itself: the chain walk must stop.
	looped := bytes.Clone(b)
	for n := uint32(1); n < cat.nodes; n++ {
		nd, err := cat.node(n)
		if err != nil || nd.kind != -1 {
			continue
		}
		off := catalogOffset(t, fsys, n)
		be.PutUint32(looped[off:], n)
	}
	checkTerminates(t, looped)
	// Garbage record offsets in every catalog node.
	garbled := bytes.Clone(b)
	for n := uint32(1); n < cat.nodes; n++ {
		off := catalogOffset(t, fsys, n)
		end := off + int(cat.nodeSize)
		for i := end - 40; i < end; i++ {
			garbled[i] ^= 0xa5
		}
	}
	checkTerminates(t, garbled)
}

// catalogOffset maps a catalog node number to its byte offset.
func catalogOffset(t *testing.T, f *FS, n uint32) int {
	t.Helper()
	logical := int64(n) * f.catalog.nodeSize
	for _, r := range f.catalog.r.runs {
		if s := r.logical * f.bs; logical >= s && logical < s+r.count*f.bs {
			return int(r.phys*f.bs + logical - s)
		}
	}
	t.Fatalf("node %d unmapped", n)
	return 0
}

func checkTerminates(t *testing.T, b []byte) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		fsys, err := OpenFS(bytes.NewReader(b), int64(len(b)))
		if err != nil {
			return
		}
		fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				fs.ReadFile(fsys, p)
			}
			return nil
		})
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("walk of a damaged volume did not terminate")
	}
}

func walkAll(t *testing.T, fsys fs.FS) {
	t.Helper()
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			if _, err := fs.ReadFile(fsys, p); err != nil && !errors.Is(err, errors.ErrUnsupported) {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
