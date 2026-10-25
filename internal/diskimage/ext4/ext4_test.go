package ext4

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func loadImage(t testing.TB, name string) []byte {
	t.Helper()
	fh, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	zr, err := gzip.NewReader(fh)
	if err != nil {
		t.Fatal(err)
	}
	b, err := io.ReadAll(zr)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// expected parses testdata/expected.txt, written by gen.sh with coreutils.
func expected(t *testing.T) map[string]string {
	t.Helper()
	fh, err := os.Open("testdata/expected.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer fh.Close()
	out := map[string]string{}
	sc := bufio.NewScanner(fh)
	for sc.Scan() {
		sum, p, ok := strings.Cut(sc.Text(), "  ")
		if ok {
			out[p] = sum
		}
	}
	return out
}

func openImage(t *testing.T, name string) *FS {
	t.Helper()
	b := loadImage(t, name)
	r := bytes.NewReader(b)
	if !Probe(r, int64(len(b))) {
		t.Fatalf("%s: Probe = false", name)
	}
	fsys, err := Open(r, int64(len(b)))
	if err != nil {
		t.Fatalf("%s: Open: %v", name, err)
	}
	return fsys.(*FS)
}

func hashFile(t *testing.T, fsys fs.FS, name string) string {
	t.Helper()
	f, err := fsys.Open(name)
	if err != nil {
		t.Fatalf("open %s: %v", name, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	return hex.EncodeToString(h.Sum(nil))
}

var fixtureTime = time.Date(2024, 3, 15, 12, 34, 56, 0, time.UTC)

func TestExt4Contents(t *testing.T) {
	fsys := openImage(t, "ext4.img.gz")
	for p, sum := range expected(t) {
		if strings.Contains(p, ":") {
			continue
		}
		if strings.HasPrefix(p, "secret/") {
			_, err := fsys.Open(p)
			if !errors.Is(err, errors.ErrUnsupported) {
				t.Errorf("open %s in encrypted dir: err = %v, want ErrUnsupported", p, err)
			}
			continue
		}
		if got := hashFile(t, fsys, p); got != sum {
			t.Errorf("%s: sha256 %s, want %s", p, got, sum)
		}
	}
	// The fragmented file really is fragmented (an index level).
	in, err := fsys.lookup("stat", "fragmented.bin")
	if err != nil {
		t.Fatal(err)
	}
	if d := le.Uint16(in.block[6:]); d < 1 {
		t.Errorf("fragmented.bin extent depth = %d, want >= 1", d)
	}
	runs, _ := fsys.mapInode(in)
	if len(runs) < 5 {
		t.Errorf("fragmented.bin has %d runs, want >= 5", len(runs))
	}
}

func TestExt4ListingAndTimes(t *testing.T) {
	fsys := openImage(t, "ext4.img.gz")
	ents, err := fsys.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	want := "docs frag fragmented.bin home known.bin link-abs link-fast link-slow lost+found secret sparse.bin"
	if got := strings.Join(names, " "); got != want {
		t.Errorf("root listing\n got %s\nwant %s", got, want)
	}
	st, err := fs.Stat(fsys, "home/alice/.claude/projects/p/session.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if !st.ModTime().Equal(fixtureTime) {
		t.Errorf("mtime = %v, want %v", st.ModTime(), fixtureTime)
	}
	sys := st.Sys().(map[string]any)
	if !sys["atime"].(time.Time).Equal(fixtureTime) || sys["fs"] != "ext4" || sys["mode"].(uint32)&0xF000 != 0x8000 {
		t.Errorf("sys = %v", sys)
	}
	if sys["inode"].(uint64) == 0 || sys["btime"].(time.Time).IsZero() || sys["ctime"].(time.Time).IsZero() {
		t.Errorf("sys inode/btime/ctime missing: %v", sys)
	}
	if st.Size() != 98 {
		t.Errorf("size = %d", st.Size())
	}
	sp, _ := fs.Stat(fsys, "sparse.bin")
	if sp.Size() != 1048576+4096 {
		t.Errorf("sparse size = %d", sp.Size())
	}
}

func TestExt4Symlinks(t *testing.T) {
	fsys := openImage(t, "ext4.img.gz")
	long := strings.Repeat("n", 240) + ".txt"
	for name, target := range map[string]string{"link-fast": "docs/small.txt", "link-slow": "docs/" + long, "link-abs": "/etc/passwd"} {
		st, err := fsys.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode()&fs.ModeSymlink == 0 {
			t.Errorf("%s mode %v", name, st.Mode())
		}
		if got, _ := fsys.ReadLink(name); got != target {
			t.Errorf("%s -> %q, want %q", name, got, target)
		}
		if got := st.Sys().(map[string]any)["symlink_target"]; got != target {
			t.Errorf("%s sys target %v", name, got)
		}
		f, err := fsys.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Read(make([]byte, 10)); err == nil {
			t.Errorf("%s: read through symlink succeeded", name)
		}
	}
	if _, err := fsys.Open("link-fast/x"); err == nil {
		t.Error("lookup through a symlink succeeded")
	}
}

func TestExt4EncryptedAndStats(t *testing.T) {
	fsys := openImage(t, "ext4.img.gz")
	if _, err := fsys.ReadDir("secret"); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("ReadDir(secret) err = %v", err)
	}
	st, _ := fsys.Stat("secret")
	if st.Sys().(map[string]any)["unsupported"] != "fscrypt-encrypted" {
		t.Errorf("secret sys = %v", st.Sys())
	}
	ents, err := fsys.ReadDir("frag")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 20 {
		t.Errorf("frag has %d entries, want 20", len(ents))
	}
	s := fsys.Stats()
	if s["deleted_entries"] < 10 || s["unsupported_entries"] < 1 {
		t.Errorf("stats = %v", s)
	}
	if md := fsys.Metadata(); md["needs_recovery"] != false || md["label"] != "adfir-ext4" || md["uuid"] != "11111111-2222-3333-4444-555555555555" {
		t.Errorf("metadata = %v", md)
	}
	root, _ := fsys.Stat(".")
	if _, ok := root.Sys().(map[string]any)["deleted_entries"]; !ok {
		t.Error("root sys lacks deleted_entries")
	}
}

func TestExt2BlockMaps(t *testing.T) {
	fsys := openImage(t, "ext2.img.gz")
	exp := expected(t)
	if got := hashFile(t, fsys, "known.bin"); got != exp["known.bin"] {
		t.Errorf("known.bin %s", got)
	}
	if got := hashFile(t, fsys, "deep.bin"); got != exp["ext2:deep.bin"] {
		t.Errorf("deep.bin (triple indirect) %s", got)
	}
	if got := hashFile(t, fsys, "home/alice/.claude/projects/p/session.jsonl"); got != exp["home/alice/.claude/projects/p/session.jsonl"] {
		t.Errorf("session.jsonl %s", got)
	}
	if md := fsys.Metadata(); md["fs"] != "ext2" {
		t.Errorf("fs = %v", md["fs"])
	}
	st, _ := fsys.Stat("known.bin")
	if !st.ModTime().Equal(fixtureTime) {
		t.Errorf("mtime %v", st.ModTime())
	}
	if !st.Sys().(map[string]any)["btime"].(time.Time).IsZero() {
		t.Error("128-byte inode has a btime")
	}
}

func TestExt4InlineMetaBg(t *testing.T) {
	fsys := openImage(t, "ext4-inline.img.gz")
	exp := expected(t)
	if got := hashFile(t, fsys, "tiny/a.txt"); got != exp["inline:tiny/a.txt"] {
		t.Errorf("tiny/a.txt %s", got)
	}
	if got := hashFile(t, fsys, "known.bin"); got != exp["known.bin"] {
		t.Errorf("known.bin %s", got)
	}
	if got := hashFile(t, fsys, "home/alice/.claude/projects/p/session.jsonl"); got != exp["home/alice/.claude/projects/p/session.jsonl"] {
		t.Errorf("session.jsonl %s", got)
	}
	ents, err := fsys.ReadDir("tiny")
	if err != nil || len(ents) != 2 || ents[0].Name() != "a.txt" || ents[1].Name() != "b.txt" {
		t.Fatalf("tiny = %v, %v", ents, err)
	}
	st, _ := fsys.Stat("tiny")
	if st.Sys().(map[string]any)["inline_data"] != true {
		t.Error("tiny is not inline")
	}
	if md := fsys.Metadata(); md["needs_recovery"] != true || md["feature_incompat"].(uint32)&incompatMetaBg == 0 {
		t.Errorf("metadata = %v", md)
	}
}

func TestFSTest(t *testing.T) {
	// ext2's deep.bin is a 70 MB sparse file; check its home subtree only.
	sub, err := fs.Sub(openImage(t, "ext2.img.gz"), "home")
	if err != nil {
		t.Fatal(err)
	}
	if err := fstest.TestFS(sub, "alice/.claude/projects/p/session.jsonl"); err != nil {
		t.Errorf("ext2: %v", err)
	}
	if err := fstest.TestFS(openImage(t, "ext4-inline.img.gz"), "known.bin", "tiny/a.txt", "home/alice/.claude/projects/p/session.jsonl"); err != nil {
		t.Errorf("inline: %v", err)
	}
	docs, _ := fs.Sub(openImage(t, "ext4.img.gz"), "docs")
	if err := fstest.TestFS(docs, "small.txt", "sub/nested.txt"); err != nil {
		t.Errorf("ext4 docs: %v", err)
	}
}

func TestCorruptAndTruncated(t *testing.T) {
	b := loadImage(t, "ext4.img.gz")
	bad := append([]byte{}, b...)
	bad[sbOffset+0x38] = 0
	if Probe(bytes.NewReader(bad), int64(len(bad))) {
		t.Error("Probe accepted a bad magic")
	}
	if _, err := Open(bytes.NewReader(bad), int64(len(bad))); err == nil {
		t.Error("Open accepted a bad magic")
	}
	half := b[:len(b)/2]
	if _, err := Open(bytes.NewReader(half), int64(len(half))); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Errorf("truncated image: err = %v", err)
	}
	if _, err := Open(bytes.NewReader(b[:100]), 100); err == nil {
		t.Error("tiny image accepted")
	}
	bad = append([]byte{}, b...)
	bad[sbOffset+0x18] = 40 // block size exponent
	if _, err := Open(bytes.NewReader(bad), int64(len(bad))); err == nil {
		t.Error("absurd block size accepted")
	}
	bad = append([]byte{}, b...)
	bad[sbOffset+0x60+2] |= 0x80 // unknown incompat bit
	if _, err := Open(bytes.NewReader(bad), int64(len(bad))); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("unknown incompat: err = %v", err)
	}
	if Probe(bytes.NewReader(nil), 0) {
		t.Error("Probe on empty input")
	}
	if _, err := openImage(t, "ext4.img.gz").Open("../x"); err == nil {
		t.Error("invalid path accepted")
	}
}

// walk reads every reachable file with a cap and returns the first error
// that is not a per-entry one; it must never panic.
func walk(fsys fs.FS) {
	n := 0
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if n++; n > 2000 {
			return fs.SkipAll
		}
		if err != nil {
			return nil
		}
		if _, err := d.Info(); err != nil {
			return nil
		}
		if d.Type().IsRegular() {
			if f, err := fsys.Open(p); err == nil {
				_, _ = io.CopyN(io.Discard, f, 1<<20)
				f.Close()
			}
		}
		return nil
	})
	if rl, ok := fsys.(interface{ ReadLink(string) (string, error) }); ok {
		_, _ = rl.ReadLink("link-slow")
	}
}

// patched overlays patch at off on top of base without copying base.
type patched struct {
	base  []byte
	off   int64
	patch []byte
}

func (p *patched) ReadAt(b []byte, off int64) (int, error) {
	if off < 0 || off >= int64(len(p.base)) {
		return 0, io.EOF
	}
	n := copy(b, p.base[off:])
	for i := 0; i < n; i++ {
		if j := off + int64(i) - p.off; j >= 0 && j < int64(len(p.patch)) {
			b[i] = p.patch[j]
		}
	}
	if n < len(b) {
		return n, io.EOF
	}
	return n, nil
}

func TestRandomCorruptionNoPanic(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	for _, img := range []string{"ext4.img.gz", "ext2.img.gz", "ext4-inline.img.gz"} {
		base := loadImage(t, img)
		for i := 0; i < 300; i++ {
			// Hit the metadata-dense head of the image most of the time.
			limit := int64(len(base))
			if i%4 != 0 {
				limit = 300 << 10
			}
			patch := make([]byte, 1+rng.Intn(16))
			rng.Read(patch)
			pr := &patched{base: base, off: rng.Int63n(limit), patch: patch}
			if fsys, err := Open(pr, int64(len(base))); err == nil {
				walk(fsys)
			}
		}
	}
}

func FuzzOpen(f *testing.F) {
	images := [][]byte{loadImage(f, "ext4.img.gz"), loadImage(f, "ext2.img.gz"), loadImage(f, "ext4-inline.img.gz")}
	for i := range images {
		f.Add(uint8(i), uint32(1024), []byte{})
		f.Add(uint8(i), uint32(2048), []byte{0xff, 0xff, 0xff, 0xff})
		f.Add(uint8(i), uint32(1024+0x38), []byte{0x53, 0xef})
	}
	f.Fuzz(func(t *testing.T, which uint8, off uint32, patch []byte) {
		base := images[int(which)%len(images)]
		pr := &patched{base: base, off: int64(off) % int64(len(base)), patch: patch}
		Probe(pr, int64(len(base)))
		if fsys, err := Open(pr, int64(len(base))); err == nil {
			walk(fsys)
		}
	})
}
