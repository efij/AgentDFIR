package fat

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
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

var images = []string{"fat12.img.gz", "fat16.img.gz", "fat32.img.gz", "exfat.img.gz"}

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
		if sum, p, ok := strings.Cut(sc.Text(), "  "); ok {
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

func TestContents(t *testing.T) {
	exp := expected(t)
	for _, img := range images {
		t.Run(img, func(t *testing.T) {
			fsys := openImage(t, img)
			kind := strings.TrimSuffix(img, ".img.gz")
			if md := fsys.Metadata(); md["fs"] != kind {
				t.Errorf("fs = %v, want %s", md["fs"], kind)
			}
			for p, sum := range exp {
				if got := hashFile(t, fsys, p); got != sum {
					t.Errorf("%s: sha256 %s, want %s", p, got, sum)
				}
			}
			ents, err := fsys.ReadDir(".")
			if err != nil {
				t.Fatal(err)
			}
			var names []string
			for _, e := range ents {
				names = append(names, e.Name())
			}
			if got := strings.Join(names, " "); got != "docs frag fragmented.bin home known.bin" {
				t.Errorf("root listing %q", got)
			}
			docs, _ := fsys.ReadDir("docs")
			if len(docs) != 2 || docs[0].Name() != "A very long file name that exceeds eight dot three.txt" || docs[1].Name() != "SHORT.TXT" {
				t.Errorf("docs listing %v", docs)
			}
			frag, err := fsys.ReadDir("frag")
			if err != nil || len(frag) != 10 {
				t.Errorf("frag: %d entries, %v", len(frag), err)
			}
			if s := fsys.Stats(); s["deleted_entries"] < 10 {
				t.Errorf("stats %v", s)
			}
			// Case-insensitive lookup, as on the original volume.
			if _, err := fsys.Stat("HOME/Alice/.CLAUDE"); err != nil {
				t.Errorf("case-insensitive lookup: %v", err)
			}
			if _, err := fsys.Stat("nope"); err == nil {
				t.Error("missing file found")
			}
		})
	}
}

func TestTimesAndSys(t *testing.T) {
	for _, img := range images {
		fsys := openImage(t, img)
		st, err := fsys.Stat("home/alice/.claude/projects/p/session.jsonl")
		if err != nil {
			t.Fatal(err)
		}
		if !st.ModTime().Equal(fixtureTime) {
			t.Errorf("%s: mtime %v, want %v", img, st.ModTime(), fixtureTime)
		}
		sys := st.Sys().(map[string]any)
		wantTZ := "local-unknown"
		if img == "exfat.img.gz" {
			wantTZ = "+00:00"
		}
		if sys["tz"] != wantTZ || sys["inode"].(uint64) == 0 || !sys["ctime"].(time.Time).IsZero() {
			t.Errorf("%s: sys %v", img, sys)
		}
		if a := sys["atime"].(time.Time); a.IsZero() || a.Year() != 2024 {
			t.Errorf("%s: atime %v", img, a)
		}
		if st.Size() != 98 {
			t.Errorf("%s: size %d", img, st.Size())
		}
		root, _ := fsys.Stat(".")
		if _, ok := root.Sys().(map[string]any)["deleted_entries"]; !ok {
			t.Errorf("%s: root sys lacks stats", img)
		}
	}
}

func TestFragmentedLayout(t *testing.T) {
	for _, img := range images {
		fsys := openImage(t, img)
		f, err := fsys.Open("fragmented.bin")
		if err != nil {
			t.Fatal(err)
		}
		if n := len(f.(*file).c.ext); n < 2 {
			t.Errorf("%s: fragmented.bin has %d extents, want >= 2", img, n)
		}
	}
	// exFAT: contiguous files use NoFatChain, the fragmented one a chain.
	fsys := openImage(t, "exfat.img.gz")
	for name, want := range map[string]bool{"known.bin": true, "fragmented.bin": false} {
		st, err := fsys.Stat(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := st.Sys().(map[string]any)["no_fat_chain"]; got != want {
			t.Errorf("exfat %s no_fat_chain = %v, want %v", name, got, want)
		}
	}
}

func TestFSTest(t *testing.T) {
	for _, img := range images {
		if err := fstest.TestFS(openImage(t, img), "known.bin", "docs/SHORT.TXT", "home/alice/.claude/projects/p/session.jsonl"); err != nil {
			t.Errorf("%s: %v", img, err)
		}
	}
}

func TestCorruptAndTruncated(t *testing.T) {
	for _, img := range images {
		b := loadImage(t, img)
		half := b[:len(b)/2]
		if _, err := Open(bytes.NewReader(half), int64(len(half))); err == nil || !strings.Contains(err.Error(), "truncated") {
			t.Errorf("%s truncated: err = %v", img, err)
		}
		bad := append([]byte{}, b...)
		bad[510] = 0
		if Probe(bytes.NewReader(bad), int64(len(bad))) {
			t.Errorf("%s: Probe accepted a missing signature", img)
		}
		bad = append([]byte{}, b...)
		if img == "exfat.img.gz" {
			bad[0x6C] = 20 // bytes-per-sector shift
		} else {
			bad[0x0B], bad[0x0C] = 0x00, 0x03 // 768 bytes per sector
		}
		if _, err := Open(bytes.NewReader(bad), int64(len(bad))); err == nil {
			t.Errorf("%s: bad geometry accepted", img)
		}
	}
	if Probe(bytes.NewReader(nil), 0) {
		t.Error("Probe on empty input")
	}
	if _, err := Open(bytes.NewReader(make([]byte, 4096)), 4096); err == nil {
		t.Error("zero image accepted")
	}
}

// TestDirectoryCycleTerminates makes home/alice point back at home and, in
// a second variant, makes docs point at the root.
func TestDirectoryCycleTerminates(t *testing.T) {
	for _, img := range []string{"fat32.img.gz", "fat12.img.gz"} {
		for _, variant := range []string{"self", "root"} {
			b := loadImage(t, img)
			clean := openImage(t, img)
			name, to := []byte("ALICE      \x10"), uint32(0)
			if variant == "self" {
				home, _, err := clean.lookup("stat", "home")
				if err != nil {
					t.Fatal(err)
				}
				to = home.cluster
			} else {
				name = []byte("DOCS       \x10")
				to = clean.rootEntry().cluster // 0 for the fixed FAT12 root
			}
			i := bytes.Index(b, name)
			if i < 0 {
				t.Fatalf("%s: entry %q not found", img, name)
			}
			le.PutUint16(b[i+0x1A:], uint16(to))
			le.PutUint16(b[i+0x14:], uint16(to>>16))
			fsys, err := Open(bytes.NewReader(b), int64(len(b)))
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan int)
			go func() {
				n := 0
				_ = fs.WalkDir(fsys, ".", func(string, fs.DirEntry, error) error {
					n++
					return nil
				})
				done <- n
			}()
			select {
			case n := <-done:
				if n > 200 {
					t.Errorf("%s/%s: walk visited %d entries", img, variant, n)
				}
			case <-time.After(10 * time.Second):
				t.Fatalf("%s/%s: walk did not terminate", img, variant)
			}
			if s := fsys.(*FS).Stats(); s["corrupt_entries"] < 1 {
				t.Errorf("%s/%s: stats %v", img, variant, s)
			}
		}
	}
}

func TestWorkBudget(t *testing.T) {
	fsys := openImage(t, "fat32.img.gz")
	fsys.workLimit = 2
	if _, err := fsys.ReadDir("."); err == nil || !strings.Contains(err.Error(), "work budget") {
		t.Errorf("err = %v", err)
	}
}

func walk(fsys fs.FS) {
	n := 0
	_ = fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if n++; n > 2000 {
			return fs.SkipAll
		}
		if err != nil {
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
	for _, img := range images {
		base := loadImage(t, img)
		for i := 0; i < 300; i++ {
			limit := int64(len(base))
			if i%4 != 0 {
				limit = min(limit, 600<<10)
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
	var bases [][]byte
	for _, img := range images {
		bases = append(bases, loadImage(f, img))
	}
	for i := range bases {
		f.Add(uint8(i), uint32(0), []byte{})
		f.Add(uint8(i), uint32(11), []byte{0x00, 0x02, 0x01})
		f.Add(uint8(i), uint32(0x60), []byte{0xff, 0xff, 0xff, 0x0f})
	}
	// Crafted LFN runs (stray sequence-0 fragments) over each FAT root.
	for i, b := range bases[:3] {
		g, err := parseBoot(b[:512])
		if err != nil {
			f.Fatal(err)
		}
		root := g.rootOff
		if g.kind == "fat32" {
			root = g.dataOff + int64(g.rootCluster-2)*g.clusterSize
		}
		for _, s := range craftedLFNSeeds() {
			f.Add(uint8(i), uint32(root), s)
			f.Add(uint8(i), uint32(root+64), s)
		}
	}
	f.Fuzz(func(t *testing.T, which uint8, off uint32, patch []byte) {
		base := bases[int(which)%len(bases)]
		pr := &patched{base: base, off: int64(off) % int64(len(base)), patch: patch}
		Probe(pr, int64(len(base)))
		if fsys, err := Open(pr, int64(len(base))); err == nil {
			walk(fsys)
		}
	})
}
