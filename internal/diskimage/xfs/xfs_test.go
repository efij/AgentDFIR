package xfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/diskimage/internal/fixture"
	"github.com/efij/AgentDFIR/v4/internal/diskimage/internal/rofs"
)

func init() { rofs.RethrowPanics = true }

var (
	loadOnce sync.Once
	images   = map[string]*fixture.Image{}
)

// image returns a private copy of a testdata fixture (made by mkfs.xfs,
// see ../testdata/README.md).
func image(t testing.TB, name string) *fixture.Image {
	t.Helper()
	loadOnce.Do(func() {
		for _, n := range []string{"xfs.img.gz", "xfs4.img.gz"} {
			im, err := fixture.Load("testdata/" + n)
			if err != nil {
				panic(err)
			}
			images[n] = im
		}
	})
	return images[name].Clone()
}

func open(t *testing.T, im *fixture.Image) *FS {
	t.Helper()
	if !Probe(im, im.Size()) {
		t.Fatal("Probe = false")
	}
	fsys, err := Open(im, im.Size())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	return fsys.(*FS)
}

// TestManifest compares the whole tree with the listing coreutils made from
// the mounted filesystem: names, types, sizes, SHA-256, link targets, mtimes.
func TestManifest(t *testing.T) {
	want, err := fixture.ReadManifest("testdata/xfs.manifest")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"xfs.img.gz", "xfs4.img.gz"} {
		t.Run(name, func(t *testing.T) {
			f := open(t, image(t, name))
			var diffs []string
			for _, d := range fixture.Compare(f, want, nil) {
				// The v4 image holds the same tree, made by another mkfs
				// run: proto files stamp the mkfs time, so mtimes differ.
				if name == "xfs4.img.gz" && strings.Contains(d, ": mtime ") {
					continue
				}
				diffs = append(diffs, d)
			}
			for i, d := range diffs {
				if i > 20 {
					t.Errorf("… %d more", len(diffs)-i)
					break
				}
				t.Error(d)
			}
			if st := f.Stats(); st["crc_errors"] != 0 || st["corrupt_entries"] != 0 || st["cycles"] != 0 {
				t.Errorf("stats on a clean image: %v (problems %v)", st, f.Problems())
			}
		})
	}
}

func TestFormatsCovered(t *testing.T) {
	f := open(t, image(t, "xfs.img.gz"))
	cases := map[string]uint8{
		"dirs/small":           fmtLocal,
		"dirs/node":            fmtExtents,
		"data/frag.bin":        fmtBtree,
		"data/big.txt":         fmtExtents,
		"home/alice/long-link": fmtLocal,
	}
	for p, want := range cases {
		n, err := f.Node(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := n.Impl.(*inode).format; got != want {
			t.Errorf("%s: fork format %d, want %d", p, got, want)
		}
	}
	// dirs/node spans more than one leaf block: node form.
	n, _ := f.Node("dirs/node")
	ex, err := f.extents(n.Impl.(*inode))
	if err != nil {
		t.Fatal(err)
	}
	var leafBlocks int
	for _, e := range ex {
		if e.off*uint64(f.sb.blockSize) >= leafOffset {
			leafBlocks += int(e.count)
		}
	}
	if leafBlocks < 2 {
		t.Errorf("dirs/node has %d leaf-area blocks, want node form (>=2)", leafBlocks)
	}
	ents, _ := fs.ReadDir(f, "dirs/node")
	if len(ents) != 2000 {
		t.Errorf("dirs/node: %d entries", len(ents))
	}
	// xfs4 stores the 308-byte symlink remotely (256-byte inodes).
	f4 := open(t, image(t, "xfs4.img.gz"))
	n, _ = f4.Node("home/alice/long-link")
	if got := n.Impl.(*inode).format; got != fmtExtents {
		t.Errorf("v4 long-link format %d, want extents", got)
	}
	if f4.Metadata()["fs"] != "xfs-v4" || f.Metadata()["fs"] != "xfs" {
		t.Error("fs names")
	}
}

func TestSysAndTimes(t *testing.T) {
	f := open(t, image(t, "xfs.img.gz"))
	fi, err := fs.Stat(f, "home/alice/notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	sys := fi.Sys().(map[string]any)
	for _, k := range []string{"inode", "mtime", "atime", "ctime", "btime", "uid", "links"} {
		if _, ok := sys[k]; !ok {
			t.Errorf("Sys missing %q", k)
		}
	}
	bt := sys["btime"].(time.Time)
	if bt.Year() != 2026 || !bt.Equal(fi.ModTime()) && bt.After(fi.ModTime().Add(time.Hour)) {
		t.Errorf("btime %v, mtime %v", bt, fi.ModTime())
	}
	if sys["fs"] != "xfs" {
		t.Errorf("fs %v", sys["fs"])
	}
	l, _ := fs.Stat(f, "home/alice/notes-link")
	if l.Mode()&fs.ModeSymlink == 0 || l.Sys().(map[string]any)["symlink_target"] != "notes.txt" {
		t.Errorf("symlink: %v %v", l.Mode(), l.Sys())
	}
	if _, err := f.Open("home/alice/notes-link"); err != nil {
		t.Errorf("open symlink: %v", err)
	}
	root, _ := fs.Stat(f, ".")
	if root.Sys().(map[string]any)["label"] != "adfirxfs" {
		t.Errorf("label %v", root.Sys().(map[string]any)["label"])
	}
}

func TestDecodeTime(t *testing.T) {
	b := make([]byte, 8)
	// bigtime: (unix + 2^31) * 1e9 + ns
	binary.BigEndian.PutUint64(b, uint64((1788084000+(1<<31))*1e9+5))
	if got := decodeTime(b, true); got.Unix() != 1788084000 || got.Nanosecond() != 5 {
		t.Errorf("bigtime %v", got)
	}
	binary.BigEndian.PutUint32(b, uint32(0x80000000)) // 1901
	binary.BigEndian.PutUint32(b[4:], 0)
	if got := decodeTime(b, false); got.Year() != 1901 {
		t.Errorf("legacy negative %v", got)
	}
}

func TestFSTest(t *testing.T) {
	f := open(t, image(t, "xfs.img.gz"))
	if err := fstest.TestFS(f, "home/alice/notes.txt", "data/frag.bin", "deep/a/b/c/d/e/f/leaf.txt"); err != nil {
		t.Fatal(err)
	}
}

// ---- damage ----

func TestTruncated(t *testing.T) {
	im := image(t, "xfs.img.gz")
	im.Truncate(100 << 20)
	if _, err := Open(im, im.Size()); err == nil || !strings.Contains(err.Error(), "truncated") {
		t.Fatalf("truncated image: %v", err)
	}
	if _, err := Open(bytes.NewReader([]byte("XFSB")), 4); err == nil {
		t.Fatal("tiny image opened")
	}
}

func TestBadCRCReported(t *testing.T) {
	im := image(t, "xfs.img.gz")
	f := open(t, im)
	n, err := f.Node("home/alice/notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	off, _ := f.inoLocation(n.ID)
	// Flip a byte of the inode's uid: CRC no longer matches.
	im.Patch(off+8, []byte{0x5a})
	f = open(t, im)
	if _, err := fs.Stat(f, "home/alice/notes.txt"); err != nil {
		t.Fatalf("stat damaged inode: %v", err)
	}
	if f.Stats()["crc_errors"] == 0 || !strings.Contains(strings.Join(f.Problems(), ";"), "CRC") {
		t.Fatalf("CRC damage not reported: %v %v", f.Stats(), f.Problems())
	}
	// Superblock CRC.
	im = image(t, "xfs.img.gz")
	im.Patch(108, []byte("tampered"))
	f = open(t, im)
	if !strings.Contains(strings.Join(f.Problems(), ";"), "superblock CRC") {
		t.Fatalf("superblock damage not reported: %v", f.Problems())
	}
}

func TestBadMagic(t *testing.T) {
	im := image(t, "xfs.img.gz")
	f := open(t, im)
	n, _ := f.Node("home/alice/notes.txt")
	off, _ := f.inoLocation(n.ID)
	im.Patch(off, []byte("XX"))
	f = open(t, im)
	if _, err := fs.Stat(f, "home/alice/notes.txt"); err == nil {
		t.Fatal("bad inode magic accepted")
	}
	// Siblings still read.
	if _, err := fs.ReadFile(f, "home/alice/.claude/settings.json"); err != nil {
		t.Fatal(err)
	}
}

func TestBtreeCycle(t *testing.T) {
	im := image(t, "xfs.img.gz")
	f := open(t, im)
	n, _ := f.Node("data/frag.bin")
	in := n.Impl.(*inode)
	maxr := (len(in.fork) - 4) / 16
	child := binary.BigEndian.Uint64(in.fork[4+maxr*8:])
	boff, _ := f.fsbToByte(child)
	// Turn the leaf into a level-1 node pointing at itself.
	b := make([]byte, f.sb.blockSize)
	im.ReadAt(b, boff)
	binary.BigEndian.PutUint16(b[4:], 1)
	binary.BigEndian.PutUint16(b[6:], 1)
	hdr := 72
	nmax := (len(b) - hdr) / 16
	binary.BigEndian.PutUint64(b[hdr+nmax*8:], child)
	im.Patch(boff, b)
	ioff, _ := f.inoLocation(n.ID)
	lvl := make([]byte, 2)
	binary.BigEndian.PutUint16(lvl, 2)
	im.Patch(ioff+176, lvl) // root level 2
	f = open(t, im)
	_, err := fs.ReadFile(f, "data/frag.bin")
	if err == nil || !strings.Contains(err.Error(), "cycle") && !strings.Contains(err.Error(), "level") {
		t.Fatalf("cyclic bmap tree: %v", err)
	}
}

func TestDirectoryCycle(t *testing.T) {
	im := image(t, "xfs.img.gz")
	f := open(t, im)
	// Point deep/a/b/c/d/e/f's shortform entry "leaf.txt" at deep/a.
	a, _ := f.Node("deep/a")
	d, _ := f.Node("deep/a/b/c/d/e/f")
	in := d.Impl.(*inode)
	off, _ := f.inoLocation(d.ID)
	fork := off + 176
	// header 6 bytes, entry: namelen, offset(2), name, ftype, ino(4)
	nl := int(in.fork[6])
	ino := make([]byte, 4)
	binary.BigEndian.PutUint32(ino, uint32(a.ID))
	im.Patch(fork+int64(6+3+nl), []byte{2})
	im.Patch(fork+int64(6+3+nl+1), ino)
	f = open(t, im)
	ents, err := fs.ReadDir(f, "deep/a/b/c/d/e/f")
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 || f.Stats()["cycles"] == 0 {
		t.Fatalf("cycle entry listed: %v, stats %v", ents, f.Stats())
	}
	if _, err := fs.Stat(f, "deep/a/b/c/d/e/f/leaf.txt/b"); err == nil {
		t.Fatal("resolved through a cycle")
	}
}

func TestUnsupported(t *testing.T) {
	im := image(t, "xfs.img.gz")
	b := make([]byte, 4)
	im.ReadAt(b, 216)
	v := binary.BigEndian.Uint32(b) | incompatMetadir
	binary.BigEndian.PutUint32(b, v)
	im.Patch(216, b)
	_, err := Open(im, im.Size())
	if !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("metadir: %v", err)
	}
	// Realtime file flag: listed, read refused.
	im = image(t, "xfs.img.gz")
	f := open(t, im)
	n, _ := f.Node("home/alice/notes.txt")
	off, _ := f.inoLocation(n.ID)
	im.Patch(off+91, []byte{diflagRealtime})
	f = open(t, im)
	fi, err := fs.Stat(f, "home/alice/notes.txt")
	if err != nil || fi.Sys().(map[string]any)["unsupported"] == nil {
		t.Fatalf("realtime stat: %v", err)
	}
	if _, err := f.Open("home/alice/notes.txt"); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("realtime open: %v", err)
	}
}

func TestReadAtBounds(t *testing.T) {
	f := open(t, image(t, "xfs.img.gz"))
	fh, err := f.Open("data/frag.bin")
	if err != nil {
		t.Fatal(err)
	}
	ra := fh.(io.ReaderAt)
	b := make([]byte, 8192)
	if n, err := ra.ReadAt(b, 4096*80-100); n != 100 || err != io.EOF {
		t.Fatalf("tail read %d %v", n, err)
	}
	// Hole between data chunks reads as zeros.
	if _, err := ra.ReadAt(b[:4096], 4096); err != nil || !bytes.Equal(b[:4096], make([]byte, 4096)) {
		t.Fatalf("hole: %v", err)
	}
}

func FuzzOpen(f *testing.F) {
	im := image(f, "xfs.img.gz")
	f.Add(im.Bytes(64 << 10))
	f.Add(image(f, "xfs4.img.gz").Bytes(64 << 10))
	f.Fuzz(func(t *testing.T, head []byte) {
		c := im.Clone()
		c.Patch(0, head)
		fsys, err := Open(c, c.Size())
		if err != nil {
			return
		}
		fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				readSome(fsys, p)
			}
			return nil
		})
	})
}

func FuzzInode(f *testing.F) {
	im := image(f, "xfs.img.gz")
	fs0, err := Open(im, im.Size())
	if err != nil {
		f.Fatal(err)
	}
	x := fs0.(*FS)
	for _, p := range []string{"dirs/small", "dirs/block", "data/frag.bin", "home/alice/long-link"} {
		n, _ := x.Node(p)
		off, _ := x.inoLocation(n.ID)
		b := make([]byte, 512)
		im.ReadAt(b, off)
		f.Add(p, b)
	}
	f.Fuzz(func(t *testing.T, p string, raw []byte) {
		c := im.Clone()
		n, err := x.Node("dirs/block")
		if err != nil {
			return
		}
		off, _ := x.inoLocation(n.ID)
		if len(raw) > 512 {
			raw = raw[:512]
		}
		c.Patch(off, raw)
		fsys, err := Open(c, c.Size())
		if err != nil {
			return
		}
		fs.ReadDir(fsys, "dirs/block")
		fs.Stat(fsys, "dirs/block")
		readSome(fsys, "dirs/block")
	})
}

// readSome reads at most 1 MiB: a hostile size must not drive the harness.
func readSome(fsys fs.FS, p string) {
	if fh, err := fsys.Open(p); err == nil {
		io.Copy(io.Discard, io.LimitReader(fh, 1<<20))
		fh.Close()
	}
}
