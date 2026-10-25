package apfs

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

func init() { rethrowPanics = false }

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
	b := loadImage(t, "apfs.img.gz")
	if !Probe(bytes.NewReader(b), int64(len(b))) {
		t.Fatal("probe failed on a real container")
	}
	if Probe(bytes.NewReader(make([]byte, 1<<16)), 1<<16) || Probe(nil, 0) {
		t.Fatal("probe accepted zeros")
	}
}

// TestFixture reads the hdiutil-made container: hashes from shasum on the
// source tree, hard link, symlink, xattrs, clone extents, timestamps.
func TestFixture(t *testing.T) {
	fsys := openBytes(t, loadImage(t, "apfs.img.gz"))
	if err := fstestQuick(fsys); err != nil {
		t.Fatal(err)
	}
	want := expected(t)
	h := "Users/alice/"
	for p, name := range map[string]string{
		h + ".claude/projects/-Users-alice-proj/session.jsonl": "session.jsonl",
		h + "known.bin": "known.bin", h + "clone.bin": "clone.bin",
		h + "small-compressed.txt": "small-compressed.txt",
	} {
		if got := sum(t, fsys, p); got != want[name] {
			t.Errorf("%s sha256 %s, want %s", p, got, want[name])
		}
	}
	vols := fsys.Volumes()
	if len(vols) != 1 || vols[0].Name != "T" || vols[0].Encrypted || vols[0].CaseSens {
		t.Fatalf("volumes %+v", vols)
	}
	// Hard link: same inode, same content.
	a, _ := fs.Stat(fsys, h+"notes.txt")
	b, _ := fs.Stat(fsys, h+"hardlink.txt")
	ia, ib := a.Sys().(map[string]any)["inode"], b.Sys().(map[string]any)["inode"]
	if ia != ib || a.Sys().(map[string]any)["links"].(int32) != 2 {
		t.Errorf("hard link inodes %v %v", ia, ib)
	}
	// Symlink: listed, never followed.
	li, err := fs.Stat(fsys, h+"link")
	if err != nil || li.Mode()&fs.ModeSymlink == 0 {
		t.Fatalf("link %v %v", li, err)
	}
	if tgt, err := fsys.ReadLink(h + "link"); err != nil || tgt != "docs/sub/nested.txt" {
		t.Errorf("readlink %q %v", tgt, err)
	}
	if _, err := fs.ReadFile(fsys, h+"link"); err == nil {
		t.Error("reading a symlink succeeded")
	}
	// Xattrs, embedded and stream.
	xs := a.Sys().(map[string]any)["xattrs"].([]string)
	if !strings.Contains(strings.Join(xs, ","), "com.example.big") || !strings.Contains(strings.Join(xs, ","), "com.example.zone") {
		t.Errorf("xattrs %v", xs)
	}
	tr := fsys.trees[0]
	l, _ := fsys.lookup("stat", h+"notes.txt")
	all, _ := tr.xattrs(l.in.id)
	for _, x := range all {
		v, err := tr.xattrValue(x, 1<<20)
		switch x.name {
		case "com.example.big":
			if err != nil || len(v) != 5999 || x.streamID == 0 {
				t.Errorf("big xattr %d bytes stream=%d %v", len(v), x.streamID, err)
			}
		case "com.example.zone":
			if string(v) != "ZoneId=3" {
				t.Errorf("zone xattr %q", v)
			}
		}
	}
	// The clone shares extents with known.bin and has a private middle one.
	cl, _ := fsys.lookup("stat", h+"clone.bin")
	d, err := tr.dataStream(cl.in.private, int64(cl.in.size))
	if err != nil || len(d.runs) < 3 {
		t.Errorf("clone runs %v %v", d, err)
	}
	if !a.ModTime().Equal(time.Date(2024, 8, 30, 10, 0, 0, 0, time.UTC)) {
		t.Errorf("mtime %v", a.ModTime())
	}
	ents, err := fs.ReadDir(fsys, "many")
	if err != nil || len(ents) != 600 {
		t.Errorf("many: %d entries, %v", len(ents), err)
	}
	// Case-insensitive volume: a case-folded lookup resolves.
	if _, err := fs.Stat(fsys, "users/ALICE/notes.txt"); err != nil {
		t.Errorf("case-insensitive lookup: %v", err)
	}
}

// TestLZVNUnsupported: ditto compresses with LZVN; the file is listed with
// its real size and reading it fails with ErrUnsupported naming the type.
func TestLZVNUnsupported(t *testing.T) {
	fsys := openBytes(t, loadImage(t, "apfs.img.gz"))
	p := "Users/alice/compressed.txt"
	fi, err := fs.Stat(fsys, p)
	if err != nil || fi.Size() != 200000 {
		t.Fatalf("stat %v %v", fi, err)
	}
	if c := fi.Sys().(map[string]any)["compression"]; c != "lzvn-resource-fork" {
		t.Errorf("compression %v", c)
	}
	_, err = fs.ReadFile(fsys, p)
	if !errors.Is(err, errors.ErrUnsupported) || !strings.Contains(err.Error(), "lzvn") {
		t.Errorf("read err %v", err)
	}
	if fsys.Stats()["unsupported_files"] < 1 {
		t.Error("unsupported file not counted")
	}
}

func TestDecmpfsZlib(t *testing.T) {
	plain := bytes.Repeat([]byte("zlib decmpfs content "), 9000)[:0x10000+5000] // two blocks
	hdr := func(typ uint32, n int) []byte {
		h := make([]byte, 16)
		binary.LittleEndian.PutUint32(h, decmpfsMagic)
		binary.LittleEndian.PutUint32(h[4:], typ)
		binary.LittleEndian.PutUint64(h[8:], uint64(n))
		return h
	}
	z := func(b []byte) []byte {
		var w bytes.Buffer
		zw := zlib.NewWriter(&w)
		zw.Write(b)
		zw.Close()
		return w.Bytes()
	}
	// Type 3: inline zlib.
	small := plain[:3000]
	got, err := DecodeDecmpfs(append(hdr(3, len(small)), z(small)...), nil)
	if err != nil || !bytes.Equal(got, small) {
		t.Fatalf("type 3: %v", err)
	}
	// Type 3 raw (0xFF marker).
	got, err = DecodeDecmpfs(append(append(hdr(3, 5), 0xff), "hello"...), nil)
	if err != nil || string(got) != "hello" {
		t.Fatalf("type 3 raw: %q %v", got, err)
	}
	// Type 4: resource fork with a block table.
	b1, b2 := z(plain[:0x10000]), z(plain[0x10000:])
	data := make([]byte, 4+16)
	binary.LittleEndian.PutUint32(data[0:], 2)
	binary.LittleEndian.PutUint32(data[4:], 20)
	binary.LittleEndian.PutUint32(data[8:], uint32(len(b1)))
	binary.LittleEndian.PutUint32(data[12:], uint32(20+len(b1)))
	binary.LittleEndian.PutUint32(data[16:], uint32(len(b2)))
	data = append(append(data, b1...), b2...)
	fork := make([]byte, 0x104)
	binary.BigEndian.PutUint32(fork, 0x100)
	binary.BigEndian.PutUint32(fork[0x100:], uint32(len(data)))
	fork = append(fork, data...)
	got, err = DecodeDecmpfs(hdr(4, len(plain)), func() ([]byte, error) { return fork, nil })
	if err != nil || !bytes.Equal(got, plain) {
		t.Fatalf("type 4: %v", err)
	}
	// A header lying about the size: never a big allocation, an error.
	if _, err := DecodeDecmpfs(append(hdr(3, 1<<29), z(small)...), nil); err == nil {
		t.Error("type 3 with a huge declared size accepted")
	}
	if _, err := DecodeDecmpfs(append(hdr(3, len(small)+1), z(small)...), nil); err == nil {
		t.Error("type 3 decoding short accepted")
	}
	if _, err := DecodeDecmpfs(hdr(4, 1<<29), func() ([]byte, error) { return fork, nil }); err == nil {
		t.Error("type 4 with a huge declared size accepted")
	}
	if _, err := DecodeDecmpfs(hdr(11, 10), nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Errorf("lzfse: %v", err)
	}
}

// TestSnapshots reads the synthetic container: the live tree and the
// snapshot differ, and the virtual directory steps aside for a real
// ".SNAPSHOTS" (case-insensitive) entry.
func TestSnapshots(t *testing.T) {
	fsys := openBytes(t, synthImage())
	v := fsys.Volumes()[0]
	if len(v.Snapshots) != 1 || v.Snapshots[0].Name != "snap-one" || v.Snapshots[0].XID != 1 {
		t.Fatalf("snapshots %+v", v.Snapshots)
	}
	dir := v.Snapshots[0].Dir
	if dir != ".apfs-snapshots/snap-one" {
		t.Fatalf("snapshot dir %q", dir)
	}
	if b, err := fs.ReadFile(fsys, "new.txt"); err != nil || string(b) != "new content" {
		t.Fatalf("live new.txt %q %v", b, err)
	}
	if _, err := fs.Stat(fsys, "old.txt"); err == nil {
		t.Fatal("old.txt visible in the live tree")
	}
	if b, err := fs.ReadFile(fsys, dir+"/old.txt"); err != nil || string(b) != "old content" {
		t.Fatalf("snapshot old.txt %q %v", b, err)
	}
	// The real directory still resolves under its own name.
	if fi, err := fs.Stat(fsys, ".SNAPSHOTS"); err != nil || fi.Sys().(map[string]any)["virtual"] != nil {
		t.Fatalf(".SNAPSHOTS %v %v", fi, err)
	}
	fi, _ := fs.Stat(fsys, dir+"/old.txt")
	if fi.Sys().(map[string]any)["snapshot"] != "snap-one" {
		t.Errorf("sys %v", fi.Sys())
	}
	li, _ := fs.Stat(fsys, "new.txt")
	if fi.Sys().(map[string]any)["inode"] == li.Sys().(map[string]any)["inode"] {
		t.Error("snapshot and live inode numbers collide")
	}
	if err := fstestQuick(fsys); err != nil {
		t.Fatal(err)
	}
}

func TestSnapDirName(t *testing.T) {
	for _, c := range []struct {
		have []string
		want string
	}{
		{nil, ".snapshots"},
		{[]string{".Snapshots"}, ".apfs-snapshots"},
		{[]string{".snapshots", ".APFS-snapshots"}, ".apfs-snapshots-2"},
		{[]string{".snapshots", ".apfs-snapshots", ".apfs-snapshots-2"}, ".apfs-snapshots-3"},
	} {
		if got := snapDirNameFor(c.have); got != c.want {
			t.Errorf("%v → %q, want %q", c.have, got, c.want)
		}
	}
}

// TestSparseXattrRejected: a stream xattr claiming 32 KiB with no extents
// is refused before any allocation of that size.
func TestSparseXattrRejected(t *testing.T) {
	fsys := openBytes(t, synthImage())
	l, err := fsys.lookup("stat", "new.txt")
	if err != nil {
		t.Fatal(err)
	}
	xs, err := l.t.xattrs(l.in.id)
	if err != nil || len(xs) != 1 {
		t.Fatalf("xattrs %v %v", xs, err)
	}
	if _, err := l.t.xattrValue(xs[0], 1<<30); err == nil || !strings.Contains(err.Error(), "allocated") {
		t.Errorf("sparse xattr: %v", err)
	}
	if _, err := l.t.dataStream(99, 1<<41); err == nil {
		t.Error("2 TiB stream accepted")
	}
}

func TestChecksumDamage(t *testing.T) {
	b := loadImage(t, "apfs.img.gz")
	n := 0
	for off := 0; off+4096 <= len(b); off += 4096 {
		blk := b[off : off+4096]
		if checksumOK(blk) && le.Uint32(blk[24:])&typeMask == typeBtreeNode && le.Uint32(blk[28:]) == 0x0e && le.Uint16(blk[34:]) == 0 {
			blk[2000] ^= 0xff // a leaf of the fs tree
			n++
		}
	}
	if n == 0 {
		t.Fatal("no fs-tree leaf found")
	}
	fsys, err := OpenFS(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		if !strings.Contains(err.Error(), "checksum") {
			t.Fatalf("open: %v", err)
		}
		return
	}
	var sawChecksum bool
	fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil && strings.Contains(err.Error(), "checksum mismatch") {
			sawChecksum = true
		}
		return nil
	})
	if !sawChecksum {
		t.Error("corrupted leaves were not reported")
	}
}

// TestLatestCheckpointDamaged: the newest checkpoint superblock is
// corrupted; the reader falls back to an older one and says so.
func TestLatestCheckpointDamaged(t *testing.T) {
	b := loadImage(t, "apfs.img.gz")
	base := le.Uint64(b[112:])
	nd := uint64(le.Uint32(b[104:]))
	best, bestXid := -1, uint64(0)
	for i := uint64(0); i < nd; i++ {
		off := int((base + i) * 4096)
		blk := b[off : off+4096]
		if le.Uint32(blk[24:])&typeMask == typeNXSB && checksumOK(blk) && le.Uint64(blk[16:]) > bestXid {
			best, bestXid = off, le.Uint64(blk[16:])
		}
	}
	b[best+100] ^= 0x55
	fsys := openBytes(t, b)
	if fsys.c.xid >= bestXid && fsys.c.checkpoint == "descriptor area" {
		t.Errorf("xid %d (damaged newest %d)", fsys.c.xid, bestXid)
	}
	if !strings.Contains(strings.Join(fsys.Problems(), ";"), "checksum mismatch") {
		t.Errorf("problems %v", fsys.Problems())
	}
	if _, err := fs.ReadFile(fsys, "Users/alice/known.bin"); err != nil {
		t.Error(err)
	}
}

// TestBTreeCycle points an fs-tree index node at itself.
func TestBTreeCycle(t *testing.T) {
	b := loadImage(t, "apfs.img.gz")
	patched := false
	for off := 0; off+4096 <= len(b) && !patched; off += 4096 {
		blk := b[off : off+4096]
		if !checksumOK(blk) || le.Uint32(blk[24:])&typeMask > typeBtreeNode || le.Uint32(blk[28:]) != 0x0e || le.Uint16(blk[34:]) == 0 {
			continue
		}
		n := &node{b: blk, flags: le.Uint16(blk[32:])}
		toc := 56 + int(le.Uint16(blk[40:]))
		valEnd := 4096
		if n.flags&btnRoot != 0 {
			valEnd -= 40
		}
		for i := 0; i < int(le.Uint32(blk[36:])); i++ {
			vo := int(le.Uint16(blk[toc+8*i+4:]))
			le.PutUint64(blk[valEnd-vo:], le.Uint64(blk[8:])) // child = itself
		}
		seal(blk)
		patched = true
	}
	if !patched {
		t.Fatal("no fs-tree index node in the fixture")
	}
	done := make(chan error, 1)
	go func() {
		_, err := OpenFS(bytes.NewReader(b), int64(len(b)))
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil || !(strings.Contains(err.Error(), "cycle") || strings.Contains(err.Error(), "level")) {
			t.Errorf("open: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("cyclic B-tree did not terminate")
	}
}

func TestTruncatedAndGarbage(t *testing.T) {
	b := loadImage(t, "apfs.img.gz")
	for _, n := range []int{100, 4096, 8192, len(b) / 2} {
		if _, err := OpenFS(bytes.NewReader(b[:n]), int64(n)); err == nil {
			t.Errorf("truncated to %d: opened", n)
		}
	}
	g := make([]byte, 64<<10)
	copy(g[32:], "NXSB")
	le.PutUint32(g[36:], 4096)
	if _, err := OpenFS(bytes.NewReader(g), int64(len(g))); err == nil {
		t.Error("garbage container opened")
	}
}

// TestEncryptedOnlyVolume clears APFS_FS_UNENCRYPTED on the only volume:
// Open fails with ErrUnsupported and says why.
func TestEncryptedOnlyVolume(t *testing.T) {
	img := synthImage()
	blk := img[4*synBS : 5*synBS]
	le.PutUint64(blk[264:], 0)
	seal(blk)
	_, err := OpenFS(bytes.NewReader(img), int64(len(img)))
	if !errors.Is(err, errors.ErrUnsupported) || !strings.Contains(err.Error(), "encrypted") {
		t.Fatalf("err %v", err)
	}
}

// fstestQuick walks every entry and reads every regular file.
func fstestQuick(fsys fs.FS) error {
	return fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
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
}
