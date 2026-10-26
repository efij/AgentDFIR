package btrfs

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"io/fs"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/efij/AgentDFIR/v4/internal/diskimage/internal/fixture"
	"github.com/efij/AgentDFIR/v4/internal/diskimage/internal/rofs"
)

func init() { rofs.RethrowPanics = true }

var (
	loadOnce sync.Once
	base     *fixture.Image
)

// image returns a private copy of testdata/btrfs.img.gz (made by
// mkfs.btrfs --rootdir plus a mounted snapshot / zstd / fallocate step,
// see ../testdata/README.md).
func image(t testing.TB) *fixture.Image {
	t.Helper()
	loadOnce.Do(func() {
		im, err := fixture.Load("testdata/btrfs.img.gz")
		if err != nil {
			panic(err)
		}
		base = im
	})
	return base.Clone()
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

const zstdFile = "zstd/z.txt"

func TestManifest(t *testing.T) {
	want, err := fixture.ReadManifest("testdata/btrfs.manifest")
	if err != nil {
		t.Fatal(err)
	}
	f := open(t, image(t))
	diffs := fixture.Compare(f, want, func(p string) bool { return p == zstdFile })
	for i, d := range diffs {
		if i > 20 {
			t.Errorf("… %d more", len(diffs)-i)
			break
		}
		t.Error(d)
	}
	if st := f.Stats(); st["csum_errors"] != 0 || st["corrupt_entries"] != 0 || st["cycles"] != 0 {
		t.Errorf("stats on a clean image: %v (problems %v)", st, f.Problems())
	}
	if u := f.Unreached(); len(u) != 0 {
		t.Errorf("subvolumes not reached by the walk: %v", u)
	}
}

func TestSubvolumesAndSnapshot(t *testing.T) {
	f := open(t, image(t))
	vol, err := fs.Stat(f, "vol1")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := fs.Stat(f, "snap1")
	if err != nil {
		t.Fatal(err)
	}
	vs, ss := vol.Sys().(map[string]any), snap.Sys().(map[string]any)
	if vs["subvolume_id"] != uint64(256) || ss["subvolume_id"] != uint64(257) {
		t.Errorf("subvolume ids %v %v", vs["subvolume_id"], ss["subvolume_id"])
	}
	if ss["subvolume_readonly"] != true || vs["subvolume_readonly"] != false {
		t.Errorf("readonly flags %v %v", ss["subvolume_readonly"], vs["subvolume_readonly"])
	}
	if ss["snapshot_parent_uuid"] == nil || vs["snapshot_parent_uuid"] != nil {
		t.Errorf("snapshot parent uuid %v / %v", ss["snapshot_parent_uuid"], vs["snapshot_parent_uuid"])
	}
	// Same inode number in two subvolumes, distinct walker keys.
	a, _ := fs.Stat(f, "vol1/inner/sub.txt")
	b, _ := fs.Stat(f, "snap1/inner/sub.txt")
	if a.Sys().(map[string]any)["inode"] != b.Sys().(map[string]any)["inode"] || vs["dir_id"] == ss["dir_id"] {
		t.Errorf("inode/dir_id: %v %v %v %v", a.Sys().(map[string]any)["inode"], b.Sys().(map[string]any)["inode"], vs["dir_id"], ss["dir_id"])
	}
	md := f.Metadata()
	if md["label"] != "adfirbtrfs" || md["default_subvolume"] != uint64(5) || len(md["subvolumes"].([]uint64)) != 3 {
		t.Errorf("metadata %v", md)
	}
}

func TestExtentKinds(t *testing.T) {
	f := open(t, image(t))
	kinds := func(p string) map[uint8]int {
		n, err := f.Node(p)
		if err != nil {
			t.Fatal(err)
		}
		r, err := f.Data(n)
		if err != nil {
			t.Fatal(err)
		}
		m := map[uint8]int{}
		for _, s := range r.(*fileData).segs {
			m[s.kind]++
		}
		return m
	}
	if k := kinds("home/alice/notes.txt"); k[segInline] != 1 {
		t.Errorf("notes.txt: %v, want inline", k)
	}
	if k := kinds("data/big.txt"); k[segZlib] == 0 {
		t.Errorf("big.txt: %v, want zlib", k)
	}
	if k := kinds("home/alice/.claude/projects/-home-alice-proj/session.jsonl"); k[segInline] != 1 {
		t.Errorf("session.jsonl: %v, want inline (zlib)", k)
	}
	if k := kinds("data/prealloc.bin"); k[segZero] != 1 {
		t.Errorf("prealloc.bin: %v, want prealloc zeros", k)
	}
	b, err := fs.ReadFile(f, "data/prealloc.bin")
	if err != nil || len(b) != 65536 || !bytes.Equal(b, make([]byte, 65536)) {
		t.Errorf("prealloc read: %v", err)
	}
}

func TestZstdUnsupported(t *testing.T) {
	f := open(t, image(t))
	fi, err := fs.Stat(f, zstdFile)
	if err != nil || fi.Size() != 54000 {
		t.Fatalf("zstd file listed: %v", err)
	}
	_, err = f.Open(zstdFile)
	if !errors.Is(err, errors.ErrUnsupported) || !strings.Contains(err.Error(), "zstd") {
		t.Fatalf("zstd open: %v", err)
	}
	if f.Stats()["unsupported_files"] != 1 {
		t.Errorf("stats %v", f.Stats())
	}
}

func TestFSTest(t *testing.T) {
	f := open(t, image(t))
	if err := fstest.TestFS(f, "home/alice/notes.txt", "vol1/inner/sub.txt", "snap1/inner/sub.txt", "data/big.txt"); err != nil {
		// zstd/z.txt cannot be opened; fstest reports it among the rest.
		for _, line := range strings.Split(err.Error(), "\n") {
			if line != "" && !strings.Contains(line, "zstd") && !strings.HasPrefix(line, "TestFS found errors") {
				t.Error(line)
			}
		}
	}
}

// ---- damage ----

func superCsum(b []byte) {
	binary.LittleEndian.PutUint32(b, crc32.Checksum(b[32:superSize], castagnoli))
}

func TestSuperblockMirrorFallback(t *testing.T) {
	im := image(t)
	im.Patch(superOffset+0x12b, []byte("tampered")) // label: checksum now wrong
	f := open(t, im)
	p := strings.Join(f.Problems(), ";")
	if !strings.Contains(p, "primary superblock checksum") {
		t.Fatalf("problems %v", p)
	}
	// 128 MiB image: the 64 MiB mirror exists and is used.
	if !strings.Contains(p, "mirror") || f.Metadata()["label"] != "adfirbtrfs" {
		t.Fatalf("mirror not used: %v %v", p, f.Metadata()["label"])
	}
	if _, err := fs.ReadFile(f, "home/alice/notes.txt"); err != nil {
		t.Fatal(err)
	}
}

func TestTreeBlockCsumReported(t *testing.T) {
	im := image(t)
	f := open(t, im)
	sv := f.subvols[fsTreeID]
	phys, _, err := f.mapLogical(sv.bytenr)
	if err != nil {
		t.Fatal(err)
	}
	b := make([]byte, f.sb.nodeSize)
	im.ReadAt(b, phys)
	// Flip a byte inside the leaf's free space: structure intact, csum wrong.
	n := binary.LittleEndian.Uint32(b[96:])
	at := headerSize + int(n)*itemSize + 8
	b[at] ^= 0xff
	im.Patch(phys, b)
	f = open(t, im)
	fs.ReadDir(f, ".")
	if f.Stats()["csum_errors"] == 0 {
		t.Fatalf("csum damage not reported: %v", f.Problems())
	}
}

func TestTruncated(t *testing.T) {
	im := image(t)
	im.Truncate(32 << 20)
	if _, err := Open(im, im.Size()); err == nil {
		t.Fatal("truncated image opened")
	}
	if Probe(bytes.NewReader(make([]byte, 1<<17)), 1<<17) {
		t.Fatal("zeros probed as btrfs")
	}
}

func TestMultiDeviceUnsupported(t *testing.T) {
	im := image(t)
	b := make([]byte, superSize)
	im.ReadAt(b, superOffset)
	binary.LittleEndian.PutUint64(b[0x88:], 2)
	superCsum(b)
	im.Patch(superOffset, b)
	_, err := Open(im, im.Size())
	if !errors.Is(err, errors.ErrUnsupported) || !strings.Contains(err.Error(), "multi-device") {
		t.Fatalf("multi-device: %v", err)
	}
}

func TestRAIDChunkUnsupported(t *testing.T) {
	im := image(t)
	b := make([]byte, superSize)
	im.ReadAt(b, superOffset)
	// First sys_chunk_array entry: key (17) + chunk item; type at +24.
	t0 := 0x32b + 17 + 24
	v := binary.LittleEndian.Uint64(b[t0:])
	binary.LittleEndian.PutUint64(b[t0:], v&^blockGroupDUP|blockGroupRAID1)
	superCsum(b)
	im.Patch(superOffset, b)
	_, err := Open(im, im.Size())
	if !errors.Is(err, errors.ErrUnsupported) || !strings.Contains(err.Error(), "RAID1") {
		t.Fatalf("raid chunk: %v", err)
	}
}

// TestCyclicTree points a node pointer back at the root: the strict level
// check stops it.
func TestCyclicTree(t *testing.T) {
	f := open(t, image(t))
	// Build a synthetic level-1 node whose child is itself.
	node := make([]byte, f.sb.nodeSize)
	copy(node[32:48], f.sb.metaUUID[:])
	logical := f.subvols[fsTreeID].bytenr
	binary.LittleEndian.PutUint64(node[48:], logical)
	binary.LittleEndian.PutUint32(node[96:], 1)
	node[100] = 1
	binary.LittleEndian.PutUint64(node[headerSize+17:], logical)
	binary.LittleEndian.PutUint32(node, crc32.Checksum(node[32:], castagnoli))
	f.nodes[logical] = node
	err := f.walk(logical, 1, key{}, key{^uint64(0), 255, ^uint64(0)}, func(key, []byte) error { return nil })
	if err == nil || !strings.Contains(err.Error(), "twice") && !strings.Contains(err.Error(), "level") {
		t.Fatalf("cyclic tree: %v", err)
	}
}

func TestReadAtBounds(t *testing.T) {
	f := open(t, image(t))
	fh, err := f.Open("data/big.txt")
	if err != nil {
		t.Fatal(err)
	}
	ra := fh.(io.ReaderAt)
	b := make([]byte, 200)
	if n, err := ra.ReadAt(b, 120000-50); n != 50 || err != io.EOF {
		t.Fatalf("tail read %d %v", n, err)
	}
	if _, err := ra.ReadAt(b[:39], 40*1000); err != nil || string(b[:39]) != "line 01001 of the multi-block text file" {
		t.Fatalf("mid read %q %v", b[:39], err)
	}
}

func FuzzOpen(f *testing.F) {
	im := image(f)
	f.Add(im.Bytes(superOffset + superSize)[superOffset:])
	f.Fuzz(func(t *testing.T, sb []byte) {
		c := im.Clone()
		if len(sb) > superSize {
			sb = sb[:superSize]
		}
		c.Patch(superOffset, sb)
		fsys, err := Open(c, c.Size())
		if err != nil {
			return
		}
		walkAll(fsys)
	})
}

// FuzzTreeBlock mutates the fs tree's root leaf.
func FuzzTreeBlock(f *testing.F) {
	im := image(f)
	fs0, err := Open(im, im.Size())
	if err != nil {
		f.Fatal(err)
	}
	x := fs0.(*FS)
	phys, _, _ := x.mapLogical(x.subvols[fsTreeID].bytenr)
	leaf := make([]byte, x.sb.nodeSize)
	im.ReadAt(leaf, phys)
	f.Add(leaf[:4096], uint16(0))
	f.Fuzz(func(t *testing.T, data []byte, at uint16) {
		c := im.Clone()
		if len(data) > len(leaf) {
			data = data[:len(leaf)]
		}
		patched := append([]byte(nil), leaf...)
		copy(patched[int(at)%len(leaf):], data)
		copy(patched[32:56], leaf[32:56]) // keep fsid and bytenr so the block is used
		binary.LittleEndian.PutUint32(patched, crc32.Checksum(patched[32:], castagnoli))
		c.Patch(phys, patched)
		fsys, err := Open(c, c.Size())
		if err != nil {
			return
		}
		walkAll(fsys)
	})
}

func walkAll(fsys fs.FS) {
	fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.Type().IsRegular() {
			if fh, err := fsys.Open(p); err == nil {
				io.Copy(io.Discard, io.LimitReader(fh, 1<<20))
				fh.Close()
			}
		}
		return nil
	})
}
