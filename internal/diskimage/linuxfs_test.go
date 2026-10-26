package diskimage

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	fx "github.com/efij/AgentDFIR/v5/internal/diskimage/internal/fixture"
)

// The fixtures below were made by qemu-img, mkfs.btrfs, mkfs.xfs and the
// LVM2 tools; see testdata/README.md and testdata/gen-linux.sh.

func sameContent(t *testing.T, a, b io.ReaderAt, size int64) {
	t.Helper()
	x, y := make([]byte, 1<<20), make([]byte, 1<<20)
	for off := int64(0); off < size; off += int64(len(x)) {
		n := int(min(int64(len(x)), size-off))
		if _, err := a.ReadAt(x[:n], off); err != nil && err != io.EOF {
			t.Fatalf("read container at %d: %v", off, err)
		}
		if _, err := b.ReadAt(y[:n], off); err != nil && err != io.EOF {
			t.Fatalf("read raw at %d: %v", off, err)
		}
		if !bytes.Equal(x[:n], y[:n]) {
			t.Fatalf("content differs in the MiB at %d", off)
		}
	}
}

func TestQCOW2MatchesRaw(t *testing.T) {
	btr, err := fx.Load("btrfs/testdata/btrfs.img.gz")
	if err != nil {
		t.Fatal(err)
	}
	xfsRaw, err := fx.Load("xfs/testdata/xfs.img.gz")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, c := range []struct {
		name    string
		raw     *fx.Image
		version string
	}{
		{"linux-btrfs.qcow2", btr, "3"},
		{"linux-btrfs-c.qcow2", btr, "3"},
		{"linux-xfs-v2.qcow2", xfsRaw, "2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			im, err := Open(fixture(t, dir, c.name))
			if err != nil {
				t.Fatal(err)
			}
			defer im.Close()
			if im.Format != FormatQCOW2 || im.Size() != c.raw.Size() || im.Meta["qcow2_version"] != c.version {
				t.Fatalf("format %s size %d meta %v", im.Format, im.Size(), im.Meta)
			}
			sameContent(t, im, c.raw, im.Size())
		})
	}
}

func TestQCOW2FilesystemReachable(t *testing.T) {
	im, err := Open(fixture(t, t.TempDir(), "linux-btrfs-c.qcow2"))
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	pt, err := Partitions(im, im.Size())
	if err != nil || len(pt.Volumes) != 1 {
		t.Fatalf("partitions %+v %v", pt, err)
	}
	res := OpenFS(pt.Volumes[0].Section(im), pt.Volumes[0].Size)
	if res.Type != "btrfs" || res.FS == nil {
		t.Fatalf("OpenFS: %+v", res)
	}
	b, err := fs.ReadFile(res.FS, "home/alice/notes.txt")
	if err != nil || string(b) != "AgentDFIR linux filesystem fixture\n" {
		t.Fatalf("notes.txt %q %v", b, err)
	}
}

func TestQCOW2Unsupported(t *testing.T) {
	dir := t.TempDir()
	_, err := Open(fixture(t, dir, "linux-backed.qcow2"))
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), `"btrfs.qcow2"`) {
		t.Errorf("backing file: %v", err)
	}
	_, err = Open(fixture(t, dir, "linux-zstd-type.qcow2"))
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "zstd") {
		t.Errorf("zstd compression type: %v", err)
	}
	p := fixture(t, dir, "linux-btrfs.qcow2")
	b, _ := os.ReadFile(p)
	patch := func(name string, fn func([]byte)) string {
		c := append([]byte(nil), b...)
		fn(c)
		q := filepath.Join(dir, name)
		os.WriteFile(q, c, 0o600)
		return q
	}
	_, err = Open(patch("enc.qcow2", func(c []byte) { binary.BigEndian.PutUint32(c[32:], 2) }))
	if !errors.Is(err, ErrEncrypted) || !strings.Contains(err.Error(), "LUKS") {
		t.Errorf("encrypted: %v", err)
	}
	_, err = Open(patch("ext.qcow2", func(c []byte) { c[79] |= qcowIncompatExtendedL2 }))
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "extended L2") {
		t.Errorf("extended L2: %v", err)
	}
	_, err = Open(patch("v1.qcow", func(c []byte) { binary.BigEndian.PutUint32(c[4:], 1) }))
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("qcow v1: %v", err)
	}
	_, err = Open(patch("l1.qcow2", func(c []byte) { binary.BigEndian.PutUint64(c[40:], 1<<40) }))
	if !errors.Is(err, ErrCorrupt) {
		t.Errorf("L1 out of bounds: %v", err)
	}
	// Truncated file: opens (header and L1 intact), reads past the end fail.
	im, err := Open(patch("trunc.qcow2", func(c []byte) {}))
	if err != nil {
		t.Fatal(err)
	}
	im.Close()
	short := filepath.Join(dir, "short.qcow2")
	os.WriteFile(short, b[:len(b)/2], 0o600)
	if im, err := Open(short); err == nil {
		buf := make([]byte, 1<<20)
		var failed bool
		for off := int64(0); off < im.Size(); off += int64(len(buf)) {
			if _, err := im.ReadAt(buf, off); err != nil && err != io.EOF {
				failed = true
				break
			}
		}
		im.Close()
		if !failed {
			t.Error("truncated qcow2 read without error")
		}
	}
}

func FuzzOpenQCOW2(f *testing.F) {
	dir := f.TempDir()
	b, err := os.ReadFile(fixture(f, dir, "linux-btrfs-c.qcow2"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b[:4096])
	f.Fuzz(func(t *testing.T, head []byte) {
		if !bytes.HasPrefix(head, []byte("QFI\xfb")) {
			return
		}
		c := append([]byte(nil), b...)
		copy(c, head)
		p := filepath.Join(t.TempDir(), "x.qcow2")
		os.WriteFile(p, c, 0o600)
		im, err := Open(p)
		if err != nil {
			return
		}
		buf := make([]byte, 64<<10)
		for off := int64(0); off < im.Size() && off < 8<<20; off += int64(len(buf)) {
			im.ReadAt(buf, off)
		}
		im.Close()
	})
}

// ---- LVM2 ----

func lvmDisk(t testing.TB) []byte {
	t.Helper()
	b, err := os.ReadFile(fixture(t, t.TempDir(), "linux-lvm.img"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func volumeByName(pt *PartitionTable, name string) *Volume {
	for i := range pt.Volumes {
		if pt.Volumes[i].Name == name {
			return &pt.Volumes[i]
		}
	}
	return nil
}

func TestLVMVolumes(t *testing.T) {
	disk := lvmDisk(t)
	r := bytes.NewReader(disk)
	pt, err := Partitions(r, int64(len(disk)))
	if err != nil {
		t.Fatal(err)
	}
	if pt.Scheme != "mbr" || len(pt.Volumes) < 2 || pt.Volumes[0].LVM == "" || pt.Volumes[1].LVM == "" {
		t.Fatalf("PV volumes: %+v", pt.Volumes)
	}
	if !strings.Contains(pt.Volumes[0].LVM, "volume group vgadfir") {
		t.Errorf("PV note %q", pt.Volumes[0].LVM)
	}
	want := map[string]string{
		"vgadfir/root":    "",
		"vgadfir/striped": "striped over 2 devices",
		"vgadfir/snap":    "snapshot of \"root\"",
		"vgadfir/mirror":  `"raid1"`,
		"vgadfir/pool":    `"thin-pool"`,
		"vgadfir/thin":    `"thin"`,
	}
	for name, reason := range want {
		v := volumeByName(pt, name)
		if v == nil {
			t.Errorf("%s not listed", name)
			continue
		}
		if v.Scheme != "lvm" || v.Index <= lvIndexBase {
			t.Errorf("%s: scheme %s index %d", name, v.Scheme, v.Index)
		}
		if reason == "" && v.Unsupported != "" || reason != "" && !strings.Contains(v.Unsupported, reason) {
			t.Errorf("%s: unsupported %q, want %q", name, v.Unsupported, reason)
		}
	}
	if len(pt.Volumes) != 2+len(want) {
		t.Errorf("%d volumes: %+v", len(pt.Volumes), pt.Volumes)
	}
	if !strings.Contains(strings.Join(pt.Problems, ";"), "hidden component") {
		t.Errorf("problems %v", pt.Problems)
	}

	// root: two non-adjacent segments (4 MiB + 2 MiB) holding an ext4.
	root := volumeByName(pt, "vgadfir/root")
	if len(root.Segments) != 2 || root.Size != 6<<20 {
		t.Fatalf("root segments %+v size %d", root.Segments, root.Size)
	}
	res := OpenFS(root.Section(r), root.Size)
	if res.Type != "ext4" || res.FS == nil {
		t.Fatalf("root LV: %+v", res)
	}
	b, err := fs.ReadFile(res.FS, "home/alice/.claude/projects/-home-alice-proj/session.jsonl")
	if err != nil {
		t.Fatal(err)
	}
	if s := sha256.Sum256(b); hex.EncodeToString(s[:]) != "4128bfda061640530d235560af704ff123cda0600636a0cbeea4a77150d6e32b" {
		t.Errorf("session.jsonl via LV: %x", s)
	}
	// Every byte of the LV is readable through the segment map.
	if n, err := io.Copy(io.Discard, root.Section(r)); err != nil || n != root.Size {
		t.Fatalf("read whole LV: %d %v", n, err)
	}
}

func TestLVMDamaged(t *testing.T) {
	disk := lvmDisk(t)
	pt, _ := Partitions(bytes.NewReader(disk), int64(len(disk)))
	pv1 := pt.Volumes[0]
	// Break the metadata text checksum on both PVs: no LVs, PVs fall back to
	// the signature table (UNSUPPORTED, with the activation workaround).
	bad := append([]byte(nil), disk...)
	for _, v := range pt.Volumes[:2] {
		mda := v.Offset + 4096
		raw := binary.LittleEndian.Uint64(bad[mda+40:])
		bad[mda+int64(raw)+10] ^= 0xff
	}
	pt2, err := Partitions(bytes.NewReader(bad), int64(len(bad)))
	if err != nil {
		t.Fatal(err)
	}
	if len(pt2.Volumes) != 2 || pt2.Volumes[0].LVM != "" || !strings.Contains(strings.Join(pt2.Problems, ";"), "checksum") {
		t.Fatalf("damaged metadata: %+v %v", pt2.Volumes, pt2.Problems)
	}
	res := OpenFS(pt2.Volumes[0].Section(bytes.NewReader(bad)), pt2.Volumes[0].Size)
	if res.Type != "lvm2" || !errors.Is(res.Err, ErrUnsupported) {
		t.Fatalf("PV fallback: %+v", res)
	}
	// Second PV missing (disk cut after the first partition): LVs touching
	// it become UNSUPPORTED, root (on pv0 only) still reads.
	cut := disk[:pv1.Offset+pv1.Size]
	pt3, _ := Partitions(bytes.NewReader(cut), int64(len(cut)))
	if v := volumeByName(pt3, "vgadfir/striped"); v == nil || v.Unsupported == "" {
		t.Errorf("striped with a missing PV: %+v", v)
	}
	if v := volumeByName(pt3, "vgadfir/root"); v == nil || v.Unsupported != "" {
		t.Errorf("root with pv1 missing: %+v", v)
	}
	if !strings.Contains(strings.Join(pt3.Problems, ";"), "not in this image") {
		t.Errorf("missing PV not reported: %v", pt3.Problems)
	}
}

func FuzzLVMPartitions(f *testing.F) {
	disk := lvmDisk(f)
	f.Add(disk[1<<20 : 1<<20+8192])
	f.Fuzz(func(t *testing.T, area []byte) {
		c := append([]byte(nil), disk...)
		copy(c[1<<20:], area) // the first PV's label + metadata area
		pt, err := Partitions(bytes.NewReader(c), int64(len(c)))
		if err != nil {
			return
		}
		for _, v := range pt.Volumes {
			if v.Unsupported == "" && v.LVM == "" {
				io.Copy(io.Discard, io.LimitReader(v.Section(bytes.NewReader(c)), 1<<20))
			}
		}
	})
}
