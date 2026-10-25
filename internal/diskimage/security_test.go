package diskimage

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/adler32"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
)

func TestStagePathRefusesHostileNames(t *testing.T) {
	dest := t.TempDir()
	bad := []string{
		"a/../b", "../x", "a/./b", "a//b", "a\\..\\b", "c:/x", "a/c:d", "a/x\x00y", "a/x\x01y", "a/x\x7fy",
		"a/CON", "a/con.txt", "a/Nul", "a/aux.json", "a/PRN", "a/COM1", "a/lpt9.log", "a/COM¹", "a/trailing.", "a/trailing ",
	}
	for _, p := range bad {
		if s, err := StagePath(dest, p); err == nil {
			t.Errorf("%q accepted as %q", p, s)
		} else if !strings.Contains(err.Error(), "refused") && !strings.Contains(err.Error(), "outside") {
			t.Errorf("%q: unexpected error %v", p, err)
		}
	}
	for _, p := range []string{"Users/alice/.claude/settings.json", "home/u/CONFIG", "a/console.log", "a/COM10"} {
		s, err := StagePath(dest, p)
		if err != nil {
			t.Errorf("%q refused: %v", p, err)
			continue
		}
		if rel, _ := filepath.Rel(dest, s); !filepath.IsLocal(rel) {
			t.Errorf("%q escaped: %s", p, s)
		}
	}
}

func TestExtractFilesHostileNames(t *testing.T) {
	m := fstest.MapFS{
		"u/.claude/ok.json":    {Data: []byte("{}")},
		"u/.claude/a\\b.json":  {Data: []byte("x")},
		"u/.claude/x:y":        {Data: []byte("x")},
		"u/.claude/CON.json":   {Data: []byte("x")},
		"u/.claude/ctl\x01.js": {Data: []byte("x")},
	}
	dest := t.TempDir()
	var files []string
	for p := range m {
		files = append(files, p)
	}
	res := ExtractFiles(m, files, dest, Limits{})
	ok := 0
	for _, f := range res.Files {
		if f.Staged != "" {
			ok++
			if f.FSPath != "u/.claude/ok.json" {
				t.Errorf("hostile %q extracted", f.FSPath)
			}
		}
	}
	if ok != 1 || len(res.Problems) != 4 {
		t.Fatalf("extracted %d, problems %v", ok, res.Problems)
	}
	// Escaped original bytes appear in the problem text.
	if !strings.Contains(strings.Join(res.Problems, " "), `ctl\x01.js`) {
		t.Fatalf("control byte not escaped: %v", res.Problems)
	}
	// Nothing written anywhere but dest.
	filepath.WalkDir(dest, func(p string, d os.DirEntry, err error) error {
		if rel, _ := filepath.Rel(dest, p); rel != "." && !filepath.IsLocal(rel) {
			t.Errorf("wrote outside staging: %s", p)
		}
		return nil
	})
}

func TestStagingNeverFollowsSymlinks(t *testing.T) {
	dest := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dest, "u")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	m := fstest.MapFS{"u/.claude/s.json": {Data: []byte("{}")}}
	res := ExtractFiles(m, []string{"u/.claude/s.json"}, dest, Limits{})
	if res.Files[0].Staged != "" || res.Files[0].Problem == "" {
		t.Fatalf("followed a symlink in staging: %+v", res.Files[0])
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Fatal("wrote through the symlink")
	}
}

// ewfSection writes a valid descriptor at off.
func ewfSection(b []byte, off int, typ string, next, size uint64) {
	d := b[off : off+76]
	clear(d)
	copy(d, typ)
	binary.LittleEndian.PutUint64(d[16:], next)
	binary.LittleEndian.PutUint64(d[24:], size)
	binary.LittleEndian.PutUint32(d[72:], adler32.Checksum(d[:72]))
}

func TestEWFOverflowingSizes(t *testing.T) {
	dir := t.TempDir()
	for _, tc := range []struct {
		name       string
		next, size uint64
	}{
		{"huge-size", 13 + 76, 1<<63 - 1},
		{"wrapping-next", 1<<63 + 5, 76},
		{"max-next", 1<<64 - 1, 76},
	} {
		b := make([]byte, 4096)
		copy(b, "EVF\x09\x0d\x0a\xff\x00\x01\x01\x00\x00\x00")
		ewfSection(b, 13, "header", tc.next, tc.size)
		p := filepath.Join(dir, tc.name+".E01")
		os.WriteFile(p, b, 0o600)
		if _, err := Open(p); !errors.Is(err, ErrCorrupt) {
			t.Errorf("%s: want corrupt, got %v", tc.name, err)
		}
	}
	// A table section claiming 2^32-1 entries is refused before allocation.
	b := make([]byte, 4096)
	copy(b, "EVF\x09\x0d\x0a\xff\x00\x01\x01\x00\x00\x00")
	ewfSection(b, 13, "table", 13+76+200, 76+200)
	h := b[13+76:]
	binary.LittleEndian.PutUint32(h[0:], 0xffffffff)
	binary.LittleEndian.PutUint32(h[20:], adler32.Checksum(h[:20]))
	p := filepath.Join(dir, "table.E01")
	os.WriteFile(p, b, 0o600)
	if _, err := Open(p); !errors.Is(err, ErrCorrupt) {
		t.Errorf("huge table: want corrupt, got %v", err)
	}
}

func TestVMDKGrainTableBounds(t *testing.T) {
	dir := t.TempDir()
	p := fixture(t, dir, "disk-sparse.vmdk")
	b, _ := os.ReadFile(p)
	orig := append([]byte(nil), b...)
	binary.LittleEndian.PutUint32(b[44:], 1<<16)
	os.WriteFile(p, b, 0o600)
	if _, err := Open(p); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("gtes 65536: want corrupt, got %v", err)
	}
	// Gigantic gdOffset must not overflow into a valid-looking offset.
	b = append([]byte(nil), orig...)
	binary.LittleEndian.PutUint64(b[56:], 1<<62)
	os.WriteFile(p, b, 0o600)
	if _, err := Open(p); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("huge gdOffset: want corrupt, got %v", err)
	}
	// The grain-table cache stays within its byte budget.
	os.WriteFile(p, orig, 0o600)
	im, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	readAll(t, im)
	sp := im.r.(*sparseExtent)
	if int64(len(sp.gtCache))*sp.gtes*4 > vmdkGTCacheBytes || len(sp.gtCache) != len(sp.gtOrder) {
		t.Fatalf("cache %d tables × %d entries", len(sp.gtCache), sp.gtes)
	}
}

func TestVHDOverflowingOffsets(t *testing.T) {
	dir := t.TempDir()
	p := fixture(t, dir, "disk-dynamic.vhd")
	b, _ := os.ReadFile(p)
	for _, f := range [][]byte{b[len(b)-512:], b[:512]} {
		binary.BigEndian.PutUint64(f[16:], 1<<63-100) // data offset
		fixVHDChecksum(f, 64)
	}
	os.WriteFile(p, b, 0o600)
	if _, err := Open(p); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want corrupt, got %v", err)
	}
}

func TestGPTOverflowingLBAs(t *testing.T) {
	raw := rawFixture(t)
	h := raw[512 : 512+92]
	binary.LittleEndian.PutUint64(h[72:], 1<<62) // entry array LBA
	binary.LittleEndian.PutUint64(h[32:], 1<<63-1)
	clear(h[16:20])
	binary.LittleEndian.PutUint32(h[16:], crc32.ChecksumIEEE(h))
	pt, err := Partitions(bytes.NewReader(raw), int64(len(raw)))
	if err != nil || !strings.Contains(strings.Join(pt.Problems, " "), "using the backup") {
		t.Fatalf("overflowing primary: %+v %v", pt, err)
	}
}

func TestSymlinkedSiblingsRefused(t *testing.T) {
	dir := t.TempDir()
	first := fixture(t, dir, "disk-gpt.raw.001")
	real2 := fixture(t, dir, "disk-gpt.raw.002")
	fixture(t, dir, "disk-gpt.raw.003")
	moved := filepath.Join(t.TempDir(), "elsewhere")
	os.Rename(real2, moved)
	if err := os.Symlink(moved, real2); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if _, err := Open(first); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("split raw via symlinked segment: %v", err)
	}

	e1 := fixture(t, dir, "disk-split.E01")
	for i := 2; i <= 9; i++ {
		fixture(t, dir, "disk-split.E0"+string(rune('0'+i)))
	}
	seg := filepath.Join(dir, "disk-split.E05")
	moved = filepath.Join(t.TempDir(), "seg")
	os.Rename(seg, moved)
	os.Symlink(moved, seg)
	if _, err := Open(e1); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("E01 via symlinked segment: %v", err)
	}

	raw := rawFixture(t)
	ext := filepath.Join(t.TempDir(), "flat.bin")
	os.WriteFile(ext, raw, 0o600)
	os.Symlink(ext, filepath.Join(dir, "link.bin"))
	desc := "# Disk DescriptorFile\nversion=1\nparentCID=ffffffff\ncreateType=\"monolithicFlat\"\nRW " + itoa(len(raw)/512) + " FLAT \"link.bin\" 0\n"
	p := filepath.Join(dir, "d.vmdk")
	os.WriteFile(p, []byte(desc), 0o600)
	if _, err := Open(p); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("VMDK symlinked extent: %v", err)
	}
}
