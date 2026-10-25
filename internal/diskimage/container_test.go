package diskimage

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// fixture gunzips testdata/<name>.gz into dir and returns the path.
func fixture(t testing.TB, dir, name string) string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name+".gz"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, name)
	w, err := os.Create(out)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(w, zr); err != nil {
		t.Fatal(err)
	}
	w.Close()
	return out
}

func rawFixture(t testing.TB) []byte {
	t.Helper()
	dir := t.TempDir()
	b, err := os.ReadFile(fixture(t, dir, "disk-gpt.raw"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func readAll(t *testing.T, im *Image) []byte {
	t.Helper()
	out := make([]byte, im.Size())
	// Odd-sized reads exercise chunk/grain/block boundaries.
	const step = 7777
	for off := int64(0); off < im.Size(); off += step {
		end := off + step
		if end > im.Size() {
			end = im.Size()
		}
		if _, err := im.ReadAt(out[off:end], off); err != nil && !(errors.Is(err, io.EOF) && end == im.Size()) {
			t.Fatalf("ReadAt(%d): %v", off, err)
		}
	}
	return out
}

func TestContainersRoundTrip(t *testing.T) {
	raw := rawFixture(t)
	cases := []struct {
		files  []string // first is opened
		format string
	}{
		{[]string{"disk-gpt.raw"}, FormatRaw},
		{[]string{"disk-gpt.raw.001", "disk-gpt.raw.002", "disk-gpt.raw.003"}, FormatSplitRaw},
		{[]string{"disk-gpt-alpha.raw.aa", "disk-gpt-alpha.raw.ab", "disk-gpt-alpha.raw.ac"}, FormatSplitRaw},
		{[]string{"disk.E01"}, FormatEWF},
		{[]string{"disk-split.E01", "disk-split.E02", "disk-split.E03", "disk-split.E04", "disk-split.E05", "disk-split.E06", "disk-split.E07", "disk-split.E08", "disk-split.E09"}, FormatEWF},
		{[]string{"disk-fixed.vhd"}, FormatVHDFixed},
		{[]string{"disk-dynamic.vhd"}, FormatVHDDynamic},
		{[]string{"disk.vhdx"}, FormatVHDX},
		{[]string{"disk-sparse.vmdk"}, FormatVMDK},
		{[]string{"disk-stream.vmdk"}, FormatVMDK},
		{[]string{"disk-flat.vmdk", "disk-flat-flat.vmdk"}, FormatVMDK},
	}
	for _, c := range cases {
		t.Run(c.files[0], func(t *testing.T) {
			dir := t.TempDir()
			var first string
			for i, f := range c.files {
				p := fixture(t, dir, f)
				if i == 0 {
					first = p
				}
			}
			im, err := Open(first)
			if err != nil {
				t.Fatal(err)
			}
			defer im.Close()
			if im.Format != c.format {
				t.Fatalf("format %q, want %q", im.Format, c.format)
			}
			if len(im.Segments) != len(c.files) {
				t.Fatalf("segments %v, want %d", im.Segments, len(c.files))
			}
			if im.Size() < int64(len(raw)) {
				t.Fatalf("size %d < raw %d", im.Size(), len(raw))
			}
			got := readAll(t, im)
			if !bytes.Equal(got[:len(raw)], raw) {
				t.Fatal("logical bytes differ from the raw image")
			}
			if !allZero(got[len(raw):]) {
				t.Fatal("bytes past the raw size are not zero")
			}
		})
	}
}

func TestEWFStoredHashes(t *testing.T) {
	dir := t.TempDir()
	p := fixture(t, dir, "disk.E01")
	im, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	if !im.HasStoredHashes() {
		t.Fatal("no stored hashes")
	}
	res := im.VerifyStored(nil)
	im.Close()
	if res.MD5 != HashMatch || res.SHA1 != HashMatch {
		t.Fatalf("verify: %+v", res)
	}
	if im.Meta["case_number"] != "case" || im.Meta["examiner"] != "examiner" {
		t.Fatalf("header meta: %v", im.Meta)
	}

	// Flip one byte inside the stored hash: verification must report a
	// mismatch for MD5 (the digest section also carries MD5 + SHA-1).
	b, _ := os.ReadFile(p)
	i := bytes.Index(b, []byte("digest\x00"))
	if i < 0 {
		t.Fatal("no digest section")
	}
	data := i + ewfDescriptorSize
	b[data] ^= 0xff
	b[data+16] ^= 0xff
	// hash section (MD5 only) is overridden by digest; flip it too.
	if j := bytes.Index(b, []byte("hash\x00")); j >= 0 {
		b[j+ewfDescriptorSize] ^= 0xff
	}
	os.WriteFile(p, b, 0o600)
	im, err = Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	res = im.VerifyStored(nil)
	if res.MD5 != HashMismatch || res.SHA1 != HashMismatch {
		t.Fatalf("flipped stored hash: %+v", res)
	}
}

func TestEWFFlippedMediaByte(t *testing.T) {
	// Uncompressed split set: flip a byte of chunk data. The chunk's
	// Adler-32 catches it on read, so verification reports an error.
	dir := t.TempDir()
	var first string
	for i := 1; i <= 9; i++ {
		p := fixture(t, dir, "disk-split.E0"+string(rune('0'+i)))
		if i == 1 {
			first = p
		}
	}
	seg3 := filepath.Join(dir, "disk-split.E03")
	b, _ := os.ReadFile(seg3)
	i := bytes.Index(b, []byte("sectors\x00"))
	if i < 0 {
		t.Fatal("no sectors section")
	}
	b[i+ewfDescriptorSize+100] ^= 0x01
	os.WriteFile(seg3, b, 0o600)
	im, err := Open(first)
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	res := im.VerifyStored(nil)
	if res.MD5 == HashMatch || res.SHA1 == HashMatch {
		t.Fatalf("flipped media byte still matches: %+v", res)
	}
	if res.Error == "" && res.MD5 != HashMismatch {
		t.Fatalf("expected mismatch or read error: %+v", res)
	}
}

func TestEWFMissingSegment(t *testing.T) {
	dir := t.TempDir()
	p := fixture(t, dir, "disk-split.E01")
	fixture(t, dir, "disk-split.E02")
	_, err := Open(p)
	if !errors.Is(err, ErrCorrupt) {
		t.Fatalf("want corrupt, got %v", err)
	}
}

func TestTruncatedContainers(t *testing.T) {
	for _, name := range []string{"disk.E01", "disk-dynamic.vhd", "disk.vhdx", "disk-sparse.vmdk", "disk-stream.vmdk"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := fixture(t, dir, name)
			b, _ := os.ReadFile(p)
			for _, cut := range []int{len(b) / 2, len(b) - 700, 2048, 100} {
				if cut <= 0 || cut >= len(b) {
					continue
				}
				os.WriteFile(p, b[:cut], 0o600)
				im, err := Open(p)
				if err != nil {
					var de *Error
					if !errors.As(err, &de) {
						t.Fatalf("cut %d: untyped error %v", cut, err)
					}
					continue
				}
				// Opened (e.g. VHD falls back to the header copy): every read
				// must fail cleanly or succeed, never panic.
				buf := make([]byte, 1<<16)
				for off := int64(0); off < im.Size(); off += int64(len(buf)) {
					im.ReadAt(buf, off)
				}
				im.Close()
			}
		})
	}
}

func TestSniffUnsupported(t *testing.T) {
	dir := t.TempDir()
	cases := map[string]string{
		"x.qcow2": "QFI\xfb",
		"x.gz":    "\x1f\x8b\x08\x00",
		"x.Ex01":  "EVF2\x0d\x0a\x81\x00",
		"x.vmdk":  "COWD",
	}
	for name, head := range cases {
		p := filepath.Join(dir, name)
		os.WriteFile(p, append([]byte(head), make([]byte, 4096)...), 0o600)
		_, err := Open(p)
		if !errors.Is(err, ErrUnsupported) {
			t.Errorf("%s: want unsupported, got %v", name, err)
		}
	}
}

func TestVHDDifferencingReportsParent(t *testing.T) {
	dir := t.TempDir()
	p := fixture(t, dir, "disk-dynamic.vhd")
	b, _ := os.ReadFile(p)
	// Patch footer (end copy and start copy) to type 4 and fix checksums,
	// and put a parent name in the dynamic header.
	patch := func(f []byte) {
		f[63] = 4
		fixVHDChecksum(f, 64)
	}
	patch(b[len(b)-512:])
	patch(b[:512])
	dyn := b[512:1536]
	name := "parent-disk.vhd"
	for i, c := range name {
		dyn[64+2*i+1] = byte(c)
	}
	fixVHDChecksum(dyn, 36)
	os.WriteFile(p, b, 0o600)
	_, err := Open(p)
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "parent-disk.vhd") {
		t.Fatalf("want unsupported naming the parent, got %v", err)
	}
}

func fixVHDChecksum(b []byte, off int) {
	clear(b[off : off+4])
	var sum uint32
	for _, x := range b {
		sum += uint32(x)
	}
	sum = ^sum
	b[off], b[off+1], b[off+2], b[off+3] = byte(sum>>24), byte(sum>>16), byte(sum>>8), byte(sum)
}

func TestVHDXDirtyLog(t *testing.T) {
	dir := t.TempDir()
	p := fixture(t, dir, "disk.vhdx")
	b, _ := os.ReadFile(p)
	for _, off := range []int{64 << 10, 128 << 10} {
		h := b[off : off+4096]
		h[48] = 0x42 // log GUID non-zero
		setCRC32C(h, 4)
	}
	os.WriteFile(p, b, 0o600)
	_, err := Open(p)
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "dirty log") {
		t.Fatalf("want unsupported dirty log, got %v", err)
	}
}

func TestVMDKDescriptorMultiExtentAndTraversal(t *testing.T) {
	raw := rawFixture(t)
	dir := t.TempDir()
	half := len(raw) / 2
	os.WriteFile(filepath.Join(dir, "a.bin"), raw[:half], 0o600)
	os.WriteFile(filepath.Join(dir, "b.bin"), raw[half:], 0o600)
	desc := "# Disk DescriptorFile\nversion=1\nCID=fffffffe\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentFlat\"\n\n# Extent description\n" +
		"RW " + itoa(half/512) + " FLAT \"a.bin\" 0\nRW " + itoa((len(raw)-half)/512) + " FLAT \"b.bin\" 0\nRW 16 ZERO\n"
	p := filepath.Join(dir, "multi.vmdk")
	os.WriteFile(p, []byte(desc), 0o600)
	im, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	got := readAll(t, im)
	im.Close()
	if !bytes.Equal(got[:len(raw)], raw) || len(got) != len(raw)+16*512 {
		t.Fatal("multi-extent bytes differ")
	}
	evil := strings.Replace(desc, "\"a.bin\"", "\"../a.bin\"", 1)
	os.WriteFile(p, []byte(evil), 0o600)
	if _, err := Open(p); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("traversal extent: want unsupported, got %v", err)
	}
	delta := strings.Replace(desc, "parentCID=ffffffff", "parentCID=1234abcd\nparentFileNameHint=\"base.vmdk\"", 1)
	os.WriteFile(p, []byte(delta), 0o600)
	if _, err := Open(p); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "base.vmdk") {
		t.Fatalf("delta disk: want unsupported naming parent, got %v", err)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

func setCRC32C(b []byte, off int) {
	clear(b[off : off+4])
	binary.LittleEndian.PutUint32(b[off:], crc32.Checksum(b, crc32c))
}
