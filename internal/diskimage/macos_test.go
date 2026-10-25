package diskimage

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/diskimage/apfs"
)

// The macOS fixtures are made by hdiutil/diskutil (testdata/gen-macos.sh).

func untar(t *testing.T, name string) string {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	tr := tar.NewReader(zr)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(dir, filepath.FromSlash(h.Name))
		if !filepath.IsLocal(h.Name) {
			t.Fatalf("tar entry %q", h.Name)
		}
		switch h.Typeflag {
		case tar.TypeDir:
			os.MkdirAll(p, 0o755)
		case tar.TypeReg:
			os.MkdirAll(filepath.Dir(p), 0o755)
			b, _ := io.ReadAll(tr)
			os.WriteFile(p, b, 0o600)
		}
	}
	return dir
}

func TestDMGAndSparseBundle(t *testing.T) {
	dir := t.TempDir()
	raw, err := os.ReadFile(fixture(t, dir, "apfs-gpt.raw"))
	if err != nil {
		t.Fatal(err)
	}
	paths := map[string]string{
		"udzo":         fixture(t, dir, "apfs-udzo.dmg"),
		"udbz":         fixture(t, dir, "apfs-udbz.dmg"),
		"sparsebundle": filepath.Join(untar(t, "apfs.sparsebundle.tar.gz"), "apfs.sparsebundle"),
	}
	for name, p := range paths {
		t.Run(name, func(t *testing.T) {
			im, err := Open(p)
			if err != nil {
				t.Fatal(err)
			}
			defer im.Close()
			want := FormatDMG
			if name == "sparsebundle" {
				want = FormatSparseBundle
				if len(im.Segments) < 3 || im.Meta["band_size"] != "1048576" {
					t.Errorf("segments %v meta %v", im.Segments, im.Meta)
				}
			}
			if im.Format != want || im.Size() != int64(len(raw)) {
				t.Fatalf("format %s size %d", im.Format, im.Size())
			}
			if got := readAll(t, im); !bytes.Equal(got, raw) {
				t.Fatal("logical disk differs from the UDTO raw conversion")
			}
			pt, err := Partitions(im, im.Size())
			if err != nil {
				t.Fatal(err)
			}
			var found bool
			for _, v := range pt.Volumes {
				if GPTTypeName(v.Type) != "Apple APFS" {
					continue
				}
				res := OpenFS(v.Section(im), v.Size)
				if res.Type != "apfs" || res.FS == nil {
					t.Fatalf("OpenFS %+v", res)
				}
				if _, err := fs.Stat(res.FS, "Users/alice/.claude/settings.json"); err != nil {
					t.Fatal(err)
				}
				found = true
			}
			if !found {
				t.Fatalf("no APFS partition in %+v", pt)
			}
		})
	}
}

func TestDMGUnsupported(t *testing.T) {
	dir := t.TempDir()
	_, err := Open(fixture(t, dir, "apfs-ulfo.dmg"))
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "LZFSE") {
		t.Errorf("ULFO: %v", err)
	}
	_, err = Open(fixture(t, dir, "enc-head.dmg"))
	if !errors.Is(err, ErrEncrypted) {
		t.Errorf("encrypted: %v", err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrUnsupported) {
		t.Errorf("plain directory: %v", err)
	}
}

// TestAPFSMultiVolume: a container with "Plain", "Enc" (encrypted) and
// "Data2". The readable volumes are top-level directories; the encrypted
// one is listed and reading it fails UNSUPPORTED.
func TestAPFSMultiVolume(t *testing.T) {
	im, err := Open(fixture(t, t.TempDir(), "apfs-multi.dmg"))
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	res := OpenFS(im, im.Size())
	if res.FS == nil {
		t.Fatalf("%+v", res)
	}
	ents, err := fs.ReadDir(res.FS, ".")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range ents {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "Data2,Enc,Plain" {
		t.Fatalf("top level %v", names)
	}
	if b, err := fs.ReadFile(res.FS, "Data2/second.txt"); err != nil || string(b) != "second volume\n" {
		t.Errorf("Data2/second.txt %q %v", b, err)
	}
	if _, err := fs.Stat(res.FS, "Plain/Users/alice/.claude/settings.json"); err != nil {
		t.Error(err)
	}
	if _, err := fs.ReadDir(res.FS, "Enc"); !errors.Is(err, errors.ErrUnsupported) || !strings.Contains(err.Error(), "encrypted") {
		t.Errorf("Enc: %v", err)
	}
	a := res.FS.(*apfs.FS)
	var enc bool
	for _, v := range a.Volumes() {
		enc = enc || v.Name == "Enc" && v.Encrypted
	}
	if !enc || !strings.Contains(strings.Join(a.Problems(), ";"), "encrypted") {
		t.Errorf("volumes %+v problems %v", a.Volumes(), a.Problems())
	}
	// Inode numbers stay distinct across volumes (both roots are inode 2).
	p, _ := fs.Stat(res.FS, "Plain/Users")
	d, _ := fs.Stat(res.FS, "Data2/second.txt")
	if p.Sys().(map[string]any)["inode"] == d.Sys().(map[string]any)["inode"] {
		t.Error("inode collision across volumes")
	}
}

func TestDMGDamaged(t *testing.T) {
	dir := t.TempDir()
	b, err := os.ReadFile(fixture(t, dir, "apfs-udzo.dmg"))
	if err != nil {
		t.Fatal(err)
	}
	write := func(name string, data []byte) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, data, 0o600)
		return p
	}
	// Truncated: the koly trailer is gone, so it is no longer a dmg.
	if im, err := Open(write("trunc.dmg", b[:len(b)-100])); err == nil {
		if im.Format == FormatDMG {
			t.Error("truncated dmg opened as a dmg")
		}
		im.Close()
	}
	// XML length past the end of the file.
	bad := bytes.Clone(b)
	binary.BigEndian.PutUint64(bad[len(bad)-512+224:], 1<<40)
	if _, err := Open(write("xml.dmg", bad)); !errors.Is(err, ErrCorrupt) {
		t.Errorf("bad xml length: %v", err)
	}
	// Garbage in the compressed data: reads fail, never panic.
	bad = bytes.Clone(b)
	for i := 0; i < 2000; i++ {
		bad[i] ^= 0x5a
	}
	im, err := Open(write("garbage.dmg", bad))
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	buf := make([]byte, 64<<10)
	var rerr error
	for off := int64(0); off < im.Size() && rerr == nil; off += int64(len(buf)) {
		_, rerr = im.ReadAt(buf, off)
	}
	if !errors.Is(rerr, ErrCorrupt) {
		t.Errorf("garbage chunk read: %v", rerr)
	}
}

func TestSparseBundleMissingBand(t *testing.T) {
	root := untar(t, "apfs.sparsebundle.tar.gz")
	sb := filepath.Join(root, "apfs.sparsebundle")
	os.Remove(filepath.Join(sb, "bands", "7"))
	os.WriteFile(filepath.Join(sb, "bands", "zz"), []byte("x"), 0o600)
	im, err := Open(sb)
	if err != nil {
		t.Fatal(err)
	}
	defer im.Close()
	if im.Meta["bands_ignored"] != "zz" {
		t.Errorf("meta %v", im.Meta)
	}
	tail := make([]byte, 4096)
	if _, err := im.ReadAt(tail, im.Size()-4096); err != nil || !bytes.Equal(tail, make([]byte, 4096)) {
		t.Errorf("missing band does not read as zeros: %v", err)
	}
}

func FuzzParseUDIF(f *testing.F) {
	b, err := os.ReadFile(fixture(f, f.TempDir(), "apfs-udzo.dmg"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Fuzz(func(t *testing.T, data []byte) {
		u, _, err := parseUDIF(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		buf := make([]byte, 32<<10)
		for off := int64(0); off < u.size && off < 8<<20; off += int64(len(buf)) {
			u.ReadAt(buf, off)
		}
	})
}

func FuzzParsePlist(f *testing.F) {
	f.Add([]byte(`<plist><dict><key>band-size</key><integer>8</integer><key>a</key><array><data>AAAA</data><true/></array></dict></plist>`))
	f.Fuzz(func(t *testing.T, b []byte) { parsePlist(b) })
}
