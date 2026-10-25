package ntfs

import (
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// volumeBytes returns the NTFS partition of the GPT fixture (LBA 2048, 6 MiB).
func volumeBytes(t testing.TB) []byte {
	t.Helper()
	f, err := os.Open(filepath.Join("..", "testdata", "disk-gpt.raw.gz"))
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
	return b[2048*512 : 2048*512+6<<20]
}

func openFixture(t *testing.T) *Volume {
	t.Helper()
	b := volumeBytes(t)
	if !Probe(bytes.NewReader(b), int64(len(b))) {
		t.Fatal("probe failed")
	}
	v, err := OpenVolume(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

var fixedTime = time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)

func TestReadSessionAndTimes(t *testing.T) {
	v := openFixture(t)
	p := "Users/alice/.claude/projects/-Users-alice-proj/session.jsonl"
	data, err := fs.ReadFile(v, p)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"sessionId":"s1"`)) || bytes.Count(data, []byte("\n")) != 3 {
		t.Fatalf("session content wrong: %q", data)
	}
	fi, err := fs.Stat(v, p)
	if err != nil {
		t.Fatal(err)
	}
	sys := fi.Sys().(map[string]any)
	if sys["fs"] != "ntfs" {
		t.Fatal("fs key")
	}
	if _, ok := sys["inode"].(uint64); !ok {
		t.Fatal("inode key")
	}
	want := fixedTime.Add(5 * time.Minute)
	if m := sys["mtime"].(time.Time); !m.Equal(want) || !fi.ModTime().Equal(want) {
		t.Fatalf("mtime %v, want %v", m, want)
	}
	if a := sys["atime"].(time.Time); !a.Equal(want) {
		t.Fatalf("atime %v, want %v", a, want)
	}
	for _, k := range []string{"btime", "ctime"} {
		if tm := sys[k].(time.Time); tm.IsZero() || tm.Location() != time.UTC {
			t.Fatalf("%s = %v", k, tm)
		}
	}
	// Case-insensitive lookup, Win32 semantics.
	if _, err := fs.Stat(v, "users/ALICE/.claude/settings.json"); err != nil {
		t.Fatal(err)
	}
}

func TestNonResidentSparseCompressed(t *testing.T) {
	v := openFixture(t)
	big, err := fs.ReadFile(v, "Users/alice/Documents/big.txt")
	if err != nil {
		t.Fatal(err)
	}
	var want bytes.Buffer
	for i := 1; i <= 2000; i++ {
		fmt.Fprintf(&want, "line %05d of the non-resident file\n", i)
	}
	if !bytes.Equal(big, want.Bytes()) {
		t.Fatalf("big.txt: %d bytes, want %d", len(big), want.Len())
	}

	sp, err := fs.ReadFile(v, "Users/alice/Documents/sparse.bin")
	if err != nil {
		t.Fatal(err)
	}
	if len(sp) != 1<<20 || string(sp[524288:524298]) != "SPARSEDATA" {
		t.Fatalf("sparse.bin: len %d", len(sp))
	}
	if !allZero(sp[:524288]) || !allZero(sp[524298:]) {
		t.Fatal("sparse.bin: holes not zero")
	}

	comp, err := fs.ReadFile(v, "Users/alice/compressed/comp.txt")
	if err != nil {
		t.Fatal(err)
	}
	want.Reset()
	for i := 1; i <= 3000; i++ {
		fmt.Fprintf(&want, "compressible text block %d\n", i%7)
	}
	if !bytes.Equal(comp, want.Bytes()) {
		t.Fatalf("comp.txt: %d bytes, want %d; prefix %q", len(comp), want.Len(), comp[:min(64, len(comp))])
	}
	fi, _ := fs.Stat(v, "Users/alice/compressed/comp.txt")
	if fi.Sys().(map[string]any)["compressed"] != true {
		t.Fatal("comp.txt not flagged compressed")
	}
}

func allZero(b []byte) bool {
	for _, x := range b {
		if x != 0 {
			return false
		}
	}
	return true
}

func TestADSDeletedHardLinks(t *testing.T) {
	v := openFixture(t)
	fi, err := fs.Stat(v, "Users/alice/notes.txt")
	if err != nil {
		t.Fatal(err)
	}
	ads, _ := fi.Sys().(map[string]any)["ads"].([]string)
	if len(ads) != 1 || ads[0] != "zone" {
		t.Fatalf("ads = %v", ads)
	}
	ents, err := fs.ReadDir(v, "Users/alice")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		if strings.Contains(e.Name(), ":") || e.Name() == "deleted.txt" {
			t.Fatalf("unexpected entry %q", e.Name())
		}
	}
	if v.Stats().Deleted < 1 {
		t.Fatalf("deleted count %d", v.Stats().Deleted)
	}
	links, err := fs.ReadDir(v, "Users/alice/links")
	if err != nil {
		t.Fatal(err)
	}
	if len(links) != 41 {
		t.Fatalf("links dir has %d entries, want 41", len(links))
	}
	last := "Users/alice/links/a-rather-long-hard-link-name-to-overflow-the-mft-record-40.txt"
	data, err := fs.ReadFile(v, last)
	if err != nil || string(data) != "hard link target\n" {
		t.Fatalf("hard link read: %q %v", data, err)
	}
	if nd, _, err := v.resolve("stat", last); err != nil || !nd.attrList {
		t.Fatal("hard-link target was expected to need an $ATTRIBUTE_LIST")
	}
	if v.Stats().Label != "ADFIRTEST" {
		t.Fatalf("label %q", v.Stats().Label)
	}
}

func TestFSConformance(t *testing.T) {
	v := openFixture(t)
	if err := fstest.TestFS(v, "Users/alice/notes.txt", "Users/alice/.claude/settings.json"); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptVolumes(t *testing.T) {
	b := volumeBytes(t)
	for _, cut := range []int{512, 4096, 64 << 10, len(b) / 2} {
		c := append([]byte(nil), b[:cut]...)
		v, err := OpenVolume(bytes.NewReader(c), int64(len(c)))
		if err == nil {
			fs.WalkDir(v, ".", func(p string, d fs.DirEntry, err error) error {
				if err == nil && !d.IsDir() {
					fs.ReadFile(v, p)
				}
				return nil
			})
		}
	}
	// Scribble over the MFT area: walk must survive.
	c := append([]byte(nil), b...)
	for i := 4 << 20; i < 4<<20+64<<10 && i < len(c); i += 97 {
		c[i] ^= 0x5a
	}
	if v, err := OpenVolume(bytes.NewReader(c), int64(len(c))); err == nil {
		fs.WalkDir(v, ".", func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				fs.ReadFile(v, p)
			}
			return nil
		})
	}
	if _, err := OpenVolume(bytes.NewReader(make([]byte, 4096)), 4096); err == nil {
		t.Fatal("zeros opened as NTFS")
	}
}

func TestLZNT1(t *testing.T) {
	// Stored chunk.
	src := append([]byte{0xff, 0x3f}, bytes.Repeat([]byte("a"), 4096)...)
	out, err := decompressLZNT1(src, 4096)
	if err != nil || len(out) != 4096 {
		t.Fatalf("stored chunk: %d %v", len(out), err)
	}
	// Compressed chunk: literal "abc" then back-ref offset 3 length 6 → "abcabcabc".
	// pos=3 → lenBits 12; token = (off-1)<<12 | (len-3)
	tok := uint16((3-1)<<12 | (6 - 3))
	data := []byte{0x08, 'a', 'b', 'c', byte(tok), byte(tok >> 8)}
	hdr := uint16(0xB000 | (len(data) - 1))
	src = append([]byte{byte(hdr), byte(hdr >> 8)}, data...)
	out, err = decompressLZNT1(src, 4096)
	if err != nil || string(out) != "abcabcabc" {
		t.Fatalf("compressed chunk: %q %v", out, err)
	}
	// Hostile: back-reference before start.
	bad := []byte{0x01, byte(tok), byte(tok >> 8)}
	hdr = uint16(0xB000 | (len(bad) - 1))
	if _, err := decompressLZNT1(append([]byte{byte(hdr), byte(hdr >> 8)}, bad...), 4096); err == nil {
		t.Fatal("back-reference at chunk start accepted")
	}
}

func TestDecodeRuns(t *testing.T) {
	// 0x21: 1 length byte, 2 offset bytes. Run 1: 0x10 clusters at 0x0100;
	// run 2: sparse 0x08 clusters (0x01 header); run 3: 4 clusters at -0x10 relative.
	b := []byte{0x21, 0x10, 0x00, 0x01, 0x01, 0x08, 0x11, 0x04, 0xF0, 0x00}
	runs, err := decodeRuns(b, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 3 || runs[0].lcn != 0x100 || runs[1].lcn != -1 || runs[2].lcn != 0xF0 || runs[2].vcn != 0x18 {
		t.Fatalf("runs = %+v", runs)
	}
	if _, err := decodeRuns([]byte{0x99, 1, 2}, 0); err == nil {
		t.Fatal("malformed header accepted")
	}
}

func TestEncryptedFileUnsupported(t *testing.T) {
	s := &stream{encrypted: true, size: 10}
	if _, err := s.ReadAt(make([]byte, 4), 0); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("want unsupported, got %v", err)
	}
}
