package ntfs

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGenerateUSNFixture writes testdata/usn-deleted.ntfs.gz from a raw
// volume made by testdata/gen-usn-deleted.sh (ntfs-3g). It is skipped
// unless ADFIR_GEN_USN names that raw volume. ntfs-3g does not write a
// USN journal, so the script creates $Extend\$UsnJrnl with a $J stream of
// a sparse 64 KiB hole plus 8 KiB of 0xFF placeholder; this step
// overwrites the placeholder clusters, in place, with documented V2/V3/V4
// records that reference the volume's real MFT records.
func TestGenerateUSNFixture(t *testing.T) {
	src := os.Getenv("ADFIR_GEN_USN")
	if src == "" {
		t.Skip("set ADFIR_GEN_USN=<raw volume from gen-usn-deleted.sh> to regenerate")
	}
	img, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	v, err := OpenVolume(bytes.NewReader(img), int64(len(img)))
	if err != nil {
		t.Fatal(err)
	}
	s, err := v.usnStream()
	if err != nil || s == nil {
		t.Fatalf("no $J placeholder: %v", err)
	}
	ex := s.extents()
	if len(ex) != 1 || ex[0][0] != 65536 || ex[0][1] != 65536+8192 {
		t.Fatalf("placeholder extents %v (want one 8 KiB extent after a 64 KiB hole)", ex)
	}
	ref := func(p string) uint64 {
		nd, _, err := v.resolve("stat", p)
		if err != nil {
			t.Fatal(err)
		}
		return mkref(nd.rec, nd.seq)
	}
	delRef := func(name string) uint64 {
		for _, n := range v.deleted {
			d, _ := v.deletedEntry(n)
			if d.Name == name {
				return mkref(d.Record, d.Seq)
			}
		}
		t.Fatalf("deleted %s not found", name)
		return 0
	}
	proj := ref("Users/alice/proj")
	ts := time.Date(2026, 8, 30, 10, 1, 0, 0, time.UTC)
	var page1, page2 []byte
	add := func(p *[]byte, b []byte) { *p = append(*p, b...) }
	add(&page1, buildUSNv2(usnSpec{file: ref("Users/alice/proj/keep.txt"), parent: proj, usn: 65536, ts: ts, reason: 0x100, attrs: 0x20, name: "keep.txt"}))
	add(&page1, buildUSNv2(usnSpec{file: ref("Users/alice/proj/keep.txt"), parent: proj, usn: 65640, ts: ts.Add(time.Second), reason: 0x80000102, attrs: 0x20, name: "keep.txt"}))
	add(&page1, buildUSNv3(usnSpec{file: ref("Users/alice/proj/newcomer.txt"), parent: proj, usn: 65744, ts: ts.Add(2 * time.Second), reason: 0x100, source: 0x2, attrs: 0x20, name: "newcomer.txt"}))
	add(&page1, buildUSNv2(usnSpec{file: delRef("deleted-big.txt"), parent: proj, usn: 65864, ts: ts.Add(3 * time.Second), reason: 0x80000200, attrs: 0x20, name: "deleted-big.txt"}))
	// Parent reference with a stale sequence number: the path must not be
	// resolved to the directory that now holds the record.
	add(&page1, buildUSNv2(usnSpec{file: ref("Users/alice/proj/keep.txt"), parent: proj + 7<<48, usn: 65976, ts: ts.Add(4 * time.Second), reason: 0x2000, attrs: 0x20, name: "renamed.txt"}))
	add(&page1, buildUSNv4(usnSpec{file: ref("Users/alice/proj/kept-big.bin"), parent: proj, usn: 66088, reason: 0x1, extents: 1}))
	add(&page1, bytes.Repeat([]byte{0xAB}, 24)) // garbage: the scanner must resync
	add(&page1, buildUSNv2(usnSpec{file: ref("Users"), parent: mkref(rootRecord, 5), usn: 66208, ts: ts.Add(5 * time.Second), reason: 0x8000, attrs: 0x10, name: "Users"}))
	add(&page1, buildUSNv2(usnSpec{file: mkref(500, 1), parent: mkref(3000, 1), usn: 66304, ts: ts.Add(6 * time.Second), reason: 0x100, name: "orphan.txt"}))
	add(&page2, buildUSNv3(usnSpec{file: ref("Users/alice/proj/kept-big.bin"), parent: proj, usn: 69632, ts: ts.Add(7 * time.Second), reason: 0x80000002, attrs: 0x20, name: "kept-big.bin"}))
	if len(page1) > 4096 || len(page2) > 4096 {
		t.Fatal("page overflow")
	}
	j := make([]byte, 8192)
	copy(j, page1)
	copy(j[4096:], page2)
	cs := v.v.clusterSize
	for off := int64(0); off < int64(len(j)); off += cs {
		r, ok := s.lookup((65536 + off) / cs)
		if !ok || r.lcn < 0 {
			t.Fatal("placeholder not mapped")
		}
		phys := (r.lcn + (65536+off)/cs - r.vcn) * cs // placeholder is cluster-aligned
		if !bytes.Equal(img[phys:phys+cs], bytes.Repeat([]byte{0xFF}, int(cs))) {
			t.Fatalf("cluster at %d is not the 0xFF placeholder", phys)
		}
		copy(img[phys:phys+cs], j[off:off+cs])
	}
	var gz bytes.Buffer
	zw, _ := gzip.NewWriterLevel(&gz, gzip.BestCompression)
	zw.Write(img)
	zw.Close()
	if err := os.WriteFile(filepath.Join("testdata", "usn-deleted.ntfs.gz"), gz.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d bytes", gz.Len())
}
