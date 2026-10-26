package ntfs

import (
	"bytes"
	"io/fs"
	"testing"
)

func FuzzParseRecord(f *testing.F) {
	b := volumeBytes(f)
	v, err := OpenVolume(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		f.Fatal(err)
	}
	// Seeds: a few real records (root, a file with an attribute list).
	for _, n := range []uint64{0, 5, 40, 78} {
		raw := make([]byte, v.v.recordSize)
		if _, err := v.v.mft.ReadAt(raw, int64(n)*v.v.recordSize); err == nil {
			f.Add(raw)
		}
	}
	f.Add([]byte("FILE"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		rec, err := ParseRecord(raw, 1)
		if err != nil || rec == nil {
			return
		}
		nd := &node{}
		nd.fill(rec.attrs)
		nd.linkNames()
		for _, a := range rec.attrs {
			if a.typ == atFileName && a.resident {
				parseFileName(a.value)
			}
		}
	})
}

func FuzzVolume(f *testing.F) {
	b := volumeBytes(f)
	// Seed with the boot sector + first MFT records region, truncated.
	f.Add(b[:64<<10])
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := OpenVolume(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		fs.WalkDir(v, ".", func(p string, d fs.DirEntry, err error) error {
			if err == nil && !d.IsDir() {
				fs.ReadFile(v, p)
			}
			return nil
		})
	})
}

func FuzzParseUSNRecord(f *testing.F) {
	f.Add(buildUSNv2(usnSpec{file: mkref(64, 1), parent: mkref(5, 5), usn: 8, reason: 0x100, name: "a.txt"}))
	f.Add(buildUSNv3(usnSpec{file: mkref(64, 1), parent: mkref(5, 5), usn: 8, reason: 0x100, name: "b.txt"}))
	f.Add(buildUSNv4(usnSpec{file: mkref(64, 1), parent: mkref(5, 5), usn: 8, reason: 0x1, extents: 2}))
	f.Fuzz(func(t *testing.T, b []byte) {
		r, err := ParseUSNRecord(b)
		if err == nil && r.Status == "" && len(r.FileName) > len(b) {
			t.Fatal("name longer than the record")
		}
	})
}

// FuzzUSNScan feeds raw bytes to the $J scanner (resync, carry, padding).
func FuzzUSNScan(f *testing.F) {
	var seed []byte
	seed = append(seed, buildUSNv2(usnSpec{file: mkref(64, 1), parent: mkref(5, 5), usn: 8, name: "a"})...)
	seed = append(seed, 0xAB, 0xAB, 0xAB, 0xAB, 0, 0, 0, 0)
	seed = append(seed, buildUSNv3(usnSpec{file: mkref(64, 1), parent: mkref(5, 5), usn: 16, name: "b"})...)
	f.Add(seed)
	f.Fuzz(func(t *testing.T, j []byte) {
		fsys := &Volume{nodes: map[uint64]*node{}}
		st := USNStats{}
		sc := &usnScanner{fsys: fsys, st: &st, fn: func(USNRecord) error { return nil }, paths: map[uint64]pathResult{}}
		s := &stream{resident: j, size: int64(len(j)), initSize: int64(len(j)), cuIdx: -1}
		if err := sc.scanExtent(s, 0, int64(len(j))); err != nil {
			t.Fatal(err)
		}
		if st.BytesScanned != int64(len(j)) {
			t.Fatalf("scanned %d of %d", st.BytesScanned, len(j))
		}
	})
}

// FuzzVolumeArtifacts mutates a volume that carries a journal and
// deleted records, then runs the USN and deleted-record readers.
func FuzzVolumeArtifacts(f *testing.F) {
	b := usnFixtureBytes(f)
	f.Add(b[:1<<20])
	f.Fuzz(func(t *testing.T, data []byte) {
		v, err := OpenVolume(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		v.USN()
		ds, _ := v.DeletedFiles()
		for _, d := range ds {
			if r, n, err := v.OpenDeleted(d.Record); err == nil && n < 1<<20 {
				r.ReadAt(make([]byte, n), 0)
			}
		}
	})
}
