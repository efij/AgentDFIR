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
