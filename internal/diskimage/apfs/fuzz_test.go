package apfs

import (
	"bytes"
	"io/fs"
	"testing"
)

// FuzzOpen feeds mutated containers (the synthetic one and the first
// blocks of the real fixture) through open, walk and read.
func FuzzOpen(f *testing.F) {
	f.Add(synthImage())
	b := loadImage(f, "apfs.img.gz")
	f.Add(b[:256<<10])
	f.Fuzz(func(t *testing.T, data []byte) {
		fsys, err := OpenFS(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return
		}
		n := 0
		fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
			n++
			if n > 2000 {
				return fs.SkipAll
			}
			if err == nil && !d.IsDir() {
				fs.ReadFile(fsys, p)
				fsys.ReadLink(p)
			}
			return nil
		})
	})
}

func FuzzDecmpfs(f *testing.F) {
	f.Add([]byte("fpmc\x03\x00\x00\x00\x05\x00\x00\x00\x00\x00\x00\x00\xffhello"), []byte{})
	f.Fuzz(func(t *testing.T, attr, fork []byte) {
		DecodeDecmpfs(attr, func() ([]byte, error) { return fork, nil })
	})
}
