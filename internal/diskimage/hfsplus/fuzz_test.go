package hfsplus

import (
	"bytes"
	"io/fs"
	"testing"
)

func FuzzOpen(f *testing.F) {
	f.Add(loadImage(f, "hfsx.img.gz"))
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
