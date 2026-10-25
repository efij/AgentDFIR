// Package fixture loads gzipped filesystem fixtures into memory keeping
// only the non-zero 4 KiB blocks. mkfs.xfs will not make a filesystem
// smaller than 300 MB, but such an image is almost all zeros; held this
// way it costs a few MB. Used by tests only.
package fixture

import (
	"compress/gzip"
	"io"
	"os"
)

const blk = 4096

// Image is a sparse in-memory image. It implements io.ReaderAt.
type Image struct {
	blocks map[int64][]byte
	size   int64
}

// Load gunzips path.
func Load(path string) (*Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return nil, err
	}
	im := &Image{blocks: map[int64][]byte{}}
	buf := make([]byte, blk)
	for {
		n, err := io.ReadFull(zr, buf)
		if n > 0 {
			if !zero(buf[:n]) {
				b := make([]byte, blk)
				copy(b, buf[:n])
				im.blocks[im.size/blk] = b
			}
			im.size += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return im, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// Size is the image length in bytes.
func (im *Image) Size() int64 { return im.size }

// ReadAt reads like a file of Size bytes.
func (im *Image) ReadAt(p []byte, off int64) (int, error) {
	if off >= im.size {
		return 0, io.EOF
	}
	n := 0
	for n < len(p) && off < im.size {
		b, in := off/blk, off%blk
		c := int(min(int64(len(p)-n), blk-in, im.size-off))
		if d, ok := im.blocks[b]; ok {
			copy(p[n:n+c], d[in:])
		} else {
			clear(p[n : n+c])
		}
		n += c
		off += int64(c)
	}
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

// Patch overwrites bytes in place (tests build damaged variants with it).
func (im *Image) Patch(off int64, data []byte) {
	for len(data) > 0 {
		b, in := off/blk, off%blk
		d, ok := im.blocks[b]
		if !ok {
			d = make([]byte, blk)
			im.blocks[b] = d
		}
		c := copy(d[in:], data)
		data = data[c:]
		off += int64(c)
	}
}

// Truncate shortens the image.
func (im *Image) Truncate(size int64) { im.size = min(size, im.size) }

// Clone returns an independent copy.
func (im *Image) Clone() *Image {
	c := &Image{blocks: make(map[int64][]byte, len(im.blocks)), size: im.size}
	for k, v := range im.blocks {
		c.blocks[k] = append([]byte(nil), v...)
	}
	return c
}

// Bytes returns the first n bytes (fuzz seeds).
func (im *Image) Bytes(n int64) []byte {
	n = min(n, im.size)
	b := make([]byte, n)
	im.ReadAt(b, 0)
	return b
}

func zero(b []byte) bool {
	for _, c := range b {
		if c != 0 {
			return false
		}
	}
	return true
}
