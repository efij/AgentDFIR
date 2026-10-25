package diskimage

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func FuzzEWFTable(f *testing.F) {
	ent := make([]byte, 16)
	binary.LittleEndian.PutUint32(ent[0:], 0x4c)
	binary.LittleEndian.PutUint32(ent[4:], 0x8000_1000)
	binary.LittleEndian.PutUint32(ent[8:], 0x2000)
	binary.LittleEndian.PutUint32(ent[12:], 0xffffffff)
	f.Add(ent, int64(0), int64(1<<20))
	f.Add([]byte{1, 2, 3}, int64(-5), int64(10))
	f.Fuzz(func(t *testing.T, raw []byte, base, sectorsEnd int64) {
		ents := ParseEWFTable(raw, base)
		if len(ents) != len(raw)/4 {
			t.Fatalf("%d entries from %d bytes", len(ents), len(raw))
		}
		c := &ewfSegCtx{e: &ewfImage{}, size: 1 << 20, sectorsEnd: sectorsEnd}
		if err := c.addEntries(ents, 1<<20-76); err == nil {
			for _, ch := range c.e.chunks {
				if ch.off < ewfHeaderSize || ch.size <= 0 || ch.off >= c.size {
					t.Fatalf("accepted out-of-bounds chunk %+v", ch)
				}
			}
		}
	})
}

// FuzzOpenEWF feeds mutated E01 segment files through the whole open +
// read path: typed errors only, never a panic or an unbounded allocation.
func FuzzOpenEWF(f *testing.F) {
	dir := f.TempDir()
	b, err := os.ReadFile(fixture(f, dir, "disk-split.E01"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(b)
	f.Add(b[:200])
	f.Fuzz(func(t *testing.T, data []byte) {
		if !bytes.HasPrefix(data, []byte("EVF")) {
			return
		}
		p := filepath.Join(t.TempDir(), "x.E01")
		os.WriteFile(p, data, 0o600)
		im, err := Open(p)
		if err != nil {
			return
		}
		buf := make([]byte, 64<<10)
		for off := int64(0); off < im.Size() && off < 4<<20; off += int64(len(buf)) {
			im.ReadAt(buf, off)
		}
		im.Close()
	})
}
