package ntfs

import (
	"bytes"
	"encoding/binary"
	"io/fs"
	"strings"
	"testing"
	"unicode/utf16"
)

func TestValidName(t *testing.T) {
	for _, s := range []string{"", ".", "..", "a/b", `a\b`, "a:b", "x\x00", "x\x01y", "x\x7f"} {
		if validName(s) {
			t.Errorf("%q accepted", s)
		}
	}
	for _, s := range []string{"notes.txt", ".claude", "CON", "naïve ünïcode"} {
		if !validName(s) {
			t.Errorf("%q refused", s)
		}
	}
}

// renameRecord rewrites the name of every $FILE_NAME in record num to
// name (same length), directly in the volume bytes.
func renameRecord(t *testing.T, v *Volume, b []byte, num uint64, name string) {
	t.Helper()
	rs, cs := v.v.recordSize, v.v.clusterSize
	r, _ := v.v.mft.lookup(int64(num) * rs / cs)
	base := r.lcn*cs + (int64(num)*rs - r.vcn*cs)
	rec := b[base : base+rs]
	off := int(binary.LittleEndian.Uint16(rec[20:22]))
	u := utf16.Encode([]rune(name))
	for off+16 < len(rec) {
		typ := binary.LittleEndian.Uint32(rec[off:])
		if typ == atEnd {
			break
		}
		ln := int(binary.LittleEndian.Uint32(rec[off+4:]))
		if typ == atFileName && rec[off+8] == 0 {
			voff := off + int(binary.LittleEndian.Uint16(rec[off+20:]))
			if int(rec[voff+64]) == len(u) {
				for i, c := range u {
					binary.LittleEndian.PutUint16(rec[voff+66+2*i:], c)
				}
			}
		}
		off += ln
	}
}

func TestHostileNamesRefusedAndRecorded(t *testing.T) {
	b := volumeBytes(t)
	v, err := OpenVolume(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	renameRecord(t, v, b, recOf(t, v, "Users/alice/notes.txt"), `n\.\s:txt`)
	v2, err := OpenVolume(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	fs.WalkDir(v2, ".", func(p string, d fs.DirEntry, err error) error {
		if strings.ContainsAny(d.Name(), `\:`) {
			t.Errorf("hostile name exposed: %q", p)
		}
		return nil
	})
	if !strings.Contains(strings.Join(v2.Stats().Problems, " "), `n\\.\\s:txt`) {
		t.Fatalf("rejected name not recorded escaped: %v", v2.Stats().Problems)
	}
}
