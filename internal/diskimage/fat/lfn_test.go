package fat

import (
	"bytes"
	"testing"
)

// lfnDir builds a raw directory: a complete one-fragment LFN run, then a
// stray fragment whose sequence number is 0, then the short entry.
func lfnDir(strayOrd byte) []byte {
	short := []byte("LONGNA~1TXT")
	sum := lfnChecksum(short)
	lfn := func(ord byte) []byte {
		e := make([]byte, 32)
		e[0], e[11], e[13] = ord, 0x0F, sum
		for j, c := range "longname.txt" {
			switch {
			case j < 5:
				le.PutUint16(e[1+2*j:], uint16(c))
			case j < 11:
				le.PutUint16(e[14+2*(j-5):], uint16(c))
			default:
				le.PutUint16(e[28+2*(j-11):], uint16(c))
			}
		}
		return e
	}
	s := make([]byte, 32)
	copy(s, short)
	s[11] = 0x20
	var b []byte
	b = append(b, lfn(0x41)...)
	b = append(b, lfn(strayOrd)...)
	b = append(b, s...)
	return append(b, make([]byte, 32)...)
}

func TestLFNSequenceZeroNoPanic(t *testing.T) {
	f := openImage(t, "fat12.img.gz")
	for _, ord := range []byte{0x20, 0x40, 0x60, 0x1F, 0x5F} {
		st := map[string]int64{}
		ents := f.parseFAT(lfnDir(ord), func(int) uint64 { return 1 }, st)
		if len(ents) != 1 {
			t.Fatalf("ord %#x: %d entries", ord, len(ents))
		}
		// The stray fragment breaks the run, so the 8.3 name is used.
		if ents[0].name != "LONGNA~1.TXT" {
			t.Errorf("ord %#x: name %q", ord, ents[0].name)
		}
	}
	// A clean run still decodes the long name.
	b := lfnDir(0)
	b = append(b[:32], b[64:]...)
	if ents := f.parseFAT(b, func(int) uint64 { return 1 }, map[string]int64{}); len(ents) != 1 || ents[0].name != "longname.txt" {
		t.Errorf("clean run: %v", ents)
	}
}

// TestCraftedLFNInImage plants the crafted run in the FAT12 root and walks.
func TestCraftedLFNInImage(t *testing.T) {
	b := loadImage(t, "fat12.img.gz")
	f := openImage(t, "fat12.img.gz")
	copy(b[f.g.rootOff:], lfnDir(0x20)[:96])
	fsys, err := Open(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	walk(fsys)
}

func craftedLFNSeeds() [][]byte {
	return [][]byte{lfnDir(0x20)[:96], lfnDir(0x40)[:96], lfnDir(0x7F)[:96]}
}
