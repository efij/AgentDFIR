package ntfs

import (
	"bytes"
	"encoding/binary"
	"io/fs"
	"testing"
)

// setParent rewrites the parent reference of every $FILE_NAME in MFT
// record num, directly in the volume bytes b.
func setParent(t *testing.T, v *Volume, b []byte, num, parent uint64) {
	t.Helper()
	rs := v.v.recordSize
	cs := v.v.clusterSize
	r, ok := v.v.mft.lookup(int64(num) * rs / cs)
	if !ok || r.lcn < 0 {
		t.Fatalf("record %d not mapped", num)
	}
	base := r.lcn*cs + (int64(num)*rs - r.vcn*cs)
	rec := b[base : base+rs]
	off := int(binary.LittleEndian.Uint16(rec[20:22]))
	patched := 0
	for off+16 < len(rec) {
		typ := binary.LittleEndian.Uint32(rec[off:])
		if typ == atEnd {
			break
		}
		ln := int(binary.LittleEndian.Uint32(rec[off+4:]))
		if typ == atFileName && rec[off+8] == 0 {
			voff := off + int(binary.LittleEndian.Uint16(rec[off+20:]))
			for i := voff; i < voff+8; i++ {
				if i%512 >= 510 {
					t.Fatalf("parent reference overlaps a fixup slot")
				}
			}
			// Keep the sequence number at zero so it is not checked.
			binary.LittleEndian.PutUint64(rec[voff:], parent)
			patched++
		}
		off += ln
	}
	if patched == 0 {
		t.Fatalf("record %d has no resident $FILE_NAME", num)
	}
}

func recOf(t *testing.T, v *Volume, p string) uint64 {
	t.Helper()
	nd, _, err := v.resolve("stat", p)
	if err != nil {
		t.Fatal(err)
	}
	return nd.rec
}

func TestParentLoopAndSelfParent(t *testing.T) {
	b := volumeBytes(t)
	v, err := OpenVolume(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	docs := recOf(t, v, "Users/alice/Documents")
	comp := recOf(t, v, "Users/alice/compressed")
	links := recOf(t, v, "Users/alice/links")
	setParent(t, v, b, docs, comp)
	setParent(t, v, b, comp, docs)
	setParent(t, v, b, links, links)

	v2, err := OpenVolume(bytes.NewReader(b), int64(len(b)))
	if err != nil {
		t.Fatal(err)
	}
	st := v2.Stats()
	if st.ParentLoops != 2 {
		t.Fatalf("parent loops = %d, want 2 (%v)", st.ParentLoops, st.Problems)
	}
	if st.SelfParent != 1 {
		t.Fatalf("self-parent = %d, want 1", st.SelfParent)
	}
	// The walk from the root terminates and never reaches the looped dirs.
	n := 0
	fs.WalkDir(v2, ".", func(p string, d fs.DirEntry, err error) error {
		n++
		if n > 10000 {
			t.Fatal("walk does not terminate")
		}
		return nil
	})
	if _, err := fs.Stat(v2, "Users/alice/Documents"); err == nil {
		t.Fatal("looped directory still linked under its old parent")
	}
}
