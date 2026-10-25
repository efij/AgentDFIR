package apfs

import (
	"encoding/binary"
	"sort"
)

// A hand-made APFS container, built here because hdiutil cannot create a
// snapshot without root (tmutil only snapshots the boot volume). It is
// synthetic: the structures follow the Apple File System Reference and
// the layout hdiutil produces, with one volume "Synth" and one snapshot
// "snap-one" taken at xid 1, then the live tree changed at xid 2.
//
// Blocks: 0 NXSB · 1 checkpoint NXSB · 2/3 container omap · 4 APSB ·
// 5/6 volume omap · 7 fs tree @xid1 · 8 fs tree @xid2 · 9 snapshot
// metadata tree · 10 APSB saved with the snapshot · 11/12 file data.

const synBS = 4096

type kv struct{ k, v []byte }

func objHeader(b []byte, oid, xid uint64, typ, subtype uint32) {
	le.PutUint64(b[8:], oid)
	le.PutUint64(b[16:], xid)
	le.PutUint32(b[24:], typ)
	le.PutUint32(b[28:], subtype)
}

func seal(b []byte) { le.PutUint64(b, fletcher64(b[8:])) }

// leafNode builds a root+leaf B-tree node holding ents (sorted by caller).
func leafNode(oid, xid uint64, typ, subtype uint32, fixed bool, ents []kv) []byte {
	b := make([]byte, synBS)
	objHeader(b, oid, xid, typ, subtype)
	flags := uint16(btnRoot | btnLeaf)
	ent := 8
	if fixed {
		flags |= btnFixedKV
		ent = 4
	}
	le.PutUint16(b[32:], flags)
	le.PutUint32(b[36:], uint32(len(ents)))
	tocLen := len(ents) * ent
	le.PutUint16(b[40:], 0)
	le.PutUint16(b[42:], uint16(tocLen))
	keys := 56 + tocLen
	valEnd := synBS - 40
	ko, vo := 0, 0
	for i, e := range ents {
		copy(b[keys+ko:], e.k)
		vo += len(e.v)
		copy(b[valEnd-vo:], e.v)
		t := b[56+i*ent:]
		if fixed {
			le.PutUint16(t, uint16(ko))
			le.PutUint16(t[2:], uint16(vo))
		} else {
			le.PutUint16(t, uint16(ko))
			le.PutUint16(t[2:], uint16(len(e.k)))
			le.PutUint16(t[4:], uint16(vo))
			le.PutUint16(t[6:], uint16(len(e.v)))
		}
		ko += len(e.k)
	}
	info := b[valEnd:]
	le.PutUint32(info[4:], synBS)
	if fixed {
		le.PutUint32(info[8:], 16)
		le.PutUint32(info[12:], 16)
	}
	le.PutUint64(info[24:], uint64(len(ents)))
	le.PutUint64(info[32:], 1)
	seal(b)
	return b
}

func jkey(id uint64, typ uint64, rest ...byte) []byte {
	k := make([]byte, 8, 8+len(rest))
	le.PutUint64(k, id&objIDMask|typ<<60)
	return append(k, rest...)
}

func omapEnt(oid, xid, paddr uint64) kv {
	k := make([]byte, 16)
	le.PutUint64(k, oid)
	le.PutUint64(k[8:], xid)
	v := make([]byte, 16)
	le.PutUint32(v[4:], synBS)
	le.PutUint64(v[8:], paddr)
	return kv{k, v}
}

func inodeVal(parent, private uint64, mode uint16, size uint64, ts uint64) []byte {
	v := make([]byte, 92)
	le.PutUint64(v, parent)
	le.PutUint64(v[8:], private)
	for _, o := range []int{16, 24, 32, 40} {
		le.PutUint64(v[o:], ts)
	}
	le.PutUint32(v[56:], 1)
	le.PutUint16(v[80:], mode)
	if mode&0xF000 == 0x8000 {
		x := make([]byte, 4+4+40)
		le.PutUint16(x, 1)
		le.PutUint16(x[2:], 40)
		x[4] = xfDstream
		le.PutUint16(x[6:], 40)
		le.PutUint64(x[8:], size)
		le.PutUint64(x[16:], synBS)
		v = append(v, x...)
	}
	return v
}

func drec(parent uint64, name string, id uint64, dtype uint16) kv {
	n := append([]byte(name), 0)
	k := jkey(parent, recDirRec)
	k = binary.LittleEndian.AppendUint32(k, uint32(len(n))|0xabcd<<10)
	k = append(k, n...)
	v := make([]byte, 18)
	le.PutUint64(v, id)
	le.PutUint16(v[16:], dtype)
	return kv{k, v}
}

func extent(private, logical, length, phys uint64) kv {
	k := jkey(private, recFileExtnt)
	k = binary.LittleEndian.AppendUint64(k, logical)
	v := make([]byte, 24)
	le.PutUint64(v, length)
	le.PutUint64(v[8:], phys)
	return kv{k, v}
}

func sortFS(ents []kv) {
	sort.SliceStable(ents, func(i, j int) bool {
		a, b := ents[i].k, ents[j].k
		ai, bi := le.Uint64(a)&objIDMask, le.Uint64(b)&objIDMask
		if ai != bi {
			return ai < bi
		}
		return le.Uint64(a)>>60 < le.Uint64(b)>>60
	})
}

func apsbBlock(oid, xid uint64, name string) []byte {
	b := make([]byte, synBS)
	objHeader(b, oid, xid, typeFS, 0)
	copy(b[32:], "APSB")
	le.PutUint64(b[56:], incompatCaseInsensitive)
	le.PutUint64(b[128:], 5)    // volume omap (physical)
	le.PutUint64(b[136:], 1028) // fs tree root (virtual)
	le.PutUint64(b[152:], 9)    // snapshot metadata tree (physical)
	le.PutUint64(b[184:], 1)
	le.PutUint64(b[264:], fsUnencrypted)
	copy(b[704:], name)
	seal(b)
	return b
}

// synthImage returns the synthetic container.
func synthImage() []byte {
	const nblocks = 16
	img := make([]byte, nblocks*synBS)
	put := func(blk int, b []byte) { copy(img[blk*synBS:], b) }

	nx := func(xid uint64) []byte {
		b := make([]byte, synBS)
		objHeader(b, 1, xid, objEphemeral|typeNXSB, 0)
		copy(b[32:], "NXSB")
		le.PutUint32(b[36:], synBS)
		le.PutUint64(b[40:], nblocks)
		le.PutUint64(b[64:], nxIncompatVersion2)
		le.PutUint32(b[104:], 1) // descriptor blocks
		le.PutUint64(b[112:], 1) // descriptor base
		le.PutUint64(b[160:], 2) // container omap
		le.PutUint32(b[180:], 1)
		le.PutUint64(b[184:], 1026)
		seal(b)
		return b
	}
	put(0, nx(2))
	put(1, nx(2))
	omapObj := func(oid, root uint64) []byte {
		b := make([]byte, synBS)
		objHeader(b, oid, 2, objPhysical|typeOmap, 0)
		le.PutUint64(b[48:], root)
		seal(b)
		return b
	}
	put(2, omapObj(2, 3))
	put(3, leafNode(3, 2, objPhysical|typeBtree, typeOmap, true, []kv{omapEnt(1026, 2, 4)}))
	put(4, apsbBlock(1026, 2, "Synth"))
	put(5, omapObj(5, 6))
	put(6, leafNode(6, 2, objPhysical|typeBtree, typeOmap, true, []kv{omapEnt(1028, 1, 7), omapEnt(1028, 2, 8)}))

	const t1, t2 = 1_700_000_000_000_000_000, 1_700_000_100_000_000_000
	a := []kv{
		{jkey(rootIno, recInode), inodeVal(1, rootIno, 0o40755, 0, t1)},
		drec(rootIno, "old.txt", 16, 8),
		{jkey(16, recInode), inodeVal(rootIno, 16, 0o100644, 11, t1)},
		extent(16, 0, synBS, 11),
	}
	sortFS(a)
	put(7, leafNode(1028, 1, typeBtree, 0x0e, false, a))

	// xid 2: old.txt gone, new.txt added, a real ".SNAPSHOTS" directory
	// (the virtual one must step aside), and an xattr stream that claims
	// 32 KiB but has no extents.
	sx := make([]byte, 4+16+40)
	le.PutUint16(sx, xattrStream)
	le.PutUint16(sx[2:], 56)
	le.PutUint64(sx[4:], 18)
	le.PutUint64(sx[12:], 1<<15)
	xk := jkey(17, recXattr)
	xk = binary.LittleEndian.AppendUint16(xk, 19)
	xk = append(xk, "com.example.sparse\x00"...)
	b := []kv{
		{jkey(rootIno, recInode), inodeVal(1, rootIno, 0o40755, 0, t2)},
		drec(rootIno, "new.txt", 17, 8),
		drec(rootIno, ".SNAPSHOTS", 19, 4),
		{jkey(17, recInode), inodeVal(rootIno, 17, 0o100644, 11, t2)},
		{xk, sx},
		extent(17, 0, synBS, 12),
		{jkey(19, recInode), inodeVal(rootIno, 19, 0o40755, 0, t2)},
	}
	sortFS(b)
	put(8, leafNode(1028, 2, typeBtree, 0x0e, false, b))

	sv := make([]byte, 50)
	le.PutUint64(sv[8:], 10) // saved superblock
	le.PutUint64(sv[16:], t1)
	le.PutUint16(sv[48:], 9)
	sv = append(sv, "snap-one\x00"...)
	put(9, leafNode(9, 2, objPhysical|typeBtree, 0x10, false, []kv{{jkey(1, recSnapMeta), sv}}))
	put(10, apsbBlock(1026, 1, "Synth"))
	copy(img[11*synBS:], "old content")
	copy(img[12*synBS:], "new content")
	return img
}
