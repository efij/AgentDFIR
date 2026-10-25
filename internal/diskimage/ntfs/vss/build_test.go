package vss

import (
	"encoding/binary"
	"time"
	"unicode/utf16"
)

// A hand-written VSS store builder, following the libvshadow format
// documentation field by field. It produces the synthetic fixture and
// the in-memory stores of the unit tests. It is NOT derived from a store
// Windows wrote; see testdata/README.md.

type synthBlock struct {
	orig   int64  // original (volume) offset of the 16 KiB block
	data   []byte // BlockSize bytes: the preserved block (overlay: sectors in place)
	flags  uint32
	bitmap uint32 // overlay sector bitmap
	rel    int64  // forwarder target
}

type synthSnap struct {
	id      byte // fills the 16-byte store / shadow copy identifiers
	created time.Time
	volSize int64
	blocks  []synthBlock
}

func putHeader(b []byte, recType uint32, cur, next int64) {
	copy(b[0:16], Identifier)
	le := binary.LittleEndian
	le.PutUint32(b[16:], 1)
	le.PutUint32(b[20:], recType)
	le.PutUint64(b[32:], uint64(cur))
	le.PutUint64(b[40:], uint64(next))
}

func fill16(id byte) []byte {
	b := make([]byte, 16)
	for i := range b {
		b[i] = id
	}
	return b
}

func ft(t time.Time) uint64 { return uint64(t.UnixNano()/100 + 116444736000000000) }

func utf16Str(s string) []byte {
	u := utf16.Encode([]rune(s))
	b := make([]byte, 2+2*len(u))
	binary.LittleEndian.PutUint16(b, uint16(2*len(u)))
	for i, c := range u {
		binary.LittleEndian.PutUint16(b[2+2*i:], c)
	}
	return b
}

// writeStore writes the volume header at 0x1e00 and the catalog, store
// headers, block lists, data blocks and bitmaps into blocks handed out
// by alloc (16 KiB-aligned offsets inside vol).
func writeStore(vol []byte, alloc func() int64, snaps []synthSnap) {
	le := binary.LittleEndian
	blk := func(off int64) []byte { return vol[off : off+BlockSize] }
	catalog := alloc()
	h := vol[HeaderOffset : HeaderOffset+512]
	clear(h)
	copy(h[0:16], Identifier)
	le.PutUint32(h[16:], 1)
	le.PutUint32(h[20:], recVolumeHeader)
	le.PutUint64(h[24:], HeaderOffset)
	le.PutUint64(h[48:], uint64(catalog))
	le.PutUint64(h[56:], 1<<20)
	cb := blk(catalog)
	clear(cb)
	putHeader(cb, recCatalog, catalog, 0)
	ent := blockHeaderSize
	for _, sn := range snaps {
		// Store header.
		hdr := alloc()
		hb := blk(hdr)
		clear(hb)
		putHeader(hb, recStoreHeader, hdr, 0)
		info := hb[blockHeaderSize:]
		copy(info[16:32], fill16(sn.id+0x10))
		copy(info[32:48], fill16(sn.id+0x20))
		n := 64 + copy(info[64:], utf16Str("WS-01.example.test"))
		n += copy(info[n:], utf16Str("WS-01.example.test"))
		le.PutUint64(hb[48:], uint64(n))
		// Block list (one block holds 511 descriptors; enough here).
		list := alloc()
		lb := blk(list)
		clear(lb)
		putHeader(lb, recBlockList, list, 0)
		for i, b := range sn.blocks {
			e := lb[blockHeaderSize+i*descriptorSize:]
			le.PutUint64(e[0:], uint64(b.orig))
			le.PutUint32(e[24:], b.flags)
			le.PutUint32(e[28:], b.bitmap)
			if b.flags&flagForwarder != 0 {
				le.PutUint64(e[8:], uint64(b.rel))
				continue
			}
			if b.data != nil {
				d := alloc()
				copy(blk(d), b.data)
				le.PutUint64(e[8:], uint64(d))
				le.PutUint64(e[16:], uint64(d))
			}
		}
		// Current bitmap: blocks 0..7 in use.
		bm := alloc()
		bb := blk(bm)
		clear(bb)
		putHeader(bb, recBitmap, bm, 0)
		bb[blockHeaderSize] = 0xFF
		// Catalog entries: type 2 then type 3.
		e2 := cb[ent : ent+catalogEntrySize]
		le.PutUint64(e2[0:], 2)
		le.PutUint64(e2[8:], uint64(sn.volSize))
		copy(e2[16:32], fill16(sn.id))
		le.PutUint64(e2[48:], ft(sn.created))
		ent += catalogEntrySize
		e3 := cb[ent : ent+catalogEntrySize]
		le.PutUint64(e3[0:], 3)
		le.PutUint64(e3[8:], uint64(list))
		copy(e3[16:32], fill16(sn.id))
		le.PutUint64(e3[32:], uint64(hdr))
		le.PutUint64(e3[48:], uint64(bm))
		ent += catalogEntrySize
	}
}
