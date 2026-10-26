// Package vss reads Volume Shadow Copy stores read-only, following the
// on-disk layout documented by the libvshadow project ("Volume Shadow
// Snapshot (VSS) format").
//
// Layout read here:
//
//	volume header   at volume offset 0x1e00: VSS identifier, version 1,
//	                record type 1, catalog offset
//	catalog         linked 16 KiB blocks (record type 2) of 128-byte
//	                entries: type 2 (store information: volume size, store
//	                identifier, creation time) and type 3 (store locations:
//	                block list, store header, block range list, current and
//	                previous bitmap)
//	store header    16 KiB block (record type 3): shadow copy and set ids
//	block list      linked 16 KiB blocks (record type 4) of 32-byte
//	                descriptors: original offset, relative store offset,
//	                store data offset, flags, allocation bitmap
//	bitmaps         linked 16 KiB blocks (record type 6); parsed and
//	                counted only
//
// Each snapshot is exposed as an io.ReaderAt over the volume as it was:
// a 16 KiB block described in the snapshot's store comes from the store
// data block, a block absent from it falls through to the next newer
// store and finally to the current volume. Overlay descriptors (flag 2)
// replace only the 512-byte sectors their bitmap names; forwarder
// descriptors (flag 1) redirect to another original block in the newer
// layers; "not used" descriptors (flag 4) are ignored.
//
// Anything outside that understanding (other versions, unknown record
// or descriptor flags, offsets outside the volume) makes the snapshot,
// or the whole store, UNSUPPORTED with a reason: no content is ever
// synthesized for a snapshot this package does not understand.
package vss

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sort"
	"time"
	"unicode/utf16"
)

// ErrUnsupported marks a store or snapshot this reader does not decode.
var ErrUnsupported = errors.New("vss: unsupported")

const (
	HeaderOffset = 0x1e00
	BlockSize    = 0x4000

	recVolumeHeader = 1
	recCatalog      = 2
	recStoreHeader  = 3
	recBlockList    = 4
	recRangeList    = 5
	recBitmap       = 6

	catalogEntrySize = 128
	descriptorSize   = 32
	blockHeaderSize  = 128

	flagForwarder = 0x1
	flagOverlay   = 0x2
	flagNotUsed   = 0x4

	maxCatalogBlocks  = 256
	maxStores         = 512
	maxListBlocks     = 1 << 16
	maxDescriptors    = 1 << 21
	maxTotalDescs     = 1 << 22
	maxBitmapBlocks   = 1 << 14
	maxForwardDepth   = 16
	maxProblems       = 50
	maxStoreInfoBytes = BlockSize - blockHeaderSize
)

// Identifier is the VSS GUID {3808876b-c176-4e48-b7ae-04046e6cc752} in
// on-disk (mixed-endian) byte order.
var Identifier = []byte{0x6b, 0x87, 0x08, 0x38, 0x76, 0xc1, 0x48, 0x4e, 0xb7, 0xae, 0x04, 0x04, 0x6e, 0x6c, 0xc7, 0x52}

// Status values.
const (
	StatusOK          = "ok"
	StatusUnsupported = "UNSUPPORTED"
)

// Snapshot is one shadow copy found in the catalog.
type Snapshot struct {
	Index        int       `json:"index"` // 1 = oldest
	StoreID      string    `json:"store_id"`
	ShadowCopyID string    `json:"shadow_copy_id,omitempty"`
	ShadowSetID  string    `json:"shadow_copy_set_id,omitempty"`
	Created      time.Time `json:"created,omitzero"`
	VolumeSize   int64     `json:"volume_size"`
	Machine      string    `json:"operating_machine,omitempty"`
	Service      string    `json:"service_machine,omitempty"`
	Blocks       int       `json:"store_blocks"` // block descriptors in use
	Overlays     int       `json:"overlay_blocks,omitempty"`
	Forwarders   int       `json:"forwarder_blocks,omitempty"`
	BitmapBlocks int64     `json:"bitmap_blocks_set,omitempty"` // set bits in the current bitmap
	Status       string    `json:"status"`
	Reason       string    `json:"reason,omitempty"`

	blockList, storeHeader, current, previous int64
	descs                                     map[int64]descriptor
}

type descriptor struct {
	orig, rel, data int64
	flags           uint32
	bitmap          uint32
	parts           []overlayPart // overlay descriptors for this block, in list order
}

// overlayPart is one overlay descriptor: the sectors its bitmap names
// are stored at data.
type overlayPart struct {
	data   int64
	bitmap uint32
}

// Store is the parsed shadow copy area of one volume.
type Store struct {
	r         io.ReaderAt
	size      int64
	Version   uint32      `json:"version"`
	Catalog   int64       `json:"catalog_offset"`
	MaxSize   int64       `json:"max_size"`
	Snapshots []*Snapshot `json:"snapshots"`
	Problems  []string    `json:"problems,omitempty"`

	totalDescs int // across all stores, bounded by maxTotalDescs
}

func (s *Store) problem(format string, args ...any) {
	if len(s.Problems) < maxProblems {
		s.Problems = append(s.Problems, fmt.Sprintf(format, args...))
	}
}

// Probe reports whether the volume carries a VSS volume header.
func Probe(r io.ReaderAt, size int64) bool {
	if size < HeaderOffset+512 {
		return false
	}
	b := make([]byte, 16)
	if _, err := r.ReadAt(b, HeaderOffset); err != nil {
		return false
	}
	return bytes.Equal(b, Identifier)
}

// ErrNoStore is returned by Open for a volume without a VSS header.
var ErrNoStore = errors.New("vss: no volume shadow copy header")

// Open parses the VSS header, catalog and every store's block list. A
// volume with a header but no catalog has zero snapshots. Per-snapshot
// failures leave that snapshot UNSUPPORTED; an error is returned only
// when the header itself cannot be used.
func Open(r io.ReaderAt, size int64) (st *Store, err error) {
	defer func() {
		if p := recover(); p != nil {
			st, err = nil, fmt.Errorf("vss: %v", p)
		}
	}()
	if !Probe(r, size) {
		return nil, ErrNoStore
	}
	h := make([]byte, 512)
	if _, err := r.ReadAt(h, HeaderOffset); err != nil {
		return nil, fmt.Errorf("vss: read volume header: %w", err)
	}
	le := binary.LittleEndian
	st = &Store{r: r, size: size, Version: le.Uint32(h[16:]), Catalog: int64(le.Uint64(h[48:])), MaxSize: int64(le.Uint64(h[56:]))}
	if st.Version != 1 || le.Uint32(h[20:]) != recVolumeHeader {
		return st, fmt.Errorf("%w: volume header version %d record type %d", ErrUnsupported, st.Version, le.Uint32(h[20:]))
	}
	if st.Catalog == 0 {
		return st, nil // shadow copies enabled, none taken (or all deleted)
	}
	if err := st.readCatalog(); err != nil {
		return st, err
	}
	for _, sn := range st.Snapshots {
		if sn.Status == "" {
			st.loadStore(sn)
		}
	}
	return st, nil
}

// block reads one 16 KiB block and checks its header.
func (s *Store) block(off int64, recType uint32) ([]byte, error) {
	if off <= 0 || off%512 != 0 || off > s.size-BlockSize {
		return nil, fmt.Errorf("block offset %d outside the volume", off)
	}
	b := make([]byte, BlockSize)
	if _, err := s.r.ReadAt(b, off); err != nil {
		return nil, fmt.Errorf("read block at %d: %w", off, err)
	}
	if !bytes.Equal(b[:16], Identifier) {
		return nil, fmt.Errorf("block at %d: no VSS identifier", off)
	}
	v, t := binary.LittleEndian.Uint32(b[16:]), binary.LittleEndian.Uint32(b[20:])
	if v != 1 {
		return nil, fmt.Errorf("%w: block at %d version %d", ErrUnsupported, off, v)
	}
	if t != recType {
		return nil, fmt.Errorf("block at %d: record type %d, want %d", off, t, recType)
	}
	return b, nil
}

func (s *Store) readCatalog() error {
	le := binary.LittleEndian
	byID := map[string]*Snapshot{}
	var order []*Snapshot
	seen := map[int64]bool{}
	for off, n := s.Catalog, 0; off != 0; n++ {
		if n >= maxCatalogBlocks || seen[off] {
			s.problem("catalog: chain loops or exceeds %d blocks at %d; stopped", maxCatalogBlocks, off)
			break
		}
		seen[off] = true
		b, err := s.block(off, recCatalog)
		if err != nil {
			if len(order) == 0 {
				return fmt.Errorf("vss: catalog: %w", err)
			}
			s.problem("catalog: %v; later entries not read", err)
			break
		}
		for i := blockHeaderSize; i+catalogEntrySize <= BlockSize; i += catalogEntrySize {
			e := b[i : i+catalogEntrySize]
			typ := le.Uint64(e[0:])
			switch typ {
			case 0, 1: // empty / unused
				continue
			case 2, 3:
			default:
				s.problem("catalog: entry type %d at %d not understood; skipped", typ, off+int64(i))
				continue
			}
			id := guid(e[16:32])
			sn := byID[id]
			if sn == nil {
				if len(order) >= maxStores {
					s.problem("catalog: more than %d stores; rest not read", maxStores)
					continue
				}
				sn = &Snapshot{StoreID: id}
				byID[id] = sn
				order = append(order, sn)
			}
			if typ == 2 {
				sn.VolumeSize = int64(le.Uint64(e[8:]))
				sn.Created = filetime(le.Uint64(e[48:]))
			} else {
				sn.blockList = int64(le.Uint64(e[8:]))
				sn.storeHeader = int64(le.Uint64(e[32:]))
				sn.current = int64(le.Uint64(e[48:]))
				sn.previous = int64(le.Uint64(e[72:]))
			}
		}
		off = int64(le.Uint64(b[40:]))
	}
	// Oldest first: a snapshot reads through every newer store.
	sort.SliceStable(order, func(i, j int) bool { return order[i].Created.Before(order[j].Created) })
	for i, sn := range order {
		sn.Index = i + 1
		switch {
		case sn.blockList == 0 || sn.storeHeader == 0:
			sn.unsupported("catalog has no store location entry (type 3) for this store")
		case sn.VolumeSize <= 0:
			sn.unsupported("catalog has no store information entry (type 2) for this store")
		case sn.VolumeSize > s.size:
			sn.unsupported(fmt.Sprintf("snapshot volume size %d exceeds the volume (%d bytes)", sn.VolumeSize, s.size))
		}
	}
	s.Snapshots = order
	return nil
}

func (sn *Snapshot) unsupported(reason string) {
	sn.Status, sn.Reason = StatusUnsupported, reason
	sn.descs = nil
}

// loadStore reads the store header, block list and current bitmap.
func (s *Store) loadStore(sn *Snapshot) {
	le := binary.LittleEndian
	hb, err := s.block(sn.storeHeader, recStoreHeader)
	if err != nil {
		sn.unsupported("store header: " + err.Error())
		return
	}
	info := hb[blockHeaderSize:]
	if n := int(le.Uint64(hb[48:])); n >= 68 && n <= maxStoreInfoBytes {
		info = info[:n]
	}
	if len(info) >= 68 {
		sn.ShadowCopyID, sn.ShadowSetID = guid(info[16:32]), guid(info[32:48])
		rest := info[64:]
		sn.Machine, rest = utf16Field(rest)
		sn.Service, _ = utf16Field(rest)
	}
	sn.descs = map[int64]descriptor{}
	seen := map[int64]bool{}
	for off, n := sn.blockList, 0; off != 0; n++ {
		if n >= maxListBlocks || seen[off] {
			sn.unsupported(fmt.Sprintf("block list chain loops or exceeds %d blocks at %d", maxListBlocks, off))
			return
		}
		seen[off] = true
		b, err := s.block(off, recBlockList)
		if err != nil {
			sn.unsupported("block list: " + err.Error())
			return
		}
		for i := blockHeaderSize; i+descriptorSize <= BlockSize; i += descriptorSize {
			e := b[i : i+descriptorSize]
			d := descriptor{
				orig: int64(le.Uint64(e[0:])), rel: int64(le.Uint64(e[8:])), data: int64(le.Uint64(e[16:])),
				flags: le.Uint32(e[24:]), bitmap: le.Uint32(e[28:]),
			}
			if d.orig == 0 && d.rel == 0 && d.data == 0 && d.flags == 0 && d.bitmap == 0 {
				continue
			}
			if d.flags&^(flagForwarder|flagOverlay|flagNotUsed) != 0 {
				sn.unsupported(fmt.Sprintf("block descriptor flags 0x%x at %d not understood", d.flags, off+int64(i)))
				return
			}
			if d.flags&flagNotUsed != 0 {
				continue
			}
			if d.orig < 0 || d.orig%BlockSize != 0 || d.orig >= sn.VolumeSize {
				sn.unsupported(fmt.Sprintf("block descriptor original offset %d invalid", d.orig))
				return
			}
			switch {
			case d.flags&flagForwarder != 0:
				if d.rel < 0 || d.rel%BlockSize != 0 || d.rel >= sn.VolumeSize {
					sn.unsupported(fmt.Sprintf("forwarder target %d invalid", d.rel))
					return
				}
				sn.Forwarders++
			default:
				if d.data <= 0 || d.data%512 != 0 || d.data > s.size-BlockSize {
					sn.unsupported(fmt.Sprintf("store data offset %d outside the volume", d.data))
					return
				}
				if d.flags&flagOverlay != 0 {
					sn.Overlays++
				}
			}
			if len(sn.descs) >= maxDescriptors || s.totalDescs >= maxTotalDescs {
				sn.unsupported(fmt.Sprintf("more than %d block descriptors (%d across all stores)", maxDescriptors, maxTotalDescs))
				return
			}
			s.totalDescs++
			prev, seenBlock := sn.descs[d.orig]
			switch {
			case !seenBlock:
				if d.flags&flagOverlay != 0 {
					d.parts = []overlayPart{{d.data, d.bitmap}}
				}
				sn.descs[d.orig] = d
			case prev.flags&flagOverlay != 0 && d.flags&flagOverlay != 0:
				// Overlays of one block accumulate sectors.
				if len(prev.parts) < 64 {
					prev.parts = append(prev.parts, overlayPart{d.data, d.bitmap})
				}
				sn.descs[d.orig] = prev
			case prev.flags&flagOverlay != 0 && d.flags == 0:
				sn.descs[d.orig] = d // a full copy supersedes partial overlays
			default:
				// The first full descriptor for a block is the copy-on-write original.
			}
		}
		off = int64(le.Uint64(b[40:]))
	}
	sn.Blocks = len(sn.descs)
	if sn.current != 0 {
		n, err := s.countBitmap(sn.current)
		if err != nil {
			s.problem("snapshot %d: current bitmap: %v (not needed for reading)", sn.Index, err)
		}
		sn.BitmapBlocks = n
	}
	sn.Status = StatusOK
}

func (s *Store) countBitmap(off int64) (int64, error) {
	var n int64
	seen := map[int64]bool{}
	for i := 0; off != 0; i++ {
		if i >= maxBitmapBlocks || seen[off] {
			return n, fmt.Errorf("bitmap chain loops or exceeds %d blocks", maxBitmapBlocks)
		}
		seen[off] = true
		b, err := s.block(off, recBitmap)
		if err != nil {
			return n, err
		}
		for _, x := range b[blockHeaderSize:] {
			for ; x != 0; x &= x - 1 {
				n++
			}
		}
		off = int64(binary.LittleEndian.Uint64(b[40:]))
	}
	return n, nil
}

// Volume returns snapshot i (1-based) as a read-only volume: the current
// volume with the snapshot's preserved blocks overlaid.
func (s *Store) Volume(i int) (io.ReaderAt, int64, error) {
	if i < 1 || i > len(s.Snapshots) {
		return nil, 0, fmt.Errorf("vss: no snapshot %d", i)
	}
	sn := s.Snapshots[i-1]
	if sn.Status != StatusOK {
		return nil, 0, fmt.Errorf("%w: snapshot %d: %s", ErrUnsupported, i, sn.Reason)
	}
	return &snapReader{s: s, idx: i - 1, size: sn.VolumeSize}, sn.VolumeSize, nil
}

type snapReader struct {
	s    *Store
	idx  int
	size int64
}

func (r *snapReader) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("vss: negative offset")
	}
	if off >= r.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > r.size-off {
		p = p[:r.size-off]
	}
	done := 0
	blk := make([]byte, BlockSize)
	for done < len(p) {
		pos := off + int64(done)
		base := pos &^ (BlockSize - 1)
		if err := r.s.readBlock(r.idx, base, blk, 0); err != nil {
			return done, err
		}
		done += copy(p[done:], blk[pos-base:])
	}
	if done < want {
		return done, io.EOF
	}
	return done, nil
}

// readBlock fills buf with the 16 KiB block at original offset base as
// snapshot idx saw it: the first store (idx, idx+1, …) holding a
// descriptor wins; with none, the current volume.
func (s *Store) readBlock(idx int, base int64, buf []byte, depth int) error {
	if depth > maxForwardDepth {
		return fmt.Errorf("%w: forwarder chain deeper than %d at %d", ErrUnsupported, maxForwardDepth, base)
	}
	for j := idx; j < len(s.Snapshots); j++ {
		sn := s.Snapshots[j]
		if sn.Status != StatusOK {
			// A newer store this reader cannot use may hold the block:
			// guessing would fabricate content.
			return fmt.Errorf("%w: newer snapshot %d is unsupported (%s)", ErrUnsupported, sn.Index, sn.Reason)
		}
		d, ok := sn.descs[base]
		if !ok {
			continue
		}
		switch {
		case d.flags&flagForwarder != 0:
			return s.readBlock(j+1, d.rel, buf, depth+1)
		case d.flags&flagOverlay != 0:
			if err := s.readBlock(j+1, base, buf, depth+1); err != nil {
				return err
			}
			for _, pt := range d.parts {
				for k := 0; k < 32; k++ {
					if pt.bitmap&(1<<k) == 0 {
						continue
					}
					if _, err := s.r.ReadAt(buf[k*512:(k+1)*512], pt.data+int64(k)*512); err != nil {
						return err
					}
				}
			}
			return nil
		default:
			_, err := s.r.ReadAt(buf, d.data)
			return err
		}
	}
	n, err := s.r.ReadAt(buf, base)
	if errors.Is(err, io.EOF) {
		clear(buf[n:])
		err = nil
	}
	return err
}

func guid(b []byte) string {
	le := binary.LittleEndian
	return fmt.Sprintf("%08x-%04x-%04x-%x-%x", le.Uint32(b[0:]), le.Uint16(b[4:]), le.Uint16(b[6:]), b[8:10], b[10:16])
}

func filetime(v uint64) time.Time {
	if v == 0 || v > math.MaxInt64 {
		return time.Time{}
	}
	d := int64(v) - 116444736000000000
	return time.Unix(d/10000000, (d%10000000)*100).UTC()
}

// utf16Field reads a u16 byte count followed by UTF-16LE text.
func utf16Field(b []byte) (string, []byte) {
	if len(b) < 2 {
		return "", nil
	}
	n := int(binary.LittleEndian.Uint16(b))
	if n%2 != 0 || 2+n > len(b) {
		return "", nil
	}
	u := make([]uint16, n/2)
	for i := range u {
		u[i] = binary.LittleEndian.Uint16(b[2+2*i:])
	}
	return string(utf16.Decode(u)), b[2+n:]
}
