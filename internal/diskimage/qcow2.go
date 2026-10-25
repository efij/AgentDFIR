package diskimage

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"io"
	"os"
	"strconv"
	"sync"
)

// QCOW2 (QEMU copy-on-write v2/v3): a big-endian header, a two-level
// cluster map (L1 table → L2 tables → host clusters) and optional
// deflate-compressed clusters. Refcounts only matter for writing and are
// ignored. Unallocated clusters read as zeros (there is no backing file:
// images that need one are refused, naming it). Encryption, external data
// files, extended L2 entries and non-deflate compression types are
// reported UNSUPPORTED. Internal snapshots are counted in Meta; the
// active layer is what is read.

const (
	qcowIncompatDirty      = 1 << 0
	qcowIncompatCorrupt    = 1 << 1
	qcowIncompatDataFile   = 1 << 2
	qcowIncompatCompType   = 1 << 3
	qcowIncompatExtendedL2 = 1 << 4
	qcowOffsetMask         = 0x00fffffffffffe00 // bits 9-55
	qcowCompressedFlag     = 1 << 62
	qcowZeroFlag           = 1 << 0
	maxQCOWL1Bytes         = 256 << 20
	maxQCOWL2Cache         = 64
	maxQCOWBackingName     = 1023
)

func openQCOW2(f *os.File, fileSize int64, path string) (*Image, error) {
	fail := func(err error) (*Image, error) {
		f.Close()
		return nil, err
	}
	h := make([]byte, 112)
	if n, _ := f.ReadAt(h, 0); n < 72 {
		return fail(corrupt("qcow2", "header truncated"))
	}
	be := binary.BigEndian
	version := be.Uint32(h[4:])
	if version != 2 && version != 3 {
		return fail(unsupported("qcow2", "QCOW version %d; only QCOW2 v2/v3 is read — convert with qemu-img convert -O raw", version))
	}
	backingOff, backingLen := be.Uint64(h[8:]), be.Uint32(h[16:])
	clusterBits := be.Uint32(h[20:])
	size := int64(be.Uint64(h[24:]))
	crypt := be.Uint32(h[32:])
	l1Size := int64(be.Uint32(h[36:]))
	l1Off := int64(be.Uint64(h[40:]))
	snapshots := be.Uint32(h[60:])
	meta := map[string]string{"qcow2_version": strconv.Itoa(int(version))}
	if backingOff != 0 {
		name := "(unreadable name)"
		if backingLen > 0 && backingLen <= maxQCOWBackingName && int64(backingOff)+int64(backingLen) <= fileSize {
			b := make([]byte, backingLen)
			if _, err := f.ReadAt(b, int64(backingOff)); err == nil {
				name = string(b)
			}
		}
		return fail(unsupported("qcow2", "image has a backing file %q; it only holds the changes — flatten it first (qemu-img convert -O raw with the backing file next to it)", name))
	}
	if crypt != 0 {
		method := "AES"
		if crypt == 2 {
			method = "LUKS"
		}
		return fail(&Error{Kind: ErrEncrypted, Format: "qcow2", Reason: method + "-encrypted image; decrypt it with qemu-img convert --object secret,... -O raw, then use the raw image"})
	}
	if clusterBits < 9 || clusterBits > 21 {
		return fail(corrupt("qcow2", "cluster bits %d", clusterBits))
	}
	if size < 0 {
		return fail(corrupt("qcow2", "negative virtual size"))
	}
	if version == 3 {
		incompat := be.Uint64(h[72:])
		hdrLen := be.Uint32(h[100:])
		switch {
		case incompat&qcowIncompatDataFile != 0:
			return fail(unsupported("qcow2", "external data file; the guest data lives outside this image"))
		case incompat&qcowIncompatExtendedL2 != 0:
			return fail(unsupported("qcow2", "extended L2 entries (subclusters)"))
		case incompat&qcowIncompatCompType != 0 && hdrLen > 104 && h[104] != 0:
			ct := "zstd"
			if h[104] != 1 {
				ct = "type " + strconv.Itoa(int(h[104]))
			}
			return fail(unsupported("qcow2", "%s cluster compression; only deflate is read — qemu-img convert -O raw", ct))
		case incompat&^uint64(qcowIncompatDirty|qcowIncompatCorrupt|qcowIncompatCompType) != 0:
			return fail(unsupported("qcow2", "unknown incompatible features 0x%x", incompat))
		}
		if incompat&qcowIncompatDirty != 0 {
			meta["dirty"] = "refcounts not flushed (image not closed cleanly); the cluster map is still read"
		}
		if incompat&qcowIncompatCorrupt != 0 {
			meta["corrupt_flag"] = "QEMU marked this image corrupt; reads are best effort"
		}
	}
	cs := int64(1) << clusterBits
	l2Entries := cs / 8
	need := (size + cs*l2Entries - 1) / (cs * l2Entries)
	if l1Size < need {
		return fail(corrupt("qcow2", "L1 table has %d entries, %d needed for %d bytes", l1Size, need, size))
	}
	if l1Size*8 > maxQCOWL1Bytes || l1Off <= 0 || l1Off%cs != 0 || l1Off > fileSize-l1Size*8 {
		return fail(corrupt("qcow2", "L1 table (%d entries at %d) out of bounds", l1Size, l1Off))
	}
	raw := make([]byte, need*8)
	if _, err := f.ReadAt(raw, l1Off); err != nil {
		return fail(corrupt("qcow2", "read L1 table: %v", err))
	}
	l1 := make([]uint64, need)
	for i := range l1 {
		l1[i] = be.Uint64(raw[8*i:]) & qcowOffsetMask
	}
	meta["cluster_size"] = strconv.FormatInt(cs, 10)
	if snapshots > 0 {
		meta["internal_snapshots"] = strconv.Itoa(int(snapshots)) + " (not read; the active layer is)"
	}
	q := &qcow2{f: f, fileSize: fileSize, clusterBits: clusterBits, cs: cs, l1: l1, l2: map[uint64][]byte{}}
	return &Image{r: q, size: size, Format: FormatQCOW2, Segments: []string{path}, Meta: meta, closers: []io.Closer{f}}, nil
}

type qcow2 struct {
	f           *os.File
	fileSize    int64
	clusterBits uint32
	cs          int64
	l1          []uint64

	mu      sync.Mutex
	l2      map[uint64][]byte
	lastOff uint64 // host offset of the cached decompressed cluster
	last    []byte
}

func (q *qcow2) l2Table(off uint64) ([]byte, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if t, ok := q.l2[off]; ok {
		return t, nil
	}
	if int64(off) > q.fileSize-q.cs {
		return nil, corrupt("qcow2", "L2 table at %d past end of file", off)
	}
	t := make([]byte, q.cs)
	if _, err := q.f.ReadAt(t, int64(off)); err != nil {
		return nil, corrupt("qcow2", "read L2 table at %d: %v", off, err)
	}
	if len(q.l2) >= maxQCOWL2Cache {
		q.l2 = map[uint64][]byte{}
	}
	q.l2[off] = t
	return t, nil
}

func (q *qcow2) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	l2Bits := q.clusterBits - 3
	for len(p) > 0 {
		in := off & (q.cs - 1)
		n := int(min(int64(len(p)), q.cs-in))
		cl := uint64(off) >> q.clusterBits
		l1i := cl >> l2Bits
		if err := q.cluster(p[:n], l1i, cl&(1<<l2Bits-1), in); err != nil {
			return total, err
		}
		total += n
		p = p[n:]
		off += int64(n)
	}
	return total, nil
}

// cluster fills p with bytes from offset in of guest cluster (l1i, l2i).
func (q *qcow2) cluster(p []byte, l1i, l2i uint64, in int64) error {
	if l1i >= uint64(len(q.l1)) || q.l1[l1i] == 0 {
		clear(p)
		return nil
	}
	t, err := q.l2Table(q.l1[l1i])
	if err != nil {
		return err
	}
	e := binary.BigEndian.Uint64(t[8*l2i:])
	if e&qcowCompressedFlag != 0 {
		buf, err := q.compressed(e)
		if err != nil {
			return err
		}
		copy(p, buf[in:])
		return nil
	}
	host := e & qcowOffsetMask
	if e&qcowZeroFlag != 0 || host == 0 {
		clear(p)
		return nil
	}
	at := int64(host) + in
	if at > q.fileSize-int64(len(p)) {
		return corrupt("qcow2", "cluster at %d past end of file", host)
	}
	_, err = q.f.ReadAt(p, at)
	return err
}

// compressed inflates a compressed cluster (raw deflate) described by an
// L2 entry: host offset in the low bits, extra 512-byte sectors above.
func (q *qcow2) compressed(e uint64) ([]byte, error) {
	x := 62 - (q.clusterBits - 8)
	host := e & (1<<x - 1)
	sectors := (e>>x)&(1<<(62-x)-1) + 1
	clen := int64(sectors)*512 - int64(host&511)
	q.mu.Lock()
	defer q.mu.Unlock()
	if q.last != nil && q.lastOff == host {
		return q.last, nil
	}
	if clen <= 0 || clen > 2*q.cs+512 || int64(host) >= q.fileSize {
		return nil, corrupt("qcow2", "compressed cluster at %d (%d bytes) out of bounds", host, clen)
	}
	clen = min(clen, q.fileSize-int64(host)) // the last cluster may end early
	raw := make([]byte, clen)
	if _, err := q.f.ReadAt(raw, int64(host)); err != nil && err != io.EOF {
		return nil, err
	}
	out := make([]byte, q.cs)
	n, err := io.ReadFull(flate.NewReader(bytes.NewReader(raw)), out)
	if err != nil && err != io.ErrUnexpectedEOF {
		return nil, corrupt("qcow2", "compressed cluster at %d: %v", host, err)
	}
	if n < len(out) {
		return nil, corrupt("qcow2", "compressed cluster at %d inflates to %d of %d bytes", host, n, len(out))
	}
	q.lastOff, q.last = host, out
	return out, nil
}
