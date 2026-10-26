// Package btrfs reads single-device Btrfs filesystems from a raw volume
// image, read-only, in pure Go. It never writes, never replays the log
// tree and never follows a symbolic link.
//
// Supported:
//   - the primary superblock (64 KiB) and its mirrors (64 MiB, 256 GiB):
//     a primary with a bad checksum falls back to the newest valid mirror,
//     and the damage is reported
//   - the sys_chunk_array bootstrap and the chunk tree (logical to physical
//     mapping) for the SINGLE and DUP profiles (DUP reads the first copy)
//   - the root tree, the top-level fs tree (FS_TREE, id 5) and every other
//     subvolume and snapshot
//   - INODE_ITEM, INODE_REF, DIR_INDEX (DIR_ITEM as fallback) and
//     EXTENT_DATA items: inline, regular and preallocated extents
//     (preallocated ranges and holes read as zeros)
//   - zlib-compressed extents (inline and regular)
//   - tree block checksums: crc32c and sha256 are verified; a mismatch is
//     counted in Stats()["csum_errors"] and listed in Problems()
//
// Subvolume convention: the fs.FS root is the top-level subvolume (id 5),
// whatever the default subvolume is (Metadata()["default_subvolume"] names
// it). Every other subvolume and snapshot appears where its directory entry
// sits, exactly as a mount of id 5 shows it, and its root directory's
// Sys() carries "subvolume_id", "subvolume_readonly" and, for snapshots,
// "snapshot_parent_uuid". Subvolumes not reachable that way are listed in
// Problems(). Inode numbers repeat across subvolumes, so Sys()["inode"] is
// the subvolume-local inode number and Sys()["dir_id"] / the walker key is
// (subvolume id << 40 | inode).
//
// Unsupported (errors wrap errors.ErrUnsupported):
//   - multi-device filesystems and RAID0/1/10/5/6/1C3/1C4 chunks (Open
//     fails, naming the profile)
//   - lzo- and zstd-compressed extents, encrypted or otherwise encoded
//     extents: the file is listed, opening it fails
//   - extent-tree-v2 and raid-stripe-tree filesystems, and unknown
//     incompatible feature bits (Open fails)
//   - xxhash64 and blake2b tree checksums are not verified (noted)
//   - data checksums (the csum tree) are not verified
package btrfs

import (
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"sort"
	"sync"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/diskimage/internal/rofs"
)

var le = binary.LittleEndian

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

const (
	superOffset  = 0x10000
	superSize    = 4096
	headerSize   = 101
	itemSize     = 25
	keyPtrSize   = 33
	maxLevel     = 8
	maxChunks    = 1 << 16
	maxDirItems  = 1 << 20
	maxExtItems  = 1 << 20
	maxLinkLen   = 4096
	maxCompBytes = 128 << 10 // BTRFS_MAX_UNCOMPRESSED / largest compressed extent
	maxProblems  = 100
	nodeCacheMax = 4096
	subvolShift  = 40

	fsTreeID       = 5
	rootTreeDirID  = 6
	firstChunkTree = 256
)

// Item key types.
const (
	typeInodeItem  = 1
	typeInodeRef   = 12
	typeDirItem    = 84
	typeDirIndex   = 96
	typeExtentData = 108
	typeRootItem   = 132
	typeRootRef    = 156
	typeChunkItem  = 228
)

// Chunk type / profile bits.
const (
	blockGroupRAID0   = 1 << 3
	blockGroupRAID1   = 1 << 4
	blockGroupDUP     = 1 << 5
	blockGroupRAID10  = 1 << 6
	blockGroupRAID5   = 1 << 7
	blockGroupRAID6   = 1 << 8
	blockGroupRAID1C3 = 1 << 9
	blockGroupRAID1C4 = 1 << 10
)

// Incompatible feature bits.
const (
	incompatMetadataUUID   = 0x400
	incompatExtentTreeV2   = 0x2000
	incompatRaidStripeTree = 0x4000
	incompatKnown          = 0x1 | 0x2 | 0x4 | 0x8 | 0x10 | 0x20 | 0x40 | 0x80 | 0x100 | 0x200 | 0x400 | 0x800 | 0x1000 | 0x10000
)

func corrupt(format string, a ...any) error {
	return fmt.Errorf("btrfs: corrupt: %s", fmt.Sprintf(format, a...))
}

func unsupported(format string, a ...any) error {
	return fmt.Errorf("btrfs: %w: %s", errors.ErrUnsupported, fmt.Sprintf(format, a...))
}

type key struct {
	obj uint64
	typ uint8
	off uint64
}

func readKey(b []byte) key { return key{le.Uint64(b), b[8], le.Uint64(b[9:])} }

func (k key) less(o key) bool {
	if k.obj != o.obj {
		return k.obj < o.obj
	}
	if k.typ != o.typ {
		return k.typ < o.typ
	}
	return k.off < o.off
}

type superblock struct {
	fsid, metaUUID [16]byte
	generation     uint64
	root           uint64
	chunkRoot      uint64
	logRoot        uint64
	totalBytes     uint64
	numDevices     uint64
	sectorSize     uint32
	nodeSize       uint32
	sysArray       []byte
	incompat       uint64
	csumType       uint16
	rootLevel      uint8
	chunkLevel     uint8
	devid          uint64
	devTotal       uint64
	label          string
	csumOK         bool
}

func parseSuper(b []byte) (*superblock, error) {
	if len(b) < superSize || string(b[0x40:0x48]) != "_BHRfS_M" {
		return nil, corrupt("no _BHRfS_M superblock magic")
	}
	s := &superblock{
		generation: le.Uint64(b[0x48:]),
		root:       le.Uint64(b[0x50:]),
		chunkRoot:  le.Uint64(b[0x58:]),
		logRoot:    le.Uint64(b[0x60:]),
		totalBytes: le.Uint64(b[0x70:]),
		numDevices: le.Uint64(b[0x88:]),
		sectorSize: le.Uint32(b[0x90:]),
		nodeSize:   le.Uint32(b[0x94:]),
		incompat:   le.Uint64(b[0xbc:]),
		csumType:   le.Uint16(b[0xc4:]),
		rootLevel:  b[0xc6],
		chunkLevel: b[0xc7],
		devid:      le.Uint64(b[0xc9:]),
		devTotal:   le.Uint64(b[0xc9+8:]),
		label:      cstr(b[0x12b : 0x12b+256]),
	}
	copy(s.fsid[:], b[0x20:0x30])
	s.metaUUID = s.fsid
	if s.incompat&incompatMetadataUUID != 0 {
		copy(s.metaUUID[:], b[0x23b:0x24b])
	}
	n := le.Uint32(b[0xa0:])
	if n > 2048 {
		return nil, corrupt("sys_chunk_array size %d", n)
	}
	s.sysArray = append([]byte(nil), b[0x32b:0x32b+int(n)]...)
	switch {
	case s.sectorSize < 512 || s.sectorSize > 65536 || s.sectorSize&(s.sectorSize-1) != 0:
		return nil, corrupt("sector size %d", s.sectorSize)
	case s.nodeSize < 4096 || s.nodeSize > 65536 || s.nodeSize&(s.nodeSize-1) != 0:
		return nil, corrupt("node size %d", s.nodeSize)
	case s.rootLevel >= maxLevel || s.chunkLevel >= maxLevel:
		return nil, corrupt("tree levels %d/%d", s.rootLevel, s.chunkLevel)
	}
	s.csumOK = verifyCsum(s.csumType, b[:superSize])
	return s, nil
}

func cstr(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return string(b[:i])
	}
	return string(b)
}

// verifyCsum checks a superblock or tree block checksum (the first 32
// bytes cover the rest). Unverifiable types report true; Open notes them.
func verifyCsum(typ uint16, b []byte) bool {
	switch typ {
	case 0: // crc32c, stored little-endian
		return crc32.Checksum(b[32:], castagnoli) == le.Uint32(b)
	case 2: // sha256
		s := sha256.Sum256(b[32:])
		return bytes.Equal(s[:], b[:32])
	}
	return true
}

func csumName(t uint16) string {
	switch t {
	case 0:
		return "crc32c"
	case 1:
		return "xxhash64"
	case 2:
		return "sha256"
	case 3:
		return "blake2b"
	}
	return fmt.Sprintf("type %d", t)
}

// Probe reports whether r holds a Btrfs primary superblock.
func Probe(r io.ReaderAt, size int64) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if r == nil || size < superOffset+superSize {
		return false
	}
	b := make([]byte, superSize)
	if rofs.ReadFull(r, b, superOffset) != nil {
		return false
	}
	_, err := parseSuper(b)
	return err == nil
}

type chunk struct {
	logical, length uint64
	typ             uint64
	physical        uint64 // first stripe on this device
}

// subvol is one fs tree (FS_TREE or a subvolume / snapshot).
type subvol struct {
	id         uint64
	bytenr     uint64
	level      uint8
	rootDir    uint64
	readonly   bool
	parentUUID [16]byte
	otime      time.Time
}

// FS is a read-only Btrfs filesystem. It implements fs.FS, fs.ReadDirFS and
// fs.StatFS and is safe for concurrent use.
type FS struct {
	*rofs.FS
	r      io.ReaderAt
	size   int64
	sb     *superblock
	chunks []chunk // sorted by logical

	mu        sync.Mutex
	problems  []string
	nodes     map[uint64][]byte
	subvols   map[uint64]*subvol
	defaultSV uint64
	reached   map[uint64]bool
}

// Open reads the superblock, chunk tree and root tree of the Btrfs
// filesystem in r (size bytes long) and returns it as an fs.FS.
func Open(r io.ReaderAt, size int64) (_ fs.FS, err error) {
	defer rofs.Guard("btrfs", "open", ".", &err)
	if r == nil || size < superOffset+superSize {
		return nil, corrupt("image too small (%d bytes)", size)
	}
	f := &FS{r: r, size: size, nodes: map[uint64][]byte{}, subvols: map[uint64]*subvol{}, reached: map[uint64]bool{}}
	f.FS = rofs.New(f, max(size/16, 1<<20))
	for _, k := range []string{"csum_errors", "corrupt_entries", "dirs_read", "unsupported_files"} {
		f.Bump(k, 0)
	}
	if err := f.loadSuper(); err != nil {
		return nil, err
	}
	sb := f.sb
	if sb.numDevices != 1 {
		return nil, unsupported("multi-device filesystem (%d devices); only single-device Btrfs is read", sb.numDevices)
	}
	switch {
	case sb.incompat&incompatExtentTreeV2 != 0:
		return nil, unsupported("extent-tree-v2 feature")
	case sb.incompat&incompatRaidStripeTree != 0:
		return nil, unsupported("raid-stripe-tree feature")
	case sb.incompat&^incompatKnown != 0:
		return nil, unsupported("unknown incompatible features 0x%x", sb.incompat&^incompatKnown)
	}
	if sb.csumType != 0 && sb.csumType != 2 {
		f.problem(fmt.Sprintf("tree block checksums are %s: not verified", csumName(sb.csumType)))
	} else if sb.csumType > 3 {
		return nil, unsupported("checksum type %d", sb.csumType)
	}
	if sb.devTotal > uint64(size) {
		return nil, corrupt("truncated image: device declares %d bytes, image has %d", sb.devTotal, size)
	}
	if sb.logRoot != 0 {
		f.problem("log tree present (unclean unmount after fsync): not replayed; the last fsync'd changes may be missing")
	}
	if err := f.bootstrap(); err != nil {
		return nil, err
	}
	if err := f.loadChunkTree(); err != nil {
		return nil, err
	}
	if err := f.loadRoots(); err != nil {
		return nil, err
	}
	root, err := f.Root()
	if err != nil {
		return nil, fmt.Errorf("btrfs: root directory: %w", err)
	}
	if !root.IsDir() {
		return nil, corrupt("root inode is not a directory")
	}
	return f, nil
}

// loadSuper reads the primary superblock and falls back to the newest
// valid mirror when the primary's checksum is wrong.
func (f *FS) loadSuper() error {
	b := make([]byte, superSize)
	if err := rofs.ReadFull(f.r, b, superOffset); err != nil {
		return fmt.Errorf("btrfs: read superblock: %w", err)
	}
	sb, err := parseSuper(b)
	if err != nil {
		return err
	}
	f.sb = sb
	if sb.csumOK {
		return nil
	}
	f.damage("primary superblock checksum mismatch")
	var best *superblock
	for _, off := range []int64{64 << 20, 256 << 30} {
		if off+superSize > f.size || rofs.ReadFull(f.r, b, off) != nil {
			continue
		}
		m, err := parseSuper(b)
		if err != nil || !m.csumOK || m.fsid != sb.fsid || le.Uint64(b[0x30:]) != uint64(off) {
			continue
		}
		if best == nil || m.generation > best.generation {
			best = m
		}
	}
	if best != nil {
		f.problem(fmt.Sprintf("using superblock mirror (generation %d)", best.generation))
		f.sb = best
	}
	return nil
}

func (f *FS) problem(p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.problems) < maxProblems {
		f.problems = append(f.problems, p)
	}
}

func (f *FS) damage(p string) {
	f.Bump("csum_errors", 1)
	f.problem(p)
}

// Problems lists damage and unsupported structures met so far.
func (f *FS) Problems() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.problems...)
}

// Stats returns counters: csum_errors, corrupt_entries, dirs_read,
// unsupported_files and cycles.
func (f *FS) Stats() map[string]int64 { return f.Counters() }

// Metadata returns volume-level facts.
func (f *FS) Metadata() map[string]any {
	sb := f.sb
	u := sb.fsid
	ids := make([]uint64, 0, len(f.subvols))
	for id := range f.subvols {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return map[string]any{
		"fs":                "btrfs",
		"label":             sb.label,
		"uuid":              fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]),
		"sector_size":       sb.sectorSize,
		"node_size":         sb.nodeSize,
		"total_bytes":       sb.totalBytes,
		"generation":        sb.generation,
		"csum_type":         csumName(sb.csumType),
		"feature_incompat":  sb.incompat,
		"subvolumes":        ids,
		"default_subvolume": f.defaultSV,
	}
}

// FSName implements rofs.Backend.
func (f *FS) FSName() string { return "btrfs" }

// ---- chunks ----

// parseChunk decodes a chunk item and checks its profile.
func (f *FS) parseChunk(logical uint64, b []byte) (chunk, int, error) {
	if len(b) < 48 {
		return chunk{}, 0, corrupt("chunk item at %d truncated", logical)
	}
	c := chunk{logical: logical, length: le.Uint64(b), typ: le.Uint64(b[24:])}
	n := int(le.Uint16(b[44:]))
	sz := 48 + 32*n
	if n == 0 || sz > len(b) {
		return chunk{}, 0, corrupt("chunk at %d: %d stripes", logical, n)
	}
	if c.length == 0 || c.logical+c.length < c.logical {
		return chunk{}, 0, corrupt("chunk at %d: length %d", logical, c.length)
	}
	if p := profileName(c.typ); p != "" {
		return chunk{}, 0, unsupported("chunk at logical %d uses the %s profile; RAID/striped chunks span devices", logical, p)
	}
	if n > 1 && c.typ&blockGroupDUP == 0 {
		return chunk{}, 0, corrupt("chunk at %d: %d stripes on a SINGLE profile", logical, n)
	}
	devid := le.Uint64(b[48:])
	if devid != f.sb.devid {
		return chunk{}, 0, unsupported("chunk at logical %d lives on device %d, this image is device %d", logical, devid, f.sb.devid)
	}
	c.physical = le.Uint64(b[56:])
	if c.physical+c.length < c.physical {
		return chunk{}, 0, corrupt("chunk at %d: physical offset overflows", logical)
	}
	return c, sz, nil
}

func profileName(t uint64) string {
	switch {
	case t&blockGroupRAID0 != 0:
		return "RAID0"
	case t&blockGroupRAID1 != 0:
		return "RAID1"
	case t&blockGroupRAID10 != 0:
		return "RAID10"
	case t&blockGroupRAID5 != 0:
		return "RAID5"
	case t&blockGroupRAID6 != 0:
		return "RAID6"
	case t&blockGroupRAID1C3 != 0:
		return "RAID1C3"
	case t&blockGroupRAID1C4 != 0:
		return "RAID1C4"
	}
	return ""
}

func (f *FS) addChunk(c chunk) error {
	i := sort.Search(len(f.chunks), func(i int) bool { return f.chunks[i].logical >= c.logical })
	if i < len(f.chunks) && f.chunks[i].logical == c.logical {
		return nil // the chunk tree repeats the bootstrap chunks
	}
	if len(f.chunks) >= maxChunks {
		return corrupt("more than %d chunks", maxChunks)
	}
	f.chunks = append(f.chunks, chunk{})
	copy(f.chunks[i+1:], f.chunks[i:])
	f.chunks[i] = c
	return nil
}

// bootstrap loads the system chunks from the superblock's sys_chunk_array.
func (f *FS) bootstrap() error {
	a := f.sb.sysArray
	for len(a) > 0 {
		if len(a) < 17 {
			return corrupt("sys_chunk_array truncated")
		}
		k := readKey(a)
		if k.typ != typeChunkItem {
			return corrupt("sys_chunk_array holds key type %d", k.typ)
		}
		c, n, err := f.parseChunk(k.off, a[17:])
		if err != nil {
			return err
		}
		if err := f.addChunk(c); err != nil {
			return err
		}
		a = a[17+n:]
	}
	if len(f.chunks) == 0 {
		return corrupt("empty sys_chunk_array")
	}
	return nil
}

func (f *FS) loadChunkTree() error {
	return f.walk(f.sb.chunkRoot, f.sb.chunkLevel, key{}, key{^uint64(0), 255, ^uint64(0)}, func(k key, data []byte) error {
		if k.typ != typeChunkItem {
			return nil
		}
		c, _, err := f.parseChunk(k.off, data)
		if err != nil {
			return err
		}
		return f.addChunk(c)
	})
}

// mapLogical returns the physical offset of logical and how many bytes are
// contiguous from there.
func (f *FS) mapLogical(logical uint64) (int64, uint64, error) {
	i := sort.Search(len(f.chunks), func(i int) bool { return f.chunks[i].logical+f.chunks[i].length > logical })
	if i == len(f.chunks) || f.chunks[i].logical > logical {
		return 0, 0, corrupt("logical address %d is in no chunk", logical)
	}
	c := f.chunks[i]
	in := logical - c.logical
	phys := c.physical + in
	if phys >= uint64(f.size) {
		return 0, 0, corrupt("logical address %d maps past the end of the image", logical)
	}
	return int64(phys), c.length - in, nil
}

// readLogical reads len(p) bytes at a logical address, across chunks.
func (f *FS) readLogical(p []byte, logical uint64) error {
	for len(p) > 0 {
		phys, run, err := f.mapLogical(logical)
		if err != nil {
			return err
		}
		n := uint64(len(p))
		if n > run {
			n = run
		}
		if err := rofs.ReadFull(f.r, p[:n], phys); err != nil {
			return err
		}
		p = p[n:]
		logical += n
	}
	return nil
}

// ---- trees ----

func (f *FS) readNode(logical uint64, level uint8) ([]byte, error) {
	f.mu.Lock()
	b, ok := f.nodes[logical]
	f.mu.Unlock()
	if !ok {
		b = make([]byte, f.sb.nodeSize)
		if err := f.readLogical(b, logical); err != nil {
			return nil, fmt.Errorf("btrfs: tree block %d: %w", logical, err)
		}
		if !bytes.Equal(b[32:48], f.sb.metaUUID[:]) {
			return nil, corrupt("tree block %d belongs to another filesystem", logical)
		}
		if le.Uint64(b[48:]) != logical {
			return nil, corrupt("tree block %d records address %d", logical, le.Uint64(b[48:]))
		}
		if !verifyCsum(f.sb.csumType, b) {
			f.damage(fmt.Sprintf("tree block %d checksum mismatch", logical))
		}
		f.mu.Lock()
		if len(f.nodes) >= nodeCacheMax {
			f.nodes = map[uint64][]byte{}
		}
		f.nodes[logical] = b
		f.mu.Unlock()
	}
	if b[100] != level {
		return nil, corrupt("tree block %d is level %d, expected %d", logical, b[100], level)
	}
	return b, nil
}

// walk visits, in key order, every leaf item with lo <= key <= hi in the
// tree rooted at root. Levels must strictly decrease on the way down, so a
// hostile tree cannot loop, and a block reached twice in one walk (a
// shared child that would make the walk explode) is rejected.
func (f *FS) walk(root uint64, level uint8, lo, hi key, fn func(key, []byte) error) error {
	return f.walkRec(root, level, lo, hi, fn, map[uint64]bool{})
}

func (f *FS) walkRec(root uint64, level uint8, lo, hi key, fn func(key, []byte) error, seen map[uint64]bool) error {
	if seen[root] {
		return corrupt("tree block %d reached twice in one walk", root)
	}
	seen[root] = true
	b, err := f.readNode(root, level)
	if err != nil {
		return err
	}
	n := int(le.Uint32(b[96:]))
	if level == 0 {
		if n > (len(b)-headerSize)/itemSize {
			return corrupt("leaf %d holds %d items", root, n)
		}
		for i := 0; i < n; i++ {
			it := b[headerSize+i*itemSize:]
			k := readKey(it)
			if k.less(lo) {
				continue
			}
			if hi.less(k) {
				return nil
			}
			off, sz := int(le.Uint32(it[17:])), int(le.Uint32(it[21:]))
			if off+sz > len(b)-headerSize || off < 0 || sz < 0 {
				return corrupt("leaf %d item %d data out of bounds", root, i)
			}
			if err := fn(k, b[headerSize+off:headerSize+off+sz]); err != nil {
				return err
			}
		}
		return nil
	}
	if n > (len(b)-headerSize)/keyPtrSize || n == 0 {
		return corrupt("node %d holds %d pointers", root, n)
	}
	for i := 0; i < n; i++ {
		p := b[headerSize+i*keyPtrSize:]
		k := readKey(p)
		if hi.less(k) {
			return nil
		}
		if i+1 < n {
			if next := readKey(b[headerSize+(i+1)*keyPtrSize:]); !lo.less(next) {
				continue // the whole child sorts below lo
			}
		}
		if err := f.walkRec(le.Uint64(p[17:]), level-1, lo, hi, fn, seen); err != nil {
			return err
		}
	}
	return nil
}

func btime(b []byte) time.Time {
	sec := int64(le.Uint64(b))
	ns := le.Uint32(b[8:])
	if ns >= 1e9 {
		ns = 0
	}
	if sec == 0 && ns == 0 {
		return time.Time{}
	}
	return time.Unix(sec, int64(ns)).UTC()
}

// loadRoots reads every fs tree's ROOT_ITEM and the default subvolume.
func (f *FS) loadRoots() error {
	err := f.walk(f.sb.root, f.sb.rootLevel, key{}, key{^uint64(0), 255, ^uint64(0)}, func(k key, d []byte) error {
		switch {
		case k.typ == typeRootItem && (k.obj == fsTreeID || k.obj >= 256 && k.obj < 1<<48):
			if len(d) < 239 {
				return corrupt("root item %d truncated", k.obj)
			}
			sv := &subvol{id: k.obj, rootDir: le.Uint64(d[168:]), bytenr: le.Uint64(d[176:]), level: d[238], readonly: le.Uint64(d[208:])&1 != 0}
			if le.Uint32(d[216:]) == 0 {
				f.problem(fmt.Sprintf("subvolume %d has no references (being deleted); not read", k.obj))
				return nil
			}
			if sv.level >= maxLevel || sv.rootDir == 0 {
				return corrupt("root item %d: level %d, root dir %d", k.obj, sv.level, sv.rootDir)
			}
			if len(d) >= 439 { // extended root item: uuids and times
				copy(sv.parentUUID[:], d[263:279])
				sv.otime = btime(d[339:])
			}
			f.subvols[k.obj] = sv
		case k.obj == rootTreeDirID && k.typ == typeDirItem && len(d) >= 30:
			if loc := readKey(d); loc.typ == typeRootItem && string(d[30:min(len(d), 30+int(le.Uint16(d[27:])))]) == "default" {
				f.defaultSV = loc.obj
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	if f.subvols[fsTreeID] == nil {
		return corrupt("no FS_TREE root item")
	}
	if f.defaultSV == 0 {
		f.defaultSV = fsTreeID
	}
	if f.defaultSV != fsTreeID {
		f.problem(fmt.Sprintf("default subvolume is %d; the tree shown starts at the top level (id 5), which contains it", f.defaultSV))
	}
	return nil
}

// ---- inodes ----

type inode struct {
	sv       *subvol
	ino      uint64
	size     int64
	nlink    uint32
	uid, gid uint32
	mode     uint32
	flags    uint64
	atime    time.Time
	ctime    time.Time
	mtime    time.Time
	otime    time.Time
	parent   uint64
	subvolRt bool // the root directory of a subvolume other than id 5
}

func nodeID(sv, ino uint64) uint64 { return sv<<subvolShift | ino&(1<<subvolShift-1) }

func (f *FS) readInode(sv *subvol, ino uint64) (*inode, error) {
	var in *inode
	err := f.walk(sv.bytenr, sv.level, key{ino, typeInodeItem, 0}, key{ino, typeInodeRef, ^uint64(0)}, func(k key, d []byte) error {
		switch k.typ {
		case typeInodeItem:
			if len(d) < 160 {
				return corrupt("subvolume %d inode %d: item truncated", sv.id, ino)
			}
			in = &inode{
				sv: sv, ino: ino,
				size:  int64(le.Uint64(d[16:])),
				nlink: le.Uint32(d[40:]),
				uid:   le.Uint32(d[44:]),
				gid:   le.Uint32(d[48:]),
				mode:  le.Uint32(d[52:]),
				flags: le.Uint64(d[64:]),
				atime: btime(d[112:]),
				ctime: btime(d[124:]),
				mtime: btime(d[136:]),
				otime: btime(d[148:]),
			}
		case typeInodeRef:
			if in != nil && in.parent == 0 {
				in.parent = k.off
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if in == nil {
		return nil, corrupt("subvolume %d inode %d: no inode item", sv.id, ino)
	}
	if in.size < 0 {
		return nil, corrupt("subvolume %d inode %d: negative size", sv.id, ino)
	}
	return in, nil
}

func (f *FS) node(in *inode) *rofs.Node {
	sys := map[string]any{
		"inode":        in.ino,
		"mtime":        in.mtime,
		"atime":        in.atime,
		"ctime":        in.ctime,
		"fs":           "btrfs",
		"mode":         in.mode,
		"uid":          in.uid,
		"gid":          in.gid,
		"links":        in.nlink,
		"subvolume_id": in.sv.id,
	}
	if !in.otime.IsZero() {
		sys["btime"] = in.otime
	}
	if in.parent != 0 {
		sys["parent_inode"] = in.parent
	}
	if in.ino == in.sv.rootDir {
		sys["subvolume_readonly"] = in.sv.readonly
		if in.sv.parentUUID != ([16]byte{}) {
			u := in.sv.parentUUID
			sys["snapshot_parent_uuid"] = fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
		}
		if !in.sv.otime.IsZero() {
			sys["subvolume_created"] = in.sv.otime
		}
		if in.sv.id == fsTreeID {
			for k, v := range f.Metadata() {
				if k != "fs" {
					sys[k] = v
				}
			}
		}
	}
	return &rofs.Node{ID: nodeID(in.sv.id, in.ino), Mode: rofs.UnixMode(in.mode), Size: in.size, MTime: in.mtime, Sys: sys, Impl: in}
}

type ref struct {
	sv  uint64
	ino uint64 // 0: the root directory of subvolume sv
}

// Root implements rofs.Backend.
func (f *FS) Root() (*rofs.Node, error) {
	sv := f.subvols[fsTreeID]
	in, err := f.readInode(sv, sv.rootDir)
	if err != nil {
		return nil, err
	}
	return f.node(in), nil
}

// Load implements rofs.Backend.
func (f *FS) Load(d rofs.Dirent) (*rofs.Node, error) {
	r := d.Ref.(ref)
	sv := f.subvols[r.sv]
	if sv == nil {
		return nil, corrupt("directory entry %q names unknown subvolume %d", d.Name, r.sv)
	}
	ino := r.ino
	if ino == 0 {
		ino = sv.rootDir
		f.mu.Lock()
		f.reached[sv.id] = true
		f.mu.Unlock()
	}
	in, err := f.readInode(sv, ino)
	if err != nil {
		return nil, err
	}
	return f.node(in), nil
}

// List implements rofs.Backend.
func (f *FS) List(n *rofs.Node) ([]rofs.Dirent, error) {
	in := n.Impl.(*inode)
	var idx, items []rofs.Dirent
	count := 0
	err := f.walk(in.sv.bytenr, in.sv.level, key{in.ino, typeDirItem, 0}, key{in.ino, typeDirIndex, ^uint64(0)}, func(k key, d []byte) error {
		// A DIR_ITEM may pack several entries (hash collisions).
		for len(d) > 0 {
			if count++; count > maxDirItems {
				return corrupt("directory inode %d: more than %d entries", in.ino, maxDirItems)
			}
			if len(d) < 30 {
				return corrupt("directory inode %d: entry truncated", in.ino)
			}
			loc := readKey(d)
			dl, nl := int(le.Uint16(d[25:])), int(le.Uint16(d[27:]))
			if 30+nl+dl > len(d) {
				return corrupt("directory inode %d: entry overruns its item", in.ino)
			}
			name := d[30 : 30+nl]
			ent, ok := f.dirent(in, name, loc, d[29])
			d = d[30+nl+dl:]
			if !ok {
				continue
			}
			if k.typ == typeDirIndex {
				idx = append(idx, ent)
			} else {
				items = append(items, ent)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	f.Bump("dirs_read", 1)
	if len(idx) == 0 && len(items) > 0 {
		f.problem(fmt.Sprintf("subvolume %d directory %d: no DIR_INDEX items; listed from DIR_ITEM", in.sv.id, in.ino))
		return items, nil
	}
	return idx, nil
}

func (f *FS) dirent(dir *inode, name []byte, loc key, ftype uint8) (rofs.Dirent, bool) {
	if !rofs.ValidName(name) || ftype == 8 { // 8: xattr
		if ftype != 8 {
			f.Bump("corrupt_entries", 1)
		}
		return rofs.Dirent{}, false
	}
	t := rofs.DirentType(ftype)
	switch loc.typ {
	case typeInodeItem:
		return rofs.Dirent{Name: string(name), ID: nodeID(dir.sv.id, loc.obj), Type: t, Ref: ref{dir.sv.id, loc.obj}}, true
	case typeRootItem:
		sv := f.subvols[loc.obj]
		if sv == nil {
			f.problem(fmt.Sprintf("%q names subvolume %d, which has no root item; not listed", name, loc.obj))
			f.Bump("corrupt_entries", 1)
			return rofs.Dirent{}, false
		}
		return rofs.Dirent{Name: string(name), ID: nodeID(sv.id, sv.rootDir), Type: fs.ModeDir, Ref: ref{sv.id, 0}}, true
	}
	f.Bump("corrupt_entries", 1)
	return rofs.Dirent{}, false
}

// Unreached lists subvolumes no directory entry visited so far points at
// (meaningful after a full walk).
func (f *FS) Unreached() []uint64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []uint64
	for id := range f.subvols {
		if id != fsTreeID && !f.reached[id] {
			out = append(out, id)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ---- file data ----

type seg struct {
	off, length int64
	kind        uint8 // 0 zero, 1 raw logical, 2 inline bytes, 3 zlib extent
	logical     uint64
	data        []byte
	diskLen     uint64
	ram         uint64
	skip        int64 // offset into the decompressed extent
}

const (
	segZero = iota
	segRaw
	segInline
	segZlib
)

type fileData struct {
	f    *FS
	ino  uint64
	segs []seg
	mu   sync.Mutex
	last *seg
	buf  []byte
}

func compressionName(c uint8) string {
	switch c {
	case 1:
		return "zlib"
	case 2:
		return "lzo"
	case 3:
		return "zstd"
	}
	return fmt.Sprintf("type %d", c)
}

// Data implements rofs.Backend.
func (f *FS) Data(n *rofs.Node) (io.ReaderAt, error) {
	in := n.Impl.(*inode)
	fd := &fileData{f: f, ino: in.ino}
	count := 0
	var next int64
	err := f.walk(in.sv.bytenr, in.sv.level, key{in.ino, typeExtentData, 0}, key{in.ino, typeExtentData, ^uint64(0)}, func(k key, d []byte) error {
		if count++; count > maxExtItems {
			return corrupt("inode %d: more than %d extents", in.ino, maxExtItems)
		}
		if len(d) < 21 {
			return corrupt("inode %d: extent item truncated", in.ino)
		}
		ram := le.Uint64(d[8:])
		comp, enc, other, typ := d[16], d[17], le.Uint16(d[18:]), d[20]
		off := int64(k.off)
		if off < next || off < 0 {
			return corrupt("inode %d: extent at %d overlaps the previous one", in.ino, off)
		}
		if enc != 0 || other != 0 {
			return unsupported("inode %d: encrypted or encoded extent (encryption %d, encoding %d)", in.ino, enc, other)
		}
		if comp > 1 {
			return unsupported("inode %d: %s-compressed extent at offset %d; only zlib is decoded", in.ino, compressionName(comp), off)
		}
		switch typ {
		case 0: // inline
			data := d[21:]
			if comp == 1 {
				if ram > maxCompBytes {
					return corrupt("inode %d: inline extent of %d bytes", in.ino, ram)
				}
				out, err := inflate(data, ram)
				if err != nil {
					return fmt.Errorf("btrfs: inode %d inline extent: %w", in.ino, err)
				}
				data = out
			}
			fd.segs = append(fd.segs, seg{off: off, length: int64(len(data)), kind: segInline, data: data})
			next = off + int64(len(data))
		case 1, 2: // regular, prealloc
			if len(d) < 53 {
				return corrupt("inode %d: extent item truncated", in.ino)
			}
			bytenr, diskLen := le.Uint64(d[21:]), le.Uint64(d[29:])
			eoff, num := int64(le.Uint64(d[37:])), int64(le.Uint64(d[45:]))
			if num <= 0 || eoff < 0 || off+num < off {
				return corrupt("inode %d: extent at %d of %d bytes", in.ino, off, num)
			}
			s := seg{off: off, length: num}
			switch {
			case typ == 2 || bytenr == 0:
				s.kind = segZero
			case comp == 1:
				if ram > maxCompBytes || diskLen > maxCompBytes || eoff+num > int64(ram) {
					return corrupt("inode %d: compressed extent %d/%d bytes (offset %d, %d used)", in.ino, diskLen, ram, eoff, num)
				}
				s.kind, s.logical, s.diskLen, s.ram, s.skip = segZlib, bytenr, diskLen, ram, eoff
			default:
				if uint64(eoff) > diskLen || uint64(eoff+num) > diskLen {
					return corrupt("inode %d: extent range %d+%d outside its %d disk bytes", in.ino, eoff, num, diskLen)
				}
				s.kind, s.logical = segRaw, bytenr+uint64(eoff)
			}
			fd.segs = append(fd.segs, s)
			next = off + num
		default:
			return corrupt("inode %d: extent type %d", in.ino, typ)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return fd, nil
}

func inflate(b []byte, ram uint64) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, corrupt("zlib: %v", err)
	}
	out, err := io.ReadAll(io.LimitReader(zr, int64(ram)+1))
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return nil, corrupt("zlib: %v", err)
	}
	if uint64(len(out)) > ram {
		return nil, corrupt("zlib extent inflates past its %d bytes", ram)
	}
	// Short output: the rest of the extent reads as zeros.
	return append(out, make([]byte, ram-uint64(len(out)))...), nil
}

func (d *fileData) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for len(p) > 0 {
		i := sort.Search(len(d.segs), func(i int) bool { return d.segs[i].off+d.segs[i].length > off })
		n := len(p)
		if i == len(d.segs) || d.segs[i].off > off {
			if i < len(d.segs) {
				n = int(min(int64(n), d.segs[i].off-off))
			}
			clear(p[:n]) // hole
		} else {
			s := &d.segs[i]
			in := off - s.off
			n = int(min(int64(n), s.length-in))
			switch s.kind {
			case segZero:
				clear(p[:n])
			case segInline:
				copy(p[:n], s.data[in:])
			case segRaw:
				if err := d.f.readLogical(p[:n], s.logical+uint64(in)); err != nil {
					return total, err
				}
			case segZlib:
				buf, err := d.extent(s)
				if err != nil {
					return total, err
				}
				copy(p[:n], buf[s.skip+in:])
			}
		}
		total += n
		p = p[n:]
		off += int64(n)
	}
	return total, nil
}

// extent returns the decompressed bytes of a zlib extent (last one cached).
func (d *fileData) extent(s *seg) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.last == s {
		return d.buf, nil
	}
	raw := make([]byte, s.diskLen)
	if err := d.f.readLogical(raw, s.logical); err != nil {
		return nil, err
	}
	out, err := inflate(raw, s.ram)
	if err != nil {
		return nil, fmt.Errorf("btrfs: inode %d: %w", d.ino, err)
	}
	d.last, d.buf = s, out
	return out, nil
}

// Link implements rofs.Backend: symlink targets are inline extents.
func (f *FS) Link(n *rofs.Node) (string, error) {
	in := n.Impl.(*inode)
	if in.size <= 0 || in.size > maxLinkLen {
		return "", corrupt("symlink inode %d length %d", in.ino, in.size)
	}
	r, err := f.Data(n)
	if err != nil {
		return "", err
	}
	b := make([]byte, in.size)
	if _, err := r.ReadAt(b, 0); err != nil {
		return "", err
	}
	return string(b), nil
}
