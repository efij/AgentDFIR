// Package ext4 reads ext2, ext3 and ext4 filesystems from a raw filesystem
// image, read-only, in pure Go. It never writes, never replays the journal
// and never follows a symbolic link.
//
// Supported:
//   - superblock (rev 0 and dynamic), 32- and 64-byte group descriptors
//     (64bit), flex_bg, sparse_super and meta_bg descriptor placement
//   - 128-byte and larger inodes, including nanosecond and creation
//     timestamps from the extra inode fields (and the 2038 epoch bits)
//   - extent trees (any depth up to 5, with depth, bounds and cycle guards;
//     unwritten extents read as zeros)
//   - legacy block maps: direct, indirect, double and triple indirect
//   - inline_data files and directories (i_block plus system.data xattr)
//   - directories by linear scan of every directory block; htree (dir_index)
//     directories are read linearly, the index blocks are skipped
//   - sparse files (holes read as zeros), huge_file, large files
//   - symlinks are reported as symlinks (fs.ModeSymlink, target in
//     Sys()["symlink_target"] and via ReadLink); they are never resolved
//
// Reported, not decoded:
//   - a filesystem that needs journal recovery is still read as it is on
//     disk; Metadata()["needs_recovery"] is true (the journal is ignored)
//   - fscrypt-encrypted directories and files: listed with
//     Sys()["unsupported"], reads return an error wrapping
//     errors.ErrUnsupported
//   - deleted directory entries (inode 0, or recoverable from directory
//     record slack) are skipped and counted in Stats()["deleted_entries"]
//
// Unsupported (Open fails with an error wrapping errors.ErrUnsupported):
// external journal devices, the compression and dirdata incompatible
// features, and any unknown incompatible feature bit.
//
// Every allocation is bounded by the filesystem size; malformed structures
// produce errors, never panics. Traversal is bounded too: a directory
// entry pointing back to a directory on the current path (or to the root)
// is not listed and not resolved, and is counted in
// Stats()["corrupt_entries"]; the total number of entries listed over the
// life of the FS is capped proportionally to the filesystem size. Walkers
// that want to skip hard-linked directories reached twice can deduplicate
// by Sys()["dir_id"] (the directory's inode number).
package ext4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	sbOffset    = 1024
	sbMagic     = 0xEF53
	rootIno     = 2
	maxPathDeep = 256      // path components accepted by lookups
	maxDirBytes = 64 << 20 // largest directory read into memory
	maxLinkLen  = 4096     // PATH_MAX
	maxExtDepth = 5
	cacheLimit  = 1 << 20 // cached directory entries before the cache resets
)

// Feature bits used by the reader.
const (
	compatHasJournal = 0x4

	incompatCompression = 0x1
	incompatFiletype    = 0x2
	incompatRecover     = 0x4
	incompatJournalDev  = 0x8
	incompatMetaBg      = 0x10
	incompatExtents     = 0x40
	incompat64bit       = 0x80
	incompatMMP         = 0x100
	incompatFlexBg      = 0x200
	incompatEAInode     = 0x400
	incompatDirdata     = 0x1000
	incompatCsumSeed    = 0x2000
	incompatLargedir    = 0x4000
	incompatInlineData  = 0x8000
	incompatEncrypt     = 0x10000
	incompatCasefold    = 0x20000

	incompatKnown = incompatCompression | incompatFiletype | incompatRecover |
		incompatJournalDev | incompatMetaBg | incompatExtents | incompat64bit |
		incompatMMP | incompatFlexBg | incompatEAInode | incompatDirdata |
		incompatCsumSeed | incompatLargedir | incompatInlineData |
		incompatEncrypt | incompatCasefold

	roCompatSparseSuper = 0x1
	roCompatHugeFile    = 0x8
	roCompatExt4Only    = 0x8 | 0x10 | 0x20 | 0x40 | 0x400 // huge_file, gdt_csum, dir_nlink, extra_isize, metadata_csum
)

// Inode flags.
const (
	flagEncrypt = 0x800
	flagIndex   = 0x1000
	flagExtents = 0x80000
	flagInline  = 0x10000000
)

var errCorrupt = errors.New("ext4: corrupt filesystem")

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errCorrupt, fmt.Sprintf(format, a...))
}

func unsupported(format string, a ...any) error {
	return fmt.Errorf("ext4: %w: %s", errors.ErrUnsupported, fmt.Sprintf(format, a...))
}

// readFull reads exactly len(p) bytes at off; a short read is an error.
func readFull(r io.ReaderAt, p []byte, off int64) error {
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil || err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

var le = binary.LittleEndian

type superblock struct {
	inodesCount    uint32
	blocksCount    uint64
	firstDataBlock uint32
	blockSize      uint32
	blocksPerGroup uint32
	inodesPerGroup uint32
	state          uint16
	rev            uint32
	inodeSize      uint32
	compat         uint32
	incompat       uint32
	roCompat       uint32
	uuid           [16]byte
	label          string
	descSize       uint32
	firstMetaBg    uint32
	mtime, wtime   time.Time
	mkfsTime       time.Time
	groups         uint64
}

func parseSuper(b []byte) (*superblock, error) {
	if len(b) < 1024 || le.Uint16(b[0x38:]) != sbMagic {
		return nil, corrupt("bad superblock magic")
	}
	s := &superblock{
		inodesCount:    le.Uint32(b[0x00:]),
		blocksCount:    uint64(le.Uint32(b[0x04:])),
		firstDataBlock: le.Uint32(b[0x14:]),
		blocksPerGroup: le.Uint32(b[0x20:]),
		inodesPerGroup: le.Uint32(b[0x28:]),
		state:          le.Uint16(b[0x3A:]),
		rev:            le.Uint32(b[0x4C:]),
		inodeSize:      128,
		descSize:       32,
	}
	logBS := le.Uint32(b[0x18:])
	if logBS > 6 {
		return nil, corrupt("block size exponent %d", logBS)
	}
	s.blockSize = 1024 << logBS
	if s.rev >= 1 {
		s.inodeSize = uint32(le.Uint16(b[0x58:]))
		s.compat = le.Uint32(b[0x5C:])
		s.incompat = le.Uint32(b[0x60:])
		s.roCompat = le.Uint32(b[0x64:])
	}
	copy(s.uuid[:], b[0x68:0x78])
	s.label = strings.TrimRight(string(b[0x78:0x88]), "\x00")
	if s.incompat&incompat64bit != 0 {
		s.blocksCount |= uint64(le.Uint32(b[0x150:])) << 32
		s.descSize = uint32(le.Uint16(b[0xFE:]))
		if s.descSize < 64 || s.descSize > 1024 || s.descSize&(s.descSize-1) != 0 {
			return nil, corrupt("group descriptor size %d", s.descSize)
		}
	}
	s.firstMetaBg = le.Uint32(b[0x104:])
	s.mtime = unixOrZero(le.Uint32(b[0x2C:]))
	s.wtime = unixOrZero(le.Uint32(b[0x30:]))
	s.mkfsTime = unixOrZero(le.Uint32(b[0x108:]))

	bs := uint64(s.blockSize)
	switch {
	case s.blocksCount == 0 || s.blocksCount > (1<<62)/bs:
		return nil, corrupt("block count %d", s.blocksCount)
	case s.blocksPerGroup == 0 || uint64(s.blocksPerGroup) > 8*bs:
		return nil, corrupt("blocks per group %d", s.blocksPerGroup)
	case s.inodesPerGroup == 0 || uint64(s.inodesPerGroup) > 8*bs:
		return nil, corrupt("inodes per group %d", s.inodesPerGroup)
	case s.inodeSize < 128 || s.inodeSize > s.blockSize || s.inodeSize&(s.inodeSize-1) != 0:
		return nil, corrupt("inode size %d", s.inodeSize)
	case uint64(s.firstDataBlock) >= s.blocksCount || s.firstDataBlock > 1:
		return nil, corrupt("first data block %d", s.firstDataBlock)
	}
	s.groups = (s.blocksCount - uint64(s.firstDataBlock) + uint64(s.blocksPerGroup) - 1) / uint64(s.blocksPerGroup)
	if s.inodesCount == 0 || uint64(s.inodesCount) > s.groups*uint64(s.inodesPerGroup) {
		return nil, corrupt("inode count %d", s.inodesCount)
	}
	return s, nil
}

func unixOrZero(v uint32) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(int64(v), 0).UTC()
}

// fsName classifies the volume the way the kernel driver family does.
func (s *superblock) fsName() string {
	if s.incompat&(incompatExtents|incompat64bit|incompatFlexBg|incompatInlineData|incompatMetaBg|incompatEncrypt|incompatCasefold|incompatLargedir|incompatEAInode|incompatCsumSeed|incompatMMP) != 0 ||
		s.roCompat&roCompatExt4Only != 0 {
		return "ext4"
	}
	if s.compat&compatHasJournal != 0 {
		return "ext3"
	}
	return "ext2"
}

// Probe reports whether r holds an ext2/3/4 superblock.
func Probe(r io.ReaderAt, size int64) bool {
	if r == nil || size < sbOffset+1024 {
		return false
	}
	b := make([]byte, 1024)
	if readFull(r, b, sbOffset) != nil {
		return false
	}
	_, err := parseSuper(b)
	return err == nil
}

type group struct {
	inodeTable uint64
	flags      uint16
}

// FS is a read-only ext2/3/4 filesystem. It implements fs.FS, fs.ReadDirFS
// and fs.StatFS and is safe for concurrent use.
type FS struct {
	r      io.ReaderAt
	size   int64
	sb     *superblock
	groups []group

	mu       sync.Mutex
	dirCache map[uint32][]dirent
	cached   int
	counted  map[uint32]bool
	cycles   map[[2]uint32]bool
	work     int64
	workMax  int64
	stats    map[string]int64
}

// Open parses the superblock and group descriptors of the ext filesystem in
// r (size bytes long) and returns it as an fs.FS.
func Open(r io.ReaderAt, size int64) (fs.FS, error) {
	if r == nil || size < sbOffset+1024 {
		return nil, corrupt("image too small (%d bytes)", size)
	}
	b := make([]byte, 1024)
	if err := readFull(r, b, sbOffset); err != nil {
		return nil, fmt.Errorf("ext4: read superblock: %w", err)
	}
	sb, err := parseSuper(b)
	if err != nil {
		return nil, err
	}
	if bad := sb.incompat &^ incompatKnown; bad != 0 {
		return nil, unsupported("unknown incompatible features 0x%x", bad)
	}
	switch {
	case sb.incompat&incompatJournalDev != 0:
		return nil, unsupported("external journal device, holds no files")
	case sb.incompat&incompatCompression != 0:
		return nil, unsupported("compression feature")
	case sb.incompat&incompatDirdata != 0:
		return nil, unsupported("dirdata feature")
	}
	if want := sb.blocksCount * uint64(sb.blockSize); want > uint64(size) {
		return nil, corrupt("truncated image: filesystem declares %d bytes, image has %d", want, size)
	}
	f := &FS{
		r: r, size: size, sb: sb,
		dirCache: map[uint32][]dirent{},
		counted:  map[uint32]bool{},
		stats:    map[string]int64{"deleted_entries": 0, "unsupported_entries": 0, "corrupt_entries": 0, "dirs_read": 0},
		cycles:   map[[2]uint32]bool{},
		workMax:  max(size/16, 1<<20),
	}
	if err := f.loadGroups(); err != nil {
		return nil, err
	}
	root, err := f.readInode(rootIno)
	if err != nil {
		return nil, fmt.Errorf("ext4: root inode: %w", err)
	}
	if !root.isDir() {
		return nil, corrupt("root inode is not a directory")
	}
	return f, nil
}

func (f *FS) hasSuper(g uint64) bool {
	if g <= 1 || f.sb.roCompat&roCompatSparseSuper == 0 {
		return true
	}
	if g&1 == 0 {
		return false
	}
	for _, p := range []uint64{3, 5, 7} {
		n := p
		for n < g {
			n *= p
		}
		if n == g {
			return true
		}
	}
	return false
}

func (f *FS) groupFirstBlock(g uint64) uint64 {
	return uint64(f.sb.firstDataBlock) + g*uint64(f.sb.blocksPerGroup)
}

// descBlock returns the block holding group-descriptor block i.
func (f *FS) descBlock(i, perBlock uint64) uint64 {
	sb := f.sb
	if sb.incompat&incompatMetaBg == 0 || i < uint64(sb.firstMetaBg) {
		return uint64(sb.firstDataBlock) + 1 + i
	}
	g := i * perBlock
	blk := f.groupFirstBlock(g)
	if f.hasSuper(g) {
		blk++
	}
	if g == 0 && sb.blockSize == 1024 && sb.firstDataBlock == 0 {
		blk++
	}
	return blk
}

func (f *FS) loadGroups() error {
	sb := f.sb
	bs := uint64(sb.blockSize)
	perBlock := bs / uint64(sb.descSize)
	nblocks := (sb.groups + perBlock - 1) / perBlock
	if nblocks > sb.blocksCount {
		return corrupt("group descriptor table larger than filesystem")
	}
	f.groups = make([]group, 0, sb.groups)
	buf := make([]byte, bs)
	itBlocks := (uint64(sb.inodesPerGroup)*uint64(sb.inodeSize) + bs - 1) / bs
	for i := uint64(0); i < nblocks; i++ {
		blk := f.descBlock(i, perBlock)
		if blk >= sb.blocksCount {
			return corrupt("group descriptor block %d out of range", blk)
		}
		if err := readFull(f.r, buf, int64(blk*bs)); err != nil {
			return fmt.Errorf("ext4: read group descriptors: %w", err)
		}
		for j := uint64(0); j < perBlock && uint64(len(f.groups)) < sb.groups; j++ {
			d := buf[j*uint64(sb.descSize):]
			g := group{inodeTable: uint64(le.Uint32(d[0x08:])), flags: le.Uint16(d[0x12:])}
			if sb.descSize >= 64 {
				g.inodeTable |= uint64(le.Uint32(d[0x28:])) << 32
			}
			if g.inodeTable != 0 && (g.inodeTable >= sb.blocksCount || g.inodeTable+itBlocks > sb.blocksCount) {
				return corrupt("group %d inode table at block %d out of range", len(f.groups), g.inodeTable)
			}
			f.groups = append(f.groups, g)
		}
	}
	return nil
}

func (f *FS) bump(key string, n int64) {
	f.mu.Lock()
	f.stats[key] += n
	f.mu.Unlock()
}

// Stats returns counters accumulated while directories were read:
// deleted_entries (skipped deleted directory entries), unsupported_entries,
// corrupt_entries and dirs_read. Each directory is counted once.
func (f *FS) Stats() map[string]int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int64, len(f.stats))
	for k, v := range f.stats {
		out[k] = v
	}
	return out
}

// Metadata returns volume-level facts: fs, label, uuid, block_size, blocks,
// inodes, needs_recovery, clean, errors, the raw feature words and the
// superblock timestamps.
func (f *FS) Metadata() map[string]any {
	sb := f.sb
	u := sb.uuid
	return map[string]any{
		"fs":               sb.fsName(),
		"label":            sb.label,
		"uuid":             fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]),
		"block_size":       sb.blockSize,
		"blocks":           sb.blocksCount,
		"inodes":           sb.inodesCount,
		"needs_recovery":   sb.incompat&incompatRecover != 0,
		"clean":            sb.state&1 != 0,
		"errors":           sb.state&2 != 0,
		"feature_compat":   sb.compat,
		"feature_incompat": sb.incompat,
		"feature_ro":       sb.roCompat,
		"last_mount":       sb.mtime,
		"last_write":       sb.wtime,
		"created":          sb.mkfsTime,
	}
}

// ---- inodes ----

type inode struct {
	ino      uint32
	mode     uint16
	uid, gid uint32
	size     uint64
	links    uint16
	flags    uint32
	block    []byte // the 60-byte i_block area
	raw      []byte
	extraEnd int // end of the valid extra inode area within raw
	atime    time.Time
	ctime    time.Time
	mtime    time.Time
	btime    time.Time
}

func (in *inode) fmt() uint16  { return in.mode & 0xF000 }
func (in *inode) isDir() bool  { return in.fmt() == 0x4000 }
func (in *inode) isReg() bool  { return in.fmt() == 0x8000 }
func (in *inode) isLink() bool { return in.fmt() == 0xA000 }

func (f *FS) readInode(ino uint32) (*inode, error) {
	sb := f.sb
	if ino == 0 || ino > sb.inodesCount {
		return nil, corrupt("inode %d out of range", ino)
	}
	g := uint64(ino-1) / uint64(sb.inodesPerGroup)
	idx := uint64(ino-1) % uint64(sb.inodesPerGroup)
	if g >= uint64(len(f.groups)) || f.groups[g].inodeTable == 0 {
		return nil, corrupt("inode %d: group %d has no inode table", ino, g)
	}
	raw := make([]byte, sb.inodeSize)
	off := f.groups[g].inodeTable*uint64(sb.blockSize) + idx*uint64(sb.inodeSize)
	if err := readFull(f.r, raw, int64(off)); err != nil {
		return nil, fmt.Errorf("ext4: read inode %d: %w", ino, err)
	}
	in := &inode{
		ino:   ino,
		mode:  le.Uint16(raw[0x00:]),
		uid:   uint32(le.Uint16(raw[0x02:])) | uint32(le.Uint16(raw[0x78:]))<<16,
		gid:   uint32(le.Uint16(raw[0x18:])) | uint32(le.Uint16(raw[0x7A:]))<<16,
		size:  uint64(le.Uint32(raw[0x04:])),
		links: le.Uint16(raw[0x1A:]),
		flags: le.Uint32(raw[0x20:]),
		block: raw[0x28:0x64],
		raw:   raw,
	}
	if in.isReg() || sb.incompat&incompatLargedir != 0 || sb.rev >= 1 && !in.isDir() {
		in.size |= uint64(le.Uint32(raw[0x6C:])) << 32
	}
	if in.size > 1<<60 {
		return nil, corrupt("inode %d: size %d", ino, in.size)
	}
	in.extraEnd = 128
	if sb.inodeSize > 128 {
		extra := int(le.Uint16(raw[0x80:]))
		if 128+extra <= int(sb.inodeSize) && extra%4 == 0 {
			in.extraEnd = 128 + extra
		}
	}
	extra := func(off int) (uint32, bool) {
		if off+4 <= in.extraEnd {
			return le.Uint32(raw[off:]), true
		}
		return 0, false
	}
	ts := func(loOff, exOff int) time.Time {
		lo := le.Uint32(raw[loOff:])
		ex, ok := extra(exOff)
		return decodeTime(lo, ex, ok)
	}
	in.ctime = ts(0x0C, 0x84)
	in.mtime = ts(0x10, 0x88)
	in.atime = ts(0x08, 0x8C)
	if _, ok := extra(0x90); ok {
		in.btime = ts(0x90, 0x94)
	}
	return in, nil
}

func decodeTime(lo, extra uint32, hasExtra bool) time.Time {
	if lo == 0 && (!hasExtra || extra == 0) {
		return time.Time{}
	}
	sec := int64(int32(lo))
	var nsec int64
	if hasExtra {
		sec += int64(extra&3) << 32
		nsec = int64(extra >> 2)
		if nsec >= 1e9 {
			nsec = 0
		}
	}
	return time.Unix(sec, nsec).UTC()
}

// inlineXattr returns the value of the in-inode xattr system.data used by
// inline_data, or nil if absent.
func (in *inode) inlineXattr() ([]byte, error) {
	start := in.extraEnd
	raw := in.raw
	if start+4 > len(raw) || le.Uint32(raw[start:]) != 0xEA020000 {
		return nil, nil
	}
	first := start + 4
	for off := first; off+16 <= len(raw); {
		if le.Uint32(raw[off:]) == 0 {
			break
		}
		nameLen := int(raw[off])
		idx := raw[off+1]
		voff := int(le.Uint16(raw[off+2:]))
		vinum := le.Uint32(raw[off+4:])
		vsize := int(le.Uint32(raw[off+8:]))
		if off+16+nameLen > len(raw) {
			return nil, corrupt("inode %d: xattr entry overruns inode", in.ino)
		}
		name := string(raw[off+16 : off+16+nameLen])
		if idx == 7 && name == "data" {
			if vinum != 0 {
				return nil, unsupported("inode %d: inline data stored in an EA inode", in.ino)
			}
			if vsize == 0 {
				return []byte{}, nil
			}
			if first+voff < first || first+voff+vsize > len(raw) || vsize < 0 {
				return nil, corrupt("inode %d: inline data xattr out of bounds", in.ino)
			}
			return raw[first+voff : first+voff+vsize], nil
		}
		off += (16 + nameLen + 3) &^ 3
	}
	return nil, nil
}

// inlineData returns the full content of an inline_data inode.
func (in *inode) inlineData() ([]byte, error) {
	x, err := in.inlineXattr()
	if err != nil {
		return nil, err
	}
	data := append(append([]byte{}, in.block...), x...)
	if in.size > uint64(len(data)) {
		return nil, corrupt("inode %d: inline size %d exceeds stored %d bytes", in.ino, in.size, len(data))
	}
	return data[:in.size], nil
}

// ---- block mapping ----

type run struct {
	logical, physical, length uint64
	unwritten                 bool
}

type mapper struct {
	f       *FS
	runs    []run
	visited map[uint64]bool
	budget  uint64 // metadata blocks we are still willing to read
}

func (m *mapper) add(logical, physical, length uint64, unwritten bool) error {
	sb := m.f.sb
	if length == 0 {
		return nil
	}
	if physical < uint64(sb.firstDataBlock) || physical >= sb.blocksCount || length > sb.blocksCount-physical {
		return corrupt("data block %d+%d out of range", physical, length)
	}
	if uint64(len(m.runs)) >= sb.blocksCount {
		return corrupt("block map larger than filesystem")
	}
	if n := len(m.runs); n > 0 {
		l := &m.runs[n-1]
		if !unwritten && !l.unwritten && l.logical+l.length == logical && l.physical+l.length == physical {
			l.length += length
			return nil
		}
	}
	m.runs = append(m.runs, run{logical, physical, length, unwritten})
	return nil
}

func (m *mapper) readMeta(blk uint64) ([]byte, error) {
	sb := m.f.sb
	if blk < uint64(sb.firstDataBlock) || blk >= sb.blocksCount {
		return nil, corrupt("metadata block %d out of range", blk)
	}
	if m.visited[blk] {
		return nil, corrupt("block %d referenced twice (cycle)", blk)
	}
	if m.budget == 0 {
		return nil, corrupt("too many metadata blocks")
	}
	m.budget--
	m.visited[blk] = true
	b := make([]byte, sb.blockSize)
	if err := readFull(m.f.r, b, int64(blk*uint64(sb.blockSize))); err != nil {
		return nil, fmt.Errorf("ext4: read block %d: %w", blk, err)
	}
	return b, nil
}

func (m *mapper) extents(node []byte, depth int, wantDepth int) error {
	if len(node) < 12 || le.Uint16(node[0:]) != 0xF30A {
		return corrupt("bad extent header")
	}
	entries := int(le.Uint16(node[2:]))
	maxEnt := int(le.Uint16(node[4:]))
	d := int(le.Uint16(node[6:]))
	if d > maxExtDepth || (wantDepth >= 0 && d != wantDepth) {
		return corrupt("extent depth %d (expected %d)", d, wantDepth)
	}
	if entries > maxEnt || 12+12*maxEnt > len(node) {
		return corrupt("extent node holds %d/%d entries", entries, maxEnt)
	}
	for i := 0; i < entries; i++ {
		e := node[12+12*i:]
		lblk := uint64(le.Uint32(e[0:]))
		if d == 0 {
			ln := uint64(le.Uint16(e[4:]))
			unwritten := false
			if ln > 32768 {
				ln -= 32768
				unwritten = true
			}
			phys := uint64(le.Uint16(e[6:]))<<32 | uint64(le.Uint32(e[8:]))
			if err := m.add(lblk, phys, ln, unwritten); err != nil {
				return err
			}
			continue
		}
		child := uint64(le.Uint16(e[8:]))<<32 | uint64(le.Uint32(e[4:]))
		b, err := m.readMeta(child)
		if err != nil {
			return err
		}
		if err := m.extents(b, depth+1, d-1); err != nil {
			return err
		}
	}
	return nil
}

func (m *mapper) indirect(blk uint64, level int, base, span, limit uint64) error {
	if blk == 0 || base >= limit {
		return nil
	}
	b, err := m.readMeta(blk)
	if err != nil {
		return err
	}
	for i := uint64(0); i < uint64(len(b))/4; i++ {
		lb := base + i*span
		if lb >= limit {
			break
		}
		p := uint64(le.Uint32(b[i*4:]))
		if p == 0 {
			continue
		}
		if level == 1 {
			if err := m.add(lb, p, 1, false); err != nil {
				return err
			}
			continue
		}
		if err := m.indirect(p, level-1, lb, span/(uint64(len(b))/4), limit); err != nil {
			return err
		}
	}
	return nil
}

// mapInode returns the sorted, non-overlapping data runs of in.
func (f *FS) mapInode(in *inode) ([]run, error) {
	sb := f.sb
	bs := uint64(sb.blockSize)
	m := &mapper{f: f, visited: map[uint64]bool{}, budget: sb.blocksCount}
	if in.flags&flagExtents != 0 {
		if err := m.extents(in.block, 0, -1); err != nil {
			return nil, fmt.Errorf("inode %d: %w", in.ino, err)
		}
	} else {
		limit := (in.size + bs - 1) / bs
		for i := uint64(0); i < 12 && i < limit; i++ {
			if p := uint64(le.Uint32(in.block[i*4:])); p != 0 {
				if err := m.add(i, p, 1, false); err != nil {
					return nil, fmt.Errorf("inode %d: %w", in.ino, err)
				}
			}
		}
		per := bs / 4
		base := uint64(12)
		span := uint64(1)
		for level := 1; level <= 3; level++ {
			if err := m.indirect(uint64(le.Uint32(in.block[(11+level)*4:])), level, base, span, limit); err != nil {
				return nil, fmt.Errorf("inode %d: %w", in.ino, err)
			}
			base += per * span
			span *= per
		}
	}
	runs := m.runs
	sort.Slice(runs, func(i, j int) bool { return runs[i].logical < runs[j].logical })
	for i := 1; i < len(runs); i++ {
		if runs[i-1].logical+runs[i-1].length > runs[i].logical {
			return nil, corrupt("inode %d: overlapping extents", in.ino)
		}
	}
	return runs, nil
}

// data is a random-access view of one inode's content.
type data struct {
	f      *FS
	size   int64
	runs   []run
	inline []byte
	inl    bool
}

func (f *FS) dataOf(in *inode) (*data, error) {
	d := &data{f: f, size: int64(in.size)}
	if in.flags&flagInline != 0 {
		b, err := in.inlineData()
		if err != nil {
			return nil, err
		}
		d.inline, d.inl = b, true
		return d, nil
	}
	if in.isLink() && in.size < 60 && in.flags&flagExtents == 0 {
		d.inline, d.inl = append([]byte{}, in.block[:in.size]...), true
		return d, nil
	}
	runs, err := f.mapInode(in)
	if err != nil {
		return nil, err
	}
	d.runs = runs
	return d, nil
}

func (d *data) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("ext4: negative offset")
	}
	if off >= d.size {
		return 0, io.EOF
	}
	if d.inl {
		n := copy(p, d.inline[off:])
		if n < len(p) {
			return n, io.EOF
		}
		return n, nil
	}
	bs := int64(d.f.sb.blockSize)
	total := 0
	for len(p) > 0 && off < d.size {
		lb := uint64(off / bs)
		inner := off % bs
		want := int64(len(p))
		if rem := d.size - off; want > rem {
			want = rem
		}
		i := sort.Search(len(d.runs), func(i int) bool { return d.runs[i].logical+d.runs[i].length > lb })
		var n int64
		if i < len(d.runs) && d.runs[i].logical <= lb {
			r := d.runs[i]
			avail := int64(r.logical+r.length-lb)*bs - inner
			n = min(want, avail)
			if r.unwritten {
				clear(p[:n])
			} else {
				pos := int64(r.physical+(lb-r.logical))*bs + inner
				if err := readFull(d.f.r, p[:n], pos); err != nil {
					return total, fmt.Errorf("ext4: read data: %w", err)
				}
			}
		} else {
			// Hole: zeros up to the next run or EOF.
			n = want
			if i < len(d.runs) {
				n = min(n, int64(d.runs[i].logical)*bs-off)
			}
			clear(p[:n])
		}
		p = p[n:]
		off += n
		total += int(n)
	}
	if len(p) > 0 {
		return total, io.EOF
	}
	return total, nil
}

// ---- directories ----

type dirent struct {
	name  string
	ino   uint32
	ftype uint8
}

func validName(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c == 0 || c == '/' {
			return false
		}
	}
	return true
}

// parseDirBlock parses one directory region. slackOK enables counting of
// deleted records recoverable from record slack.
func (f *FS) parseDirBlock(b []byte, out *[]dirent, st map[string]int64, skipSlackOf string) error {
	ftypes := f.sb.incompat&incompatFiletype != 0
	for off := 0; off+8 <= len(b); {
		ino := le.Uint32(b[off:])
		rl := int(le.Uint16(b[off+4:]))
		if (rl == 0 || rl == 65535) && f.sb.blockSize == 65536 && off == 0 && len(b) == 65536 {
			rl = 65536
		}
		nl := int(b[off+6])
		ft := b[off+7]
		if !ftypes {
			nl = int(le.Uint16(b[off+6:]))
			ft = 0
		}
		if rl < 8 || rl%4 != 0 || off+rl > len(b) || 8+nl > rl {
			st["corrupt_entries"]++
			return corrupt("directory record at offset %d (rec_len %d, name_len %d)", off, rl, nl)
		}
		name := b[off+8 : off+8+nl]
		switch {
		case ino != 0 && nl > 0:
			s := string(name)
			if s == "." || s == ".." {
				break
			}
			if !validName(name) || ino > f.sb.inodesCount {
				st["corrupt_entries"]++
				break
			}
			*out = append(*out, dirent{name: s, ino: ino, ftype: ft})
		case ino == 0 && nl > 0 && ft != 0xDE:
			st["deleted_entries"]++
		}
		if ino != 0 && string(name) != skipSlackOf {
			st["deleted_entries"] += int64(f.slackDeleted(b[off+((8+nl+3)&^3) : off+rl]))
		}
		off += rl
	}
	return nil
}

// slackDeleted counts plausible deleted records left in a record's slack.
func (f *FS) slackDeleted(gap []byte) int {
	n := 0
	ftypes := f.sb.incompat&incompatFiletype != 0
	for off := 0; off+12 <= len(gap); {
		ino := le.Uint32(gap[off:])
		rl := int(le.Uint16(gap[off+4:]))
		nl := int(gap[off+6])
		ft := gap[off+7]
		ok := ino != 0 && ino <= f.sb.inodesCount && nl > 0 && rl >= 8+nl && rl%4 == 0 && off+rl <= len(gap) && (!ftypes || (ft >= 1 && ft <= 7))
		if ok {
			for _, c := range gap[off+8 : off+8+nl] {
				if c < 0x20 || c == '/' || c == 0x7F {
					ok = false
					break
				}
			}
		}
		if ok {
			n++
			off += rl
			continue
		}
		off += 4
	}
	return n
}

// entries returns the live entries of directory inode in (unsorted).
func (f *FS) entries(in *inode) ([]dirent, error) {
	if in.flags&flagEncrypt != 0 {
		return nil, unsupported("fscrypt-encrypted directory (inode %d)", in.ino)
	}
	f.mu.Lock()
	if e, ok := f.dirCache[in.ino]; ok {
		f.mu.Unlock()
		return e, nil
	}
	f.mu.Unlock()

	st := map[string]int64{}
	var out []dirent
	if in.flags&flagInline != 0 {
		x, err := in.inlineXattr()
		if err != nil {
			return nil, err
		}
		if err := f.parseDirBlock(in.block[4:], &out, st, ""); err != nil {
			return nil, fmt.Errorf("inode %d: %w", in.ino, err)
		}
		if len(x) > 0 {
			if err := f.parseDirBlock(x, &out, st, ""); err != nil {
				return nil, fmt.Errorf("inode %d: %w", in.ino, err)
			}
		}
	} else {
		bs := uint64(f.sb.blockSize)
		if in.size > maxDirBytes || in.size > uint64(f.size) || in.size%bs != 0 {
			return nil, corrupt("directory inode %d size %d", in.ino, in.size)
		}
		d, err := f.dataOf(in)
		if err != nil {
			return nil, err
		}
		buf := make([]byte, in.size)
		if _, err := d.ReadAt(buf, 0); err != nil && err != io.EOF {
			return nil, err
		}
		for i := uint64(0); i < in.size; i += bs {
			skip := ""
			if i == 0 && in.flags&flagIndex != 0 {
				skip = ".." // the htree root lives in the ".." record slack
			}
			if err := f.parseDirBlock(buf[i:i+bs], &out, st, skip); err != nil {
				return nil, fmt.Errorf("inode %d: %w", in.ino, err)
			}
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.counted[in.ino] {
		f.counted[in.ino] = true
		f.stats["dirs_read"]++
		for k, v := range st {
			f.stats[k] += v
		}
	}
	if f.cached+len(out) > cacheLimit {
		f.dirCache, f.cached = map[uint32][]dirent{}, 0
	}
	f.dirCache[in.ino] = out
	f.cached += len(out)
	return out, nil
}

// ---- fs.FS ----

// lookup resolves name. The returned set holds the inode numbers of every
// directory on the path (root included), the target included when it is
// a directory.
func (f *FS) lookup(op, name string) (*inode, map[uint32]bool, error) {
	if !fs.ValidPath(name) {
		return nil, nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	in, err := f.readInode(rootIno)
	if err != nil {
		return nil, nil, &fs.PathError{Op: op, Path: name, Err: err}
	}
	if name == "." {
		return in, map[uint32]bool{rootIno: true}, nil
	}
	parts := strings.Split(name, "/")
	if len(parts) > maxPathDeep {
		return nil, nil, &fs.PathError{Op: op, Path: name, Err: errors.New("path too deep")}
	}
	anc := map[uint32]bool{rootIno: true}
	for _, p := range parts {
		if !in.isDir() {
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%w: not a directory", fs.ErrNotExist)}
		}
		ents, err := f.entries(in)
		if err != nil {
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: err}
		}
		var next uint32
		for _, e := range ents {
			if e.name == p {
				next = e.ino
				break
			}
		}
		if next == 0 {
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
		}
		if anc[next] {
			f.noteCycle(in.ino, next)
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: corrupt("directory cycle: %q points back to an ancestor", p)}
		}
		if in, err = f.readInode(next); err != nil {
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: err}
		}
		if in.isDir() {
			anc[next] = true
		}
	}
	return in, anc, nil
}

func fileMode(m uint16) fs.FileMode {
	mode := fs.FileMode(m & 0o777)
	switch m & 0xF000 {
	case 0x4000:
		mode |= fs.ModeDir
	case 0xA000:
		mode |= fs.ModeSymlink
	case 0x2000:
		mode |= fs.ModeDevice | fs.ModeCharDevice
	case 0x6000:
		mode |= fs.ModeDevice
	case 0x1000:
		mode |= fs.ModeNamedPipe
	case 0xC000:
		mode |= fs.ModeSocket
	case 0x8000:
	default:
		mode |= fs.ModeIrregular
	}
	if m&0o4000 != 0 {
		mode |= fs.ModeSetuid
	}
	if m&0o2000 != 0 {
		mode |= fs.ModeSetgid
	}
	if m&0o1000 != 0 {
		mode |= fs.ModeSticky
	}
	return mode
}

type fileInfo struct {
	name  string
	size  int64
	mode  fs.FileMode
	mtime time.Time
	sys   map[string]any
}

func (i *fileInfo) Name() string       { return i.name }
func (i *fileInfo) Size() int64        { return i.size }
func (i *fileInfo) Mode() fs.FileMode  { return i.mode }
func (i *fileInfo) ModTime() time.Time { return i.mtime }
func (i *fileInfo) IsDir() bool        { return i.mode.IsDir() }
func (i *fileInfo) Sys() any           { return i.sys }

func (f *FS) info(name string, in *inode) *fileInfo {
	sys := map[string]any{
		"inode": uint64(in.ino),
		"mtime": in.mtime,
		"atime": in.atime,
		"ctime": in.ctime,
		"btime": in.btime,
		"fs":    f.sb.fsName(),
		"mode":  uint32(in.mode),
		"uid":   in.uid,
		"gid":   in.gid,
		"links": in.links,
		"flags": in.flags,
	}
	if in.isDir() {
		sys["dir_id"] = uint64(in.ino)
	}
	if in.flags&flagInline != 0 {
		sys["inline_data"] = true
	}
	if in.flags&flagEncrypt != 0 {
		sys["unsupported"] = "fscrypt-encrypted"
	}
	if in.isLink() {
		if t, err := f.linkTarget(in); err == nil {
			sys["symlink_target"] = t
		} else {
			sys["symlink_error"] = err.Error()
		}
	}
	if in.ino == rootIno {
		for k, v := range f.Metadata() {
			if k != "fs" {
				sys[k] = v
			}
		}
		for k, v := range f.Stats() {
			sys[k] = v
		}
	}
	return &fileInfo{name: name, size: int64(in.size), mode: fileMode(in.mode), mtime: in.mtime, sys: sys}
}

func (f *FS) linkTarget(in *inode) (string, error) {
	if in.flags&flagEncrypt != 0 {
		return "", unsupported("fscrypt-encrypted symlink")
	}
	if in.size > maxLinkLen {
		return "", corrupt("symlink inode %d length %d", in.ino, in.size)
	}
	d, err := f.dataOf(in)
	if err != nil {
		return "", err
	}
	b := make([]byte, in.size)
	if _, err := d.ReadAt(b, 0); err != nil && err != io.EOF {
		return "", err
	}
	return string(b), nil
}

func baseName(name string) string {
	if name == "." {
		return "."
	}
	return path.Base(name)
}

// Open opens the named file or directory. Symlinks are not followed: the
// returned file reports fs.ModeSymlink and its Read fails.
func (f *FS) Open(name string) (fs.File, error) {
	in, anc, err := f.lookup("open", name)
	if err != nil {
		return nil, err
	}
	info := f.info(baseName(name), in)
	if in.isDir() {
		return &dirFile{f: f, in: in, info: info, path: name, anc: anc}, nil
	}
	if in.flags&flagEncrypt != 0 {
		f.bump("unsupported_entries", 1)
		return nil, &fs.PathError{Op: "open", Path: name, Err: unsupported("fscrypt-encrypted file")}
	}
	if !in.isReg() {
		return &file{info: info, path: name, special: true}, nil
	}
	d, err := f.dataOf(in)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &file{info: info, path: name, d: d}, nil
}

// Stat returns the FileInfo of name without following symlinks.
func (f *FS) Stat(name string) (fs.FileInfo, error) {
	in, _, err := f.lookup("stat", name)
	if err != nil {
		return nil, err
	}
	return f.info(baseName(name), in), nil
}

// ReadLink returns the target of the named symlink without resolving it.
func (f *FS) ReadLink(name string) (string, error) {
	in, _, err := f.lookup("readlink", name)
	if err != nil {
		return "", err
	}
	if !in.isLink() {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	t, err := f.linkTarget(in)
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}
	return t, nil
}

// ReadDir returns the entries of the named directory sorted by name.
func (f *FS) ReadDir(name string) ([]fs.DirEntry, error) {
	in, anc, err := f.lookup("readdir", name)
	if err != nil {
		return nil, err
	}
	return f.readDir(name, in, anc)
}

func (f *FS) readDir(name string, in *inode, anc map[uint32]bool) ([]fs.DirEntry, error) {
	if !in.isDir() {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("not a directory")}
	}
	ents, err := f.entries(in)
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			f.bump("unsupported_entries", 1)
		}
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	if err := f.spend(len(ents)); err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	out := make([]fs.DirEntry, 0, len(ents))
	for _, e := range ents {
		if anc[e.ino] || e.ino == rootIno {
			f.noteCycle(in.ino, e.ino) // points back to an ancestor or root
			continue
		}
		out = append(out, &dirEntry{f: f, d: e})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

// noteCycle counts a directory entry pointing back to an ancestor once per
// (parent, child) pair.
func (f *FS) noteCycle(parent, child uint32) {
	f.mu.Lock()
	defer f.mu.Unlock()
	k := [2]uint32{parent, child}
	if !f.cycles[k] {
		f.cycles[k] = true
		f.stats["corrupt_entries"]++
	}
}

// spend charges n listed entries against the total-work budget, which is
// proportional to the filesystem size, so that hostile hard-linked
// directory graphs cannot make a walk explode.
func (f *FS) spend(n int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.work += int64(n)
	if f.work > f.workMax {
		return corrupt("work budget exhausted after listing %d entries", f.work)
	}
	return nil
}

type dirEntry struct {
	f    *FS
	d    dirent
	once sync.Once
	info fs.FileInfo
	err  error
}

func (e *dirEntry) Name() string { return e.d.name }
func (e *dirEntry) IsDir() bool  { return e.Type().IsDir() }

func (e *dirEntry) Type() fs.FileMode {
	switch e.d.ftype {
	case 1:
		return 0
	case 2:
		return fs.ModeDir
	case 3:
		return fs.ModeDevice | fs.ModeCharDevice
	case 4:
		return fs.ModeDevice
	case 5:
		return fs.ModeNamedPipe
	case 6:
		return fs.ModeSocket
	case 7:
		return fs.ModeSymlink
	}
	if i, err := e.Info(); err == nil {
		return i.Mode().Type()
	}
	return fs.ModeIrregular
}

func (e *dirEntry) Info() (fs.FileInfo, error) {
	e.once.Do(func() {
		in, err := e.f.readInode(e.d.ino)
		if err != nil {
			e.err = err
			return
		}
		e.info = e.f.info(e.d.name, in)
	})
	return e.info, e.err
}

func (e *dirEntry) String() string { return fs.FormatDirEntry(e) }

type file struct {
	info    *fileInfo
	path    string
	d       *data
	off     int64
	special bool
	closed  bool
}

func (fl *file) Stat() (fs.FileInfo, error) { return fl.info, nil }
func (fl *file) Close() error {
	fl.closed = true
	return nil
}

func (fl *file) Read(p []byte) (int, error) {
	if fl.closed {
		return 0, &fs.PathError{Op: "read", Path: fl.path, Err: fs.ErrClosed}
	}
	if fl.special {
		return 0, &fs.PathError{Op: "read", Path: fl.path, Err: errors.New("not a regular file")}
	}
	n, err := fl.d.ReadAt(p, fl.off)
	fl.off += int64(n)
	return n, err
}

func (fl *file) ReadAt(p []byte, off int64) (int, error) {
	if fl.closed || fl.special {
		return 0, &fs.PathError{Op: "read", Path: fl.path, Err: fs.ErrInvalid}
	}
	return fl.d.ReadAt(p, off)
}

func (fl *file) Seek(offset int64, whence int) (int64, error) {
	if fl.closed || fl.special {
		return 0, &fs.PathError{Op: "seek", Path: fl.path, Err: fs.ErrInvalid}
	}
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		offset += fl.off
	case io.SeekEnd:
		offset += fl.d.size
	default:
		return 0, &fs.PathError{Op: "seek", Path: fl.path, Err: fs.ErrInvalid}
	}
	if offset < 0 {
		return 0, &fs.PathError{Op: "seek", Path: fl.path, Err: fs.ErrInvalid}
	}
	fl.off = offset
	return offset, nil
}

type dirFile struct {
	f     *FS
	in    *inode
	anc   map[uint32]bool
	info  *fileInfo
	path  string
	ents  []fs.DirEntry
	read  bool
	pos   int
	close bool
}

func (d *dirFile) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *dirFile) Close() error {
	d.close = true
	return nil
}
func (d *dirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.path, Err: errors.New("is a directory")}
}

func (d *dirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	if d.close {
		return nil, &fs.PathError{Op: "readdir", Path: d.path, Err: fs.ErrClosed}
	}
	if !d.read {
		ents, err := d.f.readDir(d.path, d.in, d.anc)
		if err != nil {
			return nil, err
		}
		d.ents, d.read = ents, true
	}
	rest := d.ents[d.pos:]
	if n <= 0 {
		d.pos = len(d.ents)
		return rest, nil
	}
	if len(rest) == 0 {
		return nil, io.EOF
	}
	n = min(n, len(rest))
	d.pos += n
	return rest[:n], nil
}
