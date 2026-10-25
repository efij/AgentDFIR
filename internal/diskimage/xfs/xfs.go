// Package xfs reads XFS filesystems from a raw volume image, read-only, in
// pure Go. It never writes, never replays the log and never follows a
// symbolic link.
//
// Supported:
//   - v5 (CRC) superblocks, and v4 superblocks with the v2 directory format
//   - every AG's superblock copy, AGF and AGI header are checked (magic,
//     CRC on v5); damage is reported in Problems(), not fatal
//   - inodes located directly from the inode number (AG number, AG block,
//     slot); dinode v1/v2/v3 cores, the nrext64 large extent counters,
//     bigtime timestamps (v5) and creation time (v3)
//   - data forks: local (shortform directories, inline symlinks), extent
//     lists and B+tree extent maps (depth, bounds and cycle guards;
//     unwritten extents read as zeros; holes read as zeros)
//   - directories: shortform, block, leaf and node forms. Leaf and node
//     directories are read by scanning every data block below the 32 GiB
//     leaf offset linearly; hash/leaf/free index blocks are not needed
//   - remote (extent) symlinks with or without the v5 block header
//   - reflinked files read as plain extents
//
// Reported, not decoded:
//   - CRC32C mismatches on the superblock, AG headers, inodes, directory
//     and B+tree blocks are counted (Stats()["crc_errors"]) and listed in
//     Problems(); the structure is still used when its magic is right
//   - a dirty log is ignored; the filesystem is read as it is on disk
//
// Unsupported (errors wrap errors.ErrUnsupported):
//   - realtime files (data on the realtime device): listed, reads fail
//   - the metadir and zoned incompatible features, and any unknown
//     incompatible feature bit (Open fails)
//   - v4 filesystems without the v2 directory format (Open fails)
package xfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"sync"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/diskimage/internal/rofs"
)

var be = binary.BigEndian

var castagnoli = crc32.MakeTable(crc32.Castagnoli)

const (
	maxDirBytes   = 64 << 20 // largest directory read into memory
	maxLinkLen    = 1024     // XFS_SYMLINK_MAXLEN
	maxBtreeDepth = 9
	maxExtents    = 1 << 22 // extents accepted for one fork
	maxProblems   = 100
	leafOffset    = 32 << 30 // XFS_DIR2_LEAF_OFFSET: data blocks live below it
)

// Incompatible feature bits (sb_features_incompat).
const (
	incompatFtype    = 1 << 0
	incompatSpinodes = 1 << 1
	incompatMetaUUID = 1 << 2
	incompatBigtime  = 1 << 3
	incompatRepair   = 1 << 4
	incompatNrext64  = 1 << 5
	incompatExchange = 1 << 6
	incompatParent   = 1 << 7
	incompatMetadir  = 1 << 8
	incompatZoned    = 1 << 9
	incompatKnown    = incompatFtype | incompatSpinodes | incompatMetaUUID | incompatBigtime | incompatRepair | incompatNrext64 | incompatExchange | incompatParent
)

func corrupt(format string, a ...any) error {
	return fmt.Errorf("xfs: corrupt: %s", fmt.Sprintf(format, a...))
}

func unsupported(format string, a ...any) error {
	return fmt.Errorf("xfs: %w: %s", errors.ErrUnsupported, fmt.Sprintf(format, a...))
}

type superblock struct {
	blockSize   uint32
	dblocks     uint64
	rblocks     uint64
	uuid        [16]byte
	rootIno     uint64
	agBlocks    uint32
	agCount     uint32
	version     uint16
	versionNum  uint16
	sectSize    uint16
	inodeSize   uint16
	label       string
	blockLog    uint8
	inopbLog    uint8
	agBlkLog    uint8
	dirBlkLog   uint8
	features2   uint32
	compat      uint32
	roCompat    uint32
	incompat    uint32
	logIncompat uint32
	icount      uint64
	ifree       uint64
	crcOK       bool
}

func parseSuper(b []byte) (*superblock, error) {
	if len(b) < 512 || string(b[:4]) != "XFSB" {
		return nil, corrupt("no XFSB superblock magic")
	}
	s := &superblock{
		blockSize:  be.Uint32(b[4:]),
		dblocks:    be.Uint64(b[8:]),
		rblocks:    be.Uint64(b[16:]),
		rootIno:    be.Uint64(b[56:]),
		agBlocks:   be.Uint32(b[84:]),
		agCount:    be.Uint32(b[88:]),
		versionNum: be.Uint16(b[100:]),
		sectSize:   be.Uint16(b[102:]),
		inodeSize:  be.Uint16(b[104:]),
		label:      cstr(b[108:120]),
		blockLog:   b[120],
		inopbLog:   b[123],
		agBlkLog:   b[124],
		icount:     be.Uint64(b[128:]),
		ifree:      be.Uint64(b[136:]),
		dirBlkLog:  b[192],
		features2:  be.Uint32(b[200:]),
	}
	copy(s.uuid[:], b[32:48])
	s.version = s.versionNum & 0xF
	if s.version == 5 {
		s.compat = be.Uint32(b[208:])
		s.roCompat = be.Uint32(b[212:])
		s.incompat = be.Uint32(b[216:])
		s.logIncompat = be.Uint32(b[220:])
	}
	switch {
	case s.version != 4 && s.version != 5:
		return nil, unsupported("superblock version %d", s.version)
	case s.blockSize < 512 || s.blockSize > 65536 || s.blockSize&(s.blockSize-1) != 0 || 1<<s.blockLog != s.blockSize:
		return nil, corrupt("block size %d (log %d)", s.blockSize, s.blockLog)
	case s.sectSize < 512 || s.sectSize > 32768 || s.sectSize&(s.sectSize-1) != 0:
		return nil, corrupt("sector size %d", s.sectSize)
	case s.inodeSize < 256 || s.inodeSize > 2048 || s.inodeSize&(s.inodeSize-1) != 0 || uint32(s.inodeSize) > s.blockSize:
		return nil, corrupt("inode size %d", s.inodeSize)
	case 1<<s.inopbLog != s.blockSize/uint32(s.inodeSize):
		return nil, corrupt("inodes-per-block log %d", s.inopbLog)
	case s.agBlocks < 5 || s.agCount == 0 || s.agCount > 1<<20 || s.agBlkLog > 31 || uint64(1)<<s.agBlkLog < uint64(s.agBlocks) || (s.agBlkLog > 0 && uint64(1)<<(s.agBlkLog-1) >= uint64(s.agBlocks)):
		return nil, corrupt("allocation groups: %d x %d blocks (log %d)", s.agCount, s.agBlocks, s.agBlkLog)
	case s.dirBlkLog > 8 || s.blockSize<<s.dirBlkLog > 65536:
		return nil, corrupt("directory block log %d", s.dirBlkLog)
	case s.dblocks == 0 || s.dblocks > uint64(s.agCount)*uint64(s.agBlocks):
		return nil, corrupt("data blocks %d for %d AGs", s.dblocks, s.agCount)
	}
	if s.version == 5 {
		s.crcOK = crcOK(b[:s.sectSize], 224)
	}
	return s, nil
}

func cstr(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

// crcOK checks the little-endian CRC32C stored at off, computed over b with
// that field zeroed (xfs_verify_cksum).
func crcOK(b []byte, off int) bool {
	if off+4 > len(b) {
		return false
	}
	want := binary.LittleEndian.Uint32(b[off:])
	var zero [4]byte
	c := crc32.Update(0, castagnoli, b[:off])
	c = crc32.Update(c, castagnoli, zero[:])
	c = crc32.Update(c, castagnoli, b[off+4:])
	return c == want
}

func (s *superblock) hasFtype() bool {
	if s.version == 5 {
		return s.incompat&incompatFtype != 0
	}
	return s.features2&0x200 != 0 // XFS_SB_VERSION2_FTYPE
}

func (s *superblock) fsName() string {
	if s.version == 5 {
		return "xfs"
	}
	return "xfs-v4"
}

// Probe reports whether r holds an XFS superblock this package can parse.
func Probe(r io.ReaderAt, size int64) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if r == nil || size < 4096 {
		return false
	}
	b := make([]byte, 512)
	if rofs.ReadFull(r, b, 0) != nil || string(b[:4]) != "XFSB" {
		return false
	}
	_, err := parseSuper(b)
	return err == nil || errors.Is(err, errors.ErrUnsupported)
}

// FS is a read-only XFS filesystem. It implements fs.FS, fs.ReadDirFS and
// fs.StatFS and is safe for concurrent use.
type FS struct {
	*rofs.FS
	r    io.ReaderAt
	size int64
	sb   *superblock

	mu       sync.Mutex
	problems []string
}

// Open parses the superblock and AG headers of the XFS filesystem in r
// (size bytes long) and returns it as an fs.FS.
func Open(r io.ReaderAt, size int64) (_ fs.FS, err error) {
	defer rofs.Guard("xfs", "open", ".", &err)
	if r == nil || size < 4096 {
		return nil, corrupt("image too small (%d bytes)", size)
	}
	b := make([]byte, 32768)
	n, _ := r.ReadAt(b, 0)
	if n < 512 {
		return nil, corrupt("cannot read superblock")
	}
	sb, err := parseSuper(b[:n])
	if err != nil {
		return nil, err
	}
	if int(sb.sectSize) > n {
		return nil, corrupt("short superblock read")
	}
	if sb.version == 4 && sb.versionNum&0x2000 == 0 { // XFS_SB_VERSION_DIRV2BIT
		return nil, unsupported("v4 filesystem with version 1 directories")
	}
	if sb.incompat&incompatMetadir != 0 {
		return nil, unsupported("metadir feature (metadata directory tree)")
	}
	if sb.incompat&incompatZoned != 0 {
		return nil, unsupported("zoned feature (zoned realtime device)")
	}
	if bad := sb.incompat &^ (incompatKnown); bad != 0 {
		return nil, unsupported("unknown incompatible features 0x%x", bad)
	}
	if want := sb.dblocks * uint64(sb.blockSize); want > uint64(size) {
		return nil, corrupt("truncated image: filesystem declares %d bytes, image has %d", want, size)
	}
	f := &FS{r: r, size: size, sb: sb}
	f.FS = rofs.New(f, max(size/16, 1<<20))
	for _, k := range []string{"crc_errors", "corrupt_entries", "dirs_read", "unsupported_files"} {
		f.Bump(k, 0)
	}
	if sb.version == 5 && !sb.crcOK {
		f.damage("primary superblock CRC mismatch")
	}
	if sb.incompat&incompatRepair != 0 {
		f.problem("needsrepair flag set: xfs_repair was interrupted; structures may be inconsistent")
	}
	if sb.rblocks > 0 {
		f.problem(fmt.Sprintf("realtime device of %d blocks: realtime file data is not read (UNSUPPORTED)", sb.rblocks))
	}
	f.checkAGs()
	root, err := f.Root()
	if err != nil {
		return nil, fmt.Errorf("xfs: root inode: %w", err)
	}
	if !root.IsDir() {
		return nil, corrupt("root inode is not a directory")
	}
	return f, nil
}

// checkAGs verifies each AG's superblock copy, AGF and AGI headers.
func (f *FS) checkAGs() {
	sb := f.sb
	ss := int(sb.sectSize)
	buf := make([]byte, 4*ss)
	for ag := uint32(0); ag < sb.agCount && ag < 1024; ag++ {
		off := int64(ag) * int64(sb.agBlocks) * int64(sb.blockSize)
		if rofs.ReadFull(f.r, buf, off) != nil {
			f.damage(fmt.Sprintf("AG %d headers unreadable", ag))
			continue
		}
		if string(buf[:4]) != "XFSB" {
			f.damage(fmt.Sprintf("AG %d superblock magic missing", ag))
		} else if sb.version == 5 && !crcOK(buf[:ss], 224) && ag > 0 {
			f.damage(fmt.Sprintf("AG %d superblock CRC mismatch", ag))
		}
		agf, agi := buf[ss:2*ss], buf[2*ss:3*ss]
		if string(agf[:4]) != "XAGF" || be.Uint32(agf[8:]) != ag {
			f.damage(fmt.Sprintf("AG %d AGF header invalid", ag))
		} else if sb.version == 5 && !crcOK(agf, 216) {
			f.damage(fmt.Sprintf("AG %d AGF CRC mismatch", ag))
		}
		if string(agi[:4]) != "XAGI" || be.Uint32(agi[8:]) != ag {
			f.damage(fmt.Sprintf("AG %d AGI header invalid", ag))
		} else if sb.version == 5 && !crcOK(agi, 312) {
			f.damage(fmt.Sprintf("AG %d AGI CRC mismatch", ag))
		}
	}
	if sb.agCount > 1024 {
		f.problem(fmt.Sprintf("%d AGs; headers of AGs beyond 1024 not checked", sb.agCount))
	}
}

func (f *FS) problem(p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.problems) < maxProblems {
		f.problems = append(f.problems, p)
	}
}

func (f *FS) damage(p string) {
	f.Bump("crc_errors", 1)
	f.problem(p)
}

// Problems lists damage and unsupported structures met so far.
func (f *FS) Problems() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.problems...)
}

// Stats returns counters: crc_errors, corrupt_entries, dirs_read,
// unsupported_files and cycles.
func (f *FS) Stats() map[string]int64 { return f.Counters() }

// Metadata returns volume-level facts.
func (f *FS) Metadata() map[string]any {
	sb := f.sb
	u := sb.uuid
	return map[string]any{
		"fs":               sb.fsName(),
		"label":            sb.label,
		"uuid":             fmt.Sprintf("%x-%x-%x-%x-%x", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16]),
		"block_size":       sb.blockSize,
		"blocks":           sb.dblocks,
		"ag_count":         sb.agCount,
		"inodes":           sb.icount,
		"inode_size":       sb.inodeSize,
		"version":          sb.version,
		"realtime_blocks":  sb.rblocks,
		"feature_incompat": sb.incompat,
		"feature_ro":       sb.roCompat,
	}
}

// FSName implements rofs.Backend.
func (f *FS) FSName() string { return "xfs" }

// ---- inodes ----

type inode struct {
	ino      uint64
	mode     uint16
	version  uint8
	format   uint8
	uid, gid uint32
	nlink    uint32
	size     int64
	nextents uint64
	flags    uint16
	flags2   uint64
	atime    time.Time
	mtime    time.Time
	ctime    time.Time
	btime    time.Time
	fork     []byte // data fork bytes
}

func (in *inode) fmtBits() uint16 { return in.mode & 0xF000 }
func (in *inode) isDir() bool     { return in.fmtBits() == 0x4000 }
func (in *inode) isReg() bool     { return in.fmtBits() == 0x8000 }
func (in *inode) isLink() bool    { return in.fmtBits() == 0xA000 }

const (
	fmtDev     = 0
	fmtLocal   = 1
	fmtExtents = 2
	fmtBtree   = 3

	diflagRealtime = 0x1
	diflag2Bigtime = 1 << 3
	diflag2Nrext64 = 1 << 4
)

// inoLocation returns the byte offset of an inode, or an error when the
// number cannot address one.
func (f *FS) inoLocation(ino uint64) (int64, error) {
	sb := f.sb
	shift := uint(sb.agBlkLog) + uint(sb.inopbLog)
	agno := ino >> shift
	agbno := (ino >> sb.inopbLog) & (1<<sb.agBlkLog - 1)
	slot := ino & (1<<sb.inopbLog - 1)
	if ino == 0 || agno >= uint64(sb.agCount) || agbno >= uint64(sb.agBlocks) {
		return 0, corrupt("inode number %d out of range", ino)
	}
	off := (agno*uint64(sb.agBlocks)+agbno)*uint64(sb.blockSize) + slot*uint64(sb.inodeSize)
	if off+uint64(sb.inodeSize) > uint64(f.size) {
		return 0, corrupt("inode %d lies past the end of the image", ino)
	}
	return int64(off), nil
}

func (f *FS) readInode(ino uint64) (*inode, error) {
	off, err := f.inoLocation(ino)
	if err != nil {
		return nil, err
	}
	b := make([]byte, f.sb.inodeSize)
	if err := rofs.ReadFull(f.r, b, off); err != nil {
		return nil, fmt.Errorf("xfs: read inode %d: %w", ino, err)
	}
	if string(b[:2]) != "IN" {
		return nil, corrupt("inode %d: bad magic", ino)
	}
	in := &inode{
		ino:     ino,
		mode:    be.Uint16(b[2:]),
		version: b[4],
		format:  b[5],
		uid:     be.Uint32(b[8:]),
		gid:     be.Uint32(b[12:]),
		nlink:   be.Uint32(b[16:]),
		size:    int64(be.Uint64(b[56:])),
		flags:   be.Uint16(b[90:]),
	}
	core := 100
	switch in.version {
	case 1:
		in.nlink = uint32(be.Uint16(b[6:]))
	case 2:
	case 3:
		if f.sb.version != 5 {
			return nil, corrupt("inode %d: v3 inode on a v4 filesystem", ino)
		}
		core = 176
		if !crcOK(b, 100) {
			f.damage(fmt.Sprintf("inode %d CRC mismatch", ino))
		}
		if got := be.Uint64(b[152:]); got != ino {
			return nil, corrupt("inode %d: records inode number %d", ino, got)
		}
		in.flags2 = be.Uint64(b[120:])
	default:
		return nil, corrupt("inode %d: version %d", ino, in.version)
	}
	if f.sb.version == 5 && in.version != 3 {
		return nil, corrupt("inode %d: version %d on a v5 filesystem", ino, in.version)
	}
	if in.size < 0 {
		return nil, corrupt("inode %d: negative size", ino)
	}
	if in.flags2&diflag2Nrext64 != 0 {
		in.nextents = be.Uint64(b[24:])
	} else {
		in.nextents = uint64(be.Uint32(b[76:]))
	}
	big := in.flags2&diflag2Bigtime != 0
	in.atime = decodeTime(b[32:40], big)
	in.mtime = decodeTime(b[40:48], big)
	in.ctime = decodeTime(b[48:56], big)
	if in.version == 3 {
		in.btime = decodeTime(b[144:152], big)
	}
	forkoff := int(b[82]) * 8
	end := len(b)
	if forkoff != 0 {
		if core+forkoff > len(b) {
			return nil, corrupt("inode %d: attribute fork offset %d", ino, forkoff)
		}
		end = core + forkoff
	}
	in.fork = b[core:end]
	return in, nil
}

// decodeTime decodes an XFS timestamp: seconds + nanoseconds (big-endian
// int32/uint32), or with bigtime nanoseconds since 1901-12-13T20:45:52Z.
func decodeTime(b []byte, bigtime bool) time.Time {
	if bigtime {
		v := be.Uint64(b)
		const off = int64(1) << 31
		sec := int64(v/1e9) - off
		return time.Unix(sec, int64(v%1e9)).UTC()
	}
	sec := int32(be.Uint32(b))
	ns := be.Uint32(b[4:])
	if ns >= 1e9 {
		ns = 0
	}
	if sec == 0 && ns == 0 {
		return time.Time{}
	}
	return time.Unix(int64(sec), int64(ns)).UTC()
}

// ---- extent maps ----

type extent struct {
	off, block, count uint64 // file block, fs block, length in blocks
	unwritten         bool
}

func decodeExtent(b []byte) extent {
	l0, l1 := be.Uint64(b), be.Uint64(b[8:])
	return extent{
		unwritten: l0>>63 != 0,
		off:       (l0 & (1<<63 - 1)) >> 9,
		block:     (l0&0x1ff)<<43 | l1>>21,
		count:     l1 & (1<<21 - 1),
	}
}

// fsbToByte converts a filesystem block number (AG number << agblklog | AG
// block) into a byte offset in the image.
func (f *FS) fsbToByte(fsb uint64) (int64, error) {
	sb := f.sb
	ag := fsb >> sb.agBlkLog
	agb := fsb & (1<<sb.agBlkLog - 1)
	if ag >= uint64(sb.agCount) || agb >= uint64(sb.agBlocks) {
		return 0, corrupt("block %d out of range", fsb)
	}
	return int64((ag*uint64(sb.agBlocks) + agb) * uint64(sb.blockSize)), nil
}

// extents returns the data fork's extent list sorted by file offset.
func (f *FS) extents(in *inode) ([]extent, error) {
	switch in.format {
	case fmtExtents:
		if in.nextents > uint64(len(in.fork)/16) {
			return nil, corrupt("inode %d: %d extents do not fit the fork", in.ino, in.nextents)
		}
		out := make([]extent, 0, in.nextents)
		for i := uint64(0); i < in.nextents; i++ {
			out = append(out, decodeExtent(in.fork[16*i:]))
		}
		return f.checkExtents(in, out)
	case fmtBtree:
		return f.btreeExtents(in)
	case fmtLocal:
		return nil, nil
	}
	return nil, corrupt("inode %d: data fork format %d", in.ino, in.format)
}

func (f *FS) checkExtents(in *inode, ex []extent) ([]extent, error) {
	var next uint64
	for i, e := range ex {
		if e.count == 0 || e.off < next || e.off+e.count < e.off {
			return nil, corrupt("inode %d: extent %d (offset %d, %d blocks) overlaps or is empty", in.ino, i, e.off, e.count)
		}
		if _, err := f.fsbToByte(e.block); err != nil {
			return nil, fmt.Errorf("inode %d extent %d: %w", in.ino, i, err)
		}
		next = e.off + e.count
	}
	return ex, nil
}

// btreeExtents walks the inode-rooted bmap B+tree.
func (f *FS) btreeExtents(in *inode) ([]extent, error) {
	root := in.fork
	if len(root) < 4 {
		return nil, corrupt("inode %d: bmap root too small", in.ino)
	}
	level := int(be.Uint16(root))
	nrecs := int(be.Uint16(root[2:]))
	maxr := (len(root) - 4) / 16
	if level == 0 || level > maxBtreeDepth || nrecs == 0 || nrecs > maxr {
		return nil, corrupt("inode %d: bmap root level %d, %d records", in.ino, level, nrecs)
	}
	w := &bmapWalk{f: f, ino: in.ino, seen: map[uint64]bool{}}
	for i := 0; i < nrecs; i++ {
		ptr := be.Uint64(root[4+maxr*8+i*8:])
		if err := w.walk(ptr, level-1); err != nil {
			return nil, err
		}
	}
	if uint64(len(w.out)) != in.nextents {
		f.problem(fmt.Sprintf("inode %d: bmap tree holds %d extents, inode records %d", in.ino, len(w.out), in.nextents))
	}
	return f.checkExtents(in, w.out)
}

type bmapWalk struct {
	f    *FS
	ino  uint64
	seen map[uint64]bool
	out  []extent
}

func (w *bmapWalk) walk(fsb uint64, level int) error {
	f := w.f
	if w.seen[fsb] {
		return corrupt("inode %d: bmap tree cycle at block %d", w.ino, fsb)
	}
	w.seen[fsb] = true
	off, err := f.fsbToByte(fsb)
	if err != nil {
		return fmt.Errorf("inode %d bmap: %w", w.ino, err)
	}
	b := make([]byte, f.sb.blockSize)
	if err := rofs.ReadFull(f.r, b, off); err != nil {
		return err
	}
	hdr := 24
	magic := "BMAP"
	if f.sb.version == 5 {
		hdr, magic = 72, "BMA3"
	}
	if string(b[:4]) != magic {
		return corrupt("inode %d: bmap block %d bad magic", w.ino, fsb)
	}
	if f.sb.version == 5 {
		if !crcOK(b, 64) {
			f.damage(fmt.Sprintf("inode %d: bmap block %d CRC mismatch", w.ino, fsb))
		}
		if owner := be.Uint64(b[56:]); owner != w.ino {
			return corrupt("inode %d: bmap block %d owned by inode %d", w.ino, fsb, owner)
		}
	}
	lvl := int(be.Uint16(b[4:]))
	n := int(be.Uint16(b[6:]))
	if lvl != level {
		return corrupt("inode %d: bmap block %d level %d, expected %d", w.ino, fsb, lvl, level)
	}
	if level == 0 {
		if n > (len(b)-hdr)/16 {
			return corrupt("inode %d: bmap leaf %d holds %d records", w.ino, fsb, n)
		}
		if len(w.out)+n > maxExtents {
			return corrupt("inode %d: more than %d extents", w.ino, maxExtents)
		}
		for i := 0; i < n; i++ {
			w.out = append(w.out, decodeExtent(b[hdr+16*i:]))
		}
		return nil
	}
	maxr := (len(b) - hdr) / 16
	if n > maxr {
		return corrupt("inode %d: bmap node %d holds %d records", w.ino, fsb, n)
	}
	for i := 0; i < n; i++ {
		if err := w.walk(be.Uint64(b[hdr+maxr*8+i*8:]), level-1); err != nil {
			return err
		}
	}
	return nil
}

// runs maps a fork's extents to image byte ranges.
func (f *FS) runs(in *inode) (*rofs.Runs, error) {
	ex, err := f.extents(in)
	if err != nil {
		return nil, err
	}
	bs := int64(f.sb.blockSize)
	m := &rofs.Runs{R: f.r, Size: f.size}
	for _, e := range ex {
		phys, _ := f.fsbToByte(e.block)
		// An extent may cross into the next AG's numbering only when
		// corrupt: its end must stay inside its own AG.
		if (e.block&(1<<f.sb.agBlkLog-1))+e.count > uint64(f.sb.agBlocks) {
			return nil, corrupt("inode %d: extent at block %d runs past its AG", in.ino, e.block)
		}
		m.Items = append(m.Items, rofs.Run{Logical: int64(e.off) * bs, Physical: phys, Length: int64(e.count) * bs, Zero: e.unwritten})
	}
	return m, nil
}

// ---- rofs.Backend ----

func (f *FS) node(in *inode) *rofs.Node {
	sys := map[string]any{
		"inode": in.ino,
		"mtime": in.mtime,
		"atime": in.atime,
		"ctime": in.ctime,
		"fs":    f.sb.fsName(),
		"mode":  uint32(in.mode),
		"uid":   in.uid,
		"gid":   in.gid,
		"links": in.nlink,
	}
	if !in.btime.IsZero() {
		sys["btime"] = in.btime
	}
	if in.flags&diflagRealtime != 0 {
		sys["unsupported"] = "realtime file (data on the realtime device)"
	}
	if in.ino == f.sb.rootIno {
		for k, v := range f.Metadata() {
			if k != "fs" {
				sys[k] = v
			}
		}
	}
	return &rofs.Node{ID: in.ino, Mode: rofs.UnixMode(uint32(in.mode)), Size: in.size, MTime: in.mtime, Sys: sys, Impl: in}
}

// Root implements rofs.Backend.
func (f *FS) Root() (*rofs.Node, error) {
	in, err := f.readInode(f.sb.rootIno)
	if err != nil {
		return nil, err
	}
	return f.node(in), nil
}

// Load implements rofs.Backend.
func (f *FS) Load(d rofs.Dirent) (*rofs.Node, error) {
	in, err := f.readInode(d.ID)
	if err != nil {
		return nil, err
	}
	return f.node(in), nil
}

// Data implements rofs.Backend.
func (f *FS) Data(n *rofs.Node) (io.ReaderAt, error) {
	in := n.Impl.(*inode)
	if in.flags&diflagRealtime != 0 {
		return nil, unsupported("inode %d: realtime file; data lives on the realtime device", in.ino)
	}
	if in.format != fmtExtents && in.format != fmtBtree {
		return nil, corrupt("inode %d: regular file with data fork format %d", in.ino, in.format)
	}
	return f.runs(in)
}

// Link implements rofs.Backend.
func (f *FS) Link(n *rofs.Node) (string, error) {
	in := n.Impl.(*inode)
	if in.size <= 0 || in.size > maxLinkLen {
		return "", corrupt("symlink inode %d length %d", in.ino, in.size)
	}
	if in.format == fmtLocal {
		if in.size > int64(len(in.fork)) {
			return "", corrupt("symlink inode %d: inline target longer than the fork", in.ino)
		}
		return string(in.fork[:in.size]), nil
	}
	ex, err := f.extents(in)
	if err != nil {
		return "", err
	}
	bs := int64(f.sb.blockSize)
	var out []byte
	for _, e := range ex {
		for i := uint64(0); i < e.count && int64(len(out)) < in.size; i++ {
			off, err := f.fsbToByte(e.block + i)
			if err != nil {
				return "", err
			}
			b := make([]byte, bs)
			if err := rofs.ReadFull(f.r, b, off); err != nil {
				return "", err
			}
			if f.sb.version == 5 {
				if string(b[:4]) != "XSLM" {
					return "", corrupt("symlink inode %d: remote block bad magic", in.ino)
				}
				nb := int64(be.Uint32(b[8:]))
				if nb > bs-56 {
					return "", corrupt("symlink inode %d: remote block length %d", in.ino, nb)
				}
				if !crcOK(b, 12) {
					f.damage(fmt.Sprintf("symlink inode %d: remote block CRC mismatch", in.ino))
				}
				out = append(out, b[56:56+nb]...)
			} else {
				out = append(out, b...)
			}
		}
	}
	if int64(len(out)) < in.size {
		return "", corrupt("symlink inode %d: target truncated", in.ino)
	}
	return string(out[:in.size]), nil
}

// List implements rofs.Backend.
func (f *FS) List(n *rofs.Node) ([]rofs.Dirent, error) {
	in := n.Impl.(*inode)
	var out []rofs.Dirent
	var err error
	switch in.format {
	case fmtLocal:
		out, err = f.shortform(in)
	case fmtExtents, fmtBtree:
		out, err = f.blockDir(in)
	default:
		err = corrupt("directory inode %d: data fork format %d", in.ino, in.format)
	}
	if err != nil {
		return nil, err
	}
	f.Bump("dirs_read", 1)
	return out, nil
}

func (f *FS) dirent(name []byte, ino uint64, ftype uint8) (rofs.Dirent, bool) {
	if !rofs.ValidName(name) || ino == 0 {
		if string(name) != "." && string(name) != ".." {
			f.Bump("corrupt_entries", 1)
		}
		return rofs.Dirent{}, false
	}
	if _, err := f.inoLocation(ino); err != nil {
		f.Bump("corrupt_entries", 1)
		return rofs.Dirent{}, false
	}
	t := rofs.UnknownType
	if f.sb.hasFtype() {
		t = rofs.DirentType(ftype)
	}
	return rofs.Dirent{Name: string(name), ID: ino, Type: t}, true
}

// shortform parses a local-format directory held in the inode.
func (f *FS) shortform(in *inode) ([]rofs.Dirent, error) {
	b := in.fork
	if in.size < 6 || in.size > int64(len(b)) {
		return nil, corrupt("directory inode %d: shortform size %d", in.ino, in.size)
	}
	b = b[:in.size]
	count, i8 := int(b[0]), b[1]
	inoLen := 4
	pos := 6
	if i8 != 0 && len(b) >= 10 { // every inode number is 8 bytes, the parent included
		inoLen, pos = 8, 10
	}
	ft := 0
	if f.sb.hasFtype() {
		ft = 1
	}
	var out []rofs.Dirent
	for i := 0; i < count; i++ {
		if pos+3 > len(b) {
			return nil, corrupt("directory inode %d: shortform entry %d truncated", in.ino, i)
		}
		nl := int(b[pos])
		end := pos + 3 + nl + ft + inoLen
		if nl == 0 || end > len(b) {
			return nil, corrupt("directory inode %d: shortform entry %d truncated", in.ino, i)
		}
		name := b[pos+3 : pos+3+nl]
		var ftype uint8
		if ft == 1 {
			ftype = b[pos+3+nl]
		}
		ip := b[pos+3+nl+ft : end]
		var ino uint64
		if inoLen == 8 {
			ino = be.Uint64(ip)
		} else {
			ino = uint64(be.Uint32(ip))
		}
		if d, ok := f.dirent(name, ino, ftype); ok {
			out = append(out, d)
		}
		pos = end
	}
	return out, nil
}

// blockDir reads every directory data block (block, leaf and node forms).
func (f *FS) blockDir(in *inode) ([]rofs.Dirent, error) {
	ex, err := f.extents(in)
	if err != nil {
		return nil, err
	}
	bs := uint64(f.sb.blockSize)
	dbs := bs << f.sb.dirBlkLog
	var total uint64
	for _, e := range ex {
		if e.off*bs < leafOffset {
			total += e.count * bs
		}
	}
	if total > maxDirBytes || total > uint64(f.size) {
		return nil, corrupt("directory inode %d: %d bytes of data blocks", in.ino, total)
	}
	m, err := f.runs(in)
	if err != nil {
		return nil, err
	}
	var out []rofs.Dirent
	buf := make([]byte, dbs)
	for _, e := range ex {
		start := e.off * bs
		if start >= leafOffset {
			continue
		}
		end := min((e.off+e.count)*bs, leafOffset)
		// Directory blocks are dirblksize-aligned in the file's offsets.
		for at := (start + dbs - 1) / dbs * dbs; at+dbs <= end; at += dbs {
			if _, err := m.ReadAt(buf, int64(at)); err != nil {
				return nil, fmt.Errorf("xfs: directory inode %d block at %d: %w", in.ino, at, err)
			}
			if err := f.dataBlock(in, buf, &out); err != nil {
				return nil, err
			}
		}
	}
	return out, nil
}

// dataBlock parses one directory data block (XDB3/XDD3 on v5, XD2B/XD2D on v4).
func (f *FS) dataBlock(in *inode, b []byte, out *[]rofs.Dirent) error {
	magic := string(b[:4])
	hdr := 16
	v5 := f.sb.version == 5
	switch {
	case v5 && (magic == "XDB3" || magic == "XDD3"):
		hdr = 64
		if !crcOK(b, 4) {
			f.damage(fmt.Sprintf("directory inode %d: data block CRC mismatch", in.ino))
		}
		if owner := be.Uint64(b[40:]); owner != in.ino {
			return corrupt("directory inode %d: data block owned by inode %d", in.ino, owner)
		}
	case !v5 && (magic == "XD2B" || magic == "XD2D"):
	default:
		return corrupt("directory inode %d: data block bad magic %q", in.ino, magic)
	}
	end := len(b)
	if magic == "XDB3" || magic == "XD2B" {
		// Single-block form: the leaf array and tail sit at the end.
		count := uint64(be.Uint32(b[len(b)-8:]))
		if count > uint64(len(b))/8 {
			return corrupt("directory inode %d: block tail count %d", in.ino, count)
		}
		end = len(b) - 8 - int(count)*8
		if end < hdr {
			return corrupt("directory inode %d: block leaf overlaps the data", in.ino)
		}
	}
	ft := 0
	if f.sb.hasFtype() {
		ft = 1
	}
	for pos := hdr; pos < end; {
		if pos+8 > end {
			return corrupt("directory inode %d: entry at %d truncated", in.ino, pos)
		}
		if be.Uint16(b[pos:]) == 0xFFFF { // unused space
			l := int(be.Uint16(b[pos+2:]))
			if l < 8 || l%8 != 0 || pos+l > end {
				return corrupt("directory inode %d: free region at %d length %d", in.ino, pos, l)
			}
			pos += l
			continue
		}
		ino := be.Uint64(b[pos:])
		nl := int(b[pos+8])
		size := (8 + 1 + nl + ft + 2 + 7) &^ 7
		if nl == 0 || pos+size > end {
			return corrupt("directory inode %d: entry at %d (name length %d) overruns the block", in.ino, pos, nl)
		}
		var ftype uint8
		if ft == 1 {
			ftype = b[pos+9+nl]
		}
		if d, ok := f.dirent(b[pos+9:pos+9+nl], ino, ftype); ok {
			*out = append(*out, d)
		}
		pos += size
	}
	return nil
}
