// Package apfs reads Apple File System containers from a raw container
// image (the bytes of one APFS partition), read-only, in pure Go. It never
// writes, never replays anything, never decrypts and never follows a
// symbolic link.
//
// Read:
//   - the container superblock (NXSB) and the latest checkpoint whose
//     superblock checksum is valid in a contiguous checkpoint descriptor
//     area (falling back to the block-0 copy, then to older checkpoints)
//   - the container and volume object maps (omap B-trees, newest mapping
//     at or below the wanted transaction)
//   - every volume superblock (APSB) and its file-system tree: inode,
//     directory-record (hashed and plain keys), xattr (embedded and
//     stream), file-extent, sibling-link and dstream records
//   - file data through its extents; clones are just shared extents and
//     sparse holes read as zeros; sealed volumes read extents from the
//     fext tree
//   - nanosecond timestamps (create, modify, change, access), owner,
//     group, mode, link count, BSD and internal flags
//   - hard links (several directory records naming one inode) and
//     symlinks (target from the com.apple.fs.symlink xattr; never resolved)
//   - snapshots: listed (Snapshots) and readable as extra trees under
//     .snapshots/<name>/ by resolving the volume omap at the snapshot's
//     transaction
//   - transparently compressed files (com.apple.decmpfs): zlib, inline
//     and in the resource fork, and uncompressed inline data
//
// Multi-volume containers: a container with one readable volume exposes
// that volume at the root. With more volumes each one is a top-level
// directory named after the volume ("Macintosh HD - Data/Users/…");
// names that are empty, duplicate or contain a slash are made unique and
// path-safe ("volume-3", "Data-2", "a_b").
//
// Reported, not decoded (listed, and reads fail with an error wrapping
// errors.ErrUnsupported and a reason):
//   - encrypted volumes (FileVault / APFS_FS_UNENCRYPTED clear, or
//     encrypted omap mappings): Open fails if no volume is readable,
//     otherwise the volume is listed and reading it fails
//   - compressed files using LZVN, LZFSE, LZBITMAP or any other type
//
// Unsupported (Open fails): Fusion containers, version-1 (pre-release)
// APFS, and a non-contiguous checkpoint descriptor area.
//
// Every object read is checked: Fletcher-64 checksum, object type and the
// object id it was reached by. A mismatch is damage: it is returned as an
// error and counted, never a panic. Allocations are bounded by the
// container size, B-tree walks are bounded in depth and node count and
// detect cycles, and a panic on malformed input is recovered at the
// reader boundary.
package apfs

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"sync"
	"time"
)

var le = binary.LittleEndian

// ErrUnsupported is errors.ErrUnsupported, re-exported for callers.
var ErrUnsupported = errors.ErrUnsupported

var errCorrupt = errors.New("apfs: corrupt")

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errCorrupt, fmt.Sprintf(format, a...))
}

func unsupported(format string, a ...any) error {
	return fmt.Errorf("apfs: %w: %s", errors.ErrUnsupported, fmt.Sprintf(format, a...))
}

const (
	minBlockSize   = 4096
	maxBlockSize   = 65536
	maxTreeDepth   = 16      // btn_level is < 16 in any real tree
	maxCheckpoints = 1 << 16 // descriptor blocks scanned
	maxVolumes     = 100     // NX_MAX_FILE_SYSTEMS
	maxNameLen     = 1024
	maxLinkLen     = 4096
	maxXattrInline = 64 << 10
	maxDecmpfs     = 1 << 30 // uncompressed size accepted for decmpfs files
	cacheLimit     = 1 << 20 // cached directory entries before the cache resets
)

// Object types and flags (obj_phys_t.o_type).
const (
	typeMask      = 0x0000ffff
	objPhysical   = 0x40000000
	objEphemeral  = 0x80000000
	objEncrypted  = 0x10000000
	typeNXSB      = 0x01
	typeBtree     = 0x02
	typeBtreeNode = 0x03
	typeOmap      = 0x0b
	typeFS        = 0x0d
)

// Container features.
const (
	nxIncompatVersion1 = 0x1
	nxIncompatVersion2 = 0x2
	nxIncompatFusion   = 0x100
)

// Volume flags and features.
const (
	fsUnencrypted = 0x1
	fsOnekey      = 0x8

	incompatCaseInsensitive = 0x1
	incompatNormInsensitive = 0x8
	incompatSealed          = 0x20
)

// omap value flags.
const (
	omapValDeleted   = 0x1
	omapValEncrypted = 0x4
	omapValNoHeader  = 0x8
)

// B-tree node flags.
const (
	btnRoot    = 0x1
	btnLeaf    = 0x2
	btnFixedKV = 0x4
)

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

// fletcher64 is the APFS object checksum over b (the checksum field
// excluded by the caller).
func fletcher64(b []byte) uint64 {
	const mod = 0xFFFFFFFF
	var s1, s2 uint64
	for i := 0; i+4 <= len(b); i += 4 {
		s1 = (s1 + uint64(le.Uint32(b[i:]))) % mod
		s2 = (s2 + s1) % mod
	}
	c1 := mod - (s1+s2)%mod
	c2 := mod - (s1+c1)%mod
	return c2<<32 | c1
}

// checksumOK verifies an object's stored Fletcher-64 checksum.
func checksumOK(b []byte) bool {
	return len(b) >= 32 && le.Uint64(b) == fletcher64(b[8:])
}

// Probe reports whether r starts with an APFS container superblock.
func Probe(r io.ReaderAt, size int64) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if r == nil || size < minBlockSize*2 {
		return false
	}
	b := make([]byte, 64)
	if readFull(r, b, 0) != nil || string(b[32:36]) != "NXSB" {
		return false
	}
	bs := le.Uint32(b[36:])
	return bs >= minBlockSize && bs <= maxBlockSize && bs&(bs-1) == 0
}

// container is the parsed container superblock that was chosen.
type container struct {
	r          io.ReaderAt
	size       int64
	bs         int64
	blocks     uint64
	xid        uint64
	omapOID    uint64
	fsOIDs     []uint64
	uuid       [16]byte
	incompat   uint64
	checkpoint string // "descriptor area" or "block 0"
	skipped    []string
}

// readBlock reads physical block paddr (bounds-checked).
func (c *container) readBlock(paddr uint64) ([]byte, error) {
	if paddr == 0 || paddr >= c.blocks || int64(paddr) > (c.size-c.bs)/c.bs {
		return nil, corrupt("block %d outside the container (%d blocks)", paddr, c.blocks)
	}
	b := make([]byte, c.bs)
	if err := readFull(c.r, b, int64(paddr)*c.bs); err != nil {
		return nil, fmt.Errorf("apfs: read block %d: %w", paddr, err)
	}
	return b, nil
}

// readObject reads and verifies an object at paddr: checksum, type and,
// when oid is non-zero, the object id it was reached by.
func (c *container) readObject(paddr uint64, wantType uint32, oid uint64) ([]byte, error) {
	b, err := c.readBlock(paddr)
	if err != nil {
		return nil, err
	}
	if !checksumOK(b) {
		return nil, corrupt("checksum mismatch in block %d (object %d)", paddr, oid)
	}
	if t := le.Uint32(b[24:]) & typeMask; wantType != 0 && t != wantType && !(wantType == typeBtree && t == typeBtreeNode) {
		return nil, corrupt("block %d holds object type 0x%x, want 0x%x", paddr, t, wantType)
	}
	if oid != 0 && le.Uint64(b[8:]) != oid {
		return nil, corrupt("block %d holds object %d, want %d", paddr, le.Uint64(b[8:]), oid)
	}
	return b, nil
}

type nxsb struct {
	bs, blocks uint64
	incompat   uint64
	xid        uint64
	descBlocks uint32
	descBase   uint64
	omapOID    uint64
	maxFS      uint32
	fsOIDs     []uint64
	uuid       [16]byte
}

func parseNXSB(b []byte) (*nxsb, error) {
	if len(b) < 1400 || string(b[32:36]) != "NXSB" {
		return nil, corrupt("no NXSB magic")
	}
	s := &nxsb{
		bs:         uint64(le.Uint32(b[36:])),
		blocks:     le.Uint64(b[40:]),
		incompat:   le.Uint64(b[64:]),
		xid:        le.Uint64(b[16:]),
		descBlocks: le.Uint32(b[104:]),
		descBase:   le.Uint64(b[112:]),
		omapOID:    le.Uint64(b[160:]),
		maxFS:      le.Uint32(b[180:]),
	}
	copy(s.uuid[:], b[72:88])
	if s.bs < minBlockSize || s.bs > maxBlockSize || s.bs&(s.bs-1) != 0 {
		return nil, corrupt("block size %d", s.bs)
	}
	for i := 0; i < maxVolumes; i++ {
		if oid := le.Uint64(b[184+8*i:]); oid != 0 {
			s.fsOIDs = append(s.fsOIDs, oid)
		}
	}
	return s, nil
}

// openContainer picks the latest valid checkpoint.
func openContainer(r io.ReaderAt, size int64) (*container, error) {
	if size < minBlockSize*2 {
		return nil, corrupt("image too small (%d bytes)", size)
	}
	head := make([]byte, minBlockSize)
	if err := readFull(r, head, 0); err != nil {
		return nil, fmt.Errorf("apfs: read block 0: %w", err)
	}
	if string(head[32:36]) != "NXSB" {
		return nil, corrupt("no container superblock (NXSB) at block 0")
	}
	bs := int64(le.Uint32(head[36:]))
	if bs < minBlockSize || bs > maxBlockSize || bs&(bs-1) != 0 {
		return nil, corrupt("block size %d", bs)
	}
	b0 := make([]byte, bs)
	if err := readFull(r, b0, 0); err != nil {
		return nil, fmt.Errorf("apfs: read block 0: %w", err)
	}
	sb0, err := parseNXSB(b0)
	if err != nil {
		return nil, err
	}
	if inc := sb0.incompat; inc&nxIncompatFusion != 0 {
		return nil, unsupported("Fusion container (two devices); image both members and merge them with native tools")
	} else if inc&nxIncompatVersion1 != 0 && inc&nxIncompatVersion2 == 0 {
		return nil, unsupported("APFS version 1 (macOS 10.12 pre-release format)")
	}
	if want := int64(sb0.blocks) * bs; sb0.blocks == 0 || want/bs != int64(sb0.blocks) || want > size {
		return nil, corrupt("truncated image: container declares %d blocks of %d bytes, image has %d bytes", sb0.blocks, bs, size)
	}
	c := &container{r: r, size: size, bs: bs, blocks: sb0.blocks}
	block0OK := checksumOK(b0)
	if !block0OK {
		c.skipped = append(c.skipped, "block-0 superblock checksum mismatch")
	}
	// Walk the checkpoint descriptor area: every valid NXSB there is a
	// checkpoint; newest transaction first.
	type cand struct {
		sb  *nxsb
		at  uint64
		src string
	}
	var cands []cand
	if sb0.descBlocks&0x80000000 != 0 {
		if !block0OK {
			return nil, corrupt("block-0 superblock checksum mismatch and the checkpoint descriptor area is a B-tree")
		}
		return nil, unsupported("non-contiguous checkpoint descriptor area (B-tree); attach read-only with native tools, then collect --import")
	}
	n := uint64(sb0.descBlocks)
	if n > maxCheckpoints || sb0.descBase == 0 || sb0.descBase+n > sb0.blocks {
		if !block0OK {
			return nil, corrupt("checkpoint descriptor area (%d blocks at %d) out of bounds", n, sb0.descBase)
		}
		n = 0
		c.skipped = append(c.skipped, "checkpoint descriptor area out of bounds; using block 0")
	}
	for i := uint64(0); i < n; i++ {
		b, err := c.readBlock(sb0.descBase + i)
		if err != nil || le.Uint32(b[24:])&typeMask != typeNXSB {
			continue
		}
		if !checksumOK(b) {
			c.skipped = append(c.skipped, fmt.Sprintf("checkpoint superblock at block %d: checksum mismatch", sb0.descBase+i))
			continue
		}
		sb, err := parseNXSB(b)
		if err != nil || sb.bs != uint64(bs) || sb.blocks != sb0.blocks {
			continue
		}
		cands = append(cands, cand{sb, sb0.descBase + i, "descriptor area"})
	}
	sort.SliceStable(cands, func(i, j int) bool { return cands[i].sb.xid > cands[j].sb.xid })
	if block0OK {
		cands = append(cands, cand{sb0, 0, "block 0"})
	}
	if len(cands) == 0 {
		return nil, corrupt("no container superblock with a valid checksum (block 0 and %d checkpoint blocks checked)", n)
	}
	// Use the newest checkpoint whose object map opens.
	var lastErr error
	for _, cd := range cands {
		c.xid, c.omapOID, c.fsOIDs, c.uuid, c.incompat = cd.sb.xid, cd.sb.omapOID, cd.sb.fsOIDs, cd.sb.uuid, cd.sb.incompat
		c.checkpoint = cd.src
		if _, err := c.omapRoot(c.omapOID); err != nil {
			lastErr = err
			c.skipped = append(c.skipped, fmt.Sprintf("checkpoint xid %d (%s): object map unreadable: %v", cd.sb.xid, cd.src, err))
			continue
		}
		return c, nil
	}
	return nil, fmt.Errorf("apfs: no usable checkpoint: %w", lastErr)
}

// omapRoot returns the physical root node address of the omap at oid.
func (c *container) omapRoot(oid uint64) (uint64, error) {
	b, err := c.readObject(oid, typeOmap, oid)
	if err != nil {
		return 0, fmt.Errorf("object map: %w", err)
	}
	root := le.Uint64(b[48:])
	if root == 0 {
		return 0, corrupt("object map %d has no tree", oid)
	}
	return root, nil
}

// omap is one object map, resolving virtual oids at or below maxXid.
type omap struct {
	c      *container
	root   uint64
	maxXid uint64
}

type omapVal struct {
	flags uint32
	size  uint32
	paddr uint64
	xid   uint64
}

// lookup returns the newest mapping of oid with xid ≤ maxXid.
func (m *omap) lookup(oid uint64) (omapVal, error) {
	var best omapVal
	found := false
	t := &btree{c: m.c, root: m.root, physical: true, fixedK: 16, fixedV: 16}
	err := t.scan(func(k []byte) int {
		if len(k) < 16 {
			return 1
		}
		ko, kx := le.Uint64(k), le.Uint64(k[8:])
		switch {
		case ko < oid:
			return -1
		case ko > oid:
			return 1
		case kx > m.maxXid:
			return 1
		}
		return 0
	}, func(k, v []byte) bool {
		if len(v) < 16 {
			return true
		}
		best = omapVal{flags: le.Uint32(v), size: le.Uint32(v[4:]), paddr: le.Uint64(v[8:]), xid: le.Uint64(k[8:])}
		found = true
		return true // keys ascend; the last match is the newest
	})
	if err != nil {
		return omapVal{}, err
	}
	if !found || best.flags&omapValDeleted != 0 {
		return omapVal{}, corrupt("object %d not in the object map at xid %d", oid, m.maxXid)
	}
	return best, nil
}

// resolve maps a virtual oid and reads the object.
func (m *omap) resolve(oid uint64, wantType uint32) ([]byte, error) {
	v, err := m.lookup(oid)
	if err != nil {
		return nil, err
	}
	if v.flags&omapValEncrypted != 0 {
		return nil, unsupported("object %d is encrypted", oid)
	}
	if v.flags&omapValNoHeader != 0 {
		return nil, unsupported("object %d has no header (unsupported layout)", oid)
	}
	return m.c.readObject(v.paddr, wantType, oid)
}

// btree is one B-tree: its root and how child pointers resolve.
type btree struct {
	c        *container
	root     uint64 // physical address, or virtual oid when om != nil
	physical bool
	om       *omap
	fixedK   int // key and value sizes of fixed-size trees (0: variable)
	fixedV   int
	budget   *int // node reads left for this tree's owner
}

type node struct {
	b      []byte
	flags  uint16
	level  uint16
	nkeys  int
	toc    int // offset of the table of contents
	keys   int // offset of the key area
	valEnd int // end of the value area
}

func (t *btree) readNode(oid uint64) (*node, error) {
	if t.budget != nil {
		if *t.budget <= 0 {
			return nil, corrupt("B-tree node budget exhausted")
		}
		*t.budget--
	}
	var b []byte
	var err error
	if t.physical {
		b, err = t.c.readObject(oid, typeBtree, oid)
	} else {
		b, err = t.om.resolve(oid, typeBtree)
	}
	if err != nil {
		return nil, err
	}
	n := &node{b: b, flags: le.Uint16(b[32:]), level: le.Uint16(b[34:]), nkeys: int(le.Uint32(b[36:]))}
	tocOff, tocLen := int(le.Uint16(b[40:])), int(le.Uint16(b[42:]))
	n.toc = 56 + tocOff
	n.keys = n.toc + tocLen
	n.valEnd = len(b)
	if n.flags&btnRoot != 0 {
		n.valEnd -= 40 // btree_info_t
	}
	ent := 8
	if n.flags&btnFixedKV != 0 {
		ent = 4
	}
	if n.level >= maxTreeDepth || n.keys > n.valEnd || n.nkeys < 0 || n.nkeys*ent > tocLen {
		return nil, corrupt("B-tree node %d header out of range (level %d, %d keys)", oid, n.level, n.nkeys)
	}
	if (n.level == 0) != (n.flags&btnLeaf != 0) {
		return nil, corrupt("B-tree node %d level %d disagrees with its leaf flag", oid, n.level)
	}
	return n, nil
}

// entry returns key and value i of a node.
func (t *btree) entry(n *node, i int) (k, v []byte, err error) {
	var ko, kl, vo, vl int
	if n.flags&btnFixedKV != 0 {
		e := n.b[n.toc+4*i:]
		ko, vo = int(le.Uint16(e)), int(le.Uint16(e[2:]))
		kl, vl = t.fixedK, t.fixedV
		if n.level > 0 {
			vl = 8
		}
		if kl == 0 {
			return nil, nil, corrupt("fixed-size node in a variable-size tree")
		}
	} else {
		e := n.b[n.toc+8*i:]
		ko, kl, vo, vl = int(le.Uint16(e)), int(le.Uint16(e[2:])), int(le.Uint16(e[4:])), int(le.Uint16(e[6:]))
	}
	ks := n.keys + ko
	if ks+kl > n.valEnd || kl == 0 {
		return nil, nil, corrupt("B-tree key %d out of the node", i)
	}
	if vo == 0xffff { // ghost entry (no value)
		return n.b[ks : ks+kl], nil, nil
	}
	vs := n.valEnd - vo
	if vs < n.keys || vs+vl > n.valEnd {
		return nil, nil, corrupt("B-tree value %d out of the node", i)
	}
	return n.b[ks : ks+kl], n.b[vs : vs+vl], nil
}

// scan visits, in key order, every leaf record for which cmp returns 0.
// cmp orders a key against the wanted range: <0 before it, >0 after it.
// visit returns false to stop. Child pointers are followed depth-first,
// the depth is bounded and a node seen twice on one walk is a cycle.
func (t *btree) scan(cmp func(k []byte) int, visit func(k, v []byte) bool) error {
	seen := map[uint64]bool{}
	_, err := t.walk(t.root, -1, cmp, visit, seen)
	return err
}

func (t *btree) walk(oid uint64, parentLevel int, cmp func([]byte) int, visit func(k, v []byte) bool, seen map[uint64]bool) (bool, error) {
	if seen[oid] {
		return false, corrupt("B-tree cycle: node %d reached twice", oid)
	}
	seen[oid] = true
	n, err := t.readNode(oid)
	if err != nil {
		return false, err
	}
	if parentLevel >= 0 && int(n.level) != parentLevel-1 {
		return false, corrupt("B-tree node %d has level %d under a level-%d parent", oid, n.level, parentLevel)
	}
	if n.level == 0 {
		for i := 0; i < n.nkeys; i++ {
			k, v, err := t.entry(n, i)
			if err != nil {
				return false, err
			}
			c := cmp(k)
			if c < 0 {
				continue
			}
			if c > 0 {
				return false, nil
			}
			if !visit(k, v) {
				return false, nil
			}
		}
		return true, nil
	}
	for i := 0; i < n.nkeys; i++ {
		k, v, err := t.entry(n, i)
		if err != nil {
			return false, err
		}
		if cmp(k) > 0 {
			return false, nil // this child and all later ones start after the range
		}
		if i+1 < n.nkeys {
			nk, _, err := t.entry(n, i+1)
			if err != nil {
				return false, err
			}
			if cmp(nk) < 0 {
				continue // the next child starts before the range ends: this one is wholly before it
			}
		}
		if len(v) < 8 {
			return false, corrupt("B-tree index value too short")
		}
		more, err := t.walk(le.Uint64(v), int(n.level), cmp, visit, seen)
		if err != nil || !more {
			return more, err
		}
	}
	return true, nil
}

// all is a cmp accepting every key.
func all([]byte) int { return 0 }

// ---- volumes ----

// Volume describes one volume of the container.
type Volume struct {
	Index     int        `json:"index"`
	Name      string     `json:"name"`
	Dir       string     `json:"dir,omitempty"` // top-level directory in a multi-volume FS
	Role      string     `json:"role,omitempty"`
	UUID      string     `json:"uuid"`
	Encrypted bool       `json:"encrypted"`
	CaseSens  bool       `json:"case_sensitive"`
	Sealed    bool       `json:"sealed,omitempty"`
	Files     uint64     `json:"files"`
	Dirs      uint64     `json:"directories"`
	Symlinks  uint64     `json:"symlinks"`
	Snapshots []Snapshot `json:"snapshots,omitempty"`
	LastMod   time.Time  `json:"last_modified"`
	Problem   string     `json:"problem,omitempty"` // why the volume is not readable
}

// Snapshot is one volume snapshot.
type Snapshot struct {
	Name    string    `json:"name"`
	XID     uint64    `json:"xid"`
	Created time.Time `json:"created"`
	Dir     string    `json:"dir"` // path of its tree inside the FS
}

func nsTime(v uint64) time.Time {
	if v == 0 || v > 1<<62 {
		return time.Time{}
	}
	return time.Unix(0, int64(v)).UTC()
}

func roleName(r uint16) string {
	switch r {
	case 0:
		return ""
	case 1:
		return "system"
	case 2:
		return "user"
	case 4:
		return "recovery"
	case 8:
		return "vm"
	case 16:
		return "preboot"
	case 32:
		return "installer"
	}
	switch r >> 6 {
	case 1:
		return "data"
	case 2:
		return "baseband"
	case 3:
		return "update"
	case 4:
		return "xart"
	case 5:
		return "hardware"
	case 6:
		return "backup"
	case 9:
		return "enterprise"
	case 11:
		return "prelogin"
	}
	return fmt.Sprintf("0x%x", r)
}

func cstring(b []byte) string {
	if i := strings.IndexByte(string(b), 0); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func uuidString(u []byte) string {
	return fmt.Sprintf("%X-%X-%X-%X-%X", u[0:4], u[4:6], u[6:8], u[8:10], u[10:16])
}

// FS is a read-only APFS container exposed as one fs.FS. It implements
// fs.FS, fs.ReadDirFS, fs.StatFS and ReadLink, and is safe for concurrent
// use.
type FS struct {
	c       *container
	vols    []*Volume
	trees   []*tree // readable trees: live volumes then snapshots
	root    *virtDir
	multi   bool
	mu      sync.Mutex
	stats   map[string]int64
	problem []string
}

// virtDir is a directory that exists only in the exposed layout (the
// container root of a multi-volume FS, .snapshots).
type virtDir struct {
	name     string
	children map[string]any // *virtDir, *tree (mounted at that name) or error (listed, unreadable)
	order    []string
}

func (d *virtDir) add(name string, v any) {
	if _, ok := d.children[name]; !ok {
		d.order = append(d.order, name)
	}
	d.children[name] = v
}

// Open parses the APFS container in r (size bytes long) and returns it as
// an fs.FS.
func Open(r io.ReaderAt, size int64) (_ fs.FS, err error) {
	defer guard("open", ".", &err)
	return OpenFS(r, size)
}

// OpenFS is Open with the concrete type.
func OpenFS(r io.ReaderAt, size int64) (_ *FS, err error) {
	defer guard("open", ".", &err)
	if r == nil {
		return nil, corrupt("nil reader")
	}
	c, err := openContainer(r, size)
	if err != nil {
		return nil, err
	}
	croot, err := c.omapRoot(c.omapOID)
	if err != nil {
		return nil, err
	}
	com := &omap{c: c, root: croot, maxXid: c.xid}
	f := &FS{c: c, stats: map[string]int64{"corrupt_records": 0, "unsupported_files": 0, "dirs_read": 0}}
	f.problem = append(f.problem, c.skipped...)
	if len(c.fsOIDs) == 0 {
		return nil, corrupt("container has no volumes")
	}
	var live []*tree
	for i, oid := range c.fsOIDs {
		v := &Volume{Index: i + 1}
		f.vols = append(f.vols, v)
		t, err := f.openVolume(com, oid, v)
		if err != nil {
			v.Problem = err.Error()
			f.problem = append(f.problem, fmt.Sprintf("volume %d %q: %v", v.Index, v.Name, err))
			continue
		}
		live = append(live, t)
	}
	if len(live) == 0 {
		var why []string
		allUnsupported := true
		for _, v := range f.vols {
			why = append(why, fmt.Sprintf("%q: %s", v.Name, v.Problem))
			allUnsupported = allUnsupported && v.Encrypted
		}
		if allUnsupported {
			return nil, unsupported("no readable volume: %s", strings.Join(why, "; "))
		}
		return nil, fmt.Errorf("apfs: no readable volume: %s", strings.Join(why, "; "))
	}
	f.multi = len(f.vols) > 1
	f.layout(live)
	return f, nil
}

// layout builds the exposed directory structure.
func (f *FS) layout(live []*tree) {
	f.root = &virtDir{name: ".", children: map[string]any{}}
	used := map[string]bool{}
	byVol := map[*Volume]*tree{}
	for _, t := range live {
		byVol[t.vol] = t
	}
	for _, v := range f.vols {
		t := byVol[v]
		if !f.multi {
			// One volume: it is the root.
			f.trees = append(f.trees, t)
			t.ns = 0
			f.addSnapshots(t, "")
			continue
		}
		name := safeName(v.Name, v.Index, used)
		v.Dir = name
		if t == nil {
			f.root.add(name, unsupportedVolume(v))
			continue
		}
		t.ns = uint64(len(f.trees))
		f.trees = append(f.trees, t)
		f.root.add(name, t)
		f.addSnapshots(t, name)
	}
}

func unsupportedVolume(v *Volume) error {
	if v.Encrypted {
		return unsupported("volume %q is encrypted (FileVault); decryption is not supported: unlock and mount it read-only with native tools (diskutil apfs unlockVolume -readOnly), then collect --import", v.Name)
	}
	return fmt.Errorf("volume %q not readable: %s", v.Name, v.Problem)
}

// safeName makes a volume name a usable, unique path element.
func safeName(name string, idx int, used map[string]bool) string {
	n := strings.Map(func(r rune) rune {
		if r == '/' || r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, name)
	if n == "" || n == "." || n == ".." {
		n = fmt.Sprintf("volume-%d", idx)
	}
	if used[n] {
		n = fmt.Sprintf("%s-%d", n, idx)
	}
	used[n] = true
	return n
}

// openVolume reads a volume superblock and prepares its live tree.
func (f *FS) openVolume(com *omap, oid uint64, v *Volume) (*tree, error) {
	b, err := com.resolve(oid, typeFS)
	if err != nil {
		return nil, fmt.Errorf("volume superblock: %w", err)
	}
	if string(b[32:36]) != "APSB" {
		return nil, corrupt("volume superblock %d has no APSB magic", oid)
	}
	sb := parseAPSB(b)
	v.Name = sb.name
	v.Role = roleName(sb.role)
	v.UUID = uuidString(sb.uuid[:])
	v.CaseSens = sb.incompat&incompatCaseInsensitive == 0
	v.Sealed = sb.incompat&incompatSealed != 0
	v.Files, v.Dirs, v.Symlinks = sb.files, sb.dirs, sb.symlinks
	v.LastMod = nsTime(sb.lastMod)
	v.Encrypted = sb.fsFlags&fsUnencrypted == 0
	if v.Encrypted {
		kind := "per-file keys"
		if sb.fsFlags&fsOnekey != 0 {
			kind = "one volume key"
		}
		return nil, unsupported("volume %q is encrypted (FileVault, %s); decryption is not supported: unlock and mount it read-only with native tools (diskutil apfs unlockVolume -readOnly), then collect --import", v.Name, kind)
	}
	t, err := f.newTree(v, sb, 0)
	if err != nil {
		return nil, err
	}
	v.Snapshots = t.listSnapshots()
	return t, nil
}

type apsb struct {
	incompat, fsFlags                  uint64
	omapOID, rootOID, snapOID, fextOID uint64
	files, dirs, symlinks              uint64
	lastMod                            uint64
	uuid                               [16]byte
	name                               string
	role                               uint16
}

func parseAPSB(b []byte) *apsb {
	s := &apsb{
		incompat: le.Uint64(b[56:]),
		omapOID:  le.Uint64(b[128:]),
		rootOID:  le.Uint64(b[136:]),
		snapOID:  le.Uint64(b[152:]),
		files:    le.Uint64(b[184:]),
		dirs:     le.Uint64(b[192:]),
		symlinks: le.Uint64(b[200:]),
		lastMod:  le.Uint64(b[256:]),
		fsFlags:  le.Uint64(b[264:]),
		name:     cstring(b[704:960]),
		role:     le.Uint16(b[964:]),
	}
	copy(s.uuid[:], b[240:256])
	if len(b) >= 1040 {
		s.fextOID = le.Uint64(b[1032:])
	}
	return s
}

// Volumes lists every volume of the container, readable or not.
func (f *FS) Volumes() []Volume {
	out := make([]Volume, len(f.vols))
	for i, v := range f.vols {
		out[i] = *v
	}
	return out
}

// Problems lists damage and unsupported structures met while opening
// (skipped checkpoints, unreadable volumes) and while reading.
func (f *FS) Problems() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.problem...)
}

func (f *FS) noteProblem(format string, a ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.problem) < 200 {
		f.problem = append(f.problem, fmt.Sprintf(format, a...))
	}
}

func (f *FS) bump(key string) {
	f.mu.Lock()
	f.stats[key]++
	f.mu.Unlock()
}

// Stats returns counters accumulated while reading: corrupt_records,
// unsupported_files and dirs_read.
func (f *FS) Stats() map[string]int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int64, len(f.stats))
	for k, v := range f.stats {
		out[k] = v
	}
	return out
}

// Metadata returns container-level facts.
func (f *FS) Metadata() map[string]any {
	names := make([]string, 0, len(f.vols))
	for _, v := range f.vols {
		names = append(names, v.Name)
	}
	return map[string]any{
		"fs":          "apfs",
		"uuid":        uuidString(f.c.uuid[:]),
		"block_size":  f.c.bs,
		"blocks":      f.c.blocks,
		"xid":         f.c.xid,
		"checkpoint":  f.c.checkpoint,
		"volumes":     names,
		"multivolume": f.multi,
	}
}

// guard turns a panic on malformed input into an error.
func guard(op, name string, err *error) {
	if r := recover(); r != nil {
		if rethrowPanics {
			panic(r)
		}
		*err = &fs.PathError{Op: op, Path: name, Err: corrupt("internal error on malformed input: %v", r)}
	}
}

// rethrowPanics makes guard re-panic; set only by tests and fuzzing.
var rethrowPanics bool
