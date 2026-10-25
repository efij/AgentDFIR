// Package hfsplus reads HFS+ and HFSX volumes from a raw volume image,
// read-only, in pure Go. It never writes, never replays the journal and
// never follows a symbolic link.
//
// Read:
//   - the volume header (H+ version 4, HX version 5)
//   - the catalog B-tree: folder and file records, names (UTF-16, stored
//     decomposed; a "/" in a stored name is a ":" in the POSIX name, as
//     the macOS VFS presents it)
//   - the extents-overflow B-tree for forks with more than eight extents
//   - data forks through their extents; resource forks for decmpfs
//   - dates (seconds since 1904, GMT), owner, group, mode, flags
//   - file hard links (best effort): an "hlnk" link record resolves to
//     its indirect node file in the private metadata folder, so every
//     link reports the node's inode number and content; directory hard
//     links resolve through the private directory-data folder
//   - symlinks (target from the data fork; never resolved)
//   - transparently compressed files (com.apple.decmpfs from the
//     attributes B-tree): zlib inline or in the resource fork, and
//     uncompressed inline data; other types (LZVN, LZFSE …) are listed
//     with their real size and reading them returns errors.ErrUnsupported
//
// Reported, not replayed: a journaled volume whose journal holds
// transactions (start ≠ end) is read as it is on disk; Metadata()
// ["journal"] says "dirty (not replayed)" and Problems() lists it.
// The two private metadata folders are not listed (they are reached only
// through hard links) and are counted in Metadata.
//
// Allocations are bounded by the volume size, B-tree walks are bounded
// and detect cycles, malformed structures are errors (never panics).
package hfsplus

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

var be = binary.BigEndian

// ErrUnsupported is errors.ErrUnsupported, re-exported for callers.
var ErrUnsupported = errors.ErrUnsupported

var errCorrupt = errors.New("hfsplus: corrupt")

func corrupt(format string, a ...any) error {
	return fmt.Errorf("%w: %s", errCorrupt, fmt.Sprintf(format, a...))
}

func unsupported(format string, a ...any) error {
	return fmt.Errorf("hfsplus: %w: %s", errors.ErrUnsupported, fmt.Sprintf(format, a...))
}

const (
	vhOffset     = 1024
	rootID       = 2
	extentsID    = 3
	catalogID    = 4
	maxPathDeep  = 256
	maxLinkLen   = 4096
	maxDirEnts   = 1 << 20
	maxExtents   = 1 << 20
	maxAttrBytes = 64 << 20
	cacheLimit   = 1 << 20

	attrJournaled = 0x2000
	attrUnmounted = 0x100
	ufCompressed  = 0x20

	privateDataName = "\x00\x00\x00\x00HFS+ Private Data"
	privateDirName  = ".HFS+ Private Directory Data\r"
)

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

// Probe reports whether r holds an HFS+ or HFSX volume header.
func Probe(r io.ReaderAt, size int64) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if r == nil || size < vhOffset+512 {
		return false
	}
	b := make([]byte, 512)
	if readFull(r, b, vhOffset) != nil {
		return false
	}
	_, err := parseHeader(b)
	return err == nil
}

type extent struct{ start, count uint32 }

type forkData struct {
	size    uint64
	blocks  uint32
	extents [8]extent
}

func parseFork(b []byte) forkData {
	f := forkData{size: be.Uint64(b), blocks: be.Uint32(b[12:])}
	for i := range f.extents {
		f.extents[i] = extent{be.Uint32(b[16+8*i:]), be.Uint32(b[20+8*i:])}
	}
	return f
}

type header struct {
	sig         string
	attributes  uint32
	lastMounted string
	journalInfo uint32
	blockSize   uint32
	totalBlocks uint32
	files       uint32
	folders     uint32
	created     uint32
	modified    uint32
	extents     forkData
	catalog     forkData
	attrs       forkData
}

func parseHeader(b []byte) (*header, error) {
	h := &header{sig: string(b[0:2])}
	v := be.Uint16(b[2:])
	if !(h.sig == "H+" && v == 4) && !(h.sig == "HX" && v == 5) {
		return nil, corrupt("no HFS+ volume header (signature %q version %d)", h.sig, v)
	}
	h.attributes = be.Uint32(b[4:])
	h.lastMounted = string(b[8:12])
	h.journalInfo = be.Uint32(b[12:])
	h.created, h.modified = be.Uint32(b[16:]), be.Uint32(b[20:])
	h.files, h.folders = be.Uint32(b[32:]), be.Uint32(b[36:])
	h.blockSize, h.totalBlocks = be.Uint32(b[40:]), be.Uint32(b[44:])
	if h.blockSize < 512 || h.blockSize > 1<<20 || h.blockSize&(h.blockSize-1) != 0 || h.totalBlocks == 0 {
		return nil, corrupt("block size %d, %d blocks", h.blockSize, h.totalBlocks)
	}
	h.extents = parseFork(b[192:])
	h.catalog = parseFork(b[272:])
	h.attrs = parseFork(b[352:])
	return h, nil
}

func hfsTime(v uint32) time.Time {
	if v == 0 {
		return time.Time{}
	}
	return time.Unix(int64(v)-2082844800, 0).UTC()
}

// FS is a read-only HFS+/HFSX volume. It implements fs.FS, fs.ReadDirFS,
// fs.StatFS and ReadLink, and is safe for concurrent use.
type FS struct {
	r       io.ReaderAt
	size    int64
	h       *header
	bs      int64
	extents *btree
	catalog *btree
	attrs   *btree // nil when the volume has no attributes file
	journal string

	mu        sync.Mutex
	dirCache  map[uint32]*dirList
	cached    int
	private   map[string]uint32 // private folder name → id (0: absent)
	privSeen  bool
	stats     map[string]int64
	problems  []string
	hiddenDir int
}

// Open parses the HFS+ volume in r and returns it as an fs.FS.
func Open(r io.ReaderAt, size int64) (_ fs.FS, err error) {
	defer guard("open", ".", &err)
	return OpenFS(r, size)
}

// OpenFS is Open with the concrete type.
func OpenFS(r io.ReaderAt, size int64) (_ *FS, err error) {
	defer guard("open", ".", &err)
	if r == nil || size < vhOffset+512 {
		return nil, corrupt("image too small (%d bytes)", size)
	}
	b := make([]byte, 512)
	if err := readFull(r, b, vhOffset); err != nil {
		return nil, fmt.Errorf("hfsplus: read volume header: %w", err)
	}
	h, err := parseHeader(b)
	if err != nil {
		return nil, err
	}
	if want := int64(h.totalBlocks) * int64(h.blockSize); want > size {
		return nil, corrupt("truncated image: volume declares %d bytes, image has %d", want, size)
	}
	f := &FS{r: r, size: size, h: h, bs: int64(h.blockSize), dirCache: map[uint32]*dirList{},
		private: map[string]uint32{}, stats: map[string]int64{"corrupt_records": 0, "unsupported_files": 0, "dirs_read": 0}}
	// The extents file's own extents must all be in the header.
	ef, err := f.forkReader(extentsID, 0, h.extents, false)
	if err != nil {
		return nil, fmt.Errorf("hfsplus: extents file: %w", err)
	}
	if f.extents, err = openBtree(f, ef, "extents"); err != nil {
		return nil, err
	}
	cf, err := f.forkReader(catalogID, 0, h.catalog, true)
	if err != nil {
		return nil, fmt.Errorf("hfsplus: catalog file: %w", err)
	}
	if f.catalog, err = openBtree(f, cf, "catalog"); err != nil {
		return nil, err
	}
	if h.attrs.blocks > 0 {
		af, err := f.forkReader(8, 0, h.attrs, true)
		if err == nil {
			f.attrs, err = openBtree(f, af, "attributes")
		}
		if err != nil {
			f.attrs = nil
			f.problem("attributes B-tree unreadable (xattrs and compressed files not decoded): %v", err)
		}
	}
	f.journal = f.journalState()
	if strings.HasPrefix(f.journal, "dirty") {
		f.problem("journal holds transactions that were not replayed; the volume is read as it is on disk")
	}
	if h.attributes&attrUnmounted == 0 {
		f.problem("volume was not cleanly unmounted")
	}
	root, err := f.record(rootID)
	if err != nil {
		return nil, fmt.Errorf("hfsplus: root folder: %w", err)
	}
	if !root.dir {
		return nil, corrupt("root is not a folder")
	}
	return f, nil
}

// journalState reads the journal header without replaying anything.
func (f *FS) journalState() string {
	if f.h.attributes&attrJournaled == 0 {
		return "none"
	}
	jib := make([]byte, 52)
	if f.h.journalInfo == 0 || f.h.journalInfo >= f.h.totalBlocks || readFull(f.r, jib, int64(f.h.journalInfo)*f.bs) != nil {
		return "unreadable (journal info block out of range)"
	}
	if be.Uint32(jib)&0x2 != 0 {
		return "external journal (not read)"
	}
	off := int64(be.Uint64(jib[36:]))
	jh := make([]byte, 24)
	if off <= 0 || off > f.size-24 || readFull(f.r, jh, off) != nil {
		return "unreadable (journal header out of range)"
	}
	var bo binary.ByteOrder = binary.BigEndian
	switch {
	case be.Uint32(jh) == 0x4a4e4c78:
	case binary.LittleEndian.Uint32(jh) == 0x4a4e4c78:
		bo = binary.LittleEndian
	default:
		return "unreadable (bad journal magic)"
	}
	if bo.Uint64(jh[8:]) != bo.Uint64(jh[16:]) {
		return "dirty (not replayed)"
	}
	return "clean"
}

func (f *FS) problem(format string, a ...any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.problems) < 200 {
		f.problems = append(f.problems, fmt.Sprintf(format, a...))
	}
}

func (f *FS) bump(k string) {
	f.mu.Lock()
	f.stats[k]++
	f.mu.Unlock()
}

// Problems lists damage and unsupported structures met so far.
func (f *FS) Problems() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.problems...)
}

// Stats returns counters: corrupt_records, unsupported_files, dirs_read.
func (f *FS) Stats() map[string]int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := map[string]int64{}
	for k, v := range f.stats {
		out[k] = v
	}
	return out
}

func (f *FS) fsName() string {
	if f.h.sig == "HX" {
		return "hfsx"
	}
	return "hfsplus"
}

// Metadata returns volume-level facts.
func (f *FS) Metadata() map[string]any {
	return map[string]any{
		"fs":              f.fsName(),
		"block_size":      f.bs,
		"blocks":          f.h.totalBlocks,
		"files":           f.h.files,
		"folders":         f.h.folders,
		"journal":         f.journal,
		"clean_unmount":   f.h.attributes&attrUnmounted != 0,
		"last_mounted_by": f.h.lastMounted,
		"modified":        hfsTime(f.h.modified),
		"case_sensitive":  f.catalog.compare == 0xBC,
		"private_folders": "not listed (hard-link targets)",
	}
}

// ---- forks ----

type frun struct {
	logical, phys, count int64 // in blocks
}

// fork is a random-access view of one fork.
type fork struct {
	f    *FS
	runs []frun
	size int64
}

// forkReader maps a fork's extents, following the extents-overflow tree
// when overflow is true.
func (f *FS) forkReader(fileID uint32, forkType byte, fd forkData, overflow bool) (*fork, error) {
	if fd.size > uint64(fd.blocks)*uint64(f.bs) {
		return nil, corrupt("fork of file %d: size %d exceeds its %d blocks", fileID, fd.size, fd.blocks)
	}
	if fd.blocks > f.h.totalBlocks {
		return nil, corrupt("fork of file %d: %d blocks on a %d-block volume", fileID, fd.blocks, f.h.totalBlocks)
	}
	fk := &fork{f: f, size: int64(fd.size)}
	var have int64
	add := func(e extent) error {
		if e.count == 0 {
			return nil
		}
		if uint64(e.start)+uint64(e.count) > uint64(f.h.totalBlocks) {
			return corrupt("fork of file %d: extent %d+%d outside the volume", fileID, e.start, e.count)
		}
		if len(fk.runs) >= maxExtents {
			return corrupt("fork of file %d: too many extents", fileID)
		}
		fk.runs = append(fk.runs, frun{have, int64(e.start), int64(e.count)})
		have += int64(e.count)
		return nil
	}
	for _, e := range fd.extents {
		if err := add(e); err != nil {
			return nil, err
		}
	}
	for have < int64(fd.blocks) {
		if !overflow || f.extents == nil {
			return nil, corrupt("fork of file %d: extents cover %d of %d blocks", fileID, have, fd.blocks)
		}
		rec, err := f.overflowRecord(fileID, forkType, uint32(have))
		if err != nil {
			return nil, err
		}
		before := have
		for i := 0; i < 8; i++ {
			if err := add(extent{be.Uint32(rec[8*i:]), be.Uint32(rec[8*i+4:])}); err != nil {
				return nil, err
			}
		}
		if have == before {
			return nil, corrupt("fork of file %d: empty overflow extent record", fileID)
		}
	}
	return fk, nil
}

// allocated is the number of bytes the fork's extents cover.
func (k *fork) allocated() int64 {
	var n int64
	for _, r := range k.runs {
		n += r.count
	}
	return n * k.f.bs
}

func (k *fork) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= k.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > k.size-off {
		p = p[:k.size-off]
	}
	total := 0
	bs := k.f.bs
	for len(p) > 0 {
		blk := off / bs
		var r *frun
		for i := range k.runs {
			if blk >= k.runs[i].logical && blk < k.runs[i].logical+k.runs[i].count {
				r = &k.runs[i]
				break
			}
		}
		if r == nil {
			return total, corrupt("fork offset %d not mapped", off)
		}
		in := off - r.logical*bs
		n := len(p)
		if rem := r.count*bs - in; int64(n) > rem {
			n = int(rem)
		}
		if err := readFull(k.f.r, p[:n], r.phys*bs+in); err != nil {
			return total, fmt.Errorf("hfsplus: read: %w", err)
		}
		total += n
		p = p[n:]
		off += int64(n)
	}
	if total < want {
		return total, io.EOF
	}
	return total, nil
}

// overflowRecord finds the extents-overflow record starting at block
// start of a fork.
func (f *FS) overflowRecord(fileID uint32, forkType byte, start uint32) ([]byte, error) {
	var out []byte
	cmp := func(k []byte) int {
		// HFSPlusExtentKey without its length: forkType, pad, fileID, startBlock.
		if len(k) < 10 {
			return 1
		}
		kf, kt, ks := be.Uint32(k[2:]), k[0], be.Uint32(k[6:])
		switch {
		case kf != fileID:
			return cmp3(kf, fileID)
		case kt != forkType:
			return cmp3(uint32(kt), uint32(forkType))
		}
		return cmp3(ks, start)
	}
	err := f.extents.scan(func(k []byte) bool { return cmp(k) <= 0 }, cmp, func(k, v []byte) bool {
		out = v
		return false
	})
	if err != nil {
		return nil, err
	}
	if len(out) < 64 {
		return nil, corrupt("fork of file %d: no overflow extents at block %d", fileID, start)
	}
	return out, nil
}

func cmp3(a, b uint32) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

// ---- B-trees ----

type btree struct {
	f        *FS
	r        *fork
	name     string
	nodeSize int64
	nodes    uint32
	root     uint32
	depth    uint16
	maxKey   int
	variable bool
	compare  byte
}

func openBtree(f *FS, r *fork, name string) (*btree, error) {
	h := make([]byte, 106)
	if err := readFull(r, h, 0); err != nil {
		return nil, fmt.Errorf("hfsplus: %s header node: %w", name, err)
	}
	if int8(h[8]) != 1 {
		return nil, corrupt("%s B-tree: node 0 is not a header node", name)
	}
	t := &btree{f: f, r: r, name: name,
		depth: be.Uint16(h[14:]), root: be.Uint32(h[16:]), nodeSize: int64(be.Uint16(h[32:])),
		maxKey: int(be.Uint16(h[34:])), nodes: be.Uint32(h[36:]), compare: h[51],
		variable: be.Uint32(h[52:])&0x4 != 0}
	if t.nodeSize < 512 || t.nodeSize > 32768 || t.nodeSize&(t.nodeSize-1) != 0 {
		return nil, corrupt("%s B-tree node size %d", name, t.nodeSize)
	}
	if int64(t.nodes)*t.nodeSize > r.size || t.depth > 16 {
		return nil, corrupt("%s B-tree: %d nodes of %d bytes, depth %d, in a %d-byte file", name, t.nodes, t.nodeSize, t.depth, r.size)
	}
	if t.root >= t.nodes {
		return nil, corrupt("%s B-tree root %d of %d nodes", name, t.root, t.nodes)
	}
	return t, nil
}

type bnode struct {
	b      []byte
	flink  uint32
	kind   int8
	height uint8
	recs   [][]byte
}

func (t *btree) node(n uint32) (*bnode, error) {
	if n == 0 || n >= t.nodes {
		return nil, corrupt("%s B-tree node %d out of range (%d nodes)", t.name, n, t.nodes)
	}
	b := make([]byte, t.nodeSize)
	if err := readFull(t.r, b, int64(n)*t.nodeSize); err != nil {
		return nil, fmt.Errorf("hfsplus: %s node %d: %w", t.name, n, err)
	}
	nd := &bnode{b: b, flink: be.Uint32(b), kind: int8(b[8]), height: b[9]}
	nrec := int(be.Uint16(b[10:]))
	if 14+2*(nrec+1) > len(b) {
		return nil, corrupt("%s node %d: %d records", t.name, n, nrec)
	}
	for i := 0; i < nrec; i++ {
		s := int(be.Uint16(b[len(b)-2*(i+1):]))
		e := int(be.Uint16(b[len(b)-2*(i+2):]))
		if s < 14 || e < s || e > len(b)-2*(nrec+1) {
			return nil, corrupt("%s node %d: record %d spans %d-%d", t.name, n, i, s, e)
		}
		nd.recs = append(nd.recs, b[s:e])
	}
	return nd, nil
}

// split returns the key (with its length prefix) and the data of a record.
func (t *btree) split(rec []byte, index bool) ([]byte, []byte, error) {
	if len(rec) < 2 {
		return nil, nil, corrupt("%s: short record", t.name)
	}
	kl := int(be.Uint16(rec)) + 2
	if index && !t.variable {
		kl = t.maxKey + 2
	}
	if kl > len(rec) {
		return nil, nil, corrupt("%s: key length %d in a %d-byte record", t.name, kl, len(rec))
	}
	return rec[:kl], rec[kl:], nil
}

// scan descends to the first leaf that may hold keys for which cmp is 0
// (before reports keys at or before the start of the range) and visits
// matching records in order along the leaf chain.
func (t *btree) scan(before func(k []byte) bool, cmp func(k []byte) int, visit func(k, v []byte) bool) error {
	n := t.root
	seen := map[uint32]bool{}
	for depth := 0; ; depth++ {
		if depth > 16 || seen[n] {
			return corrupt("%s B-tree: cycle or excessive depth at node %d", t.name, n)
		}
		seen[n] = true
		nd, err := t.node(n)
		if err != nil {
			return err
		}
		if nd.kind == -1 {
			break
		}
		if nd.kind != 0 || len(nd.recs) == 0 {
			return corrupt("%s B-tree: node %d kind %d with %d records on the search path", t.name, n, nd.kind, len(nd.recs))
		}
		child := uint32(0)
		for i, rec := range nd.recs {
			k, v, err := t.split(rec, true)
			if err != nil {
				return err
			}
			if len(v) < 4 {
				return corrupt("%s B-tree: index record without a child", t.name)
			}
			if i == 0 || before(k[2:]) {
				child = be.Uint32(v)
			}
			if !before(k[2:]) {
				break
			}
		}
		n = child
	}
	// Walk the leaf chain.
	visited := 0
	for n != 0 {
		if visited > int(t.nodes) {
			return corrupt("%s B-tree: leaf chain loops", t.name)
		}
		visited++
		nd, err := t.node(n)
		if err != nil {
			return err
		}
		if nd.kind != -1 {
			return corrupt("%s B-tree: leaf chain reaches node %d of kind %d", t.name, n, nd.kind)
		}
		for _, rec := range nd.recs {
			k, v, err := t.split(rec, false)
			if err != nil {
				return err
			}
			switch c := cmp(k[2:]); {
			case c < 0:
				continue
			case c > 0:
				return nil
			}
			if !visit(k[2:], v) {
				return nil
			}
		}
		n = nd.flink
	}
	return nil
}

// ---- catalog ----

type record struct {
	id         uint32
	dir        bool
	mode       uint16
	uid, gid   uint32
	ownerFlags uint8
	special    uint32
	fdType     string
	fdCreator  string
	created    uint32
	modified   uint32
	attrMod    uint32
	accessed   uint32
	data, rsrc forkData
	valence    uint32
}

func parseRecord(v []byte) (*record, error) {
	if len(v) < 2 {
		return nil, corrupt("empty catalog record")
	}
	r := &record{}
	switch be.Uint16(v) {
	case 1:
		if len(v) < 88 {
			return nil, corrupt("folder record %d bytes", len(v))
		}
		r.dir = true
		r.valence = be.Uint32(v[4:])
	case 2:
		if len(v) < 248 {
			return nil, corrupt("file record %d bytes", len(v))
		}
		r.fdType, r.fdCreator = string(v[48:52]), string(v[52:56])
		r.data, r.rsrc = parseFork(v[88:]), parseFork(v[168:])
	default:
		return nil, nil // thread record
	}
	r.id = be.Uint32(v[8:])
	r.created, r.modified, r.attrMod, r.accessed = be.Uint32(v[12:]), be.Uint32(v[16:]), be.Uint32(v[20:]), be.Uint32(v[24:])
	r.uid, r.gid = be.Uint32(v[32:]), be.Uint32(v[36:])
	r.ownerFlags = v[41]
	r.mode = be.Uint16(v[42:])
	r.special = be.Uint32(v[44:])
	return r, nil
}

// catName decodes a catalog key's name.
func catName(k []byte) (uint32, string, error) {
	if len(k) < 6 {
		return 0, "", corrupt("catalog key %d bytes", len(k))
	}
	n := int(be.Uint16(k[4:]))
	if 6+2*n > len(k) || n > 255 {
		return 0, "", corrupt("catalog name length %d", n)
	}
	u := make([]uint16, n)
	for i := range u {
		u[i] = be.Uint16(k[6+2*i:])
	}
	return be.Uint32(k), strings.ReplaceAll(string(utf16.Decode(u)), "/", ":"), nil
}

// record finds a folder or file by catalog node id via its thread record.
func (f *FS) record(id uint32) (*record, error) {
	var parent uint32
	var name string
	var terr error
	cmp := func(k []byte) int {
		if len(k) < 6 {
			return 1
		}
		if c := cmp3(be.Uint32(k), id); c != 0 {
			return c
		}
		if be.Uint16(k[4:]) != 0 {
			return 1
		}
		return 0
	}
	err := f.catalog.scan(func(k []byte) bool { return cmp(k) <= 0 }, cmp, func(k, v []byte) bool {
		if len(v) < 10 || (be.Uint16(v) != 3 && be.Uint16(v) != 4) {
			terr = corrupt("catalog id %d has no thread record", id)
			return false
		}
		key := make([]byte, 4, len(v))
		be.PutUint32(key, 0)
		parent, name, terr = catName(append(key, v[8:]...))
		parent = be.Uint32(v[4:])
		return false
	})
	if err == nil {
		err = terr
	}
	if err != nil {
		return nil, err
	}
	if parent == 0 && id != rootID {
		return nil, corrupt("catalog id %d not found", id)
	}
	if id == rootID && parent == 0 {
		parent = 1
	}
	dl, err := f.entries(parent)
	if err != nil {
		return nil, err
	}
	for _, e := range dl.all {
		if e.rec.id == id && e.name == name {
			return e.rec, nil
		}
	}
	return nil, corrupt("catalog id %d (%q in %d) not found", id, name, parent)
}

type dirent struct {
	name string
	rec  *record
}

type dirList struct {
	all  []dirent // including the private folders
	ents []dirent // what is listed
	idx  map[string]int
}

// entries lists folder id (cached).
func (f *FS) entries(id uint32) (*dirList, error) {
	f.mu.Lock()
	if dl, ok := f.dirCache[id]; ok {
		f.mu.Unlock()
		return dl, nil
	}
	f.mu.Unlock()
	dl := &dirList{idx: map[string]int{}}
	bad := 0
	cmp := func(k []byte) int {
		if len(k) < 4 {
			return 1
		}
		return cmp3(be.Uint32(k), id)
	}
	before := func(k []byte) bool {
		return len(k) >= 6 && (be.Uint32(k) < id || be.Uint32(k) == id && be.Uint16(k[4:]) == 0)
	}
	err := f.catalog.scan(before, cmp, func(k, v []byte) bool {
		_, name, err := catName(k)
		if err != nil {
			bad++
			return true
		}
		rec, err := parseRecord(v)
		if err != nil {
			bad++
			return true
		}
		if rec == nil {
			return true // thread
		}
		dl.all = append(dl.all, dirent{name, rec})
		return len(dl.all) < maxDirEnts
	})
	if err != nil {
		return nil, err
	}
	for _, e := range dl.all {
		switch {
		case id == rootID && (e.name == privateDataName || e.name == privateDirName):
			f.mu.Lock()
			f.private[e.name] = e.rec.id
			f.mu.Unlock()
			continue
		case e.name == "" || e.name == "." || e.name == ".." || strings.ContainsRune(e.name, 0):
			bad++
			continue
		}
		if _, dup := dl.idx[e.name]; dup {
			bad++
			continue
		}
		dl.idx[e.name] = len(dl.ents)
		dl.ents = append(dl.ents, e)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if bad > 0 {
		f.stats["corrupt_records"] += int64(bad)
		if len(f.problems) < 200 {
			f.problems = append(f.problems, fmt.Sprintf("folder %d: %d malformed catalog record(s) not listed", id, bad))
		}
	}
	if id == rootID {
		f.privSeen = true
	}
	f.stats["dirs_read"]++
	if f.cached+len(dl.all) > cacheLimit {
		f.dirCache, f.cached = map[uint32]*dirList{}, 0
	}
	f.dirCache[id] = dl
	f.cached += len(dl.all)
	return dl, nil
}

// resolveLink returns the indirect node behind a hard-link record (or the
// record itself).
func (f *FS) resolveLink(r *record) (*record, error) {
	var dir, prefix string
	switch {
	case !r.dir && r.fdType == "hlnk" && r.fdCreator == "hfs+":
		dir, prefix = privateDataName, "iNode"
	case !r.dir && r.fdType == "fdrp" && r.fdCreator == "MACS":
		dir, prefix = privateDirName, "dir_"
	default:
		return r, nil
	}
	if _, err := f.entries(rootID); err != nil {
		return nil, err
	}
	f.mu.Lock()
	pid := f.private[dir]
	f.mu.Unlock()
	if pid == 0 {
		return nil, corrupt("hard link to %s%d but no private metadata folder", prefix, r.special)
	}
	dl, err := f.entries(pid)
	if err != nil {
		return nil, err
	}
	i, ok := dl.idx[fmt.Sprintf("%s%d", prefix, r.special)]
	if !ok {
		return nil, corrupt("hard link target %s%d missing", prefix, r.special)
	}
	return dl.ents[i].rec, nil
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
