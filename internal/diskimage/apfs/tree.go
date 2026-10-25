package apfs

import (
	"bytes"
	"compress/zlib"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"time"
)

// File-system record types (j_key_t high nibble).
const (
	recSnapMeta  = 1
	recInode     = 3
	recXattr     = 4
	recFileExtnt = 8
	recDirRec    = 9

	objIDMask = 0x0fffffffffffffff
	rootIno   = 2
)

// Inode fields used by the reader.
const (
	ufCompressed = 0x20 // BSD flag: decmpfs-compressed

	xfName    = 4
	xfDstream = 8

	xattrStream   = 0x1
	xattrEmbedded = 0x2
)

// tree is one readable file-system tree: a live volume or a snapshot.
type tree struct {
	f      *FS
	vol    *Volume
	sb     *apsb
	om     *omap
	fst    *btree
	fext   *btree // sealed volumes: file extents live here
	hashed bool
	ci     bool   // case-insensitive names
	ns     uint64 // namespace for exposed inode numbers
	snap   *Snapshot

	snapDir     *virtDir // .snapshots of a live tree (nil when none)
	snapDirName string

	mu       sync.Mutex
	budget   int
	dirCache map[uint64]*dirList
	cached   int
}

func (f *FS) newTree(v *Volume, sb *apsb, maxXid uint64) (*tree, error) {
	if maxXid == 0 {
		maxXid = f.c.xid
	}
	oroot, err := f.c.omapRoot(sb.omapOID)
	if err != nil {
		return nil, fmt.Errorf("volume object map: %w", err)
	}
	t := &tree{
		f: f, vol: v, sb: sb,
		om:       &omap{c: f.c, root: oroot, maxXid: maxXid},
		hashed:   sb.incompat&(incompatCaseInsensitive|incompatNormInsensitive) != 0,
		ci:       sb.incompat&incompatCaseInsensitive != 0,
		dirCache: map[uint64]*dirList{},
		budget:   int(min(max(f.c.size/int64(f.c.bs)*4, 1<<16), 1<<26)),
	}
	t.fst = &btree{c: f.c, root: sb.rootOID, om: t.om, budget: &t.budget}
	if sb.incompat&incompatSealed != 0 && sb.fextOID != 0 {
		t.fext = &btree{c: f.c, root: sb.fextOID, physical: true, fixedK: 16, fixedV: 16, budget: &t.budget}
	}
	t.mu.Lock()
	root, err := t.readInode(rootIno)
	t.mu.Unlock()
	if err != nil {
		return nil, fmt.Errorf("root directory: %w", err)
	}
	if !root.isDir() {
		return nil, corrupt("root inode is not a directory")
	}
	return t, nil
}

// listSnapshots reads the volume's snapshot metadata tree.
func (t *tree) listSnapshots() []Snapshot {
	if t.sb.snapOID == 0 {
		return nil
	}
	bt := &btree{c: t.f.c, root: t.sb.snapOID, physical: true, budget: &t.budget}
	var out []Snapshot
	t.mu.Lock()
	defer t.mu.Unlock()
	err := bt.scan(func(k []byte) int { return cmpKey(k, 0, recSnapMeta, true) }, func(k, v []byte) bool {
		if len(v) < 50 {
			t.f.bump("corrupt_records")
			return true
		}
		nl := int(le.Uint16(v[48:]))
		if 50+nl > len(v) {
			t.f.bump("corrupt_records")
			return true
		}
		out = append(out, Snapshot{
			XID:     le.Uint64(k) & objIDMask,
			Created: nsTime(le.Uint64(v[16:])),
			Name:    cstring(v[50 : 50+nl]),
		})
		return len(out) < 10000
	})
	if err != nil {
		t.f.noteProblem("volume %q: snapshot metadata: %v", t.vol.Name, err)
	}
	return out
}

// snapshotSuper returns the volume superblock saved with a snapshot.
func (t *tree) snapshotSuper(xid uint64) (*apsb, error) {
	bt := &btree{c: t.f.c, root: t.sb.snapOID, physical: true, budget: &t.budget}
	var sblock uint64
	t.mu.Lock()
	err := bt.scan(func(k []byte) int { return cmpKey(k, xid, recSnapMeta, false) }, func(k, v []byte) bool {
		if len(v) >= 16 {
			sblock = le.Uint64(v[8:])
		}
		return false
	})
	t.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if sblock == 0 {
		return nil, corrupt("snapshot %d has no saved volume superblock", xid)
	}
	b, err := t.f.c.readObject(sblock, typeFS, 0)
	if err != nil {
		return nil, err
	}
	if string(b[32:36]) != "APSB" {
		return nil, corrupt("snapshot %d superblock has no APSB magic", xid)
	}
	return parseAPSB(b), nil
}

// addSnapshots mounts every snapshot of a live tree under .snapshots/.
func (f *FS) addSnapshots(t *tree, prefix string) {
	snaps := t.vol.Snapshots
	if len(snaps) == 0 {
		return
	}
	// Real entries always win: the virtual directory takes the first of
	// .snapshots, .apfs-snapshots, .apfs-snapshots-2 … that no root entry
	// matches, compared case-insensitively.
	var rootNames []string
	if ents, err := t.dirEntries(rootIno); err == nil {
		for _, e := range ents.ents {
			rootNames = append(rootNames, e.name)
		}
	} else {
		f.noteProblem("volume %q: root directory: %v", t.vol.Name, err)
	}
	t.snapDirName = snapDirNameFor(rootNames)
	t.snapDir = &virtDir{name: t.snapDirName, children: map[string]any{}}
	used := map[string]bool{}
	for i := range snaps {
		s := &t.vol.Snapshots[i]
		name := safeName(s.Name, i+1, used)
		s.Dir = strings.TrimPrefix(prefix+"/"+t.snapDirName+"/"+name, "/")
		sb, err := t.snapshotSuper(s.XID)
		var st *tree
		if err == nil {
			st, err = f.newTree(t.vol, sb, s.XID)
		}
		if err != nil {
			f.noteProblem("volume %q snapshot %q: %v", t.vol.Name, s.Name, err)
			t.snapDir.add(name, fmt.Errorf("snapshot %q not readable: %w", s.Name, err))
			continue
		}
		st.snap = s
		st.ns = uint64(len(f.trees))
		f.trees = append(f.trees, st)
		t.snapDir.add(name, st)
	}
}

// snapDirNameFor picks a name for the virtual snapshot directory that no
// existing name equals, ignoring case.
func snapDirNameFor(existing []string) string {
	taken := func(n string) bool {
		for _, e := range existing {
			if strings.EqualFold(e, n) {
				return true
			}
		}
		return false
	}
	for i := 0; ; i++ {
		n := ".snapshots"
		switch {
		case i == 1:
			n = ".apfs-snapshots"
		case i > 1:
			n = fmt.Sprintf(".apfs-snapshots-%d", i)
		}
		if !taken(n) {
			return n
		}
	}
}

// cmpKey orders a j_key against (id, typ). With anyID only the type is
// compared (snapshot metadata records are keyed by xid).
func cmpKey(k []byte, id uint64, typ uint64, anyID bool) int {
	if len(k) < 8 {
		return 1
	}
	kid, kt := le.Uint64(k)&objIDMask, le.Uint64(k)>>60
	if !anyID {
		switch {
		case kid < id:
			return -1
		case kid > id:
			return 1
		}
	}
	switch {
	case kt < typ:
		return -1
	case kt > typ:
		return 1
	}
	return 0
}

// records visits every fs-tree record of (id, typ). Caller holds t.mu.
func (t *tree) records(id uint64, typ uint64, visit func(k, v []byte) bool) error {
	return t.fst.scan(func(k []byte) int { return cmpKey(k, id, typ, false) }, visit)
}

// ---- inodes ----

type inode struct {
	id, parent, private        uint64
	btime, mtime, ctime, atime uint64
	iflags                     uint64
	nlink                      int32
	bsd                        uint32
	uid, gid                   uint32
	mode                       uint16
	size                       uint64 // dstream size
	name                       string
}

func (in *inode) fmt() uint16  { return in.mode & 0xF000 }
func (in *inode) isDir() bool  { return in.fmt() == 0x4000 }
func (in *inode) isReg() bool  { return in.fmt() == 0x8000 }
func (in *inode) isLink() bool { return in.fmt() == 0xA000 }

// readInode reads the inode record of id. Caller holds t.mu.
func (t *tree) readInode(id uint64) (*inode, error) {
	var in *inode
	var perr error
	err := t.records(id, recInode, func(k, v []byte) bool {
		in, perr = parseInode(id, v)
		return false
	})
	if err != nil {
		return nil, err
	}
	if perr != nil {
		t.f.bump("corrupt_records")
		return nil, perr
	}
	if in == nil {
		return nil, corrupt("inode %d not found", id)
	}
	return in, nil
}

func parseInode(id uint64, v []byte) (*inode, error) {
	if len(v) < 92 {
		return nil, corrupt("inode %d record is %d bytes", id, len(v))
	}
	in := &inode{
		id: id, parent: le.Uint64(v), private: le.Uint64(v[8:]),
		btime: le.Uint64(v[16:]), mtime: le.Uint64(v[24:]), ctime: le.Uint64(v[32:]), atime: le.Uint64(v[40:]),
		iflags: le.Uint64(v[48:]), nlink: int32(le.Uint32(v[56:])),
		bsd: le.Uint32(v[68:]), uid: le.Uint32(v[72:]), gid: le.Uint32(v[76:]), mode: le.Uint16(v[80:]),
	}
	walkXfields(v[92:], func(typ uint8, data []byte) {
		switch typ {
		case xfDstream:
			if len(data) >= 8 {
				in.size = le.Uint64(data)
			}
		case xfName:
			in.name = cstring(data)
		}
	})
	if in.size > 1<<62 {
		return nil, corrupt("inode %d size %d", id, in.size)
	}
	return in, nil
}

// walkXfields walks an xf_blob_t: a count, the x_field_t headers, then
// the values, each padded to 8 bytes.
func walkXfields(b []byte, fn func(typ uint8, data []byte)) {
	if len(b) < 4 {
		return
	}
	n := int(le.Uint16(b))
	if n > 64 || 4+4*n > len(b) {
		return
	}
	off := 4 + 4*n
	for i := 0; i < n; i++ {
		h := b[4+4*i:]
		sz := int(le.Uint16(h[2:]))
		if off+sz > len(b) {
			return
		}
		fn(h[0], b[off:off+sz])
		off += (sz + 7) &^ 7
	}
}

// ---- directories ----

type dirent struct {
	name  string
	id    uint64
	dtype uint16
}

type dirList struct {
	ents []dirent
	idx  map[string]int // name → index in ents
}

// parseDrecKey returns the name of a directory-record key, hashed or not.
func parseDrecKey(k []byte, hashed bool) (string, bool) {
	try := func(h bool) (string, bool) {
		if h {
			if len(k) < 12 {
				return "", false
			}
			n := int(le.Uint32(k[8:]) & 0x3ff)
			if n == 0 || 12+n != len(k) {
				return "", false
			}
			return cstring(k[12 : 12+n]), true
		}
		if len(k) < 10 {
			return "", false
		}
		n := int(le.Uint16(k[8:]))
		if n == 0 || 10+n != len(k) {
			return "", false
		}
		return cstring(k[10 : 10+n]), true
	}
	if s, ok := try(hashed); ok {
		return s, true
	}
	return try(!hashed)
}

func validName(s string) bool {
	return s != "" && s != "." && s != ".." && len(s) <= maxNameLen && !strings.ContainsAny(s, "/\x00")
}

// dirEntries lists directory id (cached). It takes t.mu.
func (t *tree) dirEntries(id uint64) (*dirList, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if dl, ok := t.dirCache[id]; ok {
		return dl, nil
	}
	dl := &dirList{idx: map[string]int{}}
	bad := 0
	err := t.records(id, recDirRec, func(k, v []byte) bool {
		name, ok := parseDrecKey(k, t.hashed)
		if !ok || len(v) < 18 || !validName(name) {
			bad++
			return true
		}
		if _, dup := dl.idx[name]; dup {
			bad++
			return true
		}
		dl.idx[name] = len(dl.ents)
		dl.ents = append(dl.ents, dirent{name: name, id: le.Uint64(v), dtype: le.Uint16(v[16:]) & 0xf})
		return len(dl.ents) < cacheLimit
	})
	if err != nil {
		return nil, err
	}
	if bad > 0 {
		t.f.mu.Lock()
		t.f.stats["corrupt_records"] += int64(bad)
		t.f.mu.Unlock()
		t.f.noteProblem("volume %q: directory %d: %d malformed directory record(s) not listed", t.vol.Name, id, bad)
	}
	t.f.bump("dirs_read")
	if t.cached+len(dl.ents) > cacheLimit {
		t.dirCache, t.cached = map[uint64]*dirList{}, 0
	}
	t.dirCache[id] = dl
	t.cached += len(dl.ents)
	return dl, nil
}

// child finds name in directory id; case-insensitive volumes fall back to
// a case-folded match.
func (t *tree) child(id uint64, name string) (uint64, bool, error) {
	dl, err := t.dirEntries(id)
	if err != nil {
		return 0, false, err
	}
	if i, ok := dl.idx[name]; ok {
		return dl.ents[i].id, true, nil
	}
	if t.ci {
		for _, e := range dl.ents {
			if strings.EqualFold(e.name, name) {
				return e.id, true, nil
			}
		}
	}
	return 0, false, nil
}

// inode reads an inode under the lock.
func (t *tree) inode(id uint64) (*inode, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.readInode(id)
}

// ---- xattrs ----

type xattr struct {
	name     string
	flags    uint16
	data     []byte // embedded value
	streamID uint64
	size     uint64
}

// xattrs lists the extended attributes of id. It takes t.mu.
func (t *tree) xattrs(id uint64) ([]xattr, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []xattr
	err := t.records(id, recXattr, func(k, v []byte) bool {
		if len(k) < 10 || len(v) < 4 {
			t.f.bump("corrupt_records")
			return true
		}
		nl := int(le.Uint16(k[8:]))
		if 10+nl > len(k) {
			t.f.bump("corrupt_records")
			return true
		}
		x := xattr{name: cstring(k[10 : 10+nl]), flags: le.Uint16(v)}
		dl := int(le.Uint16(v[2:]))
		if 4+dl > len(v) {
			t.f.bump("corrupt_records")
			return true
		}
		d := v[4 : 4+dl]
		switch {
		case x.flags&xattrEmbedded != 0:
			x.data = d
			x.size = uint64(len(d))
		case x.flags&xattrStream != 0 && len(d) >= 16:
			x.streamID, x.size = le.Uint64(d), le.Uint64(d[8:])
		default:
			t.f.bump("corrupt_records")
			return true
		}
		out = append(out, x)
		return len(out) < 4096
	})
	return out, err
}

// xattrValue reads one xattr in full (bounded by limit).
func (t *tree) xattrValue(x xattr, limit int64) ([]byte, error) {
	if x.data != nil || x.streamID == 0 {
		return x.data, nil
	}
	if int64(x.size) > limit || int64(x.size) > t.f.c.size {
		return nil, corrupt("xattr %q is %d bytes (limit %d, container %d)", x.name, x.size, limit, t.f.c.size)
	}
	d, err := t.dataStream(x.streamID, int64(x.size))
	if err != nil {
		return nil, err
	}
	// An xattr stream (a resource fork, a big value) is never sparse: one
	// that is mostly holes is a crafted size, not data.
	if alloc := d.allocated(); alloc+t.f.c.bs < int64(x.size) {
		return nil, corrupt("xattr %q declares %d bytes but only %d are allocated", x.name, x.size, alloc)
	}
	b, err := io.ReadAll(io.NewSectionReader(d, 0, int64(x.size)))
	if err != nil {
		return nil, err
	}
	if len(b) != int(x.size) {
		return nil, corrupt("xattr %q read %d of %d bytes", x.name, len(b), x.size)
	}
	return b, nil
}

// ---- file data ----

type run struct {
	logical int64
	phys    uint64 // block; 0 = hole
	length  int64
}

// data is a random-access view of one data stream.
type data struct {
	c    *container
	runs []run
	size int64
}

// dataStream maps the extents of a dstream (private id) of size bytes.
func (t *tree) dataStream(private uint64, size int64) (*data, error) {
	// Sparse files may exceed the container, but not by more than 64×,
	// and never past 1 TiB. Extraction is capped separately (per file and
	// in total) by diskimage.Limits.
	if size < 0 || size > t.f.c.size*64 || size > 1<<40 {
		return nil, corrupt("stream %d size %d implausible", private, size)
	}
	maxRuns := int(min(t.f.c.size/int64(t.f.c.bs)+16, 1<<22))
	var runs []run
	var bad error
	add := func(logical, lenFlags, phys uint64) bool {
		ln := int64(lenFlags & 0x00ffffffffffffff)
		if ln <= 0 || ln%t.f.c.bs != 0 || logical > 1<<62 {
			bad = corrupt("stream %d: extent at %d has length %d", private, logical, ln)
			return false
		}
		if phys != 0 && (phys >= t.f.c.blocks || uint64(ln/t.f.c.bs) > t.f.c.blocks-phys) {
			bad = corrupt("stream %d: extent at block %d (+%d) outside the container", private, phys, ln/t.f.c.bs)
			return false
		}
		if len(runs) >= maxRuns {
			bad = corrupt("stream %d: more than %d extents", private, maxRuns)
			return false
		}
		runs = append(runs, run{logical: int64(logical), phys: phys, length: ln})
		return true
	}
	t.mu.Lock()
	var err error
	if t.fext != nil {
		err = t.fext.scan(func(k []byte) int {
			if len(k) < 16 {
				return 1
			}
			switch id := le.Uint64(k); {
			case id < private:
				return -1
			case id > private:
				return 1
			}
			return 0
		}, func(k, v []byte) bool {
			return len(v) >= 16 && add(le.Uint64(k[8:]), le.Uint64(v), le.Uint64(v[8:]))
		})
	} else {
		err = t.records(private, recFileExtnt, func(k, v []byte) bool {
			if len(k) < 16 || len(v) < 16 {
				bad = corrupt("stream %d: short file-extent record", private)
				return false
			}
			return add(le.Uint64(k[8:]), le.Uint64(v), le.Uint64(v[8:]))
		})
	}
	t.mu.Unlock()
	if err == nil {
		err = bad
	}
	if err != nil {
		t.f.bump("corrupt_records")
		return nil, err
	}
	sort.Slice(runs, func(i, j int) bool { return runs[i].logical < runs[j].logical })
	for i := 1; i < len(runs); i++ {
		if runs[i].logical < runs[i-1].logical+runs[i-1].length {
			t.f.bump("corrupt_records")
			return nil, corrupt("stream %d: overlapping extents at %d", private, runs[i].logical)
		}
	}
	return &data{c: t.f.c, runs: runs, size: size}, nil
}

// allocated is the number of bytes backed by extents (holes excluded).
func (d *data) allocated() int64 {
	var n int64
	for _, r := range d.runs {
		if r.phys != 0 {
			n += r.length
		}
	}
	return n
}

func (d *data) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= d.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > d.size-off {
		p = p[:d.size-off]
	}
	total := 0
	for len(p) > 0 {
		i := sort.Search(len(d.runs), func(i int) bool { return d.runs[i].logical+d.runs[i].length > off })
		n := len(p)
		if i == len(d.runs) || d.runs[i].logical > off {
			// A hole (no extent) up to the next extent or the end.
			if i < len(d.runs) && int64(n) > d.runs[i].logical-off {
				n = int(d.runs[i].logical - off)
			}
			clear(p[:n])
		} else {
			r := d.runs[i]
			in := off - r.logical
			if int64(n) > r.length-in {
				n = int(r.length - in)
			}
			if r.phys == 0 {
				clear(p[:n])
			} else if err := readFull(d.c.r, p[:n], int64(r.phys)*d.c.bs+in); err != nil {
				return total, fmt.Errorf("apfs: read data: %w", err)
			}
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

// ---- decmpfs ----

const decmpfsMagic = 0x636d7066 // "fpmc"

// compressionName names a decmpfs compression type.
func compressionName(t uint32) string {
	switch t {
	case 1:
		return "uncompressed-inline"
	case 3:
		return "zlib-inline"
	case 4:
		return "zlib-resource-fork"
	case 5:
		return "sparse"
	case 7:
		return "lzvn-inline"
	case 8:
		return "lzvn-resource-fork"
	case 9:
		return "uncompressed-inline-9"
	case 10:
		return "uncompressed-resource-fork"
	case 11:
		return "lzfse-inline"
	case 12:
		return "lzfse-resource-fork"
	case 13:
		return "lzbitmap-inline"
	case 14:
		return "lzbitmap-resource-fork"
	}
	return fmt.Sprintf("type-%d", t)
}

// Decmpfs describes a decmpfs header. It is shared with the HFS+ reader
// through DecodeDecmpfs.
type Decmpfs struct {
	Type uint32
	Size uint64
}

// ParseDecmpfs parses a com.apple.decmpfs xattr header.
func ParseDecmpfs(b []byte) (Decmpfs, error) {
	if len(b) < 16 || le.Uint32(b) != decmpfsMagic {
		return Decmpfs{}, corrupt("decmpfs header missing or bad magic")
	}
	h := Decmpfs{Type: le.Uint32(b[4:]), Size: le.Uint64(b[8:])}
	if h.Size > maxDecmpfs {
		return h, corrupt("decmpfs uncompressed size %d over the %d limit", h.Size, maxDecmpfs)
	}
	return h, nil
}

// DecodeDecmpfs returns the uncompressed content of a decmpfs file, given
// its xattr and a reader for its resource fork (nil when absent).
// Supported: type 1 (inline, uncompressed), 3 (inline zlib) and 4 (zlib
// in the resource fork). Anything else is an error wrapping
// errors.ErrUnsupported that names the type.
func DecodeDecmpfs(attr []byte, rsrc func() ([]byte, error)) ([]byte, error) {
	h, err := ParseDecmpfs(attr)
	if err != nil {
		return nil, err
	}
	payload := attr[16:]
	switch h.Type {
	case 1:
		if uint64(len(payload)) < h.Size {
			return nil, corrupt("decmpfs inline data %d bytes, want %d", len(payload), h.Size)
		}
		return payload[:h.Size], nil
	case 3:
		return inflateBlock(payload, h.Size)
	case 4:
		if rsrc == nil {
			return nil, corrupt("decmpfs zlib resource-fork file has no resource fork")
		}
		fork, err := rsrc()
		if err != nil {
			return nil, err
		}
		return zlibResourceFork(fork, h.Size)
	}
	return nil, fmt.Errorf("decmpfs: %w: %s compression is not supported (the file is listed; its content is not decoded)", errors.ErrUnsupported, compressionName(h.Type))
}

// maxRatio bounds how far zlib data may expand (deflate's own limit is
// about 1032:1).
const maxRatio = 1032

// inflateBlock decodes one decmpfs zlib block: a leading 0xFF (or a low
// nibble of 0xF) marks data stored raw after that byte.
func inflateBlock(b []byte, want uint64) ([]byte, error) {
	if len(b) == 0 {
		if want == 0 {
			return nil, nil
		}
		return nil, corrupt("decmpfs block empty")
	}
	if b[0]&0x0f == 0x0f {
		if uint64(len(b)-1) < want {
			return nil, corrupt("decmpfs raw block %d bytes, want %d", len(b)-1, want)
		}
		return b[1 : 1+want], nil
	}
	if want > uint64(len(b))*maxRatio {
		return nil, corrupt("decmpfs zlib block of %d bytes cannot expand to %d", len(b), want)
	}
	zr, err := zlib.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, corrupt("decmpfs zlib: %v", err)
	}
	defer zr.Close()
	// Grow with the decoded data instead of trusting want up front.
	var out bytes.Buffer
	if _, err := io.Copy(&out, io.LimitReader(zr, int64(want)+1)); err != nil {
		return nil, corrupt("decmpfs zlib: %v", err)
	}
	if uint64(out.Len()) != want {
		return nil, corrupt("decmpfs zlib block decodes to %d bytes, want %d", out.Len(), want)
	}
	return out.Bytes(), nil
}

// zlibResourceFork decodes a type-4 resource fork: a resource-fork header
// whose data section holds a block table of 64 KiB zlib blocks.
func zlibResourceFork(fork []byte, size uint64) ([]byte, error) {
	be := binary.BigEndian
	if len(fork) < 16 {
		return nil, corrupt("resource fork %d bytes", len(fork))
	}
	dataOff := uint64(be.Uint32(fork))
	if dataOff+8 > uint64(len(fork)) {
		return nil, corrupt("resource fork data offset %d", dataOff)
	}
	base := dataOff + 4 // past the resource length
	nblk := uint64(le.Uint32(fork[base:]))
	need := (size + 0xffff) / 0x10000
	if nblk != need || base+4+8*nblk > uint64(len(fork)) || size > uint64(len(fork))*maxRatio {
		return nil, corrupt("resource fork block table: %d blocks for %d bytes", nblk, size)
	}
	var out []byte
	for i := uint64(0); i < nblk; i++ {
		e := fork[base+4+8*i:]
		bo, bl := uint64(le.Uint32(e)), uint64(le.Uint32(e[4:]))
		if base+bo+bl > uint64(len(fork)) {
			return nil, corrupt("resource fork block %d out of range", i)
		}
		want := min(uint64(0x10000), size-uint64(len(out)))
		blk, err := inflateBlock(fork[base+bo:base+bo+bl], want)
		if err != nil {
			return nil, err
		}
		out = append(out, blk...)
	}
	return out, nil
}

// ---- helpers ----

func (t *tree) inodeNumber(id uint64) uint64 { return t.ns<<56 | id&(1<<56-1) }

func (t *tree) label() string {
	if t.snap != nil {
		return fmt.Sprintf("%s@%s", t.vol.Name, t.snap.Name)
	}
	return t.vol.Name
}

func tsOf(v uint64) time.Time { return nsTime(v) }
