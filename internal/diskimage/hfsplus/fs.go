package hfsplus

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"github.com/efij/AgentDFIR/v5/internal/diskimage/apfs"
)

// ---- extended attributes ----

type xattr struct {
	name   string
	inline []byte
	fork   *forkData
}

// xattrs lists the attributes of a catalog node.
func (f *FS) xattrs(id uint32) ([]xattr, error) {
	if f.attrs == nil {
		return nil, nil
	}
	var out []xattr
	cmp := func(k []byte) int {
		if len(k) < 6 {
			return 1
		}
		return cmp3(be.Uint32(k[2:]), id)
	}
	before := func(k []byte) bool {
		return len(k) >= 12 && (be.Uint32(k[2:]) < id || be.Uint32(k[2:]) == id && be.Uint16(k[10:]) == 0)
	}
	err := f.attrs.scan(before, cmp, func(k, v []byte) bool {
		if len(k) < 12 || len(v) < 16 {
			f.bump("corrupt_records")
			return true
		}
		n := int(be.Uint16(k[10:]))
		if 12+2*n > len(k) || n > 127 {
			f.bump("corrupt_records")
			return true
		}
		u := make([]uint16, n)
		for i := range u {
			u[i] = be.Uint16(k[12+2*i:])
		}
		x := xattr{name: string(utf16.Decode(u))}
		switch be.Uint32(v) {
		case 0x10:
			sz := int(be.Uint32(v[12:]))
			if 16+sz > len(v) {
				f.bump("corrupt_records")
				return true
			}
			x.inline = v[16 : 16+sz]
		case 0x20:
			if len(v) < 88 {
				f.bump("corrupt_records")
				return true
			}
			fd := parseFork(v[8:])
			x.fork = &fd
		default:
			return true // overflow extents of a fork attribute
		}
		out = append(out, x)
		return len(out) < 4096
	})
	return out, err
}

// value reads one attribute in full, bounded by limit and by what the
// fork has allocated.
func (f *FS) value(id uint32, x xattr, limit int64) ([]byte, error) {
	if x.fork == nil {
		return x.inline, nil
	}
	if int64(x.fork.size) > limit || int64(x.fork.size) > f.size {
		return nil, corrupt("attribute %q is %d bytes (limit %d)", x.name, x.fork.size, limit)
	}
	k, err := f.forkReader(id, 0, *x.fork, false)
	if err != nil {
		return nil, err
	}
	return readAllExact(k, k.size)
}

// readAllExact reads n bytes, growing with what is actually read.
func readAllExact(r io.ReaderAt, n int64) ([]byte, error) {
	b, err := io.ReadAll(io.NewSectionReader(r, 0, n))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) != n {
		return nil, corrupt("read %d of %d bytes", len(b), n)
	}
	return b, nil
}

// ---- paths ----

type loc struct {
	rec  *record // the record as listed (a hard link stays a link here)
	node *record // what it resolves to (the indirect node for hard links)
	anc  map[uint32]bool
}

func (f *FS) rootLoc() (loc, error) {
	r, err := f.record(rootID)
	if err != nil {
		return loc{}, err
	}
	return loc{rec: r, node: r, anc: map[uint32]bool{rootID: true}}, nil
}

func (f *FS) lookup(op, name string) (loc, error) {
	if !fs.ValidPath(name) {
		return loc{}, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	cur, err := f.rootLoc()
	if err != nil {
		return loc{}, &fs.PathError{Op: op, Path: name, Err: err}
	}
	if name == "." {
		return cur, nil
	}
	parts := strings.Split(name, "/")
	if len(parts) > maxPathDeep {
		return loc{}, &fs.PathError{Op: op, Path: name, Err: errors.New("path too deep")}
	}
	for _, p := range parts {
		if !cur.node.dir {
			return loc{}, &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%w: not a directory", fs.ErrNotExist)}
		}
		dl, err := f.entries(cur.node.id)
		if err != nil {
			return loc{}, &fs.PathError{Op: op, Path: name, Err: err}
		}
		i, ok := dl.idx[p]
		if !ok && f.catalog.compare != 0xBC {
			for j, e := range dl.ents {
				if strings.EqualFold(e.name, p) {
					i, ok = j, true
					break
				}
			}
		}
		if !ok {
			return loc{}, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
		}
		rec := dl.ents[i].rec
		node, err := f.resolveLink(rec)
		if err != nil {
			return loc{}, &fs.PathError{Op: op, Path: name, Err: err}
		}
		if cur.anc[node.id] {
			f.bump("corrupt_records")
			return loc{}, &fs.PathError{Op: op, Path: name, Err: corrupt("directory cycle at %q", p)}
		}
		anc := cur.anc
		if node.dir {
			anc = make(map[uint32]bool, len(cur.anc)+1)
			for k := range cur.anc {
				anc[k] = true
			}
			anc[node.id] = true
		}
		cur = loc{rec: rec, node: node, anc: anc}
	}
	return cur, nil
}

func fileMode(r *record) fs.FileMode {
	m := r.mode
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
	case 0:
		// Records written without BSD info: folders and plain files.
		if r.dir {
			mode |= fs.ModeDir | 0o755
		} else {
			mode |= 0o644
		}
	default:
		mode |= fs.ModeIrregular
	}
	if r.dir {
		mode |= fs.ModeDir
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

func (f *FS) info(name string, l loc) *fileInfo {
	r := l.node
	sys := map[string]any{
		"inode": uint64(r.id),
		"mtime": hfsTime(r.modified),
		"atime": hfsTime(r.accessed),
		"ctime": hfsTime(r.attrMod),
		"btime": hfsTime(r.created),
		"fs":    f.fsName(),
		"mode":  uint32(r.mode),
		"uid":   r.uid,
		"gid":   r.gid,
	}
	if r.dir {
		sys["dir_id"] = uint64(r.id)
		sys["valence"] = r.valence
	}
	if l.rec != l.node {
		sys["hard_link"] = true
		sys["link_id"] = uint64(l.rec.id)
		sys["links"] = r.special // link count of the indirect node
	}
	size := int64(r.data.size)
	if xs, err := f.xattrs(r.id); err != nil {
		sys["xattr_error"] = err.Error()
	} else if len(xs) > 0 {
		var names []string
		for _, x := range xs {
			names = append(names, x.name)
			if x.name == "com.apple.decmpfs" && r.ownerFlags&ufCompressed != 0 {
				if h, err := apfs.ParseDecmpfs(x.inline); err == nil {
					size = int64(h.Size)
					sys["compression"] = decmpfsName(h.Type)
					if h.Type != 1 && h.Type != 3 && h.Type != 4 {
						sys["unsupported"] = decmpfsName(h.Type) + " compression"
					}
				} else {
					sys["unsupported"] = err.Error()
				}
			}
		}
		sort.Strings(names)
		sys["xattrs"] = names
	}
	mode := fileMode(r)
	if mode&fs.ModeSymlink != 0 {
		if t, err := f.linkTarget(r); err == nil {
			sys["symlink_target"] = t
		}
	} else if !mode.IsRegular() {
		size = 0
	}
	if r.id == rootID {
		for k, v := range f.Metadata() {
			sys[k] = v
		}
		for k, v := range f.Stats() {
			sys[k] = v
		}
	}
	return &fileInfo{name: name, size: size, mode: mode, mtime: hfsTime(r.modified), sys: sys}
}

func decmpfsName(t uint32) string {
	switch t {
	case 1:
		return "uncompressed-inline"
	case 3:
		return "zlib-inline"
	case 4:
		return "zlib-resource-fork"
	case 7:
		return "lzvn-inline"
	case 8:
		return "lzvn-resource-fork"
	case 11:
		return "lzfse-inline"
	case 12:
		return "lzfse-resource-fork"
	}
	return fmt.Sprintf("type-%d", t)
}

func (f *FS) linkTarget(r *record) (string, error) {
	if r.data.size > maxLinkLen {
		return "", corrupt("symlink %d target length %d", r.id, r.data.size)
	}
	k, err := f.forkReader(r.id, 0, r.data, true)
	if err != nil {
		return "", err
	}
	b, err := readAllExact(k, k.size)
	return string(b), err
}

// content returns a reader over a regular file's bytes.
func (f *FS) content(r *record) (io.ReaderAt, int64, error) {
	if r.ownerFlags&ufCompressed == 0 {
		k, err := f.forkReader(r.id, 0, r.data, true)
		if err != nil {
			return nil, 0, err
		}
		return k, k.size, nil
	}
	xs, err := f.xattrs(r.id)
	if err != nil {
		return nil, 0, err
	}
	var attr []byte
	for _, x := range xs {
		if x.name == "com.apple.decmpfs" {
			if attr, err = f.value(r.id, x, 1<<20); err != nil {
				return nil, 0, err
			}
		}
	}
	if attr == nil {
		f.bump("corrupt_records")
		return nil, 0, corrupt("compressed file %d has no decmpfs attribute", r.id)
	}
	b, err := apfs.DecodeDecmpfs(attr, func() ([]byte, error) {
		if int64(r.rsrc.size) > f.size {
			return nil, corrupt("resource fork of %d is %d bytes", r.id, r.rsrc.size)
		}
		k, err := f.forkReader(r.id, 0xFF, r.rsrc, true)
		if err != nil {
			return nil, err
		}
		return readAllExact(k, k.size)
	})
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			f.bump("unsupported_files")
		}
		return nil, 0, err
	}
	return bytes.NewReader(b), int64(len(b)), nil
}

func baseName(name string) string {
	if name == "." {
		return "."
	}
	return path.Base(name)
}

// Open opens the named file or directory. Symlinks are not followed.
func (f *FS) Open(name string) (_ fs.File, err error) {
	defer guard("open", name, &err)
	l, err := f.lookup("open", name)
	if err != nil {
		return nil, err
	}
	info := f.info(baseName(name), l)
	if l.node.dir {
		return &dirFile{f: f, l: l, info: info, path: name}, nil
	}
	if !info.mode.IsRegular() {
		return &file{info: info, path: name, special: true}, nil
	}
	r, size, err := f.content(l.node)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &file{info: info, path: name, r: r, size: size}, nil
}

// Stat returns the FileInfo of name without following symlinks.
func (f *FS) Stat(name string) (_ fs.FileInfo, err error) {
	defer guard("stat", name, &err)
	l, err := f.lookup("stat", name)
	if err != nil {
		return nil, err
	}
	return f.info(baseName(name), l), nil
}

// ReadLink returns the target of the named symlink without resolving it.
func (f *FS) ReadLink(name string) (_ string, err error) {
	defer guard("readlink", name, &err)
	l, err := f.lookup("readlink", name)
	if err != nil {
		return "", err
	}
	if fileMode(l.node)&fs.ModeSymlink == 0 {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	t, err := f.linkTarget(l.node)
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}
	return t, nil
}

// ReadDir returns the entries of the named directory sorted by name.
func (f *FS) ReadDir(name string) (_ []fs.DirEntry, err error) {
	defer guard("readdir", name, &err)
	l, err := f.lookup("readdir", name)
	if err != nil {
		return nil, err
	}
	return f.readDir(name, l)
}

func (f *FS) readDir(name string, l loc) ([]fs.DirEntry, error) {
	if !l.node.dir {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("not a directory")}
	}
	dl, err := f.entries(l.node.id)
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	out := make([]fs.DirEntry, 0, len(dl.ents))
	for _, e := range dl.ents {
		if l.anc[e.rec.id] || e.rec.id == rootID {
			f.bump("corrupt_records")
			continue
		}
		out = append(out, &dirEntry{f: f, d: e, anc: l.anc})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

type dirEntry struct {
	f    *FS
	d    dirent
	anc  map[uint32]bool
	once sync.Once
	info fs.FileInfo
	err  error
}

func (e *dirEntry) Name() string   { return e.d.name }
func (e *dirEntry) IsDir() bool    { return e.Type().IsDir() }
func (e *dirEntry) String() string { return fs.FormatDirEntry(e) }
func (e *dirEntry) Type() fs.FileMode {
	if i, err := e.Info(); err == nil {
		return i.Mode().Type()
	}
	return fileMode(e.d.rec).Type()
}

func (e *dirEntry) Info() (_ fs.FileInfo, err error) {
	defer guard("stat", e.d.name, &err)
	e.once.Do(func() {
		node, err := e.f.resolveLink(e.d.rec)
		if err != nil {
			e.err = err
			return
		}
		e.info = e.f.info(e.d.name, loc{rec: e.d.rec, node: node})
	})
	return e.info, e.err
}

type file struct {
	info    *fileInfo
	path    string
	r       io.ReaderAt
	size    int64
	off     int64
	special bool
	closed  bool
}

func (fl *file) Stat() (fs.FileInfo, error) { return fl.info, nil }
func (fl *file) Close() error {
	fl.closed = true
	return nil
}

func (fl *file) Read(p []byte) (n int, err error) {
	defer guard("read", fl.path, &err)
	if fl.closed {
		return 0, &fs.PathError{Op: "read", Path: fl.path, Err: fs.ErrClosed}
	}
	if fl.special {
		return 0, &fs.PathError{Op: "read", Path: fl.path, Err: errors.New("not a regular file")}
	}
	if fl.off >= fl.size {
		return 0, io.EOF
	}
	if int64(len(p)) > fl.size-fl.off {
		p = p[:fl.size-fl.off]
	}
	n, err = fl.r.ReadAt(p, fl.off)
	fl.off += int64(n)
	if err == io.EOF && n > 0 {
		err = nil
	}
	return n, err
}

func (fl *file) ReadAt(p []byte, off int64) (n int, err error) {
	defer guard("read", fl.path, &err)
	if fl.closed || fl.special {
		return 0, &fs.PathError{Op: "read", Path: fl.path, Err: fs.ErrInvalid}
	}
	return fl.r.ReadAt(p, off)
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
		offset += fl.size
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
	l     loc
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

func (d *dirFile) ReadDir(n int) (_ []fs.DirEntry, err error) {
	defer guard("readdir", d.path, &err)
	if d.close {
		return nil, &fs.PathError{Op: "readdir", Path: d.path, Err: fs.ErrClosed}
	}
	if !d.read {
		ents, err := d.f.readDir(d.path, d.l)
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
