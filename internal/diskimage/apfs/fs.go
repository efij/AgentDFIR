package apfs

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
)

const maxPathDeep = 256

// loc is a resolved path: a virtual directory, an unreadable listed entry,
// or an inode in a tree.
type loc struct {
	vd  *virtDir
	bad error
	t   *tree
	in  *inode
	anc map[uint64]bool // directory ids on the path inside t
}

func (f *FS) rootLoc() (loc, error) {
	if f.multi {
		return loc{vd: f.root}, nil
	}
	return f.treeRoot(f.trees[0])
}

func (f *FS) treeRoot(t *tree) (loc, error) {
	in, err := t.inode(rootIno)
	if err != nil {
		return loc{}, err
	}
	return loc{t: t, in: in, anc: map[uint64]bool{rootIno: true}}, nil
}

// lookup resolves name through the virtual layout and the trees.
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
	for i, p := range parts {
		last := i == len(parts)-1
		switch {
		case cur.bad != nil:
			return loc{}, &fs.PathError{Op: op, Path: name, Err: cur.bad}
		case cur.vd != nil:
			ch, ok := cur.vd.children[p]
			if !ok {
				return loc{}, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
			}
			switch c := ch.(type) {
			case *virtDir:
				cur = loc{vd: c}
			case *tree:
				if cur, err = f.treeRoot(c); err != nil {
					return loc{}, &fs.PathError{Op: op, Path: name, Err: err}
				}
			case error:
				if !last {
					return loc{}, &fs.PathError{Op: op, Path: name, Err: c}
				}
				cur = loc{bad: c}
			}
		default:
			t := cur.t
			if cur.in.id == rootIno && t.snapDir != nil && p == t.snapDirName {
				cur = loc{vd: t.snapDir}
				continue
			}
			if !cur.in.isDir() {
				return loc{}, &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%w: not a directory", fs.ErrNotExist)}
			}
			id, ok, err := t.child(cur.in.id, p)
			if err != nil {
				return loc{}, &fs.PathError{Op: op, Path: name, Err: err}
			}
			if !ok {
				return loc{}, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
			}
			if cur.anc[id] {
				f.bump("corrupt_records")
				return loc{}, &fs.PathError{Op: op, Path: name, Err: corrupt("directory cycle: %q points back to an ancestor", p)}
			}
			in, err := t.inode(id)
			if err != nil {
				return loc{}, &fs.PathError{Op: op, Path: name, Err: err}
			}
			anc := cur.anc
			if in.isDir() {
				anc = make(map[uint64]bool, len(cur.anc)+1)
				for k := range cur.anc {
					anc[k] = true
				}
				anc[id] = true
			}
			cur = loc{t: t, in: in, anc: anc}
		}
	}
	return cur, nil
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

func (f *FS) virtInfo(name string, l loc) *fileInfo {
	sys := map[string]any{"fs": "apfs", "virtual": true}
	if l.bad != nil {
		sys["unsupported"] = l.bad.Error()
	}
	if name == "." {
		for k, v := range f.Metadata() {
			sys[k] = v
		}
		for k, v := range f.Stats() {
			sys[k] = v
		}
	}
	return &fileInfo{name: name, mode: fs.ModeDir | 0o555, sys: sys}
}

// info builds the FileInfo of an inode. It reads the xattrs once.
func (f *FS) info(name string, t *tree, in *inode) *fileInfo {
	sys := map[string]any{
		"inode":          t.inodeNumber(in.id),
		"file_id":        in.id,
		"mtime":          tsOf(in.mtime),
		"atime":          tsOf(in.atime),
		"ctime":          tsOf(in.ctime),
		"btime":          tsOf(in.btime),
		"fs":             "apfs",
		"volume":         t.vol.Name,
		"mode":           uint32(in.mode),
		"uid":            in.uid,
		"gid":            in.gid,
		"links":          in.nlink,
		"bsd_flags":      in.bsd,
		"internal_flags": in.iflags,
	}
	if t.snap != nil {
		sys["snapshot"] = t.snap.Name
		sys["snapshot_xid"] = t.snap.XID
	}
	if in.isDir() {
		sys["dir_id"] = t.inodeNumber(in.id)
	}
	size := int64(in.size)
	if xs, err := t.xattrs(in.id); err != nil {
		sys["xattr_error"] = err.Error()
	} else if len(xs) > 0 {
		names := make([]string, 0, len(xs))
		for _, x := range xs {
			names = append(names, x.name)
			switch {
			case x.name == "com.apple.decmpfs" && in.bsd&ufCompressed != 0:
				if h, err := ParseDecmpfs(x.data); err == nil {
					size = int64(h.Size)
					sys["compression"] = compressionName(h.Type)
					if h.Type != 1 && h.Type != 3 && h.Type != 4 {
						sys["unsupported"] = compressionName(h.Type) + " compression"
					}
				} else {
					sys["unsupported"] = err.Error()
				}
			case x.name == "com.apple.fs.symlink" && in.isLink():
				sys["symlink_target"] = cstring(x.data)
			}
		}
		sort.Strings(names)
		sys["xattrs"] = names
	}
	if !in.isReg() {
		if in.isLink() {
			if t, ok := sys["symlink_target"].(string); ok {
				size = int64(len(t))
			}
		} else {
			size = 0
		}
	}
	if in.id == rootIno && t.snap == nil && !f.multi {
		for k, v := range f.Metadata() {
			if k != "fs" {
				sys[k] = v
			}
		}
		for k, v := range f.Stats() {
			sys[k] = v
		}
	}
	return &fileInfo{name: name, size: size, mode: fileMode(in.mode), mtime: tsOf(in.mtime), sys: sys}
}

func baseName(name string) string {
	if name == "." {
		return "."
	}
	return path.Base(name)
}

// Open opens the named file or directory. Symlinks are not followed: the
// returned file reports fs.ModeSymlink and its Read fails.
func (f *FS) Open(name string) (_ fs.File, err error) {
	defer guard("open", name, &err)
	l, err := f.lookup("open", name)
	if err != nil {
		return nil, err
	}
	if l.vd != nil || l.bad != nil {
		return &dirFile{f: f, l: l, info: f.virtInfo(baseName(name), l), path: name}, nil
	}
	info := f.info(baseName(name), l.t, l.in)
	if l.in.isDir() {
		return &dirFile{f: f, l: l, info: info, path: name}, nil
	}
	if !l.in.isReg() {
		return &file{info: info, path: name, special: true}, nil
	}
	r, err := f.content(l.t, l.in, info)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &file{info: info, path: name, r: r, size: info.size}, nil
}

// content returns a reader over a regular file's bytes.
func (f *FS) content(t *tree, in *inode, info *fileInfo) (io.ReaderAt, error) {
	if in.bsd&ufCompressed == 0 {
		return t.dataStream(in.private, int64(in.size))
	}
	xs, err := t.xattrs(in.id)
	if err != nil {
		return nil, err
	}
	var attr []byte
	var rsrc *xattr
	for i := range xs {
		switch xs[i].name {
		case "com.apple.decmpfs":
			if attr, err = t.xattrValue(xs[i], maxXattrInline); err != nil {
				return nil, err
			}
		case "com.apple.ResourceFork":
			rsrc = &xs[i]
		}
	}
	if attr == nil {
		f.bump("corrupt_records")
		return nil, corrupt("compressed file %d has no decmpfs xattr", in.id)
	}
	b, err := DecodeDecmpfs(attr, func() ([]byte, error) {
		if rsrc == nil {
			return nil, corrupt("compressed file %d has no resource fork", in.id)
		}
		return t.xattrValue(*rsrc, maxDecmpfs)
	})
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			f.bump("unsupported_files")
		}
		return nil, err
	}
	return bytes.NewReader(b), nil
}

// Stat returns the FileInfo of name without following symlinks.
func (f *FS) Stat(name string) (_ fs.FileInfo, err error) {
	defer guard("stat", name, &err)
	l, err := f.lookup("stat", name)
	if err != nil {
		return nil, err
	}
	if l.vd != nil || l.bad != nil {
		return f.virtInfo(baseName(name), l), nil
	}
	return f.info(baseName(name), l.t, l.in), nil
}

// ReadLink returns the target of the named symlink without resolving it.
func (f *FS) ReadLink(name string) (_ string, err error) {
	defer guard("readlink", name, &err)
	l, err := f.lookup("readlink", name)
	if err != nil {
		return "", err
	}
	if l.in == nil || !l.in.isLink() {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	xs, err := l.t.xattrs(l.in.id)
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}
	for _, x := range xs {
		if x.name == "com.apple.fs.symlink" {
			v, err := l.t.xattrValue(x, maxLinkLen)
			if err != nil {
				return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
			}
			return cstring(v), nil
		}
	}
	return "", &fs.PathError{Op: "readlink", Path: name, Err: corrupt("symlink without a target")}
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
	if l.bad != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: l.bad}
	}
	var out []fs.DirEntry
	if l.vd != nil {
		for _, n := range l.vd.order {
			out = append(out, &dirEntry{f: f, name: n, virt: l.vd.children[n]})
		}
	} else {
		if !l.in.isDir() {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("not a directory")}
		}
		dl, err := l.t.dirEntries(l.in.id)
		if err != nil {
			return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
		}
		for _, e := range dl.ents {
			if l.anc[e.id] || e.id == rootIno {
				f.bump("corrupt_records") // points back to an ancestor or the root
				continue
			}
			out = append(out, &dirEntry{f: f, name: e.name, t: l.t, d: e})
		}
		if l.in.id == rootIno && l.t.snapDir != nil {
			out = append(out, &dirEntry{f: f, name: l.t.snapDirName, virt: l.t.snapDir})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

type dirEntry struct {
	f    *FS
	name string
	virt any // *virtDir, *tree or error for virtual entries
	t    *tree
	d    dirent
	once sync.Once
	info fs.FileInfo
	err  error
}

func (e *dirEntry) Name() string { return e.name }
func (e *dirEntry) IsDir() bool  { return e.Type().IsDir() }

func (e *dirEntry) Type() fs.FileMode {
	if e.virt != nil {
		return fs.ModeDir
	}
	switch e.d.dtype {
	case 8:
		return 0
	case 4:
		return fs.ModeDir
	case 10:
		return fs.ModeSymlink
	case 2:
		return fs.ModeDevice | fs.ModeCharDevice
	case 6:
		return fs.ModeDevice
	case 1:
		return fs.ModeNamedPipe
	case 12:
		return fs.ModeSocket
	}
	if i, err := e.Info(); err == nil {
		return i.Mode().Type()
	}
	return fs.ModeIrregular
}

func (e *dirEntry) Info() (_ fs.FileInfo, err error) {
	defer guard("stat", e.name, &err)
	e.once.Do(func() {
		switch v := e.virt.(type) {
		case *virtDir:
			e.info = e.f.virtInfo(e.name, loc{vd: v})
			return
		case error:
			e.info = e.f.virtInfo(e.name, loc{bad: v})
			return
		case *tree:
			in, err := v.inode(rootIno)
			if err != nil {
				e.err = err
				return
			}
			e.info = e.f.info(e.name, v, in)
			return
		}
		in, err := e.t.inode(e.d.id)
		if err != nil {
			e.err = err
			return
		}
		e.info = e.f.info(e.name, e.t, in)
	})
	return e.info, e.err
}

func (e *dirEntry) String() string { return fs.FormatDirEntry(e) }

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
	if off >= fl.size {
		return 0, io.EOF
	}
	short := false
	if int64(len(p)) > fl.size-off {
		p, short = p[:fl.size-off], true
	}
	n, err = fl.r.ReadAt(p, off)
	if err == nil && short {
		err = io.EOF
	}
	return n, err
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
