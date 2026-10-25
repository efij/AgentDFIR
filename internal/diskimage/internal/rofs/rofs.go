// Package rofs turns a small read-only filesystem backend (the XFS and
// Btrfs readers) into an io/fs.FS. It owns everything the backends would
// otherwise duplicate: path walking, the per-directory name index, cycle
// detection, the total-work budget, panic containment and the fs.File /
// fs.DirEntry / fs.FileInfo plumbing. Symlinks are never followed.
package rofs

import (
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

// Node is one file, directory or other object as the backend decoded it.
type Node struct {
	ID    uint64      // unique within the filesystem; Sys()["inode"] unless the backend sets its own
	Mode  fs.FileMode // type bits and permissions
	Size  int64
	MTime time.Time
	Sys   map[string]any // reader-specific facts (timestamps, inode number, uid …)
	Impl  any            // backend-private
}

// IsDir reports whether n is a directory.
func (n *Node) IsDir() bool { return n.Mode.IsDir() }

// Dirent is one live directory entry.
type Dirent struct {
	Name string
	ID   uint64      // Node.ID of the target, for cycle detection
	Type fs.FileMode // type bits as the directory records them; 0xFFFFFFFF = unknown
	Ref  any         // what Backend.Load needs
}

// UnknownType marks a Dirent whose type the directory does not record.
const UnknownType fs.FileMode = 1<<32 - 1

// Backend is implemented by a filesystem reader. Every method must return
// errors (never panic) on malformed input; panics are contained anyway.
type Backend interface {
	Root() (*Node, error)
	List(dir *Node) ([]Dirent, error)  // live entries, "." and ".." excluded
	Load(d Dirent) (*Node, error)      // the node a directory entry names
	Data(n *Node) (io.ReaderAt, error) // contents of a regular file (n.Size bytes)
	Link(n *Node) (string, error)      // target of a symlink
	FSName() string                    // fs name for errors
}

// FS is the fs.FS view of a Backend. It is safe for concurrent use when the
// backend is.
type FS struct {
	B        Backend
	MaxDepth int // path components accepted by lookups

	mu      sync.Mutex
	cache   map[uint64]*dirList
	cached  int
	work    int64
	workMax int64
	cycles  map[[2]uint64]bool
	stats   map[string]int64
}

type dirList struct {
	ents []Dirent
	idx  map[string]int
}

const cacheLimit = 1 << 20

// New wraps b. workMax caps the total number of directory entries listed
// over the life of the FS (hostile hard-link graphs); callers size it from
// the image size.
func New(b Backend, workMax int64) *FS {
	return &FS{B: b, MaxDepth: 256, cache: map[uint64]*dirList{}, cycles: map[[2]uint64]bool{}, stats: map[string]int64{}, workMax: max(workMax, 1<<20)}
}

// Bump adds n to a named counter.
func (f *FS) Bump(key string, n int64) {
	f.mu.Lock()
	f.stats[key] += n
	f.mu.Unlock()
}

// Counters returns a copy of the counters rofs and the backend accumulated.
func (f *FS) Counters() map[string]int64 {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]int64, len(f.stats)+1)
	for k, v := range f.stats {
		out[k] = v
	}
	out["cycles"] = int64(len(f.cycles))
	return out
}

// Guard turns a panic into an error. It is a backstop: backends reject
// malformed structures before they can index out of range. Tests set
// RethrowPanics so fuzzing still surfaces the underlying bug.
func Guard(fsName, op, name string, err *error) {
	if r := recover(); r != nil {
		if RethrowPanics {
			panic(r)
		}
		*err = &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%s: corrupt: internal error on malformed input: %v", fsName, r)}
	}
}

// RethrowPanics makes Guard re-panic; set only by tests and fuzzing.
var RethrowPanics bool

func (f *FS) entries(n *Node) (*dirList, error) {
	f.mu.Lock()
	if dl, ok := f.cache[n.ID]; ok {
		f.mu.Unlock()
		return dl, nil
	}
	f.mu.Unlock()
	ents, err := f.B.List(n)
	if err != nil {
		return nil, err
	}
	dl := &dirList{ents: ents, idx: make(map[string]int, len(ents))}
	for i, e := range ents {
		if _, dup := dl.idx[e.Name]; !dup {
			dl.idx[e.Name] = i
		}
	}
	f.mu.Lock()
	if f.cached+len(ents) > cacheLimit {
		f.cache, f.cached = map[uint64]*dirList{}, 0
	}
	f.cache[n.ID] = dl
	f.cached += len(ents)
	f.mu.Unlock()
	return dl, nil
}

// lookup resolves name; the returned set holds the IDs of every directory
// on the path (root included).
func (f *FS) lookup(op, name string) (*Node, map[uint64]bool, error) {
	if !fs.ValidPath(name) {
		return nil, nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	n, err := f.B.Root()
	if err != nil {
		return nil, nil, &fs.PathError{Op: op, Path: name, Err: err}
	}
	anc := map[uint64]bool{n.ID: true}
	if name == "." {
		return n, anc, nil
	}
	parts := strings.Split(name, "/")
	if len(parts) > f.MaxDepth {
		return nil, nil, &fs.PathError{Op: op, Path: name, Err: errors.New("path too deep")}
	}
	for _, p := range parts {
		if !n.IsDir() {
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%w: not a directory", fs.ErrNotExist)}
		}
		dl, err := f.entries(n)
		if err != nil {
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: err}
		}
		i, ok := dl.idx[p]
		if !ok {
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
		}
		d := dl.ents[i]
		if anc[d.ID] {
			f.noteCycle(n.ID, d.ID)
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: fmt.Errorf("%s: corrupt: directory cycle: %q points back to an ancestor", f.B.FSName(), p)}
		}
		if n, err = f.B.Load(d); err != nil {
			return nil, nil, &fs.PathError{Op: op, Path: name, Err: err}
		}
		if n.IsDir() {
			anc[n.ID] = true
		}
	}
	return n, anc, nil
}

func (f *FS) noteCycle(parent, child uint64) {
	f.mu.Lock()
	f.cycles[[2]uint64{parent, child}] = true
	f.mu.Unlock()
}

func (f *FS) spend(n int) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.work += int64(n)
	if f.work > f.workMax {
		return fmt.Errorf("%s: corrupt: work budget exhausted after listing %d entries", f.B.FSName(), f.work)
	}
	return nil
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
	defer Guard(f.B.FSName(), "open", name, &err)
	n, anc, err := f.lookup("open", name)
	if err != nil {
		return nil, err
	}
	info := f.info(baseName(name), n)
	if n.IsDir() {
		return &dirFile{f: f, n: n, info: info, path: name, anc: anc}, nil
	}
	if !n.Mode.IsRegular() {
		return &file{f: f, info: info, path: name, special: true}, nil
	}
	r, err := f.B.Data(n)
	if err != nil {
		if errors.Is(err, errors.ErrUnsupported) {
			f.Bump("unsupported_files", 1)
		}
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return &file{f: f, info: info, path: name, r: r, size: n.Size}, nil
}

// Stat returns the FileInfo of name without following symlinks.
func (f *FS) Stat(name string) (_ fs.FileInfo, err error) {
	defer Guard(f.B.FSName(), "stat", name, &err)
	n, _, err := f.lookup("stat", name)
	if err != nil {
		return nil, err
	}
	return f.info(baseName(name), n), nil
}

// ReadLink returns the target of the named symlink without resolving it.
func (f *FS) ReadLink(name string) (_ string, err error) {
	defer Guard(f.B.FSName(), "readlink", name, &err)
	n, _, err := f.lookup("readlink", name)
	if err != nil {
		return "", err
	}
	if n.Mode&fs.ModeSymlink == 0 {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: fs.ErrInvalid}
	}
	t, err := f.B.Link(n)
	if err != nil {
		return "", &fs.PathError{Op: "readlink", Path: name, Err: err}
	}
	return t, nil
}

// ReadDir returns the entries of the named directory sorted by name.
func (f *FS) ReadDir(name string) (_ []fs.DirEntry, err error) {
	defer Guard(f.B.FSName(), "readdir", name, &err)
	n, anc, err := f.lookup("readdir", name)
	if err != nil {
		return nil, err
	}
	return f.readDir(name, n, anc)
}

func (f *FS) readDir(name string, n *Node, anc map[uint64]bool) ([]fs.DirEntry, error) {
	if !n.IsDir() {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("not a directory")}
	}
	dl, err := f.entries(n)
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	if err := f.spend(len(dl.ents)); err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}
	out := make([]fs.DirEntry, 0, len(dl.ents))
	for _, e := range dl.ents {
		if anc[e.ID] {
			f.noteCycle(n.ID, e.ID)
			continue
		}
		out = append(out, &dirEntry{f: f, d: e})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out, nil
}

func (f *FS) info(name string, n *Node) *fileInfo {
	sys := make(map[string]any, len(n.Sys)+2)
	for k, v := range n.Sys {
		sys[k] = v
	}
	if _, ok := sys["inode"]; !ok {
		sys["inode"] = n.ID
	}
	if n.IsDir() {
		sys["dir_id"] = n.ID
	}
	if n.Mode&fs.ModeSymlink != 0 {
		if t, err := f.B.Link(n); err == nil {
			sys["symlink_target"] = t
		} else {
			sys["symlink_error"] = err.Error()
		}
	}
	return &fileInfo{name: name, n: n, sys: sys}
}

type fileInfo struct {
	name string
	n    *Node
	sys  map[string]any
}

func (i *fileInfo) Name() string       { return i.name }
func (i *fileInfo) Size() int64        { return i.n.Size }
func (i *fileInfo) Mode() fs.FileMode  { return i.n.Mode }
func (i *fileInfo) ModTime() time.Time { return i.n.MTime }
func (i *fileInfo) IsDir() bool        { return i.n.IsDir() }
func (i *fileInfo) Sys() any           { return i.sys }

type dirEntry struct {
	f    *FS
	d    Dirent
	once sync.Once
	info fs.FileInfo
	err  error
}

func (e *dirEntry) Name() string { return e.d.Name }
func (e *dirEntry) IsDir() bool  { return e.Type().IsDir() }
func (e *dirEntry) Type() fs.FileMode {
	if e.d.Type != UnknownType {
		return e.d.Type
	}
	if i, err := e.Info(); err == nil {
		return i.Mode().Type()
	}
	return fs.ModeIrregular
}

func (e *dirEntry) Info() (_ fs.FileInfo, err error) {
	defer Guard(e.f.B.FSName(), "stat", e.d.Name, &err)
	e.once.Do(func() {
		n, err := e.f.B.Load(e.d)
		if err != nil {
			e.err = err
			return
		}
		e.info = e.f.info(e.d.Name, n)
	})
	return e.info, e.err
}

func (e *dirEntry) String() string { return fs.FormatDirEntry(e) }

type file struct {
	f       *FS
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
	defer Guard(fl.f.B.FSName(), "read", fl.path, &err)
	if fl.closed {
		return 0, &fs.PathError{Op: "read", Path: fl.path, Err: fs.ErrClosed}
	}
	if fl.special {
		return 0, &fs.PathError{Op: "read", Path: fl.path, Err: errors.New("not a regular file")}
	}
	n, err = fl.ReadAt(p, fl.off)
	fl.off += int64(n)
	return n, err
}

func (fl *file) ReadAt(p []byte, off int64) (n int, err error) {
	defer Guard(fl.f.B.FSName(), "read", fl.path, &err)
	if fl.closed || fl.special || off < 0 {
		return 0, &fs.PathError{Op: "read", Path: fl.path, Err: fs.ErrInvalid}
	}
	if off >= fl.size {
		return 0, io.EOF
	}
	want := len(p)
	if rem := fl.size - off; int64(want) > rem {
		p = p[:rem]
	}
	n, err = fl.r.ReadAt(p, off)
	if err == nil && n < want {
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
	n     *Node
	anc   map[uint64]bool
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
	defer Guard(d.f.B.FSName(), "readdir", d.path, &err)
	if d.close {
		return nil, &fs.PathError{Op: "readdir", Path: d.path, Err: fs.ErrClosed}
	}
	if !d.read {
		ents, err := d.f.readDir(d.path, d.n, d.anc)
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

// ReadFull reads exactly len(p) bytes at off; a short read is an error.
func ReadFull(r io.ReaderAt, p []byte, off int64) error {
	if off < 0 {
		return errors.New("negative offset")
	}
	n, err := r.ReadAt(p, off)
	if n == len(p) {
		return nil
	}
	if err == nil || err == io.EOF {
		err = io.ErrUnexpectedEOF
	}
	return err
}

// UnixMode maps a POSIX st_mode to an fs.FileMode.
func UnixMode(m uint32) fs.FileMode {
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

// DirentType maps the common Linux d_type / ftype codes (1 reg … 7 link).
func DirentType(t uint8) fs.FileMode {
	switch t {
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
	return UnknownType
}

// ValidName reports whether b is a usable directory entry name.
func ValidName(b []byte) bool {
	if len(b) == 0 || string(b) == "." || string(b) == ".." {
		return false
	}
	for _, c := range b {
		if c == 0 || c == '/' {
			return false
		}
	}
	return true
}

// Runs maps a file's logical byte ranges onto the image. Gaps read as
// zeros (holes, unwritten / preallocated extents).
type Runs struct {
	R     io.ReaderAt
	Size  int64 // image size; physical reads past it fail
	Items []Run // sorted by Logical, non-overlapping
}

// Run is one mapped range. Zero runs read as zeros without touching R.
type Run struct {
	Logical, Physical, Length int64
	Zero                      bool
}

// ReadAt implements io.ReaderAt over the runs.
func (m *Runs) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for len(p) > 0 {
		i := sort.Search(len(m.Items), func(i int) bool { return m.Items[i].Logical+m.Items[i].Length > off })
		n := len(p)
		if i == len(m.Items) || m.Items[i].Logical > off {
			if i < len(m.Items) {
				n = int(min(int64(n), m.Items[i].Logical-off))
			}
			clear(p[:n])
		} else {
			r := m.Items[i]
			in := off - r.Logical
			n = int(min(int64(n), r.Length-in))
			if r.Zero {
				clear(p[:n])
			} else {
				at := r.Physical + in
				if at < 0 || at > m.Size-int64(n) {
					return total, errors.New("corrupt: extent points past the end of the image")
				}
				if err := ReadFull(m.R, p[:n], at); err != nil {
					return total, err
				}
			}
		}
		total += n
		p = p[n:]
		off += int64(n)
	}
	return total, nil
}

// Node resolves name to the backend's node (tests and metadata callers).
func (f *FS) Node(name string) (_ *Node, err error) {
	defer Guard(f.B.FSName(), "stat", name, &err)
	n, _, err := f.lookup("stat", name)
	return n, err
}
