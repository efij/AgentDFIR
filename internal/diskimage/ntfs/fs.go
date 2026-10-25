package ntfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"time"
)

// File attribute bits from $STANDARD_INFORMATION.
const (
	faReparsePoint = 0x0400
	faCompressed   = 0x0800
	faEncrypted    = 0x4000
)

// node is one in-use base MFT record.
type node struct {
	rec      uint64
	seq      uint16
	dir      bool
	virtual  bool // synthesized ($OrphanFiles)
	names    []fileName
	si       stdInfo
	size     int64
	ads      []string
	reparse  bool
	attrList bool
	dataFlag uint16
	label    string
	parent   *node // directories only: the one directory this is linked under

	kids    []dirent
	byName  map[string]int
	byLower map[string]int
}

type dirent struct {
	name string
	n    *node
}

// fill extracts names, times, size and stream names from attributes.
func (nd *node) fill(as []attr) {
	for _, a := range as {
		switch a.typ {
		case atStandardInformation:
			if a.resident && !nd.si.ok {
				nd.si = parseStdInfo(a.value)
			}
		case atFileName:
			if a.resident {
				if fn, ok := parseFileName(a.value); ok {
					nd.names = append(nd.names, fn)
				}
			}
		case atData:
			if a.name != "" {
				if (a.resident || a.startVCN == 0) && !contains(nd.ads, a.name) {
					nd.ads = append(nd.ads, a.name)
				}
				continue
			}
			if a.resident || a.startVCN == 0 {
				nd.size = a.dataSize
				nd.dataFlag = a.flags
			}
		case atReparsePoint:
			nd.reparse = true
		case atVolumeName:
			if a.resident {
				nd.label = utf16LE(a.value)
			}
		}
	}
	if nd.si.attrs&faReparsePoint != 0 {
		nd.reparse = true
	}
	sort.Strings(nd.ads)
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// linkNames returns the names this record is linked under. A directory
// gets exactly one (so the tree cannot loop); a file gets one per hard
// link. Win32 / POSIX names win over DOS 8.3 aliases.
func (nd *node) linkNames() []fileName {
	var full, dos []fileName
	for _, fn := range nd.names {
		if fn.namespace == 2 {
			dos = append(dos, fn)
			continue
		}
		dup := false
		for _, g := range full {
			if g.parent == fn.parent && g.name == fn.name {
				dup = true
			}
		}
		if !dup {
			full = append(full, fn)
		}
	}
	if len(full) == 0 {
		full = dos
	}
	if nd.dir && len(full) > 1 {
		full = full[:1]
	}
	return full
}

func (nd *node) add(name string, child *node) {
	if nd.byName == nil {
		nd.byName, nd.byLower = map[string]int{}, map[string]int{}
	}
	if _, dup := nd.byName[name]; dup {
		return // two records claiming one name: first (lowest record) wins
	}
	nd.byName[name] = len(nd.kids)
	nd.kids = append(nd.kids, dirent{name: name, n: child})
}

func (nd *node) sortKids() {
	sort.Slice(nd.kids, func(i, j int) bool { return nd.kids[i].name < nd.kids[j].name })
	nd.byName, nd.byLower = map[string]int{}, map[string]int{}
	for i, k := range nd.kids {
		nd.byName[k.name] = i
		if _, ok := nd.byLower[strings.ToLower(k.name)]; !ok {
			nd.byLower[strings.ToLower(k.name)] = i
		}
	}
}

// child looks a name up exactly, then case-insensitively (Win32 semantics).
func (nd *node) child(name string) *dirent {
	if i, ok := nd.byName[name]; ok {
		return &nd.kids[i]
	}
	if i, ok := nd.byLower[strings.ToLower(name)]; ok {
		return &nd.kids[i]
	}
	return nil
}

// times returns btime, mtime, ctime (MFT change), atime.
func (nd *node) times() (b, m, c, a time.Time) {
	if nd.si.ok {
		return nd.si.btime, nd.si.mtime, nd.si.ctime, nd.si.atime
	}
	if len(nd.names) > 0 {
		t := nd.names[0].times
		return t[0], t[1], t[2], t[3]
	}
	return
}

// Volume is an opened NTFS volume; it implements fs.FS, fs.ReadDirFS and
// fs.StatFS.
type Volume struct {
	v     *volume
	nodes map[uint64]*node
	root  *node
	stats Stats
}

// Stats reports what the MFT walk found (deleted records skipped,
// orphans, corrupt records, label, shadow-copy store files).
func (f *Volume) Stats() Stats { return f.stats }

func (f *Volume) resolve(op, name string) (*node, string, error) {
	if !fs.ValidPath(name) {
		return nil, "", &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return f.root, ".", nil
	}
	cur := f.root
	base := ""
	parts := strings.Split(name, "/")
	if len(parts) > maxResolveDepth {
		return nil, "", &fs.PathError{Op: op, Path: name, Err: fs.ErrInvalid}
	}
	for _, p := range parts {
		if !cur.dir {
			return nil, "", &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
		}
		d := cur.child(p)
		if d == nil {
			return nil, "", &fs.PathError{Op: op, Path: name, Err: fs.ErrNotExist}
		}
		cur, base = d.n, d.name
	}
	return cur, base, nil
}

// Open implements fs.FS.
func (f *Volume) Open(name string) (fs.File, error) {
	nd, base, err := f.resolve("open", name)
	if err != nil {
		return nil, err
	}
	info := &fileInfo{name: base, nd: nd}
	if nd.dir {
		return &dirFile{info: info, nd: nd}, nil
	}
	h := &file{info: info}
	if nd.reparse {
		return h, nil // reads fail: reparse points are not followed
	}
	s, err := f.dataStream(nd)
	if err != nil {
		h.err = err
		return h, nil
	}
	h.s = s
	return h, nil
}

// dataStream re-reads the record and assembles its unnamed $DATA.
func (f *Volume) dataStream(nd *node) (*stream, error) {
	rec, err := f.v.readRecord(nd.rec)
	if err != nil {
		return nil, err
	}
	as := rec.attrs
	if nd.attrList {
		if as, err = f.v.withExtensions(rec); err != nil {
			return nil, err
		}
	}
	frags := dataFragments(as, "")
	if len(frags) == 0 {
		return &stream{v: f.v, resident: []byte{}, cuIdx: -1}, nil
	}
	return f.v.newStream(frags)
}

// ReadDir implements fs.ReadDirFS.
func (f *Volume) ReadDir(name string) ([]fs.DirEntry, error) {
	nd, _, err := f.resolve("readdir", name)
	if err != nil {
		return nil, err
	}
	if !nd.dir {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: errors.New("not a directory")}
	}
	out := make([]fs.DirEntry, len(nd.kids))
	for i, k := range nd.kids {
		out[i] = fs.FileInfoToDirEntry(&fileInfo{name: k.name, nd: k.n})
	}
	return out, nil
}

// Stat implements fs.StatFS.
func (f *Volume) Stat(name string) (fs.FileInfo, error) {
	nd, base, err := f.resolve("stat", name)
	if err != nil {
		return nil, err
	}
	return &fileInfo{name: base, nd: nd}, nil
}

type fileInfo struct {
	name string
	nd   *node
}

func (i *fileInfo) Name() string { return i.name }
func (i *fileInfo) Size() int64 {
	if i.nd.dir {
		return 0
	}
	return i.nd.size
}
func (i *fileInfo) Mode() fs.FileMode {
	switch {
	case i.nd.dir:
		return fs.ModeDir | 0o555
	case i.nd.reparse:
		return fs.ModeSymlink | fs.ModeIrregular | 0o444
	}
	return 0o444
}
func (i *fileInfo) ModTime() time.Time {
	_, m, _, _ := i.nd.times()
	return m
}
func (i *fileInfo) IsDir() bool { return i.nd.dir }

// Sys returns the forensic metadata: MFT record number as "inode", the
// four $STANDARD_INFORMATION timestamps (UTC), alternate data stream
// names, and NTFS attribute flags.
func (i *fileInfo) Sys() any {
	b, m, c, a := i.nd.times()
	out := map[string]any{
		"fs": "ntfs", "inode": i.nd.rec,
		"btime": b, "mtime": m, "ctime": c, "atime": a,
	}
	if len(i.nd.ads) > 0 {
		out["ads"] = append([]string(nil), i.nd.ads...)
	}
	if i.nd.si.ok {
		out["attributes"] = i.nd.si.attrs
	}
	if i.nd.dataFlag&afCompressed != 0 {
		out["compressed"] = true
	}
	if i.nd.dataFlag&afSparse != 0 {
		out["sparse"] = true
	}
	if i.nd.dataFlag&afEncrypted != 0 || i.nd.si.attrs&faEncrypted != 0 {
		out["encrypted"] = true
	}
	if i.nd.reparse {
		out["reparse_point"] = true
	}
	return out
}

// file is an open regular file.
type file struct {
	info *fileInfo
	s    *stream
	err  error // why content is unavailable
	off  int64
}

func (h *file) Stat() (fs.FileInfo, error) { return h.info, nil }
func (h *file) Close() error               { return nil }

func (h *file) ReadAt(p []byte, off int64) (int, error) {
	if h.info.nd.reparse {
		return 0, fmt.Errorf("%w: reparse point (symlink/junction) not followed", ErrUnsupported)
	}
	if h.err != nil {
		return 0, h.err
	}
	return h.s.ReadAt(p, off)
}

func (h *file) Read(p []byte) (int, error) {
	n, err := h.ReadAt(p, h.off)
	h.off += int64(n)
	return n, err
}

func (h *file) Seek(off int64, whence int) (int64, error) {
	switch whence {
	case io.SeekStart:
	case io.SeekCurrent:
		off += h.off
	case io.SeekEnd:
		off += h.info.nd.size
	}
	if off < 0 {
		return 0, fmt.Errorf("negative seek")
	}
	h.off = off
	return off, nil
}

// dirFile is an open directory.
type dirFile struct {
	info *fileInfo
	nd   *node
	pos  int
}

func (d *dirFile) Stat() (fs.FileInfo, error) { return d.info, nil }
func (d *dirFile) Close() error               { return nil }
func (d *dirFile) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.info.name, Err: errors.New("is a directory")}
}

func (d *dirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	rest := d.nd.kids[d.pos:]
	if n > 0 && len(rest) > n {
		rest = rest[:n]
	}
	if n > 0 && len(rest) == 0 {
		return nil, io.EOF
	}
	out := make([]fs.DirEntry, len(rest))
	for i, k := range rest {
		out[i] = fs.FileInfoToDirEntry(&fileInfo{name: k.name, nd: k.n})
	}
	d.pos += len(rest)
	return out, nil
}
