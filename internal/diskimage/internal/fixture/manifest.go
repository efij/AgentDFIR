package fixture

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"
)

// Entry is one line of a manifest written by gen-linux-inner.sh from the
// mounted filesystem with coreutils: "type size sha256|target mtime path".
type Entry struct {
	Type   string // f, d, l
	Size   int64
	SHA256 string // regular files
	Target string // symlinks
	MTime  int64
	Path   string
}

// ReadManifest parses a manifest file.
func ReadManifest(path string) ([]Entry, error) {
	fh, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fh.Close()
	var out []Entry
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		parts := strings.SplitN(sc.Text(), " ", 5)
		if len(parts) != 5 {
			return nil, fmt.Errorf("bad manifest line %q", sc.Text())
		}
		e := Entry{Type: parts[0], Path: parts[4]}
		e.MTime, _ = strconv.ParseInt(parts[3], 10, 64)
		switch e.Type {
		case "f":
			e.Size, _ = strconv.ParseInt(parts[1], 10, 64)
			e.SHA256 = parts[2]
		case "l":
			e.Target = parts[2]
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Compare walks fsys and checks it against the manifest: the same set of
// paths, types, sizes, contents, link targets and modification times.
// Paths for which skip returns true are ignored on both sides. It returns
// every difference (empty when they match).
func Compare(fsys fs.FS, want []Entry, skip func(string) bool) []string {
	var diffs []string
	seen := map[string]bool{}
	byPath := map[string]Entry{}
	for _, e := range want {
		if skip == nil || !skip(e.Path) {
			byPath[e.Path] = e
		}
	}
	err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			diffs = append(diffs, fmt.Sprintf("%s: %v", p, err))
			return nil
		}
		if p == "." || (skip != nil && skip(p)) {
			if p != "." && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		seen[p] = true
		e, ok := byPath[p]
		if !ok {
			diffs = append(diffs, "unexpected "+p)
			return nil
		}
		info, err := d.Info()
		if err != nil {
			diffs = append(diffs, fmt.Sprintf("%s: info: %v", p, err))
			return nil
		}
		if info.ModTime().Unix() != e.MTime {
			diffs = append(diffs, fmt.Sprintf("%s: mtime %d, want %d", p, info.ModTime().Unix(), e.MTime))
		}
		switch e.Type {
		case "d":
			if !d.IsDir() {
				diffs = append(diffs, p+": not a directory")
			}
		case "l":
			rl, ok := fsys.(interface{ ReadLink(string) (string, error) })
			if d.Type()&fs.ModeSymlink == 0 || !ok {
				diffs = append(diffs, p+": not a symlink")
				return nil
			}
			if t, err := rl.ReadLink(p); err != nil || t != e.Target {
				diffs = append(diffs, fmt.Sprintf("%s: target %q (%v), want %q", p, t, err, e.Target))
			}
		case "f":
			if !d.Type().IsRegular() || info.Size() != e.Size {
				diffs = append(diffs, fmt.Sprintf("%s: type %v size %d, want regular %d", p, d.Type(), info.Size(), e.Size))
				return nil
			}
			f, err := fsys.Open(p)
			if err != nil {
				diffs = append(diffs, fmt.Sprintf("%s: open: %v", p, err))
				return nil
			}
			h := sha256.New()
			_, err = io.Copy(h, f)
			f.Close()
			if got := hex.EncodeToString(h.Sum(nil)); err != nil || got != e.SHA256 {
				diffs = append(diffs, fmt.Sprintf("%s: sha256 %s (%v), want %s", p, got, err, e.SHA256))
			}
		}
		return nil
	})
	if err != nil {
		diffs = append(diffs, err.Error())
	}
	for p := range byPath {
		if !seen[p] {
			diffs = append(diffs, "missing "+p)
		}
	}
	return diffs
}
