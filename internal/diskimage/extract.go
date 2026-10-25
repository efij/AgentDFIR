package diskimage

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/products"
)

// Candidate discovery mirrors collector.DiscoverProfiles + the collector
// manifests, but runs against an fs.FS inside the image, so only the
// files the import pipeline would collect are ever read out.

// Limits bounds discovery and extraction on one filesystem. Hostile
// images can carry directory loops or millions of entries; every cap that
// is hit stops the work and is recorded as a problem, never silently.
type Limits struct {
	MaxEntries    int   // directory entries visited (discovery + subtree walks)
	MaxFiles      int   // candidate files
	MaxFileBytes  int64 // per extracted file
	MaxTotalBytes int64 // all extracted files
}

// DefaultLimits are generous for real profiles and small next to a disk.
func DefaultLimits() Limits {
	return Limits{MaxEntries: 2_000_000, MaxFiles: 200_000, MaxFileBytes: 512 << 20, MaxTotalBytes: 8 << 30}
}

func (l *Limits) fill() {
	d := DefaultLimits()
	if l.MaxEntries <= 0 {
		l.MaxEntries = d.MaxEntries
	}
	if l.MaxFiles <= 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxTotalBytes <= 0 {
		l.MaxTotalBytes = d.MaxTotalBytes
	}
}

// ProfileHit is a user profile directory inside the filesystem holding at
// least one known AI agent product.
type ProfileHit struct {
	Path     string   `json:"path"`
	Products []string `json:"products"`
}

// Candidates is the discovery result for one filesystem.
type Candidates struct {
	Profiles []ProfileHit
	Files    []string // fs paths, sorted, deduplicated
	Problems []string
	Capped   bool // a limit stopped discovery early
}

// profileDepth is how deep below the filesystem root a profile may sit
// (Users/<u>, home/<u>, private/var/root …).
const profileDepth = 3

// Top-level directories that never hold user profiles; skipping them keeps
// discovery cheap on a full system volume.
var skipTop = map[string]bool{
	"windows": true, "program files": true, "program files (x86)": true, "programdata": true,
	"$recycle.bin": true, "system volume information": true, "recovery": true, "perflogs": true,
	"$orphanfiles": true, "proc": true, "sys": true, "dev": true, "usr": true, "lib": true, "lib32": true,
	"lib64": true, "bin": true, "sbin": true, "boot": true, "snap": true, "run": true, "etc": true,
	"system": true, "applications": true, "cores": true, "nix": true, "lost+found": true,
}

type walker struct {
	fsys     fs.FS
	lim      Limits
	entries  int
	seenDirs map[uint64]bool // discovery
	walked   map[uint64]bool // subtree walks, across all patterns
	c        *Candidates
	files    map[string]bool
}

func (w *walker) problem(format string, args ...any) {
	if len(w.c.Problems) < 100 {
		w.c.Problems = append(w.c.Problems, fmt.Sprintf(format, args...))
	}
}

// capHit records that a limit stopped the walk.
func (w *walker) capHit(what string) {
	if !w.c.Capped {
		w.problem("stopped: %s limit reached; evidence beyond this point was not examined", what)
	}
	w.c.Capped = true
}

// enterDir reports whether a directory should be read: false when it was
// already visited under another path (a loop or a duplicate link).
func (w *walker) enterDir(p string, info fs.FileInfo) bool {
	if ino, ok := inodeOf(info); ok {
		if w.seenDirs[ino] {
			w.problem("%s: directory (inode %d) already visited; loop or duplicate link not followed", p, ino)
			return false
		}
		w.seenDirs[ino] = true
	}
	return true
}

func (w *walker) readDir(p string) []fs.DirEntry {
	if w.c.Capped {
		return nil
	}
	ents, err := fs.ReadDir(w.fsys, p)
	if err != nil {
		w.problem("%s: %v", p, err)
	}
	if w.entries+len(ents) > w.lim.MaxEntries {
		ents = ents[:max(0, w.lim.MaxEntries-w.entries)]
		w.entries = w.lim.MaxEntries
		w.capHit("directory-entry")
		return ents
	}
	w.entries += len(ents)
	return ents
}

func (w *walker) addFile(p string) {
	if w.files[p] || w.c.Capped {
		return
	}
	if len(w.files) >= w.lim.MaxFiles {
		w.capHit("candidate-file")
		return
	}
	w.files[p] = true
}

// inodeOf reads the "inode" key every reader's FileInfo.Sys() carries.
func inodeOf(info fs.FileInfo) (uint64, bool) {
	if info == nil {
		return 0, false
	}
	m, ok := info.Sys().(map[string]any)
	if !ok {
		return 0, false
	}
	switch v := m["inode"].(type) {
	case uint64:
		return v, true
	case uint32:
		return uint64(v), true
	case int64:
		return uint64(v), v >= 0
	case int:
		return uint64(v), v >= 0
	}
	return 0, false
}

// FindCandidates discovers profiles with known products and resolves
// every product's collector manifest (all platforms) against them.
func FindCandidates(fsys fs.FS, prods []products.Product, lim Limits) *Candidates {
	lim.fill()
	c := &Candidates{}
	w := &walker{fsys: fsys, lim: lim, seenDirs: map[uint64]bool{}, walked: map[uint64]bool{}, c: c, files: map[string]bool{}}
	type item struct {
		p     string
		depth int
	}
	queue := []item{{".", 0}}
	if fi, err := fs.Stat(fsys, "."); err == nil {
		w.enterDir(".", fi)
	}
	for len(queue) > 0 && !c.Capped {
		it := queue[0]
		queue = queue[1:]
		if found := productsAt(fsys, it.p, prods); len(found) > 0 {
			c.Profiles = append(c.Profiles, ProfileHit{Path: it.p, Products: found})
			continue // a profile's subtree is not itself a profile
		}
		if it.depth >= profileDepth {
			continue
		}
		for _, e := range w.readDir(it.p) {
			if !e.IsDir() || e.Type()&fs.ModeSymlink != 0 {
				continue
			}
			if it.depth == 0 && skipTop[strings.ToLower(e.Name())] {
				continue
			}
			child := path.Join(it.p, e.Name())
			info, err := e.Info()
			if err != nil || !w.enterDir(child, info) {
				continue
			}
			queue = append(queue, item{child, it.depth + 1})
		}
	}
	// System-wide manifest entries (${SYSTEM_ROOT}/etc/claude-code/** …).
	done := map[string]bool{}
	for _, pr := range c.Profiles {
		for _, pid := range pr.Products {
			man, err := products.ManifestAllPlatforms(pid)
			if err != nil || man == nil {
				continue
			}
			configRoot := pr.Path
			if p, err := products.ByID(pid); err == nil && len(p.ConfigDirs) > 0 {
				configRoot = path.Join(pr.Path, p.ConfigDirs[0])
			}
			for _, e := range man.Entries {
				for _, pat := range e.Paths {
					if strings.Contains(pat, "${SYSTEM_ROOT}") {
						if done[pat] {
							continue
						}
						done[pat] = true
					}
					w.resolvePattern(expandPattern(pat, pr.Path, configRoot))
				}
			}
		}
	}
	for p := range w.files {
		c.Files = append(c.Files, p)
	}
	sort.Strings(c.Files)
	return c
}

func productsAt(fsys fs.FS, dir string, prods []products.Product) []string {
	var found []string
	for _, p := range prods {
		hit := false
		for _, d := range p.ConfigDirs {
			if fi, err := fs.Stat(fsys, path.Join(dir, strings.ReplaceAll(d, "\\", "/"))); err == nil && fi.IsDir() {
				hit = true
				break
			}
		}
		for _, f := range p.ConfigFiles {
			if hit {
				break
			}
			if fi, err := fs.Stat(fsys, path.Join(dir, f)); err == nil && fi.Mode().IsRegular() {
				hit = true
			}
		}
		if hit {
			found = append(found, p.ID)
		}
	}
	sort.Strings(found)
	return found
}

// expandPattern resolves manifest variables to fs paths ("" when an
// unknown variable remains).
func expandPattern(pat, profile, config string) string {
	out := strings.NewReplacer("${PROFILE_ROOT}", profile, "${CONFIG_ROOT}", config, "${SYSTEM_ROOT}", ".").Replace(pat)
	if strings.Contains(out, "${") {
		return ""
	}
	out = path.Clean(strings.ReplaceAll(out, "\\", "/"))
	if !fs.ValidPath(out) {
		return ""
	}
	return out
}

func hasMeta(s string) bool { return strings.ContainsAny(s, "*?[") }

func (w *walker) resolvePattern(pat string) {
	if pat == "" || w.c.Capped {
		return
	}
	if strings.HasSuffix(pat, "/**") || pat == "**" {
		base := strings.TrimSuffix(strings.TrimSuffix(pat, "**"), "/")
		if base == "" {
			base = "."
		}
		bases := []string{base}
		if hasMeta(base) {
			m, err := fs.Glob(w.fsys, base)
			if err != nil {
				w.problem("glob %s: %v", base, err)
				return
			}
			bases = m
		}
		for _, b := range bases {
			w.walkTree(b)
		}
		return
	}
	matches := []string{pat}
	if hasMeta(pat) {
		m, err := fs.Glob(w.fsys, pat)
		if err != nil {
			w.problem("glob %s: %v", pat, err)
			return
		}
		matches = m
	}
	for _, m := range matches {
		if fi, err := fs.Stat(w.fsys, m); err == nil && fi.Mode().IsRegular() {
			w.addFile(m)
		}
	}
}

// walkTree collects every regular file below base: directories are
// deduplicated by inode, entries and files are capped.
func (w *walker) walkTree(base string) {
	fi, err := fs.Stat(w.fsys, base)
	if err != nil || !fi.IsDir() {
		return
	}
	stack := []string{base}
	for len(stack) > 0 && !w.c.Capped {
		d := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, e := range w.readDir(d) {
			p := path.Join(d, e.Name())
			switch {
			case e.Type()&fs.ModeSymlink != 0 || e.Type()&fs.ModeIrregular != 0:
				continue // never followed
			case e.IsDir():
				info, err := e.Info()
				if err != nil {
					continue
				}
				if ino, ok := inodeOf(info); ok {
					if w.walked[ino] {
						w.problem("%s: directory (inode %d) already visited; loop or duplicate link not followed", p, ino)
						continue
					}
					w.walked[ino] = true
				}
				stack = append(stack, p)
			case e.Type().IsRegular():
				w.addFile(p)
			}
		}
	}
}

// Extracted is one file read out of the image into staging.
type Extracted struct {
	FSPath  string // path inside the filesystem
	Staged  string // path under the staging directory
	Size    int64
	SHA256  string
	Sys     map[string]any
	Problem string // set when the file could not be extracted
}

// ExtractResult is the outcome of ExtractFiles.
type ExtractResult struct {
	Files    []Extracted
	Bytes    int64
	Problems []string
	Capped   bool
}

// ExtractFiles copies files from fsys into dest (created 0700; files
// 0600) and sets each staged file's mtime/atime to the original's, so the
// import pipeline records the times the image holds. Per-file and total
// byte caps stop extraction with a recorded problem.
func ExtractFiles(fsys fs.FS, files []string, dest string, lim Limits) *ExtractResult {
	lim.fill()
	res := &ExtractResult{}
	for _, p := range files {
		if res.Capped {
			res.Files = append(res.Files, Extracted{FSPath: p, Problem: "not extracted: total byte limit reached"})
			continue
		}
		ex := Extracted{FSPath: p}
		info, err := fs.Stat(fsys, p)
		if err != nil {
			ex.Problem = err.Error()
			res.Files = append(res.Files, ex)
			continue
		}
		if m, ok := info.Sys().(map[string]any); ok {
			ex.Sys = m
		}
		ex.Size = info.Size()
		switch {
		case !info.Mode().IsRegular():
			ex.Problem = "not a regular file; not extracted"
		case info.Size() > lim.MaxFileBytes:
			ex.Problem = fmt.Sprintf("size %d exceeds the per-file limit %d; not extracted", info.Size(), lim.MaxFileBytes)
		case res.Bytes+info.Size() > lim.MaxTotalBytes:
			ex.Problem = "not extracted: total byte limit reached"
			res.Capped = true
			res.Problems = append(res.Problems, fmt.Sprintf("stopped: total extraction limit %d bytes reached at %s", lim.MaxTotalBytes, p))
		default:
			staged, err := StagePath(dest, p)
			if err != nil {
				ex.Problem = err.Error()
				res.Problems = append(res.Problems, err.Error())
				break
			}
			ex.Staged = staged
			n, sum, err := copyOut(fsys, p, dest, ex.Staged, lim.MaxFileBytes)
			if err != nil {
				ex.Problem = err.Error()
				ex.Staged = ""
			} else {
				ex.Size, ex.SHA256 = n, sum
				res.Bytes += n
				setTimes(ex.Staged, ex.Sys)
			}
		}
		res.Files = append(res.Files, ex)
	}
	return res
}

// reservedDevice matches Windows device names, which address a device
// instead of a file whatever the extension (CON, NUL.txt, COM1.log …).
func reservedDevice(elem string) bool {
	base := strings.ToUpper(strings.TrimRight(elem, " ."))
	if i := strings.IndexByte(base, '.'); i >= 0 {
		base = strings.TrimRight(base[:i], " ")
	}
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		switch base[3:] {
		case "0", "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return true
		}
	}
	return false
}

// StagePath maps a filesystem path from an image onto dest. Names inside
// an image are hostile and the readers are pluggable, so this check is
// the authoritative one: every element must be a plain name on every
// host OS, and the joined result must stay inside dest. Rejections carry
// the original name escaped.
func StagePath(dest, p string) (string, error) {
	elems := strings.Split(p, "/")
	for _, e := range elems {
		bad := ""
		switch {
		case e == "" || e == "." || e == "..":
			bad = "empty or relative element"
		case strings.ContainsAny(e, "\\:"):
			bad = "contains a path or stream separator"
		case strings.TrimRight(e, " .") != e:
			bad = "ends in a space or dot (Windows strips these)"
		case reservedDevice(e):
			bad = "Windows reserved device name"
		default:
			for _, r := range e {
				if r < 0x20 || r == 0x7f {
					bad = "contains a control character"
					break
				}
			}
		}
		if bad != "" {
			return "", fmt.Errorf("name %q refused (%s); not extracted", p, bad)
		}
	}
	staged := filepath.Join(append([]string{dest}, elems...)...)
	rel, err := filepath.Rel(dest, staged)
	if err != nil || !filepath.IsLocal(rel) {
		return "", fmt.Errorf("name %q resolves outside the staging directory; not extracted", p)
	}
	return staged, nil
}

// mkdirStaging creates dir under dest one element at a time, refusing to
// pass through anything that is not a directory this process made
// (a symlink planted in staging is never followed).
func mkdirStaging(dest, dir string) error {
	rel, err := filepath.Rel(dest, dir)
	if err != nil || (rel != "." && !filepath.IsLocal(rel)) {
		return fmt.Errorf("%q outside staging", dir)
	}
	// dest itself is the caller's own directory (it may sit under a
	// system symlink such as macOS /var); only what is below it is checked.
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return err
	}
	cur := dest
	if rel == "." {
		return nil
	}
	for _, e := range strings.Split(rel, string(filepath.Separator)) {
		cur = filepath.Join(cur, e)
		fi, err := os.Lstat(cur)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := os.Mkdir(cur, 0o700); err != nil {
				return err
			}
		case err != nil:
			return err
		case !fi.IsDir():
			return fmt.Errorf("staging path %q is not a plain directory; not followed", cur)
		}
	}
	return nil
}

func copyOut(fsys fs.FS, src, dest, dst string, limit int64) (int64, string, error) {
	in, err := fsys.Open(src)
	if err != nil {
		return 0, "", err
	}
	defer in.Close()
	if err := mkdirStaging(dest, filepath.Dir(dst)); err != nil {
		return 0, "", err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return 0, "", fmt.Errorf("name collides with another file on this host's filesystem (case-insensitive?); not extracted")
	}
	if err != nil {
		return 0, "", err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(out, h), io.LimitReader(in, limit+1))
	cerr := out.Close()
	if err == nil {
		err = cerr
	}
	if err == nil && n > limit {
		err = fmt.Errorf("grew past the per-file limit while reading")
	}
	if err != nil {
		os.Remove(dst)
		return 0, "", err
	}
	return n, hex.EncodeToString(h.Sum(nil)), nil
}

func setTimes(p string, sys map[string]any) {
	m, _ := sys["mtime"].(time.Time)
	a, _ := sys["atime"].(time.Time)
	if m.IsZero() {
		return
	}
	if a.IsZero() {
		a = m
	}
	os.Chtimes(p, a, m)
}
