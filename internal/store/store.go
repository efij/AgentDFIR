// Package store resolves the per-machine AgentDFIR home and implements
// the blob store shared between cases.
//
// Why a home at all: `agentdfir run` used to write <case-id>.adfir into
// the current working directory, so running it from three directories
// produced three complete, independent copies of the same multi-gigabyte
// evidence. Cases now live at a predictable path and are reused, so a
// second run against the same machine appends a round instead of copying
// everything again.
//
// Why a shared store: identical bytes across cases (and across the
// duplicated plugin caches a single machine carries) are stored once and
// hardlinked into each case. A hardlink is a real directory entry, so a
// case directory stays self-contained: cp -a, tar, zip and the export path
// all still produce a package that stands on its own.
//
// Security posture:
//   - The home and the store are 0700 and must be owned by the current
//     user; a path that is a symlink, is group/world-writable, or is not a
//     directory is refused rather than used.
//   - Stored blobs are 0400.
//   - A blob already present in the shared store is verified against the
//     expected hash before it is reused. A file name is not a content
//     assertion: without this check, anything able to write into the store
//     could pre-place a file under the hash of evidence it expects to be
//     collected and have that substituted for the real bytes.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// EnvHome overrides the default home location.
const EnvHome = "AGENTDFIR_HOME"

// Home returns the AgentDFIR home directory, creating it if needed.
func Home() (string, error) {
	dir := os.Getenv(EnvHome)
	if dir == "" {
		base, err := defaultBase()
		if err != nil {
			return "", err
		}
		dir = base
	}
	if err := ensureSecureDir(dir); err != nil {
		return "", err
	}
	return dir, nil
}

func defaultBase() (string, error) {
	if runtime.GOOS == "windows" {
		if local := os.Getenv("LOCALAPPDATA"); local != "" {
			return filepath.Join(local, "AgentDFIR"), nil
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".agentdfir"), nil
}

// CaseDir returns the default package path for one host/user, and the
// directory it lives in.
func CaseDir(host, user string) (string, error) {
	home, err := Home()
	if err != nil {
		return "", err
	}
	cases := filepath.Join(home, "cases")
	if err := ensureSecureDir(cases); err != nil {
		return "", err
	}
	return filepath.Join(cases, safeName(host)+"-"+safeName(user)+".adfir"), nil
}

// safeName reduces a host or user name to something safe in a path.
func safeName(s string) string {
	if s == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-.")
	if out == "" {
		return "unknown"
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

// ensureSecureDir creates a directory if missing and refuses to use one
// that is not a plain, user-owned, non-group/world-writable directory.
// Evidence and the operator's whole collection history live under it.
func ensureSecureDir(dir string) error {
	fi, err := os.Lstat(dir)
	if errors.Is(err, os.ErrNotExist) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", dir, err)
		}
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink; refusing to use it for evidence storage", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s exists and is not a directory", dir)
	}
	if err := checkOwner(dir, fi); err != nil {
		return err
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group/world-writable (%o); refusing to store evidence there", dir, fi.Mode().Perm())
	}
	return nil
}

// Shared is a content-addressed blob store shared by every case on this
// machine. It satisfies casepkg.Sharer.
type Shared struct {
	dir    string
	Reused int64 // bytes served from the shared store instead of written
}

// Open prepares the shared store under the AgentDFIR home.
func Open() (*Shared, error) {
	home, err := Home()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(home, "store", "cas")
	if err := ensureSecureDir(filepath.Join(home, "store")); err != nil {
		return nil, err
	}
	if err := ensureSecureDir(dir); err != nil {
		return nil, err
	}
	return &Shared{dir: dir}, nil
}

// Dir is the shared store's blob directory.
func (s *Shared) Dir() string { return s.dir }

func (s *Shared) blob(storedSHA string) string {
	// Two-level fan-out: a flat directory with a million entries is slow to
	// read on every filesystem that matters.
	return filepath.Join(s.dir, storedSHA[:2], storedSHA)
}

// Link places the shared copy of these bytes at dst, if one exists and is
// genuinely those bytes. Returns false when the caller must write its own.
func (s *Shared) Link(storedSHA, dst string) (bool, error) {
	if len(storedSHA) < 4 {
		return false, nil
	}
	src := s.blob(storedSHA)
	fi, err := os.Lstat(src)
	if err != nil || !fi.Mode().IsRegular() {
		return false, nil
	}
	// Verify before trusting. The store is a reuse cache, not an authority:
	// a file sitting at the right name proves nothing about its contents.
	if h, err := hashFile(src); err != nil || h != storedSHA {
		return false, nil
	}
	// Blobs are stored read-only; on Windows that bit blocks unlinking.
	_ = os.Chmod(dst, 0o600)
	if err := os.Remove(dst); err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err := os.Link(src, dst); err != nil {
		// Different filesystem, or hardlinks unavailable: the caller writes
		// its own copy. Sharing is an optimization, never a requirement.
		return false, nil
	}
	s.Reused += fi.Size()
	return true, nil
}

// Adopt offers a freshly written blob to the shared store, so the next
// case that needs these bytes links instead of copying.
func (s *Shared) Adopt(storedSHA, src string) error {
	if len(storedSHA) < 4 {
		return nil
	}
	dst := s.blob(storedSHA)
	if _, err := os.Lstat(dst); err == nil {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o700); err != nil {
		return err
	}
	if err := os.Link(src, dst); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil
		}
		return nil // cross-device or unsupported: not fatal
	}
	_ = os.Chmod(dst, 0o400)
	return nil
}

// Stats describes the shared store's occupancy.
type Stats struct {
	Dir               string
	Blobs             int
	Bytes             int64
	Unreferenced      int
	UnreferencedBytes int64
}

// Status walks the shared store. A blob with a link count of 1 exists only
// in the store: no case references it any more.
func Status() (*Stats, error) {
	s, err := Open()
	if err != nil {
		return nil, err
	}
	st := &Stats{Dir: s.dir}
	err = filepath.WalkDir(s.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		st.Blobs++
		st.Bytes += info.Size()
		if linkCount(info) <= 1 {
			st.Unreferenced++
			st.UnreferencedBytes += info.Size()
		}
		return nil
	})
	return st, err
}

// GCResult reports what collection would remove, or did remove.
type GCResult struct {
	DryRun  bool
	Removed int
	Bytes   int64
}

// GC drops shared blobs no case references. A blob whose link count is
// still above one is live in at least one package and is never touched.
// dryRun is the caller's default: deleting evidence bytes, even
// unreferenced ones, is not something to do without being asked.
func GC(dryRun bool) (*GCResult, error) {
	s, err := Open()
	if err != nil {
		return nil, err
	}
	res := &GCResult{DryRun: dryRun}
	err = filepath.WalkDir(s.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil || linkCount(info) > 1 {
			return nil
		}
		res.Removed++
		res.Bytes += info.Size()
		if dryRun {
			return nil
		}
		_ = os.Chmod(path, 0o600)
		return os.Remove(path)
	})
	return res, err
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
