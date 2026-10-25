// Package compat holds the backward-compatibility guarantee for the .adfir
// evidence format: packages actually produced by released binaries, which
// the current binary must verify, read and analyze. See compat_test.go.
package compat

import (
	"archive/tar"
	"compress/gzip"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// Historical packages, each produced by the released binary of its tag
// (scripts/gen-compat-fixtures.sh): v1.0.0 as a directory, later ones as
// .tar.gz so the sealed bytes survive any checkout. They are embedded so
// `agentdfir benchmark` can check them from an installed binary.
//
//go:embed testdata/v1.0.0-package testdata/*.tar.gz
var fixtures embed.FS

// Bounds for unpacking an archive. The archives are ours, but the code
// that reads them is written as if they were not.
const (
	maxEntries    = 2000
	maxTotalBytes = 32 << 20
)

// Package names one historical package.
type Package struct {
	Version string // tag that produced it, e.g. v2.7.0
	source  string // path inside fixtures
}

// Packages lists every historical package, oldest first.
func Packages() []Package {
	out := []Package{{Version: "v1.0.0", source: "testdata/v1.0.0-package"}}
	entries, _ := fs.ReadDir(fixtures, "testdata")
	var tars []Package
	for _, e := range entries {
		if name := e.Name(); strings.HasSuffix(name, "-package.tar.gz") {
			tars = append(tars, Package{Version: strings.TrimSuffix(name, "-package.tar.gz"), source: "testdata/" + name})
		}
	}
	sort.Slice(tars, func(i, j int) bool { return versionLess(tars[i].Version, tars[j].Version) })
	return append(out, tars...)
}

// Extract writes the package into dst (which must not exist) and returns
// the package directory. Files are made writable so a caller may analyze
// or extend its copy.
func (p Package) Extract(dst string) (string, error) {
	if !strings.HasSuffix(p.source, ".tar.gz") {
		sub, err := fs.Sub(fixtures, p.source)
		if err != nil {
			return "", err
		}
		if err := os.CopyFS(dst, sub); err != nil {
			return "", err
		}
		return dst, makeWritable(dst)
	}
	f, err := fixtures.Open(p.source)
	if err != nil {
		return "", err
	}
	defer f.Close()
	zr, err := gzip.NewReader(f)
	if err != nil {
		return "", err
	}
	tr := tar.NewReader(zr)
	var total int64
	root := ""
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if n >= maxEntries {
			return "", fmt.Errorf("%s: more than %d entries", p.source, maxEntries)
		}
		name := path.Clean(h.Name)
		if !filepath.IsLocal(filepath.FromSlash(name)) {
			return "", fmt.Errorf("%s: entry outside the archive: %q", p.source, h.Name)
		}
		// Every entry sits under one top-level directory (pkg/); strip it.
		top, rest, _ := strings.Cut(name, "/")
		if root == "" {
			root = top
		} else if top != root {
			return "", fmt.Errorf("%s: more than one top-level directory", p.source)
		}
		target := filepath.Join(dst, filepath.FromSlash(rest))
		switch h.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0o700); err != nil {
				return "", err
			}
		case tar.TypeReg:
			total += h.Size
			if h.Size < 0 || total > maxTotalBytes {
				return "", fmt.Errorf("%s: larger than %d bytes", p.source, maxTotalBytes)
			}
			if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
				return "", err
			}
			out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
			if err != nil {
				return "", err
			}
			_, cerr := io.CopyN(out, tr, h.Size)
			if err := out.Close(); cerr == nil {
				cerr = err
			}
			if cerr != nil {
				return "", cerr
			}
		default:
			return "", fmt.Errorf("%s: unsupported entry type %q for %s", p.source, h.Typeflag, h.Name)
		}
	}
	return dst, nil
}

func makeWritable(dir string) error {
	return filepath.WalkDir(dir, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chmod(p, 0o700)
	})
}

// versionLess orders "vMAJOR.MINOR.PATCH" numerically.
func versionLess(a, b string) bool {
	pa, pb := parts(a), parts(b)
	for i := range pa {
		if pa[i] != pb[i] {
			return pa[i] < pb[i]
		}
	}
	return a < b
}

func parts(v string) [3]int {
	var out [3]int
	for i, s := range strings.SplitN(strings.TrimPrefix(v, "v"), ".", 3) {
		n := 0
		for _, c := range s {
			if c < '0' || c > '9' {
				break
			}
			n = n*10 + int(c-'0')
		}
		out[i] = n
	}
	return out
}
