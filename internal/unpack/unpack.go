// Package unpack turns containers and archives into a directory tree the
// import-tree collector understands. Sources: `docker export` streams (or
// saved export tars), zip / tar / tar.gz archives (GitHub Actions
// artifacts, support bundles, vendor data exports).
//
// Hostile input rules: entries are written only inside dest (traversal
// refused), symlinks/devices/hardlinks are skipped and counted, every
// entry and the total are size-bounded, nothing is executed.
package unpack

import (
	"archive/tar"
	"archive/zip"
	"bufio"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/internal/products"
)

// Options bound extraction.
type Options struct {
	MaxEntryBytes int64 // default 512 MiB
	MaxTotalBytes int64 // default 8 GiB
	// Filter, when set, decides which regular-file entries are kept
	// (docker exports are whole root filesystems — keep only agent homes).
	Filter func(cleanPath string) bool
}

// Stats summarizes an extraction.
type Stats struct {
	Files    int      `json:"files"`
	Bytes    int64    `json:"bytes"`
	Skipped  int      `json:"skipped"` // symlinks, devices, hardlinks, oversized, filtered
	Refused  int      `json:"refused"` // traversal / absolute paths
	Problems []string `json:"problems,omitempty"`
	SHA256   string   `json:"source_sha256,omitempty"`
}

func (o *Options) defaults() {
	if o.MaxEntryBytes <= 0 {
		o.MaxEntryBytes = 512 << 20
	}
	if o.MaxTotalBytes <= 0 {
		o.MaxTotalBytes = 8 << 30
	}
}

// Kind sniffs an archive by magic bytes.
func Kind(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	switch {
	case bytes.HasPrefix(head, []byte("PK\x03\x04")) || bytes.HasPrefix(head, []byte("PK\x05\x06")):
		return "zip", nil
	case bytes.HasPrefix(head, []byte{0x1f, 0x8b}):
		return "tar.gz", nil
	case n >= 262 && string(head[257:262]) == "ustar":
		return "tar", nil
	}
	// Uncompressed tar without the ustar magic (old format): try a header parse.
	if n == 512 && tarChecksumOK(head) {
		return "tar", nil
	}
	return "", errors.New("not a zip, tar or tar.gz archive")
}

func tarChecksumOK(h []byte) bool {
	var sum int64
	for i, b := range h {
		if i >= 148 && i < 156 {
			sum += ' '
		} else {
			sum += int64(b)
		}
	}
	s := strings.TrimSpace(strings.TrimRight(string(h[148:156]), "\x00"))
	var want int64
	_, err := fmt.Sscanf(s, "%o", &want)
	return err == nil && want == sum && sum > 0
}

// ExtractArchive unpacks a zip / tar / tar.gz file into dest.
func ExtractArchive(src, dest string, opts Options) (*Stats, error) {
	opts.defaults()
	kind, err := Kind(src)
	if err != nil {
		return nil, err
	}
	st := &Stats{SHA256: fileSHA256(src)}
	f, err := os.Open(src)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	switch kind {
	case "zip":
		return st, extractZip(f, dest, opts, st)
	case "tar.gz":
		gz, err := gzip.NewReader(bufio.NewReader(f))
		if err != nil {
			return nil, err
		}
		defer gz.Close()
		return st, extractTar(gz, dest, opts, st)
	default:
		return st, extractTar(bufio.NewReader(f), dest, opts, st)
	}
}

// ExtractTarStream unpacks a tar stream (e.g. `docker export`) into dest.
func ExtractTarStream(r io.Reader, dest string, opts Options) (*Stats, error) {
	opts.defaults()
	st := &Stats{}
	return st, extractTar(r, dest, opts, st)
}

func extractTar(r io.Reader, dest string, opts Options, st *Stats) error {
	tr := tar.NewReader(r)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			st.note("tar: " + err.Error())
			return nil // keep what we have; corrupt tail is recorded
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			continue
		case tar.TypeReg, tar.TypeRegA:
		default:
			st.Skipped++ // symlink, hardlink, device, fifo …
			continue
		}
		clean, ok := safeRel(hdr.Name)
		if !ok {
			st.Refused++
			continue
		}
		if opts.Filter != nil && !opts.Filter(clean) {
			st.Skipped++
			continue
		}
		if err := writeEntry(dest, clean, tr, hdr.Size, opts, st); err != nil {
			return err
		}
	}
}

func extractZip(f *os.File, dest string, opts Options, st *Stats) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(f, fi.Size())
	if err != nil {
		return err
	}
	for _, zf := range zr.File {
		mode := zf.Mode()
		if mode.IsDir() || strings.HasSuffix(zf.Name, "/") {
			continue
		}
		clean, ok := safeRel(zf.Name)
		if !ok {
			st.Refused++
			continue
		}
		if !mode.IsRegular() {
			st.Skipped++
			continue
		}
		if opts.Filter != nil && !opts.Filter(clean) {
			st.Skipped++
			continue
		}
		rc, err := zf.Open()
		if err != nil {
			st.note(zf.Name + ": " + err.Error())
			continue
		}
		err = writeEntry(dest, clean, rc, int64(zf.UncompressedSize64), opts, st)
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// writeEntry stores one regular file under dest with bounds enforced on
// the actual bytes read (declared sizes are untrusted).
func writeEntry(dest, clean string, r io.Reader, declared int64, opts Options, st *Stats) error {
	if declared > opts.MaxEntryBytes {
		st.Skipped++
		st.note(clean + ": declared size exceeds per-entry bound")
		return nil
	}
	if st.Bytes+declared > opts.MaxTotalBytes {
		st.Skipped++
		st.note(clean + ": total extraction bound reached")
		return nil
	}
	out := filepath.Join(dest, filepath.FromSlash(clean))
	if err := os.MkdirAll(filepath.Dir(out), 0o700); err != nil {
		return err
	}
	w, err := os.OpenFile(out, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	n, err := io.Copy(w, io.LimitReader(r, opts.MaxEntryBytes+1))
	w.Close()
	if err != nil {
		os.Remove(out)
		st.note(clean + ": " + err.Error())
		return nil
	}
	if n > opts.MaxEntryBytes {
		os.Remove(out)
		st.Skipped++
		st.note(clean + ": exceeds per-entry bound (undeclared)")
		return nil
	}
	st.Files++
	st.Bytes += n
	return nil
}

// safeRel normalizes an archive member name and refuses anything that
// would escape dest.
func safeRel(name string) (string, bool) {
	name = strings.ReplaceAll(name, "\\", "/")
	name = strings.TrimPrefix(name, "./")
	for strings.HasPrefix(name, "/") {
		name = name[1:]
	}
	if len(name) >= 2 && name[1] == ':' { // C:\...
		name = name[2:]
		name = strings.TrimPrefix(name, "/")
	}
	clean := path.Clean(name)
	if clean == "." || clean == "" || clean == ".." || strings.HasPrefix(clean, "../") || strings.Contains(clean, "/../") {
		return "", false
	}
	return clean, true
}

func (s *Stats) note(msg string) {
	if len(s.Problems) < 10 {
		s.Problems = append(s.Problems, msg)
	}
}

// ---- docker ----

// DockerExport streams `docker export <container>` (read-only snapshot of
// the container filesystem; no process runs inside the container). The
// binary comes from AGENTDFIR_DOCKER (default "docker"; e.g. "podman").
func DockerExport(container string) (io.ReadCloser, func() error, error) {
	bin := os.Getenv("AGENTDFIR_DOCKER")
	if bin == "" {
		bin = "docker"
	}
	if strings.ContainsAny(container, " \t\n;|&$`") || strings.HasPrefix(container, "-") {
		return nil, nil, fmt.Errorf("invalid container reference %q", container)
	}
	cmd := exec.Command(bin, "export", container)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, fmt.Errorf("%s export: %w", bin, err)
	}
	wait := func() error {
		if err := cmd.Wait(); err != nil {
			return fmt.Errorf("%s export %s: %v: %s", bin, container, err, strings.TrimSpace(stderr.String()))
		}
		return nil
	}
	return out, wait, nil
}

// AgentHomeFilter keeps only files that live under a user/workspace home
// AND inside a known agent product's config dir or config file — the
// smallest slice of a container filesystem that is agent evidence.
func AgentHomeFilter() func(string) bool {
	prods, _ := products.All()
	var dirs, files []string
	for _, p := range prods {
		for _, d := range p.ConfigDirs {
			dirs = append(dirs, strings.Trim(strings.ReplaceAll(d, "\\", "/"), "/"))
		}
		for _, f := range p.ConfigFiles {
			files = append(files, strings.Trim(f, "/"))
		}
	}
	homes := []string{"root/", "home/", "workspaces/", "workspace/", "app/", "Users/", "srv/", "opt/"}
	return func(clean string) bool {
		rest := ""
		for _, h := range homes {
			if strings.HasPrefix(clean, h) {
				rest = strings.TrimPrefix(clean, h)
				// home/<user>/… and workspaces/<name>/… carry one more segment
				if h != "root/" {
					if i := strings.IndexByte(rest, '/'); i >= 0 {
						rest = rest[i+1:]
					} else {
						rest = ""
					}
				}
				break
			}
		}
		if rest == "" {
			return false
		}
		for _, d := range dirs {
			if rest == d || strings.HasPrefix(rest, d+"/") {
				return true
			}
		}
		for _, f := range files {
			if rest == f {
				return true
			}
		}
		// Repo-scoped agent files inside a workspace (project CLAUDE.md, .mcp.json, .cursor/rules …).
		base := path.Base(rest)
		switch base {
		case "CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules", ".clinerules", ".windsurfrules", ".mcp.json", "copilot-instructions.md":
			return true
		}
		return strings.Contains(rest, "/.cursor/") || strings.HasPrefix(rest, ".cursor/") || strings.Contains(rest, "/.vscode/mcp.json")
	}
}

func fileSHA256(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}
