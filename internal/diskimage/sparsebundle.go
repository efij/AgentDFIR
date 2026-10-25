package diskimage

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
)

// Sparsebundle: a directory holding Info.plist (band-size, size) and
// bands/<hex index>, each band one fixed-size slice of the disk. A missing
// band, or the part of a band past its file's end, reads as zeros. An
// encrypted bundle (its token file carries an encrcdsa header) is
// UNSUPPORTED. Band files are opened lazily and only while needed.

const (
	maxBandSize  = 1 << 30
	maxOpenBands = 32
)

type sparseBundle struct {
	dir      string
	bandSize int64
	size     int64
	bands    map[int64]string // index → path (only bands that exist)

	mu    sync.Mutex
	open  map[int64]*os.File
	order []int64
}

func isSparseBundle(dir string) bool {
	fi, err := os.Lstat(filepath.Join(dir, "Info.plist"))
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	b, err := os.ReadFile(filepath.Join(dir, "Info.plist"))
	return err == nil && bytes.Contains(b, []byte("com.apple.diskimage.sparsebundle"))
}

func openSparseBundle(dir string) (*Image, error) {
	ipath := filepath.Join(dir, "Info.plist")
	f, err := openRegular(ipath)
	if err != nil {
		return nil, err
	}
	raw, err := io.ReadAll(io.LimitReader(f, 1<<20))
	f.Close()
	if err != nil {
		return nil, err
	}
	pl, err := parsePlist(raw)
	if err != nil {
		return nil, corrupt("sparsebundle", "Info.plist: %v", err)
	}
	m, _ := pl.(map[string]any)
	if t, _ := m["diskimage-bundle-type"].(string); t != "com.apple.diskimage.sparsebundle" {
		return nil, corrupt("sparsebundle", "Info.plist bundle type %q", t)
	}
	bandSize, _ := m["band-size"].(int64)
	size, _ := m["size"].(int64)
	if bandSize < 512 || bandSize > maxBandSize || bandSize%512 != 0 {
		return nil, corrupt("sparsebundle", "band size %d", bandSize)
	}
	if size <= 0 || size > 1<<53 {
		return nil, corrupt("sparsebundle", "size %d", size)
	}
	if tok, err := os.ReadFile(filepath.Join(dir, "token")); err == nil && bytes.HasPrefix(tok, []byte("encrcdsa")) {
		return nil, &Error{Kind: ErrEncrypted, Format: "sparsebundle", Reason: "encrypted sparsebundle; decryption is not supported: attach it read-only with hdiutil (it asks for the passphrase), image the attached device, then collect --image that raw copy"}
	}
	nbands := (size + bandSize - 1) / bandSize
	sb := &sparseBundle{dir: dir, bandSize: bandSize, size: size, bands: map[int64]string{}, open: map[int64]*os.File{}}
	ents, err := os.ReadDir(filepath.Join(dir, "bands"))
	if err != nil {
		return nil, corrupt("sparsebundle", "bands directory: %v", err)
	}
	var ignored []string
	var idx []int64
	for _, e := range ents {
		n, err := strconv.ParseInt(e.Name(), 16, 64)
		if err != nil || e.Name() != strconv.FormatInt(n, 16) || n < 0 || n >= nbands || !e.Type().IsRegular() {
			ignored = append(ignored, e.Name())
			continue
		}
		sb.bands[n] = filepath.Join(dir, "bands", e.Name())
		idx = append(idx, n)
	}
	sort.Slice(idx, func(i, j int) bool { return idx[i] < idx[j] })
	segs := []string{ipath}
	for _, n := range idx {
		segs = append(segs, sb.bands[n])
	}
	meta := map[string]string{
		"band_size": strconv.FormatInt(bandSize, 10),
		"bands":     strconv.Itoa(len(idx)),
		"bands_max": strconv.FormatInt(nbands, 10),
	}
	if len(ignored) > 0 {
		if len(ignored) > 20 {
			ignored = append(ignored[:20], "…")
		}
		meta["bands_ignored"] = strings.Join(ignored, ",")
	}
	return &Image{r: sb, size: size, Format: FormatSparseBundle, Segments: segs, Meta: meta, closers: []io.Closer{sb}}, nil
}

func (s *sparseBundle) band(n int64) (*os.File, error) {
	if f, ok := s.open[n]; ok {
		return f, nil
	}
	f, err := openRegular(s.bands[n])
	if err != nil {
		return nil, err
	}
	if len(s.order) >= maxOpenBands {
		old := s.order[0]
		s.order = s.order[1:]
		s.open[old].Close()
		delete(s.open, old)
	}
	s.open[n] = f
	s.order = append(s.order, n)
	return f, nil
}

func (s *sparseBundle) ReadAt(p []byte, off int64) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	total := 0
	for len(p) > 0 {
		if off >= s.size {
			return total, io.EOF
		}
		n := len(p)
		bi, in := off/s.bandSize, off%s.bandSize
		if rem := s.bandSize - in; int64(n) > rem {
			n = int(rem)
		}
		if rem := s.size - off; int64(n) > rem {
			n = int(rem)
		}
		chunk := p[:n]
		if _, ok := s.bands[bi]; !ok {
			clear(chunk)
		} else {
			f, err := s.band(bi)
			if err != nil {
				return total, err
			}
			got, err := f.ReadAt(chunk, in)
			if err != nil && err != io.EOF {
				return total, err
			}
			clear(chunk[got:]) // a short band ends in zeros
		}
		total += n
		p = p[n:]
		off += int64(n)
	}
	return total, nil
}

func (s *sparseBundle) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.open {
		f.Close()
	}
	s.open, s.order = map[int64]*os.File{}, nil
	return nil
}
