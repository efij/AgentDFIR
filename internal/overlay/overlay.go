// Package overlay is the single read/write path for the regenerable
// analysis overlay — normalized/, detections/, reports/, index/ — which
// lives beside the sealed zone but is not part of it.
//
// It exists because the overlay outgrew the evidence it is derived from.
// On a real case the sealed zone was 525 MB while the overlay on top of it
// was ~300 MB: normalized/ 178 MB and detections/ 120 MB. That is almost
// nothing but JSON — one object per line for events, entities and
// relationships, and indented JSON for findings — which is the most
// compressible thing a forensic tool writes. Storing it as gzip takes the
// overlay down by roughly an order of magnitude for the cost of a few
// seconds of CPU on a run that already spends minutes parsing.
//
// Two rules make that safe to switch on under existing packages:
//
//   - A reader accepts both forms. If <name>.gz exists it is used;
//     otherwise the plaintext <name> is read exactly as before. A package
//     analyzed by an older binary keeps opening, and a package analyzed by
//     this one can still be inspected with `gunzip -c` and no AgentDFIR
//     binary in the loop.
//   - A writer writes <name>.gz and then removes the plaintext <name>, so
//     re-analyzing an existing package actually reclaims the disk instead
//     of leaving both copies behind.
//
// Nothing here touches the sealed zone. The overlay is excluded from
// SHA256SUMS by design (see package casepkg), so changing how it is stored
// cannot change what `agentdfir verify` proves — and because only the
// container changes and not a byte of the JSON inside it, it cannot change
// a single detection result either.
//
// Standard library only: this project has a hard zero-runtime-dependency
// rule, so the codec is compress/gzip and nothing else.
package overlay

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// Suffix marks the compressed form of an overlay file. It is a real .gz,
// readable by gunzip, for the same reason the evidence blobs in
// casepkg/store.go carry it: an analyst must be able to get at the data
// with ordinary tools.
const Suffix = ".gz"

// Bounds on decompression. casepkg's store can bound a blob by the
// plaintext size its manifest record recorded; the overlay has no manifest
// and no recorded size, so the bound here is a ratio over the bytes
// actually on disk plus an absolute ceiling.
//
// Measured overlays compress about 10:1, so 100:1 leaves an order of
// magnitude of headroom while staying an order of magnitude below gzip's
// ~1000:1 theoretical maximum — which is exactly what a decompression bomb
// needs in order to be one. The floor keeps small files (an empty
// entities.jsonl, a one-finding findings.json) from tripping the ratio,
// and the ceiling caps the whole thing regardless of input size. A file
// that runs past its bound fails the read rather than filling memory or
// disk: a forensic tool must stay bounded on hostile input, and the
// overlay is the one part of a package an attacker with write access to
// the case directory could replace without breaking the seal.
const (
	maxRatio     = 100
	minBound     = 64 << 20 // 64 MiB
	maxPlaintext = 64 << 30 // 64 GiB
)

// Path returns the path that actually holds the content for the logical
// name p: the compressed form when it is present, otherwise p itself.
// Callers that only need to report a location to a human use this.
func Path(p string) string {
	if _, err := os.Stat(p + Suffix); err == nil {
		return p + Suffix
	}
	return p
}

// Stat reports on whichever form exists. Callers use it for staleness
// comparisons against the manifest, so it must not care which form the
// last writer chose.
func Stat(p string) (os.FileInfo, error) {
	if fi, err := os.Stat(p + Suffix); err == nil {
		return fi, nil
	}
	return os.Stat(p)
}

// Exists reports whether either form is present.
func Exists(p string) bool {
	_, err := Stat(p)
	return err == nil
}

// Open returns a reader over the plaintext content of p, transparently
// decompressing (and bounding) the .gz form when that is what is there.
func Open(p string) (io.ReadCloser, error) {
	if f, err := os.Open(p + Suffix); err == nil {
		zr, zErr := gzip.NewReader(f)
		if zErr != nil {
			f.Close()
			return nil, fmt.Errorf("%s: %w", filepath.Base(p)+Suffix, zErr)
		}
		return &boundedReader{zr: zr, f: f, rem: bound(f), name: filepath.Base(p) + Suffix}, nil
	}
	return os.Open(p)
}

// bound computes the decompression ceiling for one file from its size on
// disk. A stat failure yields the floor rather than no limit: failing
// closed is the whole point.
func bound(f *os.File) int64 {
	fi, err := f.Stat()
	if err != nil {
		return minBound
	}
	n := fi.Size() * maxRatio
	if n < minBound {
		n = minBound
	}
	if n > maxPlaintext {
		n = maxPlaintext
	}
	return n
}

// boundedReader enforces the ceiling while decompressing, the same way
// casepkg's gzipUnit enforces the recorded plaintext size. Reading is
// stopped at the limit and turned into an error, so an overlay file that
// was swapped for a bomb cannot expand without limit.
type boundedReader struct {
	zr   *gzip.Reader
	f    *os.File
	rem  int64
	name string
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.rem <= 0 {
		return 0, fmt.Errorf("%s: decompressed size exceeds the %d:1 overlay bound", b.name, maxRatio)
	}
	if int64(len(p)) > b.rem {
		p = p[:b.rem]
	}
	n, err := b.zr.Read(p)
	b.rem -= int64(n)
	return n, err
}

func (b *boundedReader) Close() error {
	err := b.zr.Close()
	if cErr := b.f.Close(); err == nil {
		err = cErr
	}
	return err
}

// ReadFile reads a whole overlay file into memory (the small ones:
// findings.json, analysis.json, corroboration.json).
func ReadFile(p string) ([]byte, error) {
	rc, err := Open(p)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// Writer streams into the compressed form. Close finishes the gzip
// member, closes the file and only then removes the plaintext
// counterpart, so an interrupted write never leaves the package with
// neither form readable.
type Writer struct {
	zw   *gzip.Writer
	f    *os.File
	path string
}

// Create opens the compressed form of p for writing.
// CreatePlain writes the file uncompressed. Used for the one overlay file
// that must stay randomly addressable: internal/index records a byte offset
// per event so the explorer can open a single event without loading the
// rest, and a gzip stream cannot be seeked. Everything else in the overlay
// is read whole and is compressed.
func CreatePlain(p string) (*Writer, error) {
	// Remove a compressed form left by an earlier version, so the two
	// cannot disagree about which is current.
	_ = os.Remove(p + Suffix)
	f, err := os.OpenFile(p, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &Writer{f: f, path: p}, nil
}

func Create(p string) (*Writer, error) {
	f, err := os.OpenFile(p+Suffix, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return nil, err
	}
	return &Writer{zw: gzip.NewWriter(f), f: f, path: p}, nil
}

func (w *Writer) Write(p []byte) (int, error) {
	if w.zw == nil {
		return w.f.Write(p)
	}
	return w.zw.Write(p)
}

func (w *Writer) Close() error {
	if w.zw == nil {
		return w.f.Close()
	}
	err := w.zw.Close()
	if cErr := w.f.Close(); err == nil {
		err = cErr
	}
	if err != nil {
		return err
	}
	// The plaintext form left by an older binary would otherwise sit there
	// forever: readers prefer the .gz, so it would be invisible and still
	// cost the full 178 MB. Removing it is what makes re-analysis of an
	// existing package reclaim disk rather than add to it.
	if rmErr := os.Remove(w.path); rmErr != nil && !os.IsNotExist(rmErr) {
		return rmErr
	}
	return nil
}

// WriteJSON writes one indented JSON document, compressed. Indentation is
// kept because these files are read by humans and by `jq`, and it costs
// nothing once gzipped.
func WriteJSON(p string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	w, err := Create(p)
	if err != nil {
		return err
	}
	if _, err := w.Write(append(data, '\n')); err != nil {
		w.f.Close()
		return err
	}
	return w.Close()
}

// WriteJSONL writes n JSON objects, one per line, compressed. The
// get-by-index signature avoids materializing a []any copy of an event
// slice that is already the largest thing in memory.
func WriteJSONL(p string, n int, get func(int) any) error {
	w, err := Create(p)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(w)
	for i := 0; i < n; i++ {
		if err := enc.Encode(get(i)); err != nil {
			w.f.Close()
			return err
		}
	}
	return w.Close()
}

// Scan calls fn for each line of a JSONL overlay file without holding the
// file in memory. The buffer bound is the same 16 MiB the streaming
// readers used before: one pathological line must not be able to allocate
// without limit either.
func Scan(p string, fn func([]byte)) error {
	rc, err := Open(p)
	if err != nil {
		return err
	}
	defer rc.Close()
	sc := bufio.NewScanner(rc)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		fn(sc.Bytes())
	}
	return sc.Err()
}

// ReadJSONL decodes a JSONL overlay file into a slice. Malformed lines are
// skipped rather than failing the read: they were already recorded as
// trace_gap events during normalization, and a single bad line must not
// cost an analyst the rest of the case.
func ReadJSONL[T any](p string) []T {
	var out []T
	_ = Scan(p, func(line []byte) {
		var v T
		if json.Unmarshal(line, &v) == nil {
			out = append(out, v)
		}
	})
	return out
}

// CountLines counts records without decoding them.
func CountLines(p string) int {
	rc, err := Open(p)
	if err != nil {
		return 0
	}
	defer rc.Close()
	n := 0
	buf := make([]byte, 256<<10)
	for {
		k, err := rc.Read(buf)
		for i := 0; i < k; i++ {
			if buf[i] == '\n' {
				n++
			}
		}
		if err != nil {
			return n
		}
	}
}

// Compress converts a plaintext overlay file to the compressed form in
// place and reports the bytes reclaimed. It is a no-op when the file is
// already compressed or is not there at all.
//
// This is what an existing package needs. The overlay is only rewritten
// when it is stale, so on a case that was already analyzed the reuse path
// never touches normalized/ — and without this step an analyst who
// upgraded the binary would keep carrying the full 178 MB of plaintext
// until they re-collected or forced a re-parse. Recompressing is a
// streaming copy of a file that is being read anyway, which is orders of
// magnitude cheaper than the re-parse that produced it.
func Compress(p string) (int64, error) {
	if _, err := os.Stat(p + Suffix); err == nil {
		return 0, nil // already the current form
	}
	fi, err := os.Stat(p)
	if err != nil {
		return 0, nil // nothing to migrate
	}
	src, err := os.Open(p)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	w, err := Create(p)
	if err != nil {
		return 0, err
	}
	if _, err := io.Copy(w, src); err != nil {
		w.f.Close()
		_ = os.Remove(p + Suffix)
		return 0, err
	}
	// src must be closed before Close removes it: on Windows a file cannot
	// be unlinked while a handle is open, and the removal is the whole
	// point of the migration.
	if err := src.Close(); err != nil {
		w.f.Close()
		_ = os.Remove(p + Suffix)
		return 0, err
	}
	if err := w.Close(); err != nil {
		return 0, err
	}
	out, err := os.Stat(p + Suffix)
	if err != nil {
		return 0, err
	}
	return fi.Size() - out.Size(), nil
}

// Remove deletes both forms of an overlay file.
func Remove(p string) error {
	gErr := os.Remove(p + Suffix)
	pErr := os.Remove(p)
	if gErr != nil && !os.IsNotExist(gErr) {
		return gErr
	}
	if pErr != nil && !os.IsNotExist(pErr) {
		return pErr
	}
	return nil
}
