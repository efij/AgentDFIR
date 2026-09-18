package casepkg

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Store is the single read path to a package's content-addressed evidence.
// It hides the on-disk representation — plaintext or compressed, one blob
// or a chunk list — from every consumer, so the storage format can change
// without any analysis code knowing.
//
// Invariants it guarantees to callers:
//
//   - What comes out is the exact plaintext the artifact_id addresses.
//   - Decompression is bounded by the recorded plaintext size and fails
//     closed on overrun, so a tampered package cannot expand without limit
//     before the content address would catch it.
//   - A blob is never trusted because of its filename; length is enforced
//     and Verify re-checks both the plaintext and the stored-byte hashes.
type Store struct {
	dir  string
	byID map[string]ArtifactRecord

	// Random access to a compressed or chunked artifact cannot seek: the
	// bytes before the offset have to be produced to reach it. Analysis
	// reads many lines out of the same transcript by offset (provenance
	// walks every tool call; the explorer's evidence pane fetches one line
	// at a time), so without a cache each of those reads would decompress
	// the file from the start again — quadratic in the number of lines.
	// A small bounded cache of recently seeked artifacts turns that back
	// into one decompression per artifact.
	mu         sync.Mutex
	cache      map[string][]byte
	cacheOrder []string
	cacheBytes int64
}

// Bounds on the seek cache. Anything larger is streamed and discarded
// instead: a forensic tool must stay bounded on hostile input.
const (
	seekCacheMaxArtifact = 32 << 20
	seekCacheMaxTotal    = 64 << 20
)

// Codec values for stored blob bytes.
const (
	CodecNone = "none"
	CodecGzip = "gzip"
)

// NewStore builds a store over a package directory using a manifest the
// caller has already read (the common case — every consumer iterates
// manifest records).
func NewStore(pkgDir string, man *Manifest) *Store {
	s := &Store{dir: pkgDir, byID: make(map[string]ArtifactRecord, len(man.Artifacts))}
	for _, a := range man.Artifacts {
		if a.ArtifactID == "" {
			continue
		}
		// Later rounds supersede earlier ones for the same content address;
		// content is identical by definition, so last-write-wins is safe and
		// keeps the newest layout (a chunked record replaces a whole one).
		s.byID[a.ArtifactID] = a
	}
	return s
}

// OpenStore reads the manifest itself. For callers that do not already
// hold one (serve's raw endpoint, provenance line lookups).
func OpenStore(pkgDir string) (*Store, error) {
	man, err := ReadManifest(pkgDir)
	if err != nil {
		return nil, err
	}
	return NewStore(pkgDir, man), nil
}

// Record returns the manifest record for a content address.
func (s *Store) Record(id string) (ArtifactRecord, bool) {
	rec, ok := s.byID[id]
	return rec, ok
}

// Size returns the plaintext size of an artifact.
func (s *Store) Size(id string) (int64, bool) {
	rec, ok := s.byID[id]
	if !ok {
		return 0, false
	}
	return rec.Size, true
}

// blobName is the on-disk file name for one stored unit. The codec suffix
// is part of the name so an analyst can recognize and `gunzip` a blob by
// hand, with no AgentDFIR binary in the loop.
func blobName(id, codec string) string {
	if codec == CodecGzip {
		return id + ".gz"
	}
	return id
}

// blobPath resolves one stored unit inside the package.
func (s *Store) blobPath(id, codec string) string {
	return filepath.Join(s.dir, "raw", blobName(id, codec))
}

// openUnit opens one stored unit (whole artifact or one chunk) and returns
// a reader over its plaintext, bounded by size.
func (s *Store) openUnit(id, codec string, size int64) (io.ReadCloser, error) {
	// Packages written before codecs existed carry no codec field and store
	// plaintext at raw/<sha256>. Fall back to that whenever the recorded
	// codec's file is absent, so old packages keep opening.
	path := s.blobPath(id, codec)
	f, err := os.Open(path)
	if err != nil && codec != "" && codec != CodecNone {
		if plain, pErr := os.Open(s.blobPath(id, CodecNone)); pErr == nil {
			f, err, codec = plain, nil, CodecNone
		}
	}
	if err != nil {
		return nil, err
	}
	if codec != CodecGzip {
		return f, nil
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("blob %.12s: %w", id, err)
	}
	return &gzipUnit{zr: zr, f: f, rem: size + 1, id: id}, nil
}

// gzipUnit enforces the recorded plaintext length while decompressing.
// A blob that expands past it is tampered with or hostile; the read fails
// rather than filling memory or disk.
type gzipUnit struct {
	zr  *gzip.Reader
	f   *os.File
	rem int64
	id  string
}

func (g *gzipUnit) Read(p []byte) (int, error) {
	if g.rem <= 0 {
		return 0, fmt.Errorf("blob %.12s: decompressed size exceeds recorded size", g.id)
	}
	if int64(len(p)) > g.rem {
		p = p[:g.rem]
	}
	n, err := g.zr.Read(p)
	g.rem -= int64(n)
	return n, err
}

func (g *gzipUnit) Close() error {
	err := g.zr.Close()
	if cErr := g.f.Close(); err == nil {
		err = cErr
	}
	return err
}

// Open returns the artifact's plaintext. Chunked artifacts (a file that
// grew between rounds and was stored as a prefix plus appended tails) are
// concatenated transparently, in order.
func (s *Store) Open(id string) (io.ReadCloser, error) {
	rec, ok := s.byID[id]
	if !ok {
		// Not in the manifest: fall back to a plain blob so tooling pointed
		// at a raw content address still works.
		return os.Open(s.blobPath(id, CodecNone))
	}
	if len(rec.Chunks) == 0 {
		return s.openUnit(id, rec.Codec, rec.Size)
	}
	return newChunkReader(s, rec)
}

// OpenAt returns the artifact's plaintext positioned at off. A plaintext
// blob seeks. A compressed or chunked one has no seek, so it is served
// from the bounded cache above when it fits, and otherwise streamed and
// discarded up to off.
func (s *Store) OpenAt(id string, off int64) (io.ReadCloser, error) {
	if off <= 0 {
		return s.Open(id)
	}
	if rec, ok := s.byID[id]; ok && needsDecode(rec) {
		if data, ok := s.seekable(id, rec); ok {
			if off > int64(len(data)) {
				off = int64(len(data))
			}
			return io.NopCloser(bytes.NewReader(data[off:])), nil
		}
	}
	rc, err := s.Open(id)
	if err != nil {
		return nil, err
	}
	if f, ok := rc.(*os.File); ok {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			f.Close()
			return nil, err
		}
		return f, nil
	}
	if _, err := io.CopyN(io.Discard, rc, off); err != nil {
		rc.Close()
		return nil, err
	}
	return rc, nil
}

// needsDecode reports whether reaching an offset in this artifact costs
// more than a seek.
func needsDecode(rec ArtifactRecord) bool {
	return rec.Codec == CodecGzip || len(rec.Chunks) > 0
}

// seekable returns the artifact's full plaintext for random access,
// decoding it at most once while it stays in the cache.
func (s *Store) seekable(id string, rec ArtifactRecord) ([]byte, bool) {
	if rec.Size <= 0 || rec.Size > seekCacheMaxArtifact {
		return nil, false
	}
	s.mu.Lock()
	if data, ok := s.cache[id]; ok {
		s.mu.Unlock()
		return data, true
	}
	s.mu.Unlock()

	data, err := s.ReadAll(id, seekCacheMaxArtifact)
	if err != nil {
		return nil, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cache == nil {
		s.cache = map[string][]byte{}
	}
	if _, ok := s.cache[id]; !ok {
		s.cache[id] = data
		s.cacheOrder = append(s.cacheOrder, id)
		s.cacheBytes += int64(len(data))
		for s.cacheBytes > seekCacheMaxTotal && len(s.cacheOrder) > 1 {
			oldest := s.cacheOrder[0]
			s.cacheOrder = s.cacheOrder[1:]
			s.cacheBytes -= int64(len(s.cache[oldest]))
			delete(s.cache, oldest)
		}
	}
	return data, true
}

// ReadAll reads a whole artifact into memory, refusing anything over max.
// max <= 0 means "no explicit cap beyond the recorded size".
func (s *Store) ReadAll(id string, max int64) ([]byte, error) {
	if size, ok := s.Size(id); ok && max > 0 && size > max {
		return nil, fmt.Errorf("artifact %.12s: %d bytes exceeds limit %d", id, size, max)
	}
	rc, err := s.Open(id)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	if max <= 0 {
		return io.ReadAll(rc)
	}
	data, err := io.ReadAll(io.LimitReader(rc, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("artifact %.12s exceeds limit %d", id, max)
	}
	return data, nil
}

// chunkReader concatenates an artifact's chunks into one plaintext stream.
type chunkReader struct {
	s      *Store
	chunks []Chunk
	i      int
	cur    io.ReadCloser
}

func newChunkReader(s *Store, rec ArtifactRecord) (io.ReadCloser, error) {
	return &chunkReader{s: s, chunks: rec.Chunks}, nil
}

func (c *chunkReader) Read(p []byte) (int, error) {
	for {
		if c.cur == nil {
			if c.i >= len(c.chunks) {
				return 0, io.EOF
			}
			ch := c.chunks[c.i]
			rc, err := c.s.openUnit(ch.ID, ch.Codec, ch.Size)
			if err != nil {
				return 0, err
			}
			c.cur, c.i = rc, c.i+1
		}
		n, err := c.cur.Read(p)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			c.cur.Close()
			c.cur = nil
			continue
		}
		if err != nil {
			return 0, err
		}
	}
}

func (c *chunkReader) Close() error {
	if c.cur != nil {
		return c.cur.Close()
	}
	return nil
}

// ReadManifest reads manifest.jsonl (current) or manifest.json (packages
// written before the append-only manifest). Both forms stay readable for
// the life of the format.
func ReadManifest(pkgDir string) (*Manifest, error) {
	if m, err := readManifestJSONL(filepath.Join(pkgDir, manifestJSONL)); err == nil {
		return m, nil
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	data, err := os.ReadFile(filepath.Join(pkgDir, manifestJSON))
	if err != nil {
		return nil, err
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &m, nil
}

// readManifestJSONL parses the append-only manifest: one header line
// followed by one artifact record per line.
func readManifestJSONL(path string) (*Manifest, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var m Manifest
	dec := json.NewDecoder(f)
	first := true
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err == io.EOF {
			break
		} else if err != nil {
			return nil, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
		}
		if first {
			if err := json.Unmarshal(raw, &m); err != nil {
				return nil, fmt.Errorf("parse %s header: %w", filepath.Base(path), err)
			}
			first = false
			continue
		}
		var rec ArtifactRecord
		if err := json.Unmarshal(raw, &rec); err != nil {
			return nil, fmt.Errorf("parse %s record: %w", filepath.Base(path), err)
		}
		m.Artifacts = append(m.Artifacts, rec)
	}
	if first {
		return nil, fmt.Errorf("%s: empty manifest", filepath.Base(path))
	}
	return &m, nil
}

// storedUnits lists every on-disk blob name an artifact record refers to.
func storedUnits(rec ArtifactRecord) []string {
	if rec.Status != StatusOK || rec.ArtifactID == "" {
		return nil
	}
	if len(rec.Chunks) == 0 {
		return []string{blobName(rec.ArtifactID, rec.Codec)}
	}
	out := make([]string, 0, len(rec.Chunks))
	for _, c := range rec.Chunks {
		out = append(out, blobName(c.ID, c.Codec))
	}
	return out
}

// idFromBlobName maps a blob file name back to its content address.
func idFromBlobName(name string) string {
	return strings.TrimSuffix(name, ".gz")
}
