// Package artmemo remembers what a per-artifact scan found, so a scan that
// depends only on one artifact's bytes runs once per artifact, not once
// per collection round.
//
// The content scans — rule packs over raw transcripts and configs, the
// credential, injection and invisible-character scans — read every
// artifact in full. On a real case that was most of the analysis: minutes
// of regular expressions over 2.4 GB of transcripts, repeated on every run
// although almost none of them had changed. Their result is a function of
// the artifact (its content address and the record fields the scan reads)
// and of the scanning code and rules. That is the memo key; nothing else
// can reach the result.
//
// The memo is derived data in the analysis overlay, and it is trusted only
// when it is authenticated: it is written with an HMAC under the machine's
// cache key and read back only if the MAC verifies and it was produced by
// the same scanning code with the same rules and options. Without a key it
// is neither read nor written, and every scan runs. A tampered memo is a
// re-scan, never a hidden finding.
package artmemo

import (
	"bytes"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/fingerprint"
	"github.com/efij/AgentDFIR/v3/internal/store"
)

// Memo is one scan's remembered results, by artifact.
type Memo[T any] struct {
	path  string
	key   []byte
	scope string

	mu      sync.Mutex
	entries map[string]T
	used    map[string]bool
	hits    int
}

type file[T any] struct {
	Scope   string       `json:"scope"`
	Entries map[string]T `json:"entries"`
}

// Open loads the memo named name for the package. scope names everything
// besides the artifact the scan depends on (rules, options); the analysis
// code fingerprint is always part of it. A memo that is missing, from other
// code or rules, or fails authentication starts empty.
func Open[T any](pkgDir, name, scope string) *Memo[T] {
	m := &Memo[T]{
		path:    filepath.Join(pkgDir, "detections", "memo", name+".json.gz"),
		key:     store.CacheKey(),
		scope:   fingerprint.Analysis() + "\x00" + scope,
		entries: map[string]T{},
		used:    map[string]bool{},
	}
	if m.key == nil {
		return m
	}
	data, err := os.ReadFile(m.path)
	if err != nil {
		return m
	}
	mac, err := os.ReadFile(m.path + ".mac")
	if err != nil || !hmac.Equal(bytes.TrimSpace(mac), []byte(sum(m.key, data))) {
		return m
	}
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return m
	}
	plain, err := io.ReadAll(io.LimitReader(zr, 512<<20))
	if err != nil {
		return m
	}
	var f file[T]
	if json.Unmarshal(plain, &f) != nil || f.Scope != m.scope || f.Entries == nil {
		return m
	}
	m.entries = f.Entries
	return m
}

// Enabled reports whether results can be remembered at all (this machine
// has a cache key).
func (m *Memo[T]) Enabled() bool { return m.key != nil }

// Key names an artifact by everything a scan reads off its record.
func Key(a casepkg.ArtifactRecord) string {
	h := sha256.New()
	for _, f := range []string{a.ArtifactID, a.LogicalPath, a.SourcePath, a.ArtifactType, a.Product, a.Status, a.Codec} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Get returns a remembered result. Safe for concurrent use.
func (m *Memo[T]) Get(a casepkg.ArtifactRecord) (T, bool) {
	k := Key(a)
	m.mu.Lock()
	defer m.mu.Unlock()
	v, ok := m.entries[k]
	if ok {
		m.used[k] = true
		m.hits++
	}
	return v, ok
}

// Put remembers a result. Safe for concurrent use.
func (m *Memo[T]) Put(a casepkg.ArtifactRecord, v T) {
	if m.key == nil {
		return
	}
	k := Key(a)
	m.mu.Lock()
	m.entries[k] = v
	m.used[k] = true
	m.mu.Unlock()
}

// Hits is how many results were served from the memo.
func (m *Memo[T]) Hits() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.hits
}

// Save writes the memo, keeping only the artifacts this run touched, so it
// never grows past the case's current evidence. It does nothing without a
// key.
func (m *Memo[T]) Save() error {
	if m.key == nil {
		return nil
	}
	m.mu.Lock()
	keep := make(map[string]T, len(m.used))
	for k := range m.used {
		keep[k] = m.entries[k]
	}
	m.mu.Unlock()
	plain, err := json.Marshal(file[T]{Scope: m.scope, Entries: keep})
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(plain); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(m.path), 0o700); err != nil {
		return err
	}
	data := buf.Bytes()
	// MAC first: a crash between the two writes leaves a memo that fails
	// authentication and is re-scanned, never one trusted without a MAC.
	if err := writeAtomic(m.path+".mac", []byte(sum(m.key, data)+"\n")); err != nil {
		return err
	}
	return writeAtomic(m.path, data)
}

func sum(key, data []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return hex.EncodeToString(h.Sum(nil))
}

func writeAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".memo-*.tmp")
	if err != nil {
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		os.Remove(tmp.Name())
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmp.Name())
		return err
	}
	return os.Rename(tmp.Name(), path)
}
