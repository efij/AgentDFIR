// Package journal makes agent transcripts tamper-evident while `agentdfir
// monitor` runs.
//
// The OpenAI–Hugging Face agents researched how to spoof tool calls and
// rewrite their own transcripts (METR, Aug 2026); agents that delete prod
// data then misreport what they did are a recurring 2025–2026 pattern. A
// transcript collected after the fact proves nothing about whether it was
// edited. The journal records, as the monitor watches each append-only
// JSONL transcript grow, the byte range, its SHA-256, a running SHA-256
// of the whole prefix and the file's device:inode, in a hash-chained log.
// Analysis then checks the collected transcripts against it.
//
// Honest scope: the journal lives on the watched host. It detects edits
// made by anything that does not know it exists or cannot rewrite it
// consistently. An attacker running as the same user who knows about it
// can rebuild the chain; what defeats that is the chain head leaving the
// file — every seal is written to the system log (macOS unified log /
// syslog), printed on stderr, optionally appended to --journal-anchor, and
// `agentdfir journal verify --anchor <head>` checks a head recorded
// elsewhere is still in the chain.
package journal

import (
	"crypto/sha256"
	"encoding"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/hashchain"
)

// SealEvery is how often a seal record (and an off-file anchor) is written.
var SealEvery = 10 * time.Minute

// maxBaselineHash bounds the full-content hash taken of a file that already
// exists when monitoring starts.
const maxBaselineHash = 512 << 20

// DefaultPath is where the monitor keeps its journal; the Claude manifest
// collects it (agentdfir.monitor_journal).
func DefaultPath(home string) string {
	return filepath.Join(home, ".agentdfir", "monitor", "journal.jsonl")
}

type fileState struct {
	id   string
	size int64
	h    hash.Hash // running prefix hash
}

// Journal is an open, appending journal.
type Journal struct {
	mu       sync.Mutex
	w        *hashchain.Writer
	path     string
	files    map[string]*fileState
	lastSeal time.Time
	closed   bool
	records  int
	head     string
	Anchor   func(head string) // extra anchor sink (stderr, --journal-anchor file)
	now      func() time.Time
}

// Open continues the journal at path, or starts one. A journal whose chain
// is already broken is kept aside (journal.broken-<ts>.jsonl) and the new
// one records that it was, so the break reaches the case.
func Open(path string) (*Journal, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	j := &Journal{path: path, files: map[string]*fileState{}, now: time.Now}
	prevBroken := ""
	var w *hashchain.Writer
	var err error
	if _, statErr := os.Stat(path); statErr == nil {
		w, err = hashchain.NewAppender(path)
		if err != nil {
			aside := filepath.Join(filepath.Dir(path), fmt.Sprintf("journal.broken-%s.jsonl", time.Now().UTC().Format("20060102T150405Z")))
			_ = os.Rename(path, aside)
			prevBroken = err.Error()
			w, err = hashchain.NewWriter(path)
		}
	} else {
		w, err = hashchain.NewWriter(path)
	}
	if err != nil {
		return nil, err
	}
	j.w = w
	host, _ := os.Hostname()
	rec := map[string]any{"kind": "start", "host": host, "pid": os.Getpid()}
	if prevBroken != "" {
		rec["previous_chain_broken"] = prevBroken
	}
	if err := j.append(rec); err != nil {
		return nil, err
	}
	j.lastSeal = j.now()
	return j, nil
}

func (j *Journal) append(rec map[string]any) error {
	rec["monitor_utc"] = j.now().UTC().Format(time.RFC3339Nano)
	if err := j.w.Append(rec); err != nil {
		return err
	}
	j.records++
	return nil
}

// Baseline records a file that already exists: its size, full-content
// SHA-256 and identity. Later appends continue its prefix hash.
func (j *Journal) Baseline(path string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return
	}
	h := sha256.New()
	f, err := os.Open(path)
	if err != nil {
		return
	}
	n, _ := io.Copy(h, io.LimitReader(f, maxBaselineHash))
	f.Close()
	st := &fileState{id: fileID(fi), size: n, h: h}
	j.files[path] = st
	_ = j.append(map[string]any{"kind": "baseline", "path": path, "size": n, "sha256": sum(h), "file_id": st.id})
}

// Grow records the bytes [from,to) appended to path.
func (j *Journal) Grow(path string, from, to int64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	st := j.files[path]
	fi, err := os.Stat(path)
	if err != nil {
		return
	}
	id := fileID(fi)
	if st == nil {
		// A new file: everything from 0 is an append.
		st = &fileState{id: id, h: sha256.New()}
		j.files[path] = st
		from = 0
	} else if st.id != "" && id != "" && id != st.id {
		_ = j.append(map[string]any{"kind": "replaced", "path": path, "old_file_id": st.id, "new_file_id": id, "old_size": st.size})
		st = &fileState{id: id, h: sha256.New()}
		j.files[path] = st
		from = 0
	}
	if from != st.size {
		from = st.size
	}
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return
	}
	chunk := sha256.New()
	n, _ := io.Copy(io.MultiWriter(chunk, st.h), io.LimitReader(f, to-from))
	if n == 0 {
		return
	}
	st.size = from + n
	_ = j.append(map[string]any{"kind": "append", "path": path, "offset": from, "len": n, "sha256": sum(chunk), "prefix_sha256": sum(st.h), "file_id": id})
	j.maybeSeal()
}

// Shrink records a file that got shorter than what was journaled.
func (j *Journal) Shrink(path string, was, now int64) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	_ = j.append(map[string]any{"kind": "truncate", "path": path, "was": was, "now": now})
	delete(j.files, path)
}

// Gone records a journaled file that disappeared.
func (j *Journal) Gone(path string) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return
	}
	if st, ok := j.files[path]; ok {
		_ = j.append(map[string]any{"kind": "deleted", "path": path, "size": st.size})
		delete(j.files, path)
	}
}

func (j *Journal) maybeSeal() {
	if j.now().Sub(j.lastSeal) >= SealEvery {
		j.seal()
	}
}

// seal writes a seal record and sends the chain head off-file.
func (j *Journal) seal() {
	_ = j.append(map[string]any{"kind": "seal", "records": j.records, "files": len(j.files)})
	j.lastSeal = j.now()
	head, _ := Head(j.path)
	j.head = head
	msg := fmt.Sprintf("agentdfir journal %s head %s records %d", j.path, head, j.records)
	anchorSyslog(msg)
	if j.Anchor != nil {
		j.Anchor(head)
	}
}

// Close writes a final seal and a stop record.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.closed {
		return nil
	}
	j.closed = true
	j.seal()
	_ = j.append(map[string]any{"kind": "stop"})
	return j.w.Close()
}

// Head returns the SHA-256 of the journal's last line: the value an anchor
// must match.
func Head(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	end := len(b)
	for end > 0 && (b[end-1] == '\n' || b[end-1] == '\r') {
		end--
	}
	start := end
	for start > 0 && b[start-1] != '\n' {
		start--
	}
	s := sha256.Sum256(b[start:end])
	return hex.EncodeToString(s[:]), nil
}

func sum(h hash.Hash) string {
	// Sum on a copy so the running state continues.
	if m, ok := h.(encoding.BinaryMarshaler); ok {
		if st, err := m.MarshalBinary(); err == nil {
			c := sha256.New()
			if u, ok := c.(encoding.BinaryUnmarshaler); ok && u.UnmarshalBinary(st) == nil {
				return hex.EncodeToString(c.Sum(nil))
			}
		}
	}
	return hex.EncodeToString(h.Sum(nil))
}
