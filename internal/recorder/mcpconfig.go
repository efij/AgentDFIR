package recorder

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"time"
)

// maxConfigHash bounds the bytes hashed of one MCP config file.
const maxConfigHash = 4 << 20

// MCPConfigWatcher records MCP server-definition changes. Each poll it
// looks at every known config location; a file that appears, changes
// content or disappears produces one JSON line in the capture: its path,
// size, mtime and SHA-256. The content itself is not copied (MCP configs
// carry API keys in env blocks); the hash ties the record to the file a
// later collection seals.
type MCPConfigWatcher struct {
	Patterns []string // absolute paths, globs allowed (mcpaudit.ConfigPatterns)
	Out      io.Writer
	Src      *Source
	seen     map[string]cfgState
	now      func() time.Time
}

type cfgState struct {
	size  int64
	mtime time.Time
	sha   string
}

type cfgRecord struct {
	Time   string `json:"time"`
	Source string `json:"source"`
	Event  string `json:"event"` // present (at start) | created | changed | removed
	Path   string `json:"path"`
	Size   int64  `json:"size,omitempty"`
	MTime  string `json:"mtime,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
	Note   string `json:"note,omitempty"`
}

// Poll checks every config location once.
func (w *MCPConfigWatcher) Poll() {
	if w.now == nil {
		w.now = time.Now
	}
	first := w.seen == nil
	if first {
		w.seen = map[string]cfgState{}
		w.Src.SetState("running")
	}
	present := map[string]bool{}
	var paths []string
	for _, pat := range w.Patterns {
		m, _ := filepath.Glob(pat)
		paths = append(paths, m...)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if present[p] {
			continue
		}
		fi, err := os.Stat(p)
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		present[p] = true
		old, known := w.seen[p]
		if known && old.size == fi.Size() && old.mtime.Equal(fi.ModTime()) {
			continue
		}
		sha, note := hashFile(p, maxConfigHash)
		if note != "" {
			w.Src.Problem(note)
		}
		w.seen[p] = cfgState{size: fi.Size(), mtime: fi.ModTime(), sha: sha}
		event := "changed"
		switch {
		case first:
			event = "present"
		case !known:
			event = "created"
		case old.sha == sha:
			continue // touched, same content
		}
		w.emit(cfgRecord{Event: event, Path: p, Size: fi.Size(), MTime: fi.ModTime().UTC().Format(time.RFC3339Nano), SHA256: sha, Note: note})
	}
	var gone []string
	for p := range w.seen {
		if !present[p] {
			gone = append(gone, p)
		}
	}
	sort.Strings(gone)
	for _, p := range gone {
		delete(w.seen, p)
		w.emit(cfgRecord{Event: "removed", Path: p})
	}
}

func (w *MCPConfigWatcher) emit(r cfgRecord) {
	r.Time = w.now().UTC().Format(time.RFC3339Nano)
	r.Source = "mcp-config"
	b, _ := json.Marshal(r)
	_, _ = w.Out.Write(append(b, '\n'))
}

// hashFile returns the SHA-256 of a file, reading at most max bytes (a
// note says when the file was larger); max <= 0 reads it all.
func hashFile(p string, max int64) (string, string) {
	f, err := os.Open(p)
	if err != nil {
		return "", "cannot read " + p + ": " + err.Error()
	}
	defer f.Close()
	h := sha256.New()
	var r io.Reader = f
	if max > 0 {
		r = io.LimitReader(f, max+1)
	}
	n, err := io.Copy(h, r)
	if err != nil {
		return "", "cannot read " + p + ": " + err.Error()
	}
	if max > 0 && n > max {
		return "", p + " is larger than the hash bound; not hashed"
	}
	return hex.EncodeToString(h.Sum(nil)), ""
}
