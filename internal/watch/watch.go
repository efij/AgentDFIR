// Package watch implements live monitoring of agent session directories
// (killer feature #5): it tails growing transcript files and emits
// normalized event lines in real time. Read-only — it never blocks,
// modifies or signals the observed agents.
//
// Polling (stdlib-only) rather than OS file notification: forensically
// predictable, cross-platform, and dependency-free. New files start at
// offset 0; files existing at startup start at their current size so
// only NEW activity is reported.
package watch

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/parsers/linereader"
	"github.com/efij/AgentDFIR/internal/sanitize"
)

// MaxLineBytes bounds one tailed line.
const MaxLineBytes = 8 << 20

// Watcher polls transcript trees for growth.
type Watcher struct {
	Paths    []string // directory roots to watch (recursive, *.jsonl)
	Interval time.Duration
	Out      io.Writer
	// OnLine, when set, receives every new transcript line with its
	// absolute byte offset and 1-based line number (real-time detection).
	OnLine func(path string, raw []byte, off int64, line int)
	// Quiet suppresses the per-line console rendering.
	Quiet bool

	offsets map[string]int64
	lines   map[string]int
}

// Run polls for the given number of cycles (<=0 = until error/forever).
func (w *Watcher) Run(cycles int) error {
	if w.Interval <= 0 {
		w.Interval = 2 * time.Second
	}
	if w.offsets == nil {
		w.offsets = map[string]int64{}
		w.lines = map[string]int{}
		// Baseline pass: existing content is history, not live activity.
		w.scan(func(path string, size int64) { w.offsets[path] = size; w.lines[path] = countLines(path) })
	}
	for i := 0; cycles <= 0 || i < cycles; i++ {
		if i > 0 || cycles <= 0 {
			time.Sleep(w.Interval)
		}
		w.scan(func(path string, size int64) {
			last, known := w.offsets[path]
			switch {
			case !known:
				w.emitNew(path, 0, size)
				w.offsets[path] = size
			case size > last:
				w.emitNew(path, last, size)
				w.offsets[path] = size
			case size < last:
				// Truncation/rewrite is itself a signal.
				fmt.Fprintf(w.Out, "%s TRUNCATED  %s (was %d bytes, now %d)\n",
					time.Now().UTC().Format(time.RFC3339), sanitize.Terminal(path), last, size)
				w.offsets[path] = size
			}
		})
	}
	return nil
}

func (w *Watcher) scan(visit func(path string, size int64)) {
	for _, root := range w.Paths {
		_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".jsonl") {
				return nil
			}
			info, err := d.Info()
			if err != nil || !info.Mode().IsRegular() {
				return nil
			}
			visit(path, info.Size())
			return nil
		})
	}
}

// emitNew reads [from,to) of a transcript and prints one line per event.
func (w *Watcher) emitNew(path string, from, to int64) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()
	if _, err := f.Seek(from, io.SeekStart); err != nil {
		return
	}
	lr := linereader.New(io.LimitReader(f, to-from), MaxLineBytes)
	for {
		ln, err := lr.Next()
		if err != nil {
			return
		}
		w.lines[path]++
		if ln.Overflow {
			fmt.Fprintf(w.Out, "%s OVERSIZED  %s: line > bound\n",
				time.Now().UTC().Format(time.RFC3339), sanitize.Terminal(path))
			continue
		}
		if w.OnLine != nil {
			w.OnLine(path, ln.Bytes, from+ln.Offset, w.lines[path])
		}
		if !w.Quiet {
			w.emitLine(path, ln.Bytes)
		}
	}
}

// emitLine renders one transcript line as a compact live event.
func (w *Watcher) emitLine(path string, raw []byte) {
	var tl struct {
		Type      string `json:"type"`
		SessionID string `json:"sessionId"`
		AgentID   string `json:"agentId"`
		Timestamp string `json:"timestamp"`
		Message   struct {
			Content json.RawMessage `json:"content"`
		} `json:"message"`
	}
	label := "raw"
	detail := ""
	if err := json.Unmarshal(raw, &tl); err == nil && tl.Type != "" {
		label = tl.Type
		if tool, cmd := toolCallOf(tl.Message.Content); tool != "" {
			label = "tool_call:" + tool
			detail = cmd
		}
	}
	sess := tl.SessionID
	if len(sess) > 8 {
		sess = sess[:8]
	}
	fmt.Fprintf(w.Out, "%s %-22s sess=%-8s %s  %s\n",
		time.Now().UTC().Format(time.RFC3339),
		sanitize.Terminal(label), sanitize.Terminal(sess),
		sanitize.Terminal(filepath.Base(path)), sanitize.Terminal(trim(detail, 120)))
}

func toolCallOf(content json.RawMessage) (tool, cmd string) {
	var items []struct {
		Type  string `json:"type"`
		Name  string `json:"name"`
		Input struct {
			Command string `json:"command"`
		} `json:"input"`
	}
	if err := json.Unmarshal(content, &items); err != nil {
		return "", ""
	}
	for _, it := range items {
		if it.Type == "tool_use" {
			return it.Name, it.Input.Command
		}
	}
	return "", ""
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

// countLines counts newline-terminated lines in an existing file so live
// line numbers continue the file's real numbering.
func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	buf := make([]byte, 256<<10)
	n := 0
	for {
		k, err := f.Read(buf)
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
