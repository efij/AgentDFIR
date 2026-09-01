package watch

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestWatcherReportsOnlyNewActivity(t *testing.T) {
	dir := t.TempDir()
	sess := filepath.Join(dir, "projects", "p")
	if err := os.MkdirAll(sess, 0o755); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(sess, "s1.jsonl")
	pre := `{"type":"user","sessionId":"sess-pre","message":{"role":"user","content":"old history"}}` + "\n"
	if err := os.WriteFile(file, []byte(pre), 0o644); err != nil {
		t.Fatal(err)
	}

	var out strings.Builder
	w := &Watcher{Paths: []string{dir}, Interval: 10 * time.Millisecond, Out: &out}

	// Cycle 1: baseline only — pre-existing content must NOT be emitted.
	if err := w.Run(1); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "sess-pre") {
		t.Fatal("pre-existing history reported as live activity")
	}

	// Append live activity: a Bash tool call.
	f, _ := os.OpenFile(file, os.O_APPEND|os.O_WRONLY, 0o644)
	f.WriteString(`{"type":"assistant","sessionId":"sess-live","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"curl example.com"}}]}}` + "\n")
	f.Close()

	if err := w.Run(1); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if !strings.Contains(got, "tool_call:Bash") || !strings.Contains(got, "curl example.com") {
		t.Fatalf("live tool call not reported: %q", got)
	}

	// Truncation must be flagged.
	os.WriteFile(file, []byte("{}"), 0o644)
	if err := w.Run(1); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "TRUNCATED") {
		t.Fatal("file truncation not reported")
	}
}
