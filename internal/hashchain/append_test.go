package hashchain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func newChain(t *testing.T, records ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range records {
		if err := w.Append(map[string]any{"event": r}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// TestAppenderContinuesChain: a second collection round extends the logs
// rather than starting them over.
func TestAppenderContinuesChain(t *testing.T) {
	path := newChain(t, "first", "second")
	w, err := NewAppender(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(map[string]any{"event": "third"}); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	n, err := VerifyFile(path)
	if err != nil {
		t.Fatalf("appended chain does not verify: %v", err)
	}
	if n != 3 {
		t.Fatalf("records = %d, want 3", n)
	}
}

// TestAppenderRefusesBrokenChain is the reason the appender verifies
// before writing: appending a correctly-linked tail to an already-broken
// chain would make the file verify from the break onward and hide the
// tampering behind fresh, valid-looking records.
func TestAppenderRefusesBrokenChain(t *testing.T) {
	path := newChain(t, "first", "second", "third")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	lines[1] = strings.Replace(lines[1], `"second"`, `"TAMPERED"`, 1)
	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := NewAppender(path); err == nil {
		t.Fatal("appending to a broken chain was allowed")
	}
}
