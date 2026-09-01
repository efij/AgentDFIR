package hashchain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeChain(t *testing.T, n int) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	w, err := NewWriter(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		if err := w.Append(map[string]any{"event": "e", "i": i}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestChainRoundTrip(t *testing.T) {
	path := writeChain(t, 10)
	n, err := VerifyFile(path)
	if err != nil {
		t.Fatalf("verify failed: %v", err)
	}
	if n != 10 {
		t.Fatalf("got %d records, want 10", n)
	}
}

func TestChainDetectsModification(t *testing.T) {
	path := writeChain(t, 5)
	data, _ := os.ReadFile(path)
	tampered := strings.Replace(string(data), `"i":2`, `"i":99`, 1)
	if tampered == string(data) {
		t.Fatal("test setup: substitution had no effect")
	}
	os.WriteFile(path, []byte(tampered), 0o600)
	if _, err := VerifyFile(path); err == nil {
		t.Fatal("modified record not detected")
	}
}

func TestChainDetectsDeletion(t *testing.T) {
	path := writeChain(t, 5)
	data, _ := os.ReadFile(path)
	lines := strings.SplitAfter(string(data), "\n")
	// Drop the third record.
	tampered := strings.Join(append(lines[:2], lines[3:]...), "")
	os.WriteFile(path, []byte(tampered), 0o600)
	if _, err := VerifyFile(path); err == nil {
		t.Fatal("deleted record not detected")
	}
}

func TestChainDetectsAppendAfterClose(t *testing.T) {
	path := writeChain(t, 3)
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString(`{"event":"forged","seq":3,"prev":"beef"}` + "\n")
	f.Close()
	if _, err := VerifyFile(path); err == nil {
		t.Fatal("forged appended record not detected")
	}
}
