package journal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeStore-free test: journal a file, then check the file against the
// journal records by replaying checkPath's logic through Check requires a
// package; here we test the writer and the anchor.
func TestJournalChainAndAnchor(t *testing.T) {
	dir := t.TempDir()
	tr := filepath.Join(dir, "s.jsonl")
	if err := os.WriteFile(tr, []byte("{\"a\":1}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	jp := filepath.Join(dir, "j", "journal.jsonl")
	j, err := Open(jp)
	if err != nil {
		t.Fatal(err)
	}
	j.Baseline(tr)
	f, _ := os.OpenFile(tr, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("{\"b\":2}\n")
	f.Close()
	j.Grow(tr, 8, 16)
	var anchored string
	j.Anchor = func(h string) { anchored = h }
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	if anchored == "" {
		t.Fatal("no anchor on close")
	}
	ok, _, err := VerifyAnchor(jp, anchored)
	if err != nil || !ok {
		t.Fatalf("anchor not found in chain: %v", err)
	}
	// Reopen continues the chain; editing it makes the next Open set it aside.
	b, _ := os.ReadFile(jp)
	b[20] ^= 1
	os.WriteFile(jp, b, 0o600)
	j2, err := Open(jp)
	if err != nil {
		t.Fatal(err)
	}
	j2.Close()
	m, _ := filepath.Glob(filepath.Join(dir, "j", "journal.broken-*.jsonl"))
	if len(m) != 1 {
		t.Fatalf("broken journal not set aside: %v", m)
	}
	if ok, _, _ := VerifyAnchor(jp, anchored); ok {
		t.Error("anchor from the old chain found in the new one")
	}
}

// TestRestartAfterEditStillCaught: stop the monitor, edit the transcript,
// start it again — the new baseline covers the edited file, but the append
// journaled before the stop still has the original bytes' hash.
func TestRestartAfterEditStillCaught(t *testing.T) {
	dir := t.TempDir()
	tr := filepath.Join(dir, "s.jsonl")
	os.WriteFile(tr, []byte(""), 0o644)
	jp := filepath.Join(dir, "journal.jsonl")
	j, _ := Open(jp)
	j.Baseline(tr)
	os.WriteFile(tr, []byte("{\"cmd\":\"curl 169.254.169.254\"}\n"), 0o644)
	j.Grow(tr, 0, 30)
	j.Close()
	os.WriteFile(tr, []byte("{\"cmd\":\"ls                 \"}\n"), 0o644) // same length
	j2, _ := Open(jp)
	j2.Baseline(tr)
	j2.Close()
	rs := readRecs(t, jp)
	if len(rs) == 0 {
		t.Fatal("no records")
	}
	var appendRec *rec
	for i := range rs {
		if rs[i].Kind == "append" {
			appendRec = &rs[i]
		}
	}
	if appendRec == nil {
		t.Fatal("append not journaled")
	}
	b, _ := os.ReadFile(tr)
	if sha(b[appendRec.Offset:appendRec.Offset+appendRec.Len]) == appendRec.SHA256 {
		t.Fatal("edit not visible in the pre-restart append hash")
	}
}

func readRecs(t *testing.T, p string) []rec {
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var out []rec
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		var r rec
		if json.Unmarshal([]byte(l), &r) == nil {
			out = append(out, r)
		}
	}
	return out
}

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
