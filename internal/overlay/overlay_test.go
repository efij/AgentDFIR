package overlay

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type rec struct {
	ID      string `json:"event_id"`
	Session string `json:"session_id"`
	Summary string `json:"summary"`
}

// sample builds records shaped like the normalized overlay: the same keys
// on every line, a handful of repeated session ids, long repeated text.
// That shape is why the overlay compresses at all, so a test about the
// size has to use it rather than random bytes.
func sample(n int) []rec {
	out := make([]rec, n)
	for i := range out {
		out[i] = rec{
			ID:      fmt.Sprintf("ev-%08d", i),
			Session: fmt.Sprintf("9b2d7e3a-2222-4f5b-8c2b-%012d", i%4),
			Summary: "Bash(cat ~/.aws/credentials) executed by the agent and recorded in the transcript",
		}
	}
	return out
}

func writeSample(t *testing.T, path string, recs []rec) {
	t.Helper()
	if err := WriteJSONL(path, len(recs), func(i int) any { return recs[i] }); err != nil {
		t.Fatal(err)
	}
}

// The whole point of the package: the overlay on disk is materially
// smaller than the JSON it holds. On the real case this is 178 MB of
// normalized/ and 120 MB of detections/, and without compression a 525 MB
// evidence package carried another ~300 MB of derived data.
func TestWriteJSONLCompresses(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")
	recs := sample(5000)
	writeSample(t, p, recs)

	var plain bytes.Buffer
	enc := json.NewEncoder(&plain)
	for _, r := range recs {
		if err := enc.Encode(r); err != nil {
			t.Fatal(err)
		}
	}
	fi, err := os.Stat(p + Suffix)
	if err != nil {
		t.Fatalf("compressed form not written: %v", err)
	}
	ratio := float64(plain.Len()) / float64(fi.Size())
	if ratio < 4 {
		t.Fatalf("overlay only shrank %.1f:1 (%d -> %d bytes); expected the JSON to compress far better",
			ratio, plain.Len(), fi.Size())
	}
	t.Logf("%d bytes of JSONL -> %d bytes on disk (%.1f:1)", plain.Len(), fi.Size(), ratio)
}

// Round trip: what comes back out is exactly what went in. Compression is
// a storage detail and must not change one byte of analysis input.
func TestRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")
	recs := sample(200)
	writeSample(t, p, recs)

	got := ReadJSONL[rec](p)
	if len(got) != len(recs) {
		t.Fatalf("read %d records, wrote %d", len(got), len(recs))
	}
	for i := range recs {
		if got[i] != recs[i] {
			t.Fatalf("record %d: got %+v want %+v", i, got[i], recs[i])
		}
	}
	if n := CountLines(p); n != len(recs) {
		t.Fatalf("CountLines = %d, want %d", n, len(recs))
	}
}

// A package produced by an older binary carries plaintext overlay files.
// Every reader must keep working against it, or upgrading the binary would
// silently make existing cases unreadable.
func TestReadsPlaintextOverlay(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")
	recs := sample(50)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range recs {
		_ = enc.Encode(r)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	if !Exists(p) {
		t.Fatal("Exists false for a plaintext overlay file")
	}
	if Path(p) != p {
		t.Fatalf("Path = %s, want the plaintext path", Path(p))
	}
	if _, err := Stat(p); err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if got := ReadJSONL[rec](p); len(got) != len(recs) || got[0] != recs[0] {
		t.Fatalf("plaintext read back %d records", len(got))
	}
	if n := CountLines(p); n != len(recs) {
		t.Fatalf("CountLines = %d, want %d", n, len(recs))
	}
	data, err := ReadFile(p)
	if err != nil || !bytes.Equal(data, buf.Bytes()) {
		t.Fatalf("ReadFile: %v, %d bytes", err, len(data))
	}
}

// Re-analyzing an old package must reclaim its disk, not add to it: the
// writer replaces the plaintext form rather than leaving it beside the
// compressed one where no reader would ever look at it again.
func TestWriteReplacesPlaintextForm(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(p, []byte(`{"event_id":"stale"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recs := sample(10)
	writeSample(t, p, recs)

	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("plaintext form survived the write: %v", err)
	}
	if _, err := os.Stat(p + Suffix); err != nil {
		t.Fatalf("compressed form missing: %v", err)
	}
	if got := ReadJSONL[rec](p); len(got) != len(recs) || got[0].ID == "stale" {
		t.Fatalf("stale content read back: %+v", got)
	}
}

// With both forms present — an interrupted upgrade, or a hand-placed file
// — the compressed one is the current one and wins.
func TestCompressedFormWins(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")
	if err := os.WriteFile(p, []byte(`{"event_id":"old"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write([]byte(`{"event_id":"new"}` + "\n"))
	_ = zw.Close()
	if err := os.WriteFile(p+Suffix, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	if Path(p) != p+Suffix {
		t.Fatalf("Path = %s, want the compressed form", Path(p))
	}
	got := ReadJSONL[rec](p)
	if len(got) != 1 || got[0].ID != "new" {
		t.Fatalf("read %+v, want the compressed form's content", got)
	}
}

// The overlay is the one part of a case directory that carries no seal, so
// an attacker who can write to it can swap a file for a decompression
// bomb. The read has to fail rather than expand without limit — the same
// guarantee casepkg's store gives for evidence blobs.
func TestDecompressionIsBounded(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")

	// A gzip member whose plaintext is far past what its size on disk may
	// legitimately expand to: minBound is the floor for a small file, so
	// the bomb has to clear that to prove the ceiling is enforced.
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	chunk := bytes.Repeat([]byte("A"), 1<<20)
	for written := 0; written < minBound+(8<<20); written += len(chunk) {
		if _, err := zw.Write(chunk); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p+Suffix, gz.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	rc, err := Open(p)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	var n int64
	buf := make([]byte, 1<<20)
	for {
		k, rErr := rc.Read(buf)
		n += int64(k)
		if rErr != nil {
			if !strings.Contains(rErr.Error(), "exceeds the") {
				t.Fatalf("read stopped with %v, want the overlay bound error (after %d bytes)", rErr, n)
			}
			break
		}
		if n > maxPlaintext {
			t.Fatal("decompression ran past the absolute ceiling unbounded")
		}
	}
	limit := int64(len(gz.Bytes())) * maxRatio
	if limit < minBound {
		limit = minBound
	}
	if n > limit {
		t.Fatalf("decompressed %d bytes, past the %d-byte bound", n, limit)
	}
}

// A truncated or non-gzip .gz is a corrupt overlay, not evidence: the read
// reports it instead of returning half a case as if it were whole.
func TestCorruptCompressedFormErrors(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(p+Suffix, []byte("this is not gzip"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(p); err == nil {
		t.Fatal("Open accepted a non-gzip .gz")
	}
	if _, err := ReadFile(p); err == nil {
		t.Fatal("ReadFile accepted a non-gzip .gz")
	}
}

func TestWriteJSONAndRemove(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "findings.json")
	want := map[string]any{"rule_id": "ORPHAN_AGENT", "severity": "HIGH"}
	if err := WriteJSON(p, want); err != nil {
		t.Fatal(err)
	}
	data, err := ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("%v (content %q)", err, data)
	}
	if got["rule_id"] != want["rule_id"] || got["severity"] != want["severity"] {
		t.Fatalf("got %v want %v", got, want)
	}

	// Remove clears both forms, whichever one a package happens to hold.
	if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Remove(p); err != nil {
		t.Fatal(err)
	}
	if Exists(p) {
		t.Fatal("Remove left one of the two forms behind")
	}
	if err := Remove(p); err != nil {
		t.Fatalf("Remove on an absent file: %v", err)
	}
}

// An existing case is the whole reason Compress exists: its overlay is not
// stale, so nothing would rewrite it, and the plaintext would be carried
// forever. Migrating must reclaim the space and change nothing else.
func TestCompressMigratesPlaintextInPlace(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")
	recs := sample(2000)
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, r := range recs {
		_ = enc.Encode(r)
	}
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	saved, err := Compress(p)
	if err != nil {
		t.Fatal(err)
	}
	if saved <= 0 {
		t.Fatalf("Compress reclaimed %d bytes", saved)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("plaintext form survived migration: %v", err)
	}
	fi, err := os.Stat(p + Suffix)
	if err != nil {
		t.Fatal(err)
	}
	if saved != int64(buf.Len())-fi.Size() {
		t.Fatalf("reported %d bytes reclaimed, actual %d", saved, int64(buf.Len())-fi.Size())
	}
	got := ReadJSONL[rec](p)
	if len(got) != len(recs) {
		t.Fatalf("migration lost records: %d of %d", len(got), len(recs))
	}
	for i := range recs {
		if got[i] != recs[i] {
			t.Fatalf("migration changed record %d", i)
		}
	}
}

// Compress must be safe to call on every run: an already-migrated file and
// an absent one are both no-ops, and it must never rewrite a compressed
// file that is already current.
func TestCompressIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events.jsonl")

	if n, err := Compress(p); n != 0 || err != nil {
		t.Fatalf("Compress on an absent file: %d, %v", n, err)
	}
	writeSample(t, p, sample(100))
	before, err := os.Stat(p + Suffix)
	if err != nil {
		t.Fatal(err)
	}
	if n, err := Compress(p); n != 0 || err != nil {
		t.Fatalf("Compress on an already-compressed file: %d, %v", n, err)
	}
	after, err := os.Stat(p + Suffix)
	if err != nil {
		t.Fatal(err)
	}
	if !before.ModTime().Equal(after.ModTime()) || before.Size() != after.Size() {
		t.Fatal("Compress rewrote a file that was already current")
	}
}
