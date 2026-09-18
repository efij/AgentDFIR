package casepkg

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ingest is a small helper: put one file into an open package.
func ingest(t *testing.T, b *Builder, src, logical string) {
	t.Helper()
	if err := b.IngestFile(src, ArtifactRecord{
		SourcePath: src, LogicalPath: logical, Product: "claude-code",
	}); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func recordFor(t *testing.T, pkg, logical string) ArtifactRecord {
	t.Helper()
	man, err := ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var found ArtifactRecord
	for _, a := range man.Artifacts {
		if a.LogicalPath == logical {
			found = a // last record wins: the newest round's view
		}
	}
	if found.LogicalPath == "" {
		t.Fatalf("no manifest record for %s", logical)
	}
	return found
}

// TestSecondRoundAppendsAndArchivesSeal is the core of incremental
// collection: a second round must extend the package without rewriting
// anything the first round sealed.
func TestSecondRoundAppendsAndArchivesSeal(t *testing.T) {
	src := t.TempDir()
	writeFile(t, filepath.Join(src, "a.jsonl"), `{"x":1}`)
	pkg := filepath.Join(t.TempDir(), "case.adfir")

	b, err := New(pkg, "TEST-ROUNDS", CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b, filepath.Join(src, "a.jsonl"), "a.jsonl")
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	firstSeal, err := os.ReadFile(filepath.Join(pkg, sumsFile))
	if err != nil {
		t.Fatal(err)
	}

	writeFile(t, filepath.Join(src, "b.jsonl"), `{"y":2}`)
	b2, err := Reopen(pkg, CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	if b2.Round() != 2 {
		t.Fatalf("round = %d, want 2", b2.Round())
	}
	ingest(t, b2, filepath.Join(src, "b.jsonl"), "b.jsonl")
	if err := b2.Seal(); err != nil {
		t.Fatal(err)
	}

	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("verify after round 2: %v", res.Problems)
	}
	if res.Rounds != 2 {
		t.Fatalf("rounds = %d, want 2", res.Rounds)
	}
	// The first round's seal must still be provable.
	archived, err := os.ReadFile(filepath.Join(pkg, sealsDir, "SHA256SUMS.1"))
	if err != nil {
		t.Fatalf("round 1 seal not archived: %v", err)
	}
	if !bytes.Equal(archived, firstSeal) {
		t.Fatal("archived seal does not match the seal round 1 was closed with")
	}
	// Both records are present, and the round-1 record is untouched.
	man, err := ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(man.Artifacts) != 2 {
		t.Fatalf("manifest records = %d, want 2", len(man.Artifacts))
	}
	if man.Artifacts[0].Round != 1 || man.Artifacts[1].Round != 2 {
		t.Fatalf("rounds on records = %d,%d; want 1,2", man.Artifacts[0].Round, man.Artifacts[1].Round)
	}
}

// TestCarryForwardIsLabelledAndNotReRead: an unchanged file must not be
// re-read, and the record that says so must never look like a fresh
// acquisition.
func TestCarryForwardIsLabelledAndNotReRead(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "a.jsonl")
	writeFile(t, path, `{"x":1}`)
	pkg := filepath.Join(t.TempDir(), "case.adfir")

	b, err := New(pkg, "TEST-CARRY", CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b, path, "a.jsonl")
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	first := recordFor(t, pkg, "a.jsonl")

	b2, err := Reopen(pkg, CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	prev, ok := b2.Unchanged(path, info)
	if !ok {
		t.Fatal("unchanged file was not recognized; a second round would re-read every byte")
	}
	if err := b2.CarryForward(prev, ArtifactRecord{SourcePath: path, LogicalPath: "a.jsonl"}); err != nil {
		t.Fatal(err)
	}
	if err := b2.Seal(); err != nil {
		t.Fatal(err)
	}

	carried := recordFor(t, pkg, "a.jsonl")
	if carried.Method != MethodCarriedForward {
		t.Fatalf("method = %q, want %q", carried.Method, MethodCarriedForward)
	}
	if carried.AcquiredIn != 1 {
		t.Fatalf("acquired_in_round = %d, want 1 — carried evidence must say which round read it", carried.AcquiredIn)
	}
	if carried.ArtifactID != first.ArtifactID {
		t.Fatal("carried record points at different content than the round that acquired it")
	}
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("verify: %v", res.Problems)
	}
	if res.Carried != 1 {
		t.Fatalf("carried artifacts reported = %d, want 1", res.Carried)
	}
}

// TestModifiedFileIsNotCarriedForward: the whole point of using ctime and
// inode is that restoring an mtime must not buy a skipped re-read.
func TestModifiedFileIsNotCarriedForward(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "a.jsonl")
	writeFile(t, path, `{"x":1}`)
	pkg := filepath.Join(t.TempDir(), "case.adfir")

	b, err := New(pkg, "TEST-MOD", CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b, path, "a.jsonl")
	orig, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}

	// Same length, different content, mtime restored: only ctime and inode
	// give this away.
	writeFile(t, path, `{"x":9}`)
	if err := os.Chtimes(path, orig.ModTime(), orig.ModTime()); err != nil {
		t.Fatal(err)
	}

	b2, err := Reopen(pkg, CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := b2.Unchanged(path, info); ok {
		t.Fatal("a modified file with a restored mtime was treated as unchanged")
	}
	b2.Close()
}

// TestAppendedFileStoresOnlyTheTail is the mechanism that keeps repeat
// collections of growing transcripts cheap.
func TestAppendedFileStoresOnlyTheTail(t *testing.T) {
	src := t.TempDir()
	path := filepath.Join(src, "session.jsonl")
	head := strings.Repeat(`{"turn":"first"}`+"\n", 400)
	writeFile(t, path, head)
	pkg := filepath.Join(t.TempDir(), "case.adfir")

	b, err := New(pkg, "TEST-APPEND", CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b, path, "session.jsonl")
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	blobsAfterFirst := countBlobs(t, pkg)

	tail := strings.Repeat(`{"turn":"second"}`+"\n", 400)
	writeFile(t, path, head+tail)

	b2, err := Reopen(pkg, CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b2, path, "session.jsonl")
	if err := b2.Seal(); err != nil {
		t.Fatal(err)
	}

	rec := recordFor(t, pkg, "session.jsonl")
	if rec.Method != MethodAppended {
		t.Fatalf("method = %q, want %q", rec.Method, MethodAppended)
	}
	if len(rec.Chunks) != 2 {
		t.Fatalf("chunks = %d, want 2 (proven prefix + new tail)", len(rec.Chunks))
	}
	if blobsAfterFirst+1 != countBlobs(t, pkg) {
		t.Fatalf("expected exactly one new blob for the tail; blobs went %d -> %d", blobsAfterFirst, countBlobs(t, pkg))
	}
	// artifact_id must still address the whole plaintext.
	want := sha256.Sum256([]byte(head + tail))
	if rec.ArtifactID != hex.EncodeToString(want[:]) {
		t.Fatal("artifact_id is not the SHA-256 of the full file after appending")
	}
	if rec.Size != int64(len(head+tail)) {
		t.Fatalf("size = %d, want %d", rec.Size, len(head+tail))
	}
	// And the store must hand back the whole plaintext, in order.
	man, err := ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewStore(pkg, man).ReadAll(rec.ArtifactID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != head+tail {
		t.Fatal("chunked artifact did not read back as the original file")
	}
	// Full verification must check the concatenation, not skip it.
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("verify: %v", res.Problems)
	}
}

func countBlobs(t *testing.T, pkg string) int {
	t.Helper()
	entries, err := os.ReadDir(filepath.Join(pkg, "raw"))
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

// TestCompressionPreservesContentAddress: compression is a storage detail
// and must be invisible above the store.
func TestCompressionPreservesContentAddress(t *testing.T) {
	content := strings.Repeat(`{"event":"tool_call","command":"ls -la"}`+"\n", 2000)
	src := t.TempDir()
	path := filepath.Join(src, "big.jsonl")
	writeFile(t, path, content)
	pkg := filepath.Join(t.TempDir(), "case.adfir")

	b, err := New(pkg, "TEST-GZ", CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b, path, "big.jsonl")
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}

	rec := recordFor(t, pkg, "big.jsonl")
	if rec.Codec != CodecGzip {
		t.Fatalf("codec = %q, want %q on highly compressible JSONL", rec.Codec, CodecGzip)
	}
	if rec.StoredSize >= rec.Size {
		t.Fatalf("stored %d bytes for %d bytes of evidence — compression did not pay", rec.StoredSize, rec.Size)
	}
	want := sha256.Sum256([]byte(content))
	if rec.ArtifactID != hex.EncodeToString(want[:]) {
		t.Fatal("artifact_id is not the SHA-256 of the plaintext")
	}
	if _, err := os.Stat(filepath.Join(pkg, "raw", rec.ArtifactID+".gz")); err != nil {
		t.Fatalf("compressed blob not named for manual inspection: %v", err)
	}
	man, err := ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	got, err := NewStore(pkg, man).ReadAll(rec.ArtifactID, 0)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != content {
		t.Fatal("store did not return the original plaintext")
	}
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("verify: %v", res.Problems)
	}
}

// TestIncompressibleContentIsStoredPlain: sampling must stop us paying
// gzip on both sides for nothing.
func TestIncompressibleContentIsStoredPlain(t *testing.T) {
	// Already-gzipped bytes: no further compression is available.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte(strings.Repeat("payload", 20000)))
	zw.Close()

	src := t.TempDir()
	path := filepath.Join(src, "blob.gz")
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := New(pkg, "TEST-PLAIN", CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b, path, "blob.gz")
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	if rec := recordFor(t, pkg, "blob.gz"); rec.Codec == CodecGzip {
		t.Fatal("already-compressed content was compressed again")
	}
}

// TestDecompressionIsBounded: a blob that expands past its recorded size
// must fail before it can fill memory, not after the content address
// eventually disagrees.
func TestDecompressionIsBounded(t *testing.T) {
	content := strings.Repeat(`{"a":1}`+"\n", 3000)
	src := t.TempDir()
	path := filepath.Join(src, "x.jsonl")
	writeFile(t, path, content)
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := New(pkg, "TEST-BOMB", CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	ingest(t, b, path, "x.jsonl")
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	rec := recordFor(t, pkg, "x.jsonl")
	if rec.Codec != CodecGzip {
		t.Skip("content was not compressed; bound does not apply")
	}
	// Replace the blob with one that decompresses far larger than recorded.
	blob := filepath.Join(pkg, "raw", rec.ArtifactID+".gz")
	if err := os.Chmod(blob, 0o600); err != nil {
		t.Fatal(err)
	}
	var big bytes.Buffer
	zw := gzip.NewWriter(&big)
	zw.Write(bytes.Repeat([]byte("A"), int(rec.Size)*50))
	zw.Close()
	if err := os.WriteFile(blob, big.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	man, err := ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := NewStore(pkg, man).Open(rec.ArtifactID)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	n, err := io.Copy(io.Discard, rc)
	if err == nil {
		t.Fatal("oversized blob read to completion; the decompression bound did not hold")
	}
	if n > rec.Size+1 {
		t.Fatalf("read %d bytes before failing, recorded size is %d", n, rec.Size)
	}
}

// TestSecondWriterIsRefused: with one predictable package location, two
// concurrent collections are easy to start and would corrupt the chain.
func TestSecondWriterIsRefused(t *testing.T) {
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := New(pkg, "TEST-LOCK", CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := Reopen(pkg, CaseInfo{OperatorOSUser: "tester"}); err == nil {
		t.Fatal("a second writer was allowed into a package already being written")
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	// After sealing the lock is released and a new round may start.
	b2, err := Reopen(pkg, CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatalf("lock not released after sealing: %v", err)
	}
	b2.Close()
}

// TestLegacyPackageStaysReadable: packages written before manifest.jsonl
// and compression existed must keep opening and verifying.
func TestLegacyPackageStaysReadable(t *testing.T) {
	pkg := filepath.Join(t.TempDir(), "legacy.adfir")
	if err := os.MkdirAll(filepath.Join(pkg, "raw"), 0o700); err != nil {
		t.Fatal(err)
	}
	content := []byte(`{"legacy":true}`)
	sum := sha256.Sum256(content)
	id := hex.EncodeToString(sum[:])
	if err := os.WriteFile(filepath.Join(pkg, "raw", id), content, 0o600); err != nil {
		t.Fatal(err)
	}
	man := Manifest{
		ADFIRVersion: "0.1", CaseID: "LEGACY-1", CollectorName: "agentdfir",
		Artifacts: []ArtifactRecord{{
			ArtifactID: id, LogicalPath: "a.jsonl", Size: int64(len(content)),
			Status: StatusOK, Method: MethodFileCopy,
		}},
	}
	data, _ := json.MarshalIndent(man, "", "  ")
	if err := os.WriteFile(filepath.Join(pkg, manifestJSON), append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := ReadManifest(pkg)
	if err != nil {
		t.Fatalf("legacy manifest.json no longer readable: %v", err)
	}
	if len(got.Artifacts) != 1 || got.Artifacts[0].ArtifactID != id {
		t.Fatal("legacy manifest did not round-trip")
	}
	blob, err := NewStore(pkg, got).ReadAll(id, 0)
	if err != nil {
		t.Fatalf("legacy uncompressed blob not readable through the store: %v", err)
	}
	if !bytes.Equal(blob, content) {
		t.Fatal("legacy blob content changed")
	}
}
