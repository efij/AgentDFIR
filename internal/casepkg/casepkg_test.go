package casepkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func buildPackage(t *testing.T, files map[string]string) string {
	t.Helper()
	src := t.TempDir()
	for name, content := range files {
		p := filepath.Join(src, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := New(pkg, "TEST-001", CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	for name := range files {
		rec := ArtifactRecord{
			SourcePath:  filepath.Join(src, name),
			LogicalPath: name,
			Product:     "claude-code",
			Status:      StatusOK,
		}
		if err := b.IngestFile(filepath.Join(src, name), rec); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return pkg
}

func TestSealAndVerifyRoundTrip(t *testing.T) {
	pkg := buildPackage(t, map[string]string{
		"a.jsonl":      `{"x":1}`,
		"sub/b.json":   `{"y":2}`,
		"dupe1.txt":    "same-content",
		"sub/dupe.txt": "same-content",
	})
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("expected clean verify, got: %v", res.Problems)
	}
	if res.ArtifactsOK != 4 {
		t.Fatalf("artifacts ok = %d, want 4", res.ArtifactsOK)
	}
	// Dedupe: 4 artifacts but only 3 unique blobs.
	entries, _ := os.ReadDir(filepath.Join(pkg, "raw"))
	if len(entries) != 3 {
		t.Fatalf("raw blobs = %d, want 3 (dedupe)", len(entries))
	}
}

func TestVerifyDetectsEvidenceTampering(t *testing.T) {
	pkg := buildPackage(t, map[string]string{"a.jsonl": `{"x":1}`})
	entries, _ := os.ReadDir(filepath.Join(pkg, "raw"))
	if len(entries) != 1 {
		t.Fatal("expected one blob")
	}
	blob := filepath.Join(pkg, "raw", entries[0].Name())
	if err := os.WriteFile(blob, []byte(`{"x":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) == 0 {
		t.Fatal("tampered evidence blob not detected")
	}
}

func TestVerifyDetectsManifestTampering(t *testing.T) {
	pkg := buildPackage(t, map[string]string{"a.jsonl": `{"x":1}`})
	manPath := filepath.Join(pkg, "manifest.json")
	data, _ := os.ReadFile(manPath)
	tampered := strings.Replace(string(data), "a.jsonl", "b.jsonl", 1)
	os.WriteFile(manPath, []byte(tampered), 0o600)
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) == 0 {
		t.Fatal("tampered manifest not detected")
	}
}

func TestVerifyDetectsPlantedEvidence(t *testing.T) {
	pkg := buildPackage(t, map[string]string{"a.jsonl": `{"x":1}`})
	planted := filepath.Join(pkg, "raw", strings.Repeat("f", 64))
	os.WriteFile(planted, []byte("planted"), 0o600)
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) == 0 {
		t.Fatal("planted (uncovered) blob not detected")
	}
}

func TestVerifyDetectsCustodyLogTampering(t *testing.T) {
	pkg := buildPackage(t, map[string]string{"a.jsonl": `{"x":1}`})
	// Rebuilding SHA256SUMS after editing the log would still break the
	// internal hash chain — simulate a sophisticated attacker who fixes
	// the outer hashes but edits a chained record.
	logPath := filepath.Join(pkg, "chain-of-custody.jsonl")
	data, _ := os.ReadFile(logPath)
	tampered := strings.Replace(string(data), "tester", "nobody", 1)
	if tampered == string(data) {
		t.Fatal("test setup: operator name not found in custody log")
	}
	os.WriteFile(logPath, []byte(tampered), 0o600)
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range res.Problems {
		if strings.Contains(p, "chain-of-custody.jsonl") {
			found = true
		}
	}
	if !found {
		t.Fatalf("custody log tampering not detected: %v", res.Problems)
	}
}
