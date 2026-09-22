// Package compat holds the backward-compatibility guarantee for the
// .adfir evidence format, enforced against a package that was actually
// produced by a released binary rather than by a fixture this repository
// wrote for itself.
//
// testdata/v1.0.0-package was collected by agentdfir v1.0.0 (manifest.json
// as a JSON array, uncompressed blobs at raw/<sha256>, no rounds, no
// chunks). Evidence outlives the tool that collected it: a case sealed
// last year has to open, verify and analyze with the binary an analyst has
// today, or the format's integrity promise is worth nothing.
package compat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/analysis"
	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/normalize"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

const corpus = "testdata/v1.0.0-package"

// copyCorpus gives each test a writable copy: analysis writes an overlay,
// and a round-2 test writes to the sealed zone.
func copyCorpus(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "case.adfir")
	if err := os.CopyFS(dst, os.DirFS(corpus)); err != nil {
		t.Fatal(err)
	}
	// os.CopyFS preserves read-only bits; the copy must be writable.
	if err := filepath.WalkDir(dst, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chmod(p, 0o700)
	}); err != nil {
		t.Fatal(err)
	}
	return dst
}

// TestV1PackageStillVerifies is the guarantee itself.
func TestV1PackageStillVerifies(t *testing.T) {
	res, err := casepkg.Verify(corpus)
	if err != nil {
		t.Fatalf("v1.0.0 package no longer verifies: %v", err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("v1.0.0 package reports integrity problems: %v", res.Problems)
	}
	if res.ArtifactsOK == 0 {
		t.Fatal("no artifacts read from the v1.0.0 package")
	}
	quick, err := casepkg.VerifyQuick(corpus)
	if err != nil || len(quick.Problems) != 0 {
		t.Fatalf("quick verification of a v1.0.0 package: %v %v", err, quick.Problems)
	}
}

// TestV1PackageBlobsReadThroughStore: every consumer now goes through the
// store, so the store must handle the old uncompressed, unchunked layout.
func TestV1PackageBlobsReadThroughStore(t *testing.T) {
	man, err := casepkg.ReadManifest(corpus)
	if err != nil {
		t.Fatalf("legacy manifest.json unreadable: %v", err)
	}
	store := casepkg.NewStore(corpus, man)
	read := 0
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK {
			continue
		}
		data, err := store.ReadAll(a.ArtifactID, 0)
		if err != nil {
			t.Fatalf("%s: %v", a.LogicalPath, err)
		}
		if int64(len(data)) != a.Size {
			t.Fatalf("%s: read %d bytes, manifest says %d", a.LogicalPath, len(data), a.Size)
		}
		read++
	}
	if read == 0 {
		t.Fatal("no blobs read")
	}
}

// TestV1PackageStillNormalizesAndAnalyzes: opening an old case must still
// produce events and findings, not just pass an integrity check.
func TestV1PackageStillNormalizesAndAnalyzes(t *testing.T) {
	pkg := copyCorpus(t)
	var events []schema.Event
	sr, err := normalize.ParseStream(pkg, func(ev schema.Event) error {
		events = append(events, ev)
		return nil
	})
	if err != nil {
		t.Fatalf("normalizing a v1.0.0 package: %v", err)
	}
	if len(events) == 0 {
		t.Fatal("no events parsed from a v1.0.0 package")
	}
	if len(sr.Entities) == 0 {
		t.Fatal("no entities derived from a v1.0.0 package")
	}
	if _, err := analysis.Run(pkg, analysis.Options{}); err != nil {
		t.Fatalf("analyzing a v1.0.0 package: %v", err)
	}
}

// TestV1PackageAcceptsANewRound: an old case must be extensible, and the
// migration to the append-only manifest must not lose a single record.
func TestV1PackageAcceptsANewRound(t *testing.T) {
	pkg := copyCorpus(t)
	before, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(t.TempDir(), "new.jsonl")
	if err := os.WriteFile(src, []byte(`{"type":"user","message":"added later"}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, err := casepkg.Reopen(pkg, casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatalf("cannot add a round to a v1.0.0 package: %v", err)
	}
	if b.Round() != 2 {
		t.Fatalf("round = %d, want 2 (a pre-rounds package is round 1 by definition)", b.Round())
	}
	if err := b.IngestFile(src, casepkg.ArtifactRecord{
		SourcePath: src, LogicalPath: "new.jsonl", Product: "claude-code",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}

	after, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Artifacts) != len(before.Artifacts)+1 {
		t.Fatalf("records = %d after migration + one round, want %d", len(after.Artifacts), len(before.Artifacts)+1)
	}
	for i, a := range before.Artifacts {
		if after.Artifacts[i].ArtifactID != a.ArtifactID || after.Artifacts[i].LogicalPath != a.LogicalPath {
			t.Fatalf("record %d changed while migrating manifest.json to manifest.jsonl", i)
		}
	}
	res, err := casepkg.Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("v1.0.0 package does not verify after a new round: %v", res.Problems)
	}
	// The seal the v1.0.0 binary wrote must still be on record.
	if _, err := os.Stat(filepath.Join(pkg, "seals", "SHA256SUMS.1")); err != nil {
		t.Fatalf("the seal v1.0.0 closed this package with was not archived: %v", err)
	}
}
