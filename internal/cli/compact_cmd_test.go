package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/overlay"
	"github.com/efij/AgentDFIR/v2/internal/simulate"
)

// buildAnalyzedPackage produces a real sealed package with a full analysis
// overlay on top of it, which is what compact is meant to be pointed at.
func buildAnalyzedPackage(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := simulate.ToxicChain(home); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	out := filepath.Join(t.TempDir(), "compact.adfir")
	if code := Main([]string{"run", "--no-serve", "--out", out, "--case-id", "COMPACT"}); code != 3 {
		t.Fatalf("run exit %d, want 3 (findings above INFO)", code)
	}
	for _, d := range []string{"normalized", "detections"} {
		if _, err := os.Stat(filepath.Join(out, d)); err != nil {
			t.Fatalf("no %s/ to compact: %v", d, err)
		}
	}
	return out
}

// compact removes every derived directory and nothing else. The sealed
// zone is what the case rests on; if compact could touch it, the command
// would be unusable on a real investigation.
func TestCompactRemovesOverlayAndKeepsEvidence(t *testing.T) {
	pkg := buildAnalyzedPackage(t)

	before, err := casepkg.Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(before.Problems) != 0 {
		t.Fatalf("package did not verify before compacting: %v", before.Problems)
	}

	if code := Main([]string{"compact", pkg}); code != 0 {
		t.Fatalf("compact exit %d, want 0", code)
	}
	for _, d := range overlayDirs {
		if _, err := os.Stat(filepath.Join(pkg, d)); !os.IsNotExist(err) {
			t.Errorf("%s/ survived compact: %v", d, err)
		}
	}
	for _, f := range []string{"SHA256SUMS", "manifest.jsonl", "case.json", "collection.jsonl", "chain-of-custody.jsonl", "raw"} {
		if _, err := os.Stat(filepath.Join(pkg, f)); err != nil {
			t.Errorf("compact removed sealed %s: %v", f, err)
		}
	}

	after, err := casepkg.Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Problems) != 0 {
		t.Fatalf("package stopped verifying after compacting: %v", after.Problems)
	}
	if after.ArtifactsOK != before.ArtifactsOK || after.FilesChecked != before.FilesChecked {
		t.Fatalf("seal coverage changed: before %d/%d artifacts/files, after %d/%d",
			before.ArtifactsOK, before.FilesChecked, after.ArtifactsOK, after.FilesChecked)
	}
}

// The overlay is regenerable by definition, and an analyst who compacts a
// case and reopens it must get the same answers back.
func TestCompactedPackageReanalyzes(t *testing.T) {
	pkg := buildAnalyzedPackage(t)
	beforeFindings := findingRuleIDs(t, pkg)

	if code := Main([]string{"compact", pkg}); code != 0 {
		t.Fatalf("compact exit %d", code)
	}
	if code := Main([]string{"analyze", pkg}); code != 3 {
		t.Fatalf("analyze after compact exit %d, want 3", code)
	}
	afterFindings := findingRuleIDs(t, pkg)
	if len(beforeFindings) != len(afterFindings) {
		t.Fatalf("rebuilt %d findings, had %d", len(afterFindings), len(beforeFindings))
	}
	for id, n := range beforeFindings {
		if afterFindings[id] != n {
			t.Errorf("rule %s: %d finding(s) before compact, %d after rebuild", id, n, afterFindings[id])
		}
	}
}

// --dry-run must leave the package exactly as it found it; an analyst
// checks what a destructive command would do before running it.
func TestCompactDryRunDeletesNothing(t *testing.T) {
	pkg := buildAnalyzedPackage(t)
	if code := Main([]string{"compact", "--dry-run", pkg}); code != 0 {
		t.Fatalf("compact --dry-run exit %d, want 0", code)
	}
	for _, d := range []string{"normalized", "detections"} {
		if _, err := os.Stat(filepath.Join(pkg, d)); err != nil {
			t.Errorf("--dry-run removed %s/: %v", d, err)
		}
	}
}

// Pointed anywhere that is not a sealed package, compact must refuse
// rather than delete four directories that happen to share those names.
func TestCompactRefusesNonPackage(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "detections"), 0o700); err != nil {
		t.Fatal(err)
	}
	if code := Main([]string{"compact", dir}); code != 1 {
		t.Fatalf("compact exit %d on a non-package, want 1", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "detections")); err != nil {
		t.Fatal("compact deleted from a directory it should have refused")
	}
	if code := Main([]string{"compact"}); code != 2 {
		t.Fatalf("compact with no argument exit %d, want 2", code)
	}
}

func findingRuleIDs(t *testing.T, pkg string) map[string]int {
	t.Helper()
	data, err := overlay.ReadFile(filepath.Join(pkg, "detections", "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var findings []struct {
		RuleID string `json:"rule_id"`
	}
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	for _, f := range findings {
		out[f.RuleID]++
	}
	return out
}
