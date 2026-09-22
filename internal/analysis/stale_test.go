package analysis

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/overlay"
)

// A package analyzed by an older binary must be re-analyzed: the served
// numbers came from the rules of the binary that wrote them, not the one
// that is running.
func TestStaleWhenAnalyzerVersionDiffers(t *testing.T) {
	pkg := buildPkg(t)
	if _, err := Run(pkg, Options{}); err != nil {
		t.Fatal(err)
	}
	if Stale(pkg) {
		t.Fatal("fresh analysis by the running binary reported stale")
	}
	p := filepath.Join(pkg, "detections", "analysis.json")
	if err := overlay.WriteJSON(p, map[string]any{"agentdfir_version": "0.0.1", "findings": 66}); err != nil {
		t.Fatal(err)
	}
	if !Stale(pkg) {
		t.Fatal("analysis.json written by agentdfir 0.0.1 was served as current")
	}
}

// serve/report re-run silently today; when the reason is a version change
// the analyst should see which version's numbers they were about to read.
func TestEnsureSaysWhichVersionItReplaces(t *testing.T) {
	pkg := buildPkg(t)
	if _, err := Run(pkg, Options{}); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(pkg, "detections", "analysis.json")
	if err := overlay.WriteJSON(p, map[string]any{"agentdfir_version": "0.0.1"}); err != nil {
		t.Fatal(err)
	}
	var log strings.Builder
	if _, err := Ensure(pkg, &log); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(log.String(), "0.0.1") {
		t.Fatalf("Ensure re-ran without naming the replaced version; log:\n%s", log.String())
	}
}
