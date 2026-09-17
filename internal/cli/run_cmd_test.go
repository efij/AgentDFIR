package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/internal/simulate"
)

// TestRunNoServe drives the one-shot workflow against a simulated home:
// detect finds the synthetic Claude Code profile, collect seals it, analyze
// produces the orphan-agent findings, --no-serve stops before the server.
func TestRunNoServe(t *testing.T) {
	home := t.TempDir()
	if err := simulate.OrphanAgent(home); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	out := filepath.Join(t.TempDir(), "case.adfir")

	code := Main([]string{"run", "--no-serve", "--out", out, "--case-id", "RUN-TEST"})
	if code != 0 && code != 3 { // 3 = findings above INFO, expected for the orphan-agent scenario
		t.Fatalf("run exit %d, want 0 or 3", code)
	}
	for _, p := range []string{"SHA256SUMS", filepath.Join("detections", "findings.json"), filepath.Join("detections", "analysis.json")} {
		if _, err := os.Stat(filepath.Join(out, p)); err != nil {
			t.Errorf("missing %s after run: %v", p, err)
		}
	}
}

func TestRunRejectsPositional(t *testing.T) {
	if code := Main([]string{"run", "some.adfir"}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}
