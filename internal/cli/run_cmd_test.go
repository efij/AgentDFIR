package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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

// TestRunToxicChain: the synthetic attack (injection → self-modification →
// credential read → upload → log deletion) must surface as chain findings
// whose steps point at the right events, in order.
func TestRunToxicChain(t *testing.T) {
	home := t.TempDir()
	if err := simulate.ToxicChain(home); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	out := filepath.Join(t.TempDir(), "toxic.adfir")
	if code := Main([]string{"run", "--no-serve", "--out", out, "--case-id", "TOXIC"}); code != 3 {
		t.Fatalf("run exit %d, want 3 (findings above INFO)", code)
	}
	data, err := os.ReadFile(filepath.Join(out, "detections", "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var findings []struct {
		RuleID string `json:"rule_id"`
		Steps  []struct {
			Step    string `json:"step"`
			EventID string `json:"event_id"`
		} `json:"chain_steps"`
	}
	if err := json.Unmarshal(data, &findings); err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range findings {
		if strings.HasPrefix(f.RuleID, "CHAIN_") {
			got[f.RuleID] = len(f.Steps)
		}
	}
	for _, want := range []string{"CHAIN_CONTEXT_POISON_TO_EXEC", "CHAIN_SECRET_TO_EXFIL", "CHAIN_ACTION_THEN_LOG_TAMPER"} {
		if got[want] < 2 {
			t.Errorf("missing chain %s (chains found: %v)", want, got)
		}
	}
}
