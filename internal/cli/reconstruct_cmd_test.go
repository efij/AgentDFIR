package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/reconstruct"
)

func TestReconstructCommand(t *testing.T) {
	t.Setenv("AGENTDFIR_HOME", t.TempDir())
	t.Setenv("AGENTDFIR_MIN_FREE_GB", "1")
	a := scenarioPackage(t, "toxic-chain")
	b := scenarioPackage(t, "orphan-agent")
	// Not analyzed yet: reconstruct analyzes first.
	code, out := capture(t, "reconstruct", a, b)
	if code != 0 {
		t.Fatalf("reconstruct exit %d:\n%s", code, out)
	}
	for _, want := range []string{"== Summary", "== Timeline", "== Delegation", "== Hand-offs", "== Cross-host links", "== Attack stages", "== Missing evidence"} {
		if !strings.Contains(out, want) {
			t.Errorf("text lacks %q", want)
		}
	}
	if !overlay.Exists(filepath.Join(a, "normalized", reconstruct.OverlayFile)) {
		t.Fatal("overlay not written")
	}
	code, out = capture(t, "reconstruct", a, "--json")
	var rep reconstruct.Report
	if code != 0 || json.Unmarshal([]byte(out), &rep) != nil || rep.Schema != reconstruct.Schema || rep.Summary.Cases != 1 {
		t.Fatalf("--json exit %d:\n%s", code, out)
	}
	if code, out := capture(t, "reconstruct", a, b, "--mermaid"); code != 0 || !strings.HasPrefix(out, "flowchart LR") {
		t.Fatalf("--mermaid exit %d:\n%s", code, out)
	}
	f := filepath.Join(t.TempDir(), "r.dot")
	if code, _ := capture(t, "reconstruct", a, "--dot", "--out", f, "--no-overlay"); code != 0 {
		t.Fatalf("--dot --out exit %d", code)
	}
	if data, err := os.ReadFile(f); err != nil || !strings.HasPrefix(string(data), "digraph reconstruct {") {
		t.Fatalf("dot file: %v %q", err, data)
	}
	if code, _ := capture(t, "reconstruct"); code != 2 {
		t.Errorf("no args exit %d, want 2", code)
	}
	if code, _ := capture(t, "reconstruct", a, "--json", "--dot"); code != 2 {
		t.Errorf("two formats exit %d, want 2", code)
	}
	if code, _ := capture(t, "reconstruct", "no-such-case"); code != 2 {
		t.Errorf("unknown case exit %d, want 2", code)
	}
}
