package fingerprint

import (
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/fingerprint/compute"
)

// TestCurrent fails when a parser, rule or analysis stage changed without
// regenerating the fingerprints. Shipping that would let every cached
// overlay and stored analysis survive a change that alters their content.
func TestCurrent(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]string{"parse": Parse(), "analysis": Analysis()} {
		got, err := compute.Compute(root, compute.Roots[name])
		if err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Errorf("%s fingerprint is stale: run `go generate ./internal/fingerprint` and commit zz_generated.go", name)
		}
	}
	if Parse() == Analysis() {
		t.Error("parse and analysis fingerprints must differ: analysis is a strict superset")
	}
}
