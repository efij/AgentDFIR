package cli

import (
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/integrity"
	"github.com/efij/AgentDFIR/v3/internal/seal"
	"github.com/efij/AgentDFIR/v3/internal/simulate"
)

func simHome(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	if err := simulate.OrphanAgent(home); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
}

// `run --sign` used to sign before sealing, so the signature covered the
// previous round's SHA256SUMS and never verified. It must verify now, and
// so must the machine-key signature every round gets by default.
func TestRunSignaturesVerify(t *testing.T) {
	simHome(t)
	key := filepath.Join(t.TempDir(), "k")
	if err := seal.GenerateKey(key, key+".pub"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		args []string
	}{
		{"explicit key", []string{"--sign", key}},
		{"machine key", nil},
	} {
		out := filepath.Join(t.TempDir(), "c.adfir")
		args := append([]string{"run", "--no-serve", "--no-witness", "--out", out, "--case-id", "SIGN"}, tc.args...)
		if code := Main(args); code != 0 && code != 3 {
			t.Fatalf("%s: run exit %d", tc.name, code)
		}
		res, err := seal.Verify(out, "")
		if err != nil || !res.Present || !res.Valid {
			t.Fatalf("%s: signature after run: %+v %v", tc.name, res, err)
		}
	}
}

// A second run proves the first round before adding its own, and a run
// in which nothing changed reuses the analysis.
func TestSecondRunVerifiesAndReuses(t *testing.T) {
	simHome(t)
	out := filepath.Join(t.TempDir(), "c.adfir")
	for i := 0; i < 2; i++ {
		if code := Main([]string{"run", "--no-serve", "--out", out, "--case-id", "TWICE"}); code != 0 && code != 3 {
			t.Fatalf("run %d exit %d", i+1, code)
		}
	}
	ci, err := casepkg.ReadCaseInfo(out)
	if err != nil {
		t.Fatal(err)
	}
	if len(ci.Rounds) != 2 {
		t.Fatalf("rounds = %d, want 2", len(ci.Rounds))
	}
	if got := ci.Rounds[1].PriorIntegrity; got != integrity.Verified {
		t.Fatalf("round 2 prior integrity %q, want %q", got, integrity.Verified)
	}
	if p := integrity.CheckPrior(out, true); p.Status != integrity.Verified {
		t.Fatalf("after two runs: %+v", p)
	}
}
