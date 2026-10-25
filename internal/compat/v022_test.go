package compat

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/integrity"
	"github.com/efij/AgentDFIR/v4/internal/repro"
)

// Spec 0.2.2 adds only optional, overlay-side files. Every package a
// released binary wrote (0.1, 0.2, 0.2.1) must still verify before and
// after a 4.5 analysis writes them, the seal must not move, the new files
// must check, and a second analysis from the sealed zone alone must give
// the same findings fingerprint — by agentdfir and by the independent
// Python verifier.
func TestHistoricalPackagesUnder022(t *testing.T) {
	py, _ := exec.LookPath("python3")
	script, _ := filepath.Abs("../../tools/adfir-verify/adfir_verify.py")
	for _, p := range Packages() {
		p := p
		t.Run(p.Version, func(t *testing.T) {
			dir, err := p.Extract(filepath.Join(t.TempDir(), "pkg"))
			if err != nil {
				t.Fatal(err)
			}
			sums, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
			if _, err := analysis.Run(dir, analysis.Options{}); err != nil {
				t.Fatal(err)
			}
			if after, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS")); !bytes.Equal(sums, after) {
				t.Fatal("analysis moved the seal")
			}
			c, err := integrity.VerifyPackage(dir, "")
			if err != nil || len(c.Package.Problems) > 0 {
				t.Fatalf("no longer verifies after a 4.5 analysis: %v %v", err, c.Package.Problems)
			}
			ov := repro.CheckOverlay(dir)
			if len(ov.Problems) > 0 || len(ov.Checked) < 2 {
				t.Fatalf("analysis files: %+v", ov)
			}
			m, err := repro.Read(repro.Path(dir))
			if err != nil {
				t.Fatal(err)
			}
			again, err := p.Extract(filepath.Join(t.TempDir(), "again"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := analysis.Run(again, analysis.Options{}); err != nil {
				t.Fatal(err)
			}
			m2, _ := repro.Read(repro.Path(again))
			if m2 == nil || m2.FindingsFingerprint != m.FindingsFingerprint {
				t.Fatalf("not reproducible: %s vs %v", m.FindingsFingerprint, m2)
			}
			if py == "" {
				return
			}
			out, err := exec.Command(py, "-I", script, "--json", dir).Output()
			var res struct {
				Verdict  string   `json:"verdict"`
				Analysis string   `json:"analysis_verdict"`
				Problems []string `json:"problems"`
			}
			if jerr := json.Unmarshal(out, &res); jerr != nil {
				t.Fatalf("adfir_verify.py: %v %v\n%s", err, jerr, out)
			}
			if res.Verdict != "VERIFIED" || res.Analysis != "VERIFIED" {
				t.Fatalf("python verifier on the analyzed %s package: %s / %s %v", p.Version, res.Verdict, res.Analysis, res.Problems)
			}
		})
	}
}
