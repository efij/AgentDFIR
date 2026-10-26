package benchmark

import (
	"encoding/json"
	"flag"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/compat"
	"github.com/efij/AgentDFIR/v5/internal/integrity"
	"github.com/efij/AgentDFIR/v5/internal/repro"
)

// Conformance fixtures for the .adfir format live at the repository root,
// testdata/conformance/<name>/{package/,expected.json}: one valid package
// and one invalid-<mutation> per integrity mutation. Any verifier — this
// one, tools/adfir-verify, or a third party's — must reach the expected
// verdict on each. Regenerate with:
//
//	go test ./internal/benchmark -run TestConformance -update-conformance
var updateConformance = flag.Bool("update-conformance", false, "regenerate testdata/conformance")
var updateAnalysisConformance = flag.Bool("update-conformance-analysis", false, "regenerate only the 0.2.2 analysis fixtures in testdata/conformance")

const conformanceDir = "../../testdata/conformance"

type conformanceExpect struct {
	Verdict     string `json:"verdict"` // VERIFIED | FAILED
	Description string `json:"description"`
	Mutation    string `json:"mutation,omitempty"`
	// Pubkey, when set, is pinned (`verify --pubkey`, adfir_verify.py --pubkey).
	Pubkey string `json:"pubkey,omitempty"`
	Spec   string `json:"spec"`
	// Kind is "analysis" for the 0.2.2 fixtures of the optional analysis
	// files (whose verdict covers those files; the sealed zone is valid),
	// empty for the integrity fixtures.
	Kind string `json:"kind,omitempty"`
}

func generateConformance(t *testing.T) {
	t.Helper()
	if err := os.RemoveAll(conformanceDir); err != nil {
		t.Fatal(err)
	}
	work := t.TempDir()
	base := filepath.Join(work, "reference.adfir")
	ref, err := BuildReference(base, filepath.Join(work, "seal.key"), filepath.Join(work, "src"))
	if err != nil {
		t.Fatal(err)
	}
	writeFrom := func(name string, e conformanceExpect, base string, mutate func(string) error) {
		writeFixture(t, name, e, base, mutate)
	}
	write := func(name string, e conformanceExpect, mutate func(string) error) { writeFrom(name, e, base, mutate) }
	writeAnalysisConformance(t, writeFrom)
	write("valid", conformanceExpect{Verdict: "VERIFIED", Pubkey: ref.Signer,
		Description: "two rounds, both signed (ed25519); a plain blob, a gzip blob, a chunked artifact; round 1's seal and signature archived in seals/"}, nil)
	for _, m := range Mutations() {
		m := m
		e := conformanceExpect{Verdict: "FAILED", Mutation: m.ID, Description: m.What}
		if m.Pinned {
			e.Pubkey = ref.Signer
		}
		write("invalid-"+m.ID, e, func(pkg string) error { return m.Apply(pkg, ref) })
	}
}

// writeFixture copies base to testdata/conformance/<name>/package, applies
// mutate, and writes expected.json.
func writeFixture(t *testing.T, name string, e conformanceExpect, base string, mutate func(string) error) {
	t.Helper()
	dir := filepath.Join(conformanceDir, name)
	pkg := filepath.Join(dir, "package")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyTree(base, pkg); err != nil {
		t.Fatal(err)
	}
	if mutate != nil {
		if err := mutate(pkg); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	// Modes are not part of the format; keep the checkout tidy.
	_ = filepath.WalkDir(pkg, func(p string, d os.DirEntry, _ error) error {
		if d.IsDir() {
			return os.Chmod(p, 0o755)
		}
		return os.Chmod(p, 0o644)
	})
	if e.Spec = "0.2"; e.Kind == "analysis" {
		e.Spec = "0.2.2"
	}
	data, _ := json.MarshalIndent(e, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "expected.json"), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// generateAnalysisConformance rewrites only the 0.2.2 analysis fixtures,
// leaving the integrity fixtures byte-for-byte as they are:
//
//	go test ./internal/benchmark -run TestConformance -update-conformance-analysis
func generateAnalysisConformance(t *testing.T) {
	t.Helper()
	entries, _ := os.ReadDir(conformanceDir)
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "analysis-") {
			if err := os.RemoveAll(filepath.Join(conformanceDir, e.Name())); err != nil {
				t.Fatal(err)
			}
		}
	}
	writeAnalysisConformance(t, func(name string, e conformanceExpect, base string, mutate func(string) error) {
		writeFixture(t, name, e, base, mutate)
	})
}

func loadConformance(t *testing.T) map[string]conformanceExpect {
	t.Helper()
	entries, err := os.ReadDir(conformanceDir)
	if err != nil {
		t.Fatalf("conformance fixtures missing (%v); run with -update-conformance", err)
	}
	out := map[string]conformanceExpect{}
	for _, e := range entries {
		if !e.IsDir() {
			continue // README.md
		}
		data, err := os.ReadFile(filepath.Join(conformanceDir, e.Name(), "expected.json"))
		if err != nil {
			t.Fatal(err)
		}
		var x conformanceExpect
		if err := json.Unmarshal(data, &x); err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		out[e.Name()] = x
	}
	if want := len(Mutations()) + 1 + len(analysisMutations()) + 2; len(out) != want {
		t.Fatalf("%d conformance fixtures, want %d (valid + one per mutation, and the analysis set); regenerate with -update-conformance", len(out), want)
	}
	return out
}

func sortedNames(m map[string]conformanceExpect) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestConformanceGoVerify: agentdfir verify's verdict on every fixture.
func TestConformanceGoVerify(t *testing.T) {
	if *updateConformance {
		generateConformance(t)
	} else if *updateAnalysisConformance {
		generateAnalysisConformance(t)
	}
	fx := loadConformance(t)
	for _, name := range sortedNames(fx) {
		want := fx[name]
		t.Run(name, func(t *testing.T) {
			// Verification only reads; a copy keeps the fixture pristine
			// should that ever change.
			pkg := filepath.Join(t.TempDir(), "package")
			if err := copyTree(filepath.Join(conformanceDir, name, "package"), pkg); err != nil {
				t.Fatal(err)
			}
			c, err := integrity.VerifyPackage(pkg, want.Pubkey)
			// The analysis files are checked too (0.2.2); a fixture of
			// either kind passes only when both checks agree with it.
			ov := repro.CheckOverlay(pkg)
			got := "VERIFIED"
			if err != nil || len(c.Package.Problems) > 0 || len(ov.Problems) > 0 {
				got = "FAILED"
			}
			if want.Kind == "analysis" && (err != nil || len(c.Package.Problems) > 0) {
				t.Fatalf("an analysis fixture's sealed zone must verify: %v %v", err, c.Package.Problems)
			}
			if want.Kind == "analysis" && want.Verdict == "VERIFIED" && len(ov.Checked) < 3 {
				t.Fatalf("analysis fixture checked only %v", ov.Checked)
			}
			if got != want.Verdict {
				problems := ov.Problems
				if c != nil {
					problems = append(problems, c.Package.Problems...)
				}
				t.Fatalf("verdict %s, want %s (%s): %v %v", got, want.Verdict, want.Description, err, problems)
			}
		})
	}
}

// TestConformancePythonVerifier: the independent stdlib-only verifier,
// written from the specification, must reach the same verdicts — on the
// conformance fixtures and on the packages released binaries wrote.
// Skipped when python3 is not on PATH.
func TestConformancePythonVerifier(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH")
	}
	script, err := filepath.Abs("../../tools/adfir-verify/adfir_verify.py")
	if err != nil {
		t.Fatal(err)
	}
	run := func(t *testing.T, pkg, pubkey string) (string, []string) {
		t.Helper()
		args := []string{"-I", script, "--json"}
		if pubkey != "" {
			args = append(args, "--pubkey", pubkey)
		}
		out, err := exec.Command(py, append(args, pkg)...).Output()
		if err != nil {
			if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 1 {
				t.Fatalf("adfir_verify.py: %v\n%s", err, out)
			}
		}
		var res struct {
			Verdict          string   `json:"verdict"`
			IntegrityVerdict string   `json:"integrity_verdict"`
			Problems         []string `json:"problems"`
		}
		if err := json.Unmarshal(out, &res); err != nil {
			t.Fatalf("adfir_verify.py output: %v\n%s", err, out)
		}
		if res.IntegrityVerdict != "" && res.IntegrityVerdict != "VERIFIED" && strings.Contains(pkg, "analysis-") {
			t.Fatalf("an analysis fixture's sealed zone must verify: %v", res.Problems)
		}
		return res.Verdict, res.Problems
	}
	fx := loadConformance(t)
	for _, name := range sortedNames(fx) {
		want := fx[name]
		t.Run(name, func(t *testing.T) {
			got, problems := run(t, filepath.Join(conformanceDir, name, "package"), want.Pubkey)
			if got != want.Verdict {
				t.Fatalf("python verdict %s, want %s (%s): %v", got, want.Verdict, want.Description, problems)
			}
		})
	}
	for _, p := range compat.Packages() {
		p := p
		t.Run("historical-"+p.Version, func(t *testing.T) {
			dir, err := p.Extract(filepath.Join(t.TempDir(), "pkg"))
			if err != nil {
				t.Fatal(err)
			}
			if got, problems := run(t, dir, ""); got != "VERIFIED" {
				t.Fatalf("python verdict on the %s package: %s %v", p.Version, got, problems)
			}
		})
	}
}
