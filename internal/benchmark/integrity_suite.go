package benchmark

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/compat"
)

// EvidenceIntegrity is the evidence-integrity suite: the mutation suite
// and the historical packages (both measured in their own sections), plus
// the independent Python verifier (tools/adfir-verify, written from the
// specification, not from this code) over packages this run built and
// over the historical packages.
type EvidenceIntegrity struct {
	Label     string        `json:"label"`
	Mutations string        `json:"mutations"`
	Compat    string        `json:"historical_packages"`
	Verifier  VerifierCheck `json:"python_verifier"`
	Checks    []Check       `json:"checks"`
}

// VerifierCheck is the Python verifier's part.
type VerifierCheck struct {
	Status   string           `json:"status"` // PASS | FAIL | SKIP
	Reason   string           `json:"reason,omitempty"`
	Python   string           `json:"python,omitempty"`
	Script   string           `json:"script,omitempty"` // the verifier that ran, resolved path
	Packages []VerifierResult `json:"packages,omitempty"`
}

// VerifierResult is one package checked by the Python verifier.
type VerifierResult struct {
	Package  string   `json:"package"`
	Verdict  string   `json:"verdict"`
	Problems []string `json:"problems,omitempty"`
}

func runEvidenceIntegrity(r *Report, o Options, work string) {
	ei := &EvidenceIntegrity{Label: SuiteLabel, Checks: []Check{}}
	r.IntegritySet = ei
	in, cp := r.Integrity, r.Compat
	ei.Mutations = fmt.Sprintf("%d/%d mutations detected by agentdfir verify", in.Detected, in.Total)
	ei.Compat = fmt.Sprintf("%d/%d historical packages verify and analyze", cp.OK, cp.Total)
	c := Check{Name: "mutation suite", Want: fmt.Sprintf("%d/%d detected", in.Total, in.Total), Got: fmt.Sprintf("%d/%d detected", in.Detected, in.Total)}
	r.record("evidence integrity", &c, in.Total > 0 && in.Detected == in.Total)
	ei.Checks = append(ei.Checks, c)
	c = Check{Name: "historical packages", Want: fmt.Sprintf("%d/%d verify and analyze", cp.Total, cp.Total), Got: fmt.Sprintf("%d/%d", cp.OK, cp.Total)}
	r.record("evidence integrity", &c, cp.Total > 0 && cp.OK == cp.Total)
	ei.Checks = append(ei.Checks, c)

	v := &ei.Verifier
	// The verifier is a script from the checkout, so it runs only when
	// the operator named the checkout (--repo) or opted in
	// (--python-verifier): a checkout found by walking up from the
	// working directory may be anyone's directory.
	root := ""
	switch {
	case o.RepoRoot != "":
		if abs, err := filepath.Abs(o.RepoRoot); err == nil && isRepoRoot(abs) {
			root = abs
		}
	case o.PythonVerifier:
		root = repoFinder("")
	}
	py, err := exec.LookPath("python3")
	switch {
	case o.RepoRoot == "" && !o.PythonVerifier:
		v.Status, v.Reason = SuiteSkip, "the Python verifier is a script in the source checkout and runs only when asked: pass --repo <checkout> or --python-verifier"
	case root == "":
		v.Status, v.Reason = SuiteSkip, "tools/adfir-verify/adfir_verify.py not found: --repo does not name a checkout of this module, or no checkout was found from the working directory"
	case err != nil:
		v.Status, v.Reason = SuiteSkip, "python3 is not on PATH"
	default:
		v.Status, v.Python = SuitePass, "python3"
		if out, err := exec.Command(py, "--version").Output(); err == nil {
			v.Python = strings.TrimSpace(string(out))
		}
		script := filepath.Join(root, "tools", "adfir-verify", "adfir_verify.py")
		v.Script = script
		logf(o, "evidence integrity: running %s", script)
		var pkgs, names []string
		if ref := filepath.Join(work, "..", "..", "integrity", "reference.adfir"); dirExists(ref) {
			pkgs, names = append(pkgs, ref), append(names, "integrity reference package (signed, 2 rounds)")
		}
		for _, p := range r.newPackages {
			pkgs, names = append(pkgs, p), append(names, describePkg(p, work))
		}
		for i, p := range compat.Packages() {
			dir, err := p.Extract(filepath.Join(work, fmt.Sprintf("compat%d", i)))
			if err != nil {
				r.fail("evidence integrity: extract %s package: %v", p.Version, err)
				continue
			}
			pkgs, names = append(pkgs, dir), append(names, "historical package written by "+p.Version)
		}
		for i, p := range pkgs {
			res := pyVerify(py, script, p)
			res.Package = names[i]
			v.Packages = append(v.Packages, res)
			c := Check{Name: "python verifier: " + res.Package, Want: "VERIFIED", Got: res.Verdict}
			if len(res.Problems) > 0 {
				c.Got += " (" + truncate(res.Problems[0], 120) + ")"
			}
			ok := res.Verdict == "VERIFIED"
			if !ok {
				v.Status = SuiteFail
			}
			r.record("evidence integrity", &c, ok)
			ei.Checks = append(ei.Checks, c)
		}
		if len(pkgs) == 0 {
			v.Status, v.Reason = SuiteFail, "no package to verify"
		}
	}
	sum := ei.Mutations + "; " + ei.Compat + "; Python verifier: "
	switch v.Status {
	case SuiteSkip:
		sum += "SKIP (" + v.Reason + ")"
	default:
		ok := 0
		for _, p := range v.Packages {
			if p.Verdict == "VERIFIED" {
				ok++
			}
		}
		sum += fmt.Sprintf("%d/%d packages VERIFIED", ok, len(v.Packages))
	}
	s := verdict("evidence integrity", sum, ei.Checks, v.Status == SuiteFail)
	r.Suites = append(r.Suites, s)
}

func logf(o Options, format string, a ...any) {
	if o.Log != nil {
		fmt.Fprintf(o.Log, format+"\n", a...)
	}
}

// pyVerify runs the Python verifier on one package: exit 0 verified, 1
// problems; anything else is reported as the verdict.
func pyVerify(py, script, pkg string) VerifierResult {
	cmd := exec.Command(py, "-I", script, "--json", pkg)
	done := make(chan struct{})
	var out []byte
	var err error
	go func() { out, err = cmd.Output(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Minute):
		_ = cmd.Process.Kill()
		<-done
		return VerifierResult{Verdict: "TIMEOUT"}
	}
	var ee *exec.ExitError
	if err != nil && (!errors.As(err, &ee) || ee.ExitCode() != 1) {
		return VerifierResult{Verdict: "ERROR", Problems: []string{err.Error()}}
	}
	var res struct {
		Verdict  string   `json:"verdict"`
		Problems []string `json:"problems"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return VerifierResult{Verdict: "ERROR", Problems: []string{"unreadable output: " + err.Error()}}
	}
	return VerifierResult{Verdict: res.Verdict, Problems: res.Problems}
}

// describePkg names a package without the scratch path.
func describePkg(p, work string) string {
	base := filepath.Dir(filepath.Dir(work))
	if rel, err := filepath.Rel(base, p); err == nil && !strings.HasPrefix(rel, "..") {
		return filepath.ToSlash(rel)
	}
	return filepath.Base(p)
}

func dirExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && fi.IsDir()
}

// runSuites runs the cross-platform suites after the sections they build
// on (detection, integrity, compatibility).
func runSuites(r *Report, o Options, work string, prov *provenanceChecker) {
	logf := func(format string, a ...any) {
		if o.Log != nil {
			fmt.Fprintf(o.Log, format+"\n", a...)
		}
	}
	logf("acquisition: disk-image fixtures")
	runAcquisition(r, o, filepath.Join(work, "suites", "acquisition"))
	logf("per-OS corroboration: Windows, macOS, Linux telemetry")
	runPlatforms(r, o, filepath.Join(work, "suites", "platforms"), prov)
	logf("forensic interop: UFDR, AXIOM, Plaso, Autopsy")
	runInterop(r, o, filepath.Join(work, "suites", "interop"))
	detectionSuite(r, o)
	logf("evidence integrity: mutations, historical packages, Python verifier")
	runEvidenceIntegrity(r, o, filepath.Join(work, "suites", "integrity"))
}

// detectionSuite turns the detection section (measured earlier) into a
// suite verdict with a per-platform breakdown.
func detectionSuite(r *Report, o Options) {
	d := r.Detection
	var checks []Check
	failed := false
	for _, f := range r.Failures {
		if strings.HasPrefix(f, "detection:") {
			failed = true
			break
		}
	}
	var parts []string
	seen := map[string]bool{}
	for _, p := range d.Platforms {
		seen[p.Platform] = true
		parts = append(parts, fmt.Sprintf("%s: %d attack / %d benign, P %s R %s, %d rules", p.Platform, p.AttackCases, p.BenignCases, pct(p.Precision), pct(p.Recall), len(p.Rules)))
	}
	if !o.Quick {
		for _, os := range []string{"windows", "macos", "linux"} {
			c := Check{Name: os + " has labeled attack fixtures", Want: "at least one", Got: "none"}
			for _, p := range d.Platforms {
				if p.Platform == os {
					c.Got = fmt.Sprintf("%d attack fixtures, rules %s", p.AttackCases, strings.Join(p.Rules, ", "))
				}
			}
			ok := seen[os] && c.Got != "none" && !strings.HasPrefix(c.Got, "0 attack")
			r.record("detection", &c, ok)
			checks = append(checks, c)
		}
	}
	sum := fmt.Sprintf("precision %s, recall %s (%d TP, %d FP, %d FN); %s", pct(d.Precision), pct(d.Recall), d.TP, d.FP, d.FN, strings.Join(parts, "; "))
	r.Suites = append(r.Suites, verdict("detection quality", sum, checks, failed))
}
