package benchmark

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/corpus"
)

func newReport() *Report { return &Report{Label: Label, Failures: []string{}, Warnings: []string{}} }

func suiteNamed(t *testing.T, r *Report, name string) Suite {
	t.Helper()
	for _, s := range r.Suites {
		if s.Name == name {
			if s.Label != SuiteLabel {
				t.Errorf("%s: label %q", name, s.Label)
			}
			return s
		}
	}
	t.Fatalf("suite %q not reported: %+v", name, r.Suites)
	return Suite{}
}

// TestAcquisitionSuite opens every disk-image fixture in the repository.
func TestAcquisitionSuite(t *testing.T) {
	r := newReport()
	runAcquisition(r, Options{}, t.TempDir())
	s := suiteNamed(t, r, "acquisition")
	if s.Status != SuitePass {
		t.Fatalf("acquisition %s:\n  %s", s.Status, strings.Join(r.Failures, "\n  "))
	}
	a := r.Acquisition
	if a.Totals.Fixtures != len(acqFixtures()) || a.Totals.ReadOnlyProof != a.Totals.Fixtures {
		t.Fatalf("totals %+v", a.Totals)
	}
	if a.Totals.Expected == 0 || a.Totals.HashMatch == 0 || a.Totals.Unsupported == 0 {
		t.Fatalf("nothing compared: %+v", a.Totals)
	}
	for _, f := range a.Fixtures {
		if !f.SourceUnchanged || len(f.SourceSHA256) == 0 {
			t.Errorf("%s: no read-only proof", f.Name)
		}
	}
	// Every gzipped image fixture in the tree is covered: a new fixture
	// must be added to the table (with its manifest or "not compared").
	root := findRepoRoot("")
	listed := map[string]bool{}
	for _, f := range acqFixtures() {
		for _, p := range append(f.files, f.tar) {
			listed[p] = true
		}
	}
	_ = filepath.WalkDir(filepath.Join(root, "internal", "diskimage"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, ".gz") || !strings.Contains(p, "testdata") {
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if !listed[filepath.ToSlash(rel)] {
			t.Errorf("disk-image fixture %s is not in the acquisition suite", rel)
		}
		return nil
	})
}

// TestAcquisitionDetectsChangedSource: the read-only proof and the
// manifest comparison must be able to fail.
func TestAcquisitionDetectsMismatch(t *testing.T) {
	root := findRepoRoot("")
	fx := acqFixtures()[0]
	fx.unchecked = false
	fx.manifest = func(string) ([]manifestEntry, string, error) {
		return []manifestEntry{{Path: "Users/alice/notes.txt", SHA256: strings.Repeat("0", 64)}}, "planted", nil
	}
	res := acquire(root, t.TempDir(), fx)
	if res.OK || res.HashMatch != 0 || !strings.Contains(strings.Join(res.Problems, ";"), "sha256") {
		t.Fatalf("a wrong manifest hash passed: %+v", res)
	}
	fx = acqFixtures()[0]
	fx.unsup = nil
	fx.minUnsup = 1
	if res := acquire(root, t.TempDir(), fx); res.OK {
		t.Fatal("a missing UNSUPPORTED state passed")
	}
}

func TestGunzipSparseRoundTrip(t *testing.T) {
	dir := t.TempDir()
	root := findRepoRoot("")
	out := filepath.Join(dir, "x.img")
	if err := gunzipSparse(filepath.Join(root, "internal/diskimage/fat/testdata/fat12.img.gz"), out); err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(out)
	if err != nil || fi.Size() == 0 {
		t.Fatalf("%v %v", fi, err)
	}
	if err := untarGz(filepath.Join(root, "internal/diskimage/fat/testdata/fat12.img.gz"), dir); err == nil {
		t.Fatal("a non-tar gzip extracted")
	}
}

// TestPlatformsSuite runs the per-OS corroboration scenarios.
func TestPlatformsSuite(t *testing.T) {
	r := newReport()
	prov := newProvenanceChecker()
	runPlatforms(r, Options{}, t.TempDir(), prov)
	s := suiteNamed(t, r, "per-OS corroboration")
	if s.Status != SuitePass {
		t.Fatalf("per-OS %s:\n  %s", s.Status, strings.Join(r.Failures, "\n  "))
	}
	seen := map[string]int{}
	for _, sc := range r.Platforms.Scenarios {
		seen[sc.Platform]++
		if sc.WantCorr >= 0 && sc.Corroborated != sc.WantCorr {
			t.Errorf("%s/%s: corroborated %d, want %d", sc.Platform, sc.Name, sc.Corroborated, sc.WantCorr)
		}
	}
	for _, p := range []string{"windows", "macos", "linux"} {
		if seen[p] < 4 {
			t.Errorf("%s: %d scenarios", p, seen[p])
		}
	}
	corp := map[string]int{}
	for _, c := range r.Platforms.Corpus {
		corp[c.Platform]++
	}
	if corp["windows"] == 0 || corp["macos"] == 0 || corp["linux"] == 0 {
		t.Errorf("corpus cases per platform: %v", corp)
	}
	if prov.result().Dangling() != 0 {
		t.Errorf("provenance: %+v", prov.result())
	}
}

// TestCheckStatuses: an expected failure that fails is XFAIL and does
// not fail the run; one that passes warns; a plain failure fails.
func TestCheckStatuses(t *testing.T) {
	r := newReport()
	c1 := Check{Name: "a", ExpectedFail: "known"}
	r.record("s", &c1, false)
	c2 := Check{Name: "b", ExpectedFail: "known"}
	r.record("s", &c2, true)
	c3 := Check{Name: "c"}
	r.record("s", &c3, false)
	if c1.Status != CheckXFail || c2.Status != CheckXPass || c3.Status != SuiteFail {
		t.Fatalf("%s %s %s", c1.Status, c2.Status, c3.Status)
	}
	if len(r.Failures) != 1 || len(r.Warnings) != 1 {
		t.Fatalf("failures %v warnings %v", r.Failures, r.Warnings)
	}
	v := verdict("s", "x", []Check{c1}, false)
	if v.Status != SuitePass || len(v.ExpectedFailures) != 1 {
		t.Fatalf("%+v", v)
	}
	if verdict("s", "x", []Check{c1, c3}, false).Status != SuiteFail {
		t.Fatal("a failed check did not fail the suite")
	}
}

func TestInteropSuite(t *testing.T) {
	r := newReport()
	runInterop(r, Options{}, t.TempDir())
	s := suiteNamed(t, r, "forensic interop")
	if s.Status != SuitePass {
		t.Fatalf("interop %s:\n  %s", s.Status, strings.Join(r.Failures, "\n  "))
	}
	var caseDB bool
	for _, f := range r.Interop.Fixtures {
		caseDB = caseDB || f.CaseDB
		if f.Identical != f.Files || f.Files == 0 {
			t.Errorf("%s: %d/%d sealed identical", f.Name, f.Identical, f.Files)
		}
	}
	if !caseDB {
		t.Error("no Case.mfdb UNSUPPORTED finding")
	}
}

// TestSuitesSkipWithoutCheckout: an installed binary without the
// repository reports the fixture-based suites as SKIP with the reason,
// and never fails for it.
func TestSuitesSkipWithoutCheckout(t *testing.T) {
	if isRepoRoot(t.TempDir()) {
		t.Fatal("an empty directory is a checkout")
	}
	defer func(f func(string) string) { repoFinder = f }(repoFinder)
	repoFinder = func(string) string { return "" }
	r := newReport()
	r.Integrity, r.Compat = Integrity{Detected: 1, Total: 1}, Compat{OK: 1, Total: 1}
	runAcquisition(r, Options{}, t.TempDir())
	runInterop(r, Options{}, t.TempDir())
	runEvidenceIntegrity(r, Options{}, t.TempDir())
	if len(r.Failures) != 0 {
		t.Fatalf("skips failed the run: %v", r.Failures)
	}
	for _, name := range []string{"acquisition", "forensic interop"} {
		if s := suiteNamed(t, r, name); s.Status != SuiteSkip || !strings.Contains(s.Reason, "--repo") {
			t.Errorf("%s: %+v", name, s)
		}
	}
	if s := suiteNamed(t, r, "evidence integrity"); s.Status != SuitePass || r.IntegritySet.Verifier.Status != SuiteSkip {
		t.Errorf("evidence integrity: %+v, verifier %+v", s, r.IntegritySet.Verifier)
	}
}

func TestCasePlatform(t *testing.T) {
	for want, c := range map[string]corpus.Case{
		"windows": {Name: "x", Endpoint: []string{"windows.evtx"}},
		"macos":   {Name: "x", Endpoint: []string{"eslogger.jsonl"}},
		"linux":   {Name: "package-postinstall", Endpoint: []string{"tetragon.jsonl"}},
		"any":     {Name: "secret-then-exfil"},
	} {
		if got := casePlatform(c); got != want {
			t.Errorf("%+v: %s, want %s", c, got, want)
		}
	}
}

// TestSuiteReportRendering: text and JSON both carry each suite's label
// and verdict.
func TestSuiteReportRendering(t *testing.T) {
	r := newReport()
	r.Suites = []Suite{{Name: "acquisition", Label: SuiteLabel, Status: SuitePass, Summary: "1 fixture"},
		{Name: "forensic interop", Label: SuiteLabel, Status: SuiteSkip, Reason: noCheckout}}
	r.Platforms = &Platforms{Checks: []Check{{Name: "w", Want: "x", Got: "y", Status: CheckXFail, ExpectedFail: perKindFix}}}
	var md, js bytes.Buffer
	if err := r.WriteMarkdown(&md); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{SuiteLabel, "| acquisition | PASS |", "SKIP", "fixed by per-kind coverage"} {
		if !strings.Contains(md.String(), want) {
			t.Errorf("markdown lacks %q", want)
		}
	}
	if err := r.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var back struct {
		Suites []Suite `json:"suites"`
	}
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || len(back.Suites) != 2 || back.Suites[1].Status != SuiteSkip {
		t.Fatalf("json suites: %v %+v", err, back.Suites)
	}
}

// TestUntarRefusesUnsafeEntries: only regular files and directories with
// local, slash-separated names are extracted.
func TestUntarRefusesUnsafeEntries(t *testing.T) {
	mk := func(h *tar.Header, body string) string {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(zw)
		h.Size = int64(len(body))
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body)[:h.Size])
		tw.Close()
		zw.Close()
		p := filepath.Join(t.TempDir(), "x.tar.gz")
		os.WriteFile(p, buf.Bytes(), 0o600)
		return p
	}
	bad := []*tar.Header{
		{Name: "../escape", Typeflag: tar.TypeReg, Mode: 0o600},
		{Name: `a\..\..\escape`, Typeflag: tar.TypeReg, Mode: 0o600},
		{Name: "C:escape", Typeflag: tar.TypeReg, Mode: 0o600},
		{Name: "/abs", Typeflag: tar.TypeReg, Mode: 0o600},
		{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "hard", Typeflag: tar.TypeLink, Linkname: "../x"},
	}
	for _, h := range bad {
		dir := t.TempDir()
		if err := untarGz(mk(h, "x"), dir); err == nil {
			t.Errorf("%q (type %c) extracted", h.Name, h.Typeflag)
		}
	}
	dir := t.TempDir()
	if err := untarGz(mk(&tar.Header{Name: "b.sparsebundle/bands/0", Typeflag: tar.TypeReg, Mode: 0o600}, "data"), dir); err != nil {
		t.Fatal(err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "b.sparsebundle", "bands", "0")); err != nil || string(b) != "data" {
		t.Fatalf("%q %v", b, err)
	}
}

// TestPythonVerifierNeedsOptIn: the verifier script is executed only from
// a checkout the operator named (--repo) or opted into (--python-verifier).
func TestPythonVerifierNeedsOptIn(t *testing.T) {
	run := func(o Options) *EvidenceIntegrity {
		r := newReport()
		r.Integrity, r.Compat = Integrity{Detected: 1, Total: 1}, Compat{OK: 1, Total: 1}
		runEvidenceIntegrity(r, o, filepath.Join(t.TempDir(), "suites", "integrity"))
		return r.IntegritySet
	}
	if v := run(Options{}).Verifier; v.Status != SuiteSkip || !strings.Contains(v.Reason, "--python-verifier") || v.Script != "" {
		t.Fatalf("ran without opt-in: %+v", v)
	}
	// A directory that merely looks for a script must not be trusted.
	fake := t.TempDir()
	os.MkdirAll(filepath.Join(fake, "tools", "adfir-verify"), 0o755)
	os.WriteFile(filepath.Join(fake, "tools", "adfir-verify", "adfir_verify.py"), []byte("raise SystemExit(0)\n"), 0o644)
	if v := run(Options{RepoRoot: fake}).Verifier; v.Status != SuiteSkip || v.Script != "" {
		t.Fatalf("ran from a directory that is not a checkout: %+v", v)
	}
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not on PATH")
	}
	root := findRepoRoot("")
	v := run(Options{RepoRoot: root}).Verifier
	if v.Status != SuitePass || v.Script != filepath.Join(root, "tools", "adfir-verify", "adfir_verify.py") || len(v.Packages) == 0 {
		t.Fatalf("--repo: %+v", v)
	}
}
