package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/overlay"
)

func suiteFixture(rel string) string {
	return filepath.Join("..", "parsers", "suite", "testdata", filepath.FromSlash(rel))
}

func copyFile(t *testing.T, src, dst string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.MkdirAll(filepath.Dir(dst), 0o755)
	if err := os.WriteFile(dst, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCollectSuiteExportFile(t *testing.T) {
	out := filepath.Join(t.TempDir(), "p.adfir")
	if code := Main([]string{"collect", "--suite-export", suiteFixture("plaso/timeline.jsonl"), "--out", out, "--no-sign"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if r := rulesByPath(t, out); r["timeline.jsonl"] != "suite.plaso" || len(r) != 1 {
		t.Fatalf("%+v", r)
	}
	if code := Main([]string{"collect", "--suite-export", suiteFixture("README.md"), "--out", filepath.Join(t.TempDir(), "n.adfir"), "--no-sign"}); code != 1 {
		t.Fatalf("unrecognized file: exit %d", code)
	}
}

// An AXIOM Portable Case found inside an --import tree: the CSV and the
// Case.mfdb are sealed, and analysis reports the Case.mfdb UNSUPPORTED.
func TestImportPortableCaseAndAnalyze(t *testing.T) {
	tree := t.TempDir()
	for _, f := range []string{"Case.mfdb", "Web Related.csv", "Attachments/a.txt"} {
		copyFile(t, suiteFixture("portable/"+f), filepath.Join(tree, "Exports", "Portable Case", filepath.FromSlash(f)))
	}
	out := filepath.Join(t.TempDir(), "i.adfir")
	if code := Main([]string{"collect", "--import", tree, "--out", out, "--no-sign"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	r := rulesByPath(t, out)
	if r["Exports/Portable Case/Case.mfdb"] != "suite.axiom.casedb" || r["Exports/Portable Case/Web Related.csv"] != "suite.axiom.csv" || len(r) != 2 {
		t.Fatalf("%+v", r)
	}
	if code := Main([]string{"analyze", out}); code != 0 && code != 3 {
		t.Fatalf("analyze exit %d", code)
	}
	data, err := overlay.ReadFile(filepath.Join(out, "detections", "findings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "AXIOM_CASE_DB_UNSUPPORTED") {
		t.Fatal("no AXIOM_CASE_DB_UNSUPPORTED finding")
	}
	for _, rule := range []string{"SESSION_TAMPERING", "AGENT_IDENTITY_MISMATCH"} {
		if findingRuleIDs(t, out)[rule] > 0 {
			t.Errorf("%s fired on a suite export", rule)
		}
	}
}

func TestCollectSuiteExportUFDRDir(t *testing.T) {
	out := filepath.Join(t.TempDir(), "u.adfir")
	if code := Main([]string{"collect", "--suite-export", suiteFixture("ufdr"), "--out", out, "--no-sign"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if r := rulesByPath(t, out); r["report.xml"] != "ufdr.report" {
		t.Fatalf("%+v", r)
	}
}
