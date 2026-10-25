package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/custody"
	"github.com/efij/AgentDFIR/v4/internal/report"
	"github.com/efij/AgentDFIR/v4/internal/simulate"
)

func runCase(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	if err := simulate.OrphanAgent(home); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	out := filepath.Join(t.TempDir(), "case.adfir")
	if code := Main([]string{"run", "--no-serve", "--out", out, "--case-id", "EDISC"}); code != 0 && code != 3 {
		t.Fatalf("run exit %d", code)
	}
	return out
}

func TestReportRSMFAndProductionCLI(t *testing.T) {
	pkg := runCase(t)

	rdir := filepath.Join(t.TempDir(), "rsmf")
	if code := Main([]string{"report", pkg, "--format", "rsmf", "--out", rdir, "--redact", "paths"}); code != 0 {
		t.Fatalf("report rsmf exit %d", code)
	}
	ents, _ := os.ReadDir(rdir)
	if len(ents) == 0 {
		t.Fatal("no RSMF written")
	}
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(rdir, e.Name()))
		if p := report.ValidateRSMF(b); len(p) > 0 {
			t.Errorf("%s: %v", e.Name(), p)
		}
	}

	// SOURCE_DATE_EPOCH makes two productions byte-identical.
	t.Setenv("SOURCE_DATE_EPOCH", "1793000000")
	a := filepath.Join(t.TempDir(), "a")
	b := filepath.Join(t.TempDir(), "b")
	for _, out := range []string{a, b} {
		if code := Main([]string{"export", pkg, "--production", "--out", out, "--examiner", "Q"}); code != 0 {
			t.Fatalf("export --production exit %d", code)
		}
	}
	for _, rel := range []string{"production-manifest.json", "production-manifest.csv", "report/report.html", "report/report.pdf", "traceability.csv"} {
		x, _ := os.ReadFile(filepath.Join(a, rel))
		y, _ := os.ReadFile(filepath.Join(b, rel))
		if len(x) == 0 || !bytes.Equal(x, y) {
			t.Errorf("%s differs between SOURCE_DATE_EPOCH runs", rel)
		}
	}
	man, _ := os.ReadFile(filepath.Join(a, "production-manifest.json"))
	if !strings.Contains(string(man), `"produced_at": "2026-10-26T`) || !strings.Contains(string(man), "SOURCE_DATE_EPOCH") {
		t.Errorf("produced_at not taken from SOURCE_DATE_EPOCH")
	}

	// Each production is recorded in the post-seal activity log.
	recs, chainErr, err := custody.Read(pkg)
	if err != nil || chainErr != "" {
		t.Fatalf("activity log: %v %s", err, chainErr)
	}
	n := 0
	for _, r := range recs {
		if r.Event == custody.EventProductionGenerated {
			n++
		}
	}
	if n != 2 {
		t.Errorf("want 2 production_generated records, got %d", n)
	}

	// Default export behaviour (no --production) is unchanged: usage errors
	// still exit 2, and bad production options are refused.
	if code := Main([]string{"export", pkg, "--production", "--redact", "bogus", "--out", filepath.Join(t.TempDir(), "c")}); code != 2 {
		t.Errorf("bad --redact exit %d, want 2", code)
	}
	if code := Main([]string{"export", pkg, "--production", "--produced-at", "yesterday", "--out", filepath.Join(t.TempDir(), "d")}); code != 2 {
		t.Errorf("bad --produced-at exit %d, want 2", code)
	}
	if code := Main([]string{"export", pkg, "--production", "--out", a}); code != 1 {
		t.Errorf("non-empty out exit %d, want 1", code)
	}
}

func TestProducedAtSources(t *testing.T) {
	t.Setenv("SOURCE_DATE_EPOCH", "")
	if _, src, err := producedAt(""); err != nil || src != "clock" {
		t.Errorf("default: %s %v", src, err)
	}
	if tm, src, err := producedAt("2026-01-02T03:04:05+02:00"); err != nil || src != "--produced-at" || tm.Format("15") != "01" {
		t.Errorf("flag: %v %s %v", tm, src, err)
	}
	t.Setenv("SOURCE_DATE_EPOCH", "-5")
	if _, _, err := producedAt(""); err == nil {
		t.Error("negative SOURCE_DATE_EPOCH accepted")
	}
	if !isRSMFReport([]string{"pkg", "--format=rsmf"}) || isRSMFReport([]string{"pkg", "--format", "pdf"}) {
		t.Error("rsmf format detection")
	}
}
