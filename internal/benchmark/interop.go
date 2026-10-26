package benchmark

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/analysis"
	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/collector"
	"github.com/efij/AgentDFIR/v5/internal/parsers/aiexport"
	"github.com/efij/AgentDFIR/v5/internal/parsers/suite"
	"github.com/efij/AgentDFIR/v5/internal/products"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// Interop is the forensic-interop section: another tool's export (all
// fixtures hand-made in that tool's documented layout, see
// internal/parsers/suite/testdata/README.md) sealed the way
// `collect --suite-export` seals it and analyzed by the full pipeline.
type Interop struct {
	Label    string          `json:"label"`
	Fixtures []InteropResult `json:"fixtures"`
	Checks   []Check         `json:"checks"`
	Skipped  string          `json:"skipped,omitempty"`
}

// InteropResult is one export.
type InteropResult struct {
	Name        string `json:"name"`
	Imitates    string `json:"imitates"`
	Files       int    `json:"files"`
	Sealed      int    `json:"sealed"`
	Identical   int    `json:"sealed_byte_identical"`
	Records     int    `json:"records"` // normalized rows / models (action suite_record)
	WantRecords int    `json:"want_records"`
	Unsupported int    `json:"unsupported_notices"`
	WantUnsup   int    `json:"want_unsupported_notices"`
	Unparsed    int    `json:"unparsed_notices"`
	WantUnparse int    `json:"want_unparsed_notices"`
	SuiteEvents int    `json:"suite_events"`
	CaseDB      bool   `json:"case_mfdb_unsupported_finding,omitempty"`
	OK          bool   `json:"ok"`
	Problem     string `json:"problem,omitempty"`
}

type interopFixture struct {
	dir, imitates           string
	records, unsup, unparse int
	caseDB                  bool
}

// The expected counts are the ones the suite reader's own tests pin
// (internal/parsers/suite/suite_test.go), here measured through the
// whole collect + analyze pipeline.
func interopFixtures() []interopFixture {
	return []interopFixture{
		{dir: "ufdr", imitates: "Cellebrite UFDR report.xml", records: 5, unsup: 1},
		{dir: "ufd", imitates: "Cellebrite .ufd / .ufdx descriptors + image", records: 0},
		{dir: "axiom", imitates: "Magnet AXIOM CSV export (UTF-8 and UTF-16LE)", records: 4},
		{dir: "portable", imitates: "AXIOM Portable Case (Case.mfdb + CSV + attachment)", records: 2, unsup: 1, caseDB: true},
		{dir: "plaso", imitates: "Plaso psort json_line + l2tcsv", records: 4, unparse: 2},
		{dir: "autopsy", imitates: `Autopsy "Files - Text" report`, records: 2},
	}
}

// suiteRecord is the Action of a normalized suite row (internal/parsers/suite).
const suiteRecord = "suite_record"

func runInterop(r *Report, o Options, work string) {
	in := &Interop{Label: SuiteLabel, Fixtures: []InteropResult{}, Checks: []Check{}}
	r.Interop = in
	root := repoFinder(o.RepoRoot)
	if root == "" {
		in.Skipped = noCheckout
		r.Suites = append(r.Suites, Suite{Name: "forensic interop", Label: SuiteLabel, Status: SuiteSkip, Reason: noCheckout})
		return
	}
	failed := false
	tot := InteropResult{}
	for _, fx := range interopFixtures() {
		res := interopOne(r, filepath.Join(root, "internal", "parsers", "suite", "testdata", fx.dir), filepath.Join(work, fx.dir), fx)
		in.Fixtures = append(in.Fixtures, res)
		c := Check{Name: fx.dir + " (" + fx.imitates + ")",
			Want: fmt.Sprintf("%d records, %d UNSUPPORTED, %d unparsed notices, originals sealed byte-identical", fx.records, fx.unsup, fx.unparse),
			Got:  fmt.Sprintf("%d records, %d UNSUPPORTED, %d unparsed, %d/%d sealed identical", res.Records, res.Unsupported, res.Unparsed, res.Identical, res.Files)}
		if fx.caseDB {
			c.Want += ", AXIOM_CASE_DB_UNSUPPORTED finding"
			c.Got += fmt.Sprintf(", case-db finding %t", res.CaseDB)
		}
		if res.Problem != "" {
			c.Got += "; " + res.Problem
		}
		r.record("forensic interop", &c, res.OK)
		in.Checks = append(in.Checks, c)
		if !res.OK {
			failed = true
		}
		tot.Files += res.Files
		tot.Identical += res.Identical
		tot.Records += res.Records
		tot.WantRecords += res.WantRecords
		tot.Unsupported += res.Unsupported
	}
	sum := fmt.Sprintf("%d exports, %d/%d records, %d/%d originals sealed byte-identical, %d UNSUPPORTED notices (Case.mfdb, unknown UFDR structure)",
		len(in.Fixtures), tot.Records, tot.WantRecords, tot.Identical, tot.Files, tot.Unsupported)
	r.Suites = append(r.Suites, verdict("forensic interop", sum, in.Checks, failed))
}

func interopOne(r *Report, src, work string, fx interopFixture) (res InteropResult) {
	res = InteropResult{Name: fx.dir, Imitates: fx.imitates, WantRecords: fx.records, WantUnsup: fx.unsup, WantUnparse: fx.unparse}
	defer func() {
		if p := recover(); p != nil {
			res.OK, res.Problem = false, fmt.Sprintf("panic: %v", p)
		}
	}()
	fail := func(format string, a ...any) {
		if res.Problem == "" {
			res.Problem = fmt.Sprintf(format, a...)
		}
	}
	originals := map[string]bool{}
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		s, err := fileSHA256(p)
		if err != nil {
			return err
		}
		originals[s] = true
		res.Files++
		return nil
	})
	if err != nil {
		fail("read fixture: %v", err)
		return res
	}
	pkg, err := sealSuiteExport(src, filepath.Join(work, "case.adfir"))
	if err != nil {
		fail("seal: %v", err)
		return res
	}
	r.newPackages = append(r.newPackages, pkg)
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		fail("manifest: %v", err)
		return res
	}
	st := casepkg.NewStore(pkg, man)
	for _, a := range man.Current() {
		res.Sealed++
		rc, err := st.Open(a.ArtifactID)
		if err != nil {
			fail("open sealed %s: %v", a.LogicalPath, err)
			continue
		}
		h := sha256.New()
		_, err = io.Copy(h, rc)
		rc.Close()
		if sum := hex.EncodeToString(h.Sum(nil)); err == nil && sum == a.ArtifactID && originals[sum] {
			res.Identical++
		} else {
			fail("%s: sealed bytes differ from the original", a.LogicalPath)
		}
	}
	ar, err := analysis.Run(pkg, analysis.Options{})
	if err != nil {
		fail("analyze: %v", err)
		return res
	}
	for _, e := range analysis.LoadEvents(pkg) {
		if !strings.HasPrefix(e.TimestampSrc, suite.TimestampPrefix) {
			continue
		}
		res.SuiteEvents++
		switch {
		case e.Action == suiteRecord:
			res.Records++
		case e.EventType == schema.EventTraceGap && e.Result == "unsupported":
			res.Unsupported++
		case e.EventType == schema.EventTraceGap && e.Result == "unparsed":
			res.Unparsed++
		}
	}
	if b, err := json.Marshal(ar.Findings); err == nil {
		res.CaseDB = strings.Contains(string(b), "AXIOM_CASE_DB_UNSUPPORTED")
	}
	switch {
	case res.Identical != res.Files || res.Sealed != res.Files:
		fail("%d of %d originals sealed byte-identical (%d sealed)", res.Identical, res.Files, res.Sealed)
	case res.Records != fx.records:
		fail("%d records, want %d", res.Records, fx.records)
	case res.Unsupported != fx.unsup:
		fail("%d UNSUPPORTED notices, want %d", res.Unsupported, fx.unsup)
	case res.Unparsed != fx.unparse:
		fail("%d unparsed notices, want %d", res.Unparsed, fx.unparse)
	case fx.caseDB && !res.CaseDB:
		fail("no AXIOM_CASE_DB_UNSUPPORTED finding")
	}
	res.OK = res.Problem == ""
	return res
}

// sealSuiteExport seals a forensic-suite export directory the way
// `collect --suite-export <dir>` does: the export planner decides each
// file's rule, every file is sealed.
func sealSuiteExport(src, pkg string) (string, error) {
	pl, err := aiexport.PlanTree(src, aiexport.PlanAll, nil)
	if err != nil {
		return "", err
	}
	if !pl.Found() {
		return "", fmt.Errorf("no forensic-suite export recognized in %s", filepath.Base(src))
	}
	specs := make([]collector.FileSpec, 0, len(pl.Files))
	for _, f := range pl.Files {
		specs = append(specs, collector.FileSpec{Path: f.Path, Product: f.Product,
			Entry: products.ManifestEntry{ID: f.Rule, Category: f.Type, Sensitivity: "high"}})
	}
	if err := os.MkdirAll(filepath.Dir(pkg), 0o700); err != nil {
		return "", err
	}
	b, err := casepkg.New(pkg, "BENCH-interop", casepkg.CaseInfo{OperatorOSUser: "benchmark"})
	if err != nil {
		return "", err
	}
	defer b.Close()
	if _, err := collector.IngestFiles(b, specs, collector.Options{ProfileRoot: pl.Root, ConfigRoot: pl.Root, SystemRoot: pl.Root}); err != nil {
		return "", err
	}
	return pkg, b.Seal()
}
