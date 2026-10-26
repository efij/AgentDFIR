package coverage

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/mitre"
)

// enforcePlannedResolved turns on the integration gate in
// TestRelevancePlannedResolved. Workstream branches add the planned rules
// and chains; the integration branch flips this to true once they are all
// merged and listed under rules/chains (or sets
// AGENTDFIR_ENFORCE_PLANNED_RESOLVED=1 to try it early).
const enforcePlannedResolved = true

func repoRoot(t *testing.T) string {
	root, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	return root
}

// TestRelevanceInventory is the CI gate on the inventory: 208/208 entries,
// no duplicates, valid IDs and names, every listed rule or chain exists,
// every rule or chain with a mitre_atlas is listed under that technique,
// and every P0 observable technique has a rule, chain, planned detection
// or written exception.
func TestRelevanceInventory(t *testing.T) {
	if err := mitre.Err(); err != nil {
		t.Fatal(err)
	}
	u, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(u.Rules) < 200 || len(u.Chains) < 13 {
		t.Fatalf("rule universe too small: %d rules, %d chains", len(u.Rules), len(u.Chains))
	}
	if n := len(mitre.Relevance()); n != 208 {
		t.Errorf("%d inventory entries, ATLAS %s has 208", n, mitre.ATLASVersion)
	}
	for _, e := range Validate(u) {
		t.Error(e)
	}
}

var (
	testFuncRe = regexp.MustCompile(`(?m)^func (Test\w+)\(`)
	quotedIDRe = regexp.MustCompile(`"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)"`)
)

// testIndex maps every Test function in the repository to the quoted rule
// and chain IDs its body names.
func testIndex(t *testing.T) map[string]map[string]bool {
	root := repoRoot(t)
	idx := map[string]map[string]bool{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" || d.Name() == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		src := string(data)
		locs := testFuncRe.FindAllStringSubmatchIndex(src, -1)
		for i, l := range locs {
			name := src[l[2]:l[3]]
			end := len(src)
			if i+1 < len(locs) {
				end = locs[i+1][0]
			}
			if idx[name] == nil {
				idx[name] = map[string]bool{}
			}
			for _, m := range quotedIDRe.FindAllStringSubmatch(src[l[1]:end], -1) {
				idx[name][m[1]] = true
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

// TestRelevanceTestsAreReal: every `tests` entry names a Test function that
// exists in the repository and names at least one of the rules or chains
// listed for that technique, so "validated" cannot be claimed with a test
// that never touches the detection.
func TestRelevanceTestsAreReal(t *testing.T) {
	idx := testIndex(t)
	for _, e := range mitre.Relevance() {
		dets := append(append([]string{}, e.Rules...), e.Chains...)
		for _, name := range e.Tests {
			ids, ok := idx[name]
			if !ok {
				t.Errorf("%s: test %s does not exist", e.ID, name)
				continue
			}
			hit := false
			for _, d := range dets {
				hit = hit || ids[d]
			}
			if !hit {
				t.Errorf("%s: test %s names none of %v", e.ID, name, dets)
			}
		}
	}
}

// TestRelevancePlannedResolved is the integration gate (PLAN-v5 §5): no
// planned placeholders remain, and every P0 observable technique has a
// rule or chain with a referenced test, or a documented exception. It is
// off on workstream branches; see enforcePlannedResolved.
func TestRelevancePlannedResolved(t *testing.T) {
	if !enforcePlannedResolved && os.Getenv("AGENTDFIR_ENFORCE_PLANNED_RESOLVED") != "1" {
		t.Skip("integration gate: flip enforcePlannedResolved once the v5 detection workstreams are merged")
	}
	u, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range mitre.Relevance() {
		for _, id := range e.Planned {
			_, isRule := u.Rules[id]
			_, isChain := u.Chains[id]
			t.Errorf("%s: planned %s still unresolved (exists: %v); list it under rules/chains with its tests, or drop it", e.ID, id, isRule || isChain)
		}
		if e.Priority == "P0" && e.Observable() && e.Exception == "" && (len(e.Rules)+len(e.Chains) == 0 || len(e.Tests) == 0) {
			t.Errorf("%s: P0 %s technique needs a rule or chain with a referenced test, or an exception", e.ID, e.Class)
		}
	}
}

// TestCoverageDocCurrent holds docs/atlas-coverage.md to the command
// output. Regenerate: go run ./cmd/agentdfir rules coverage --format md > docs/atlas-coverage.md
func TestCoverageDocCurrent(t *testing.T) {
	want := Build().Markdown()
	got, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "atlas-coverage.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Error("docs/atlas-coverage.md is stale: run `go run ./cmd/agentdfir rules coverage --format md > docs/atlas-coverage.md`")
	}
}

func TestReportSummary(t *testing.T) {
	r := Build()
	s := r.Summary
	if s.Techniques != 208 || s.Classified != 208 || len(r.Techniques) != 208 {
		t.Fatalf("summary %+v", s)
	}
	if s.Direct+s.Supporting+s.Unobservable+s.OutOfScope != s.Classified {
		t.Errorf("class counts do not add up: %+v", s)
	}
	if s.Validated > s.Covered || s.P0Covered > s.P0Observable {
		t.Errorf("inconsistent: %+v", s)
	}
	for _, row := range r.Techniques {
		if row.Class == mitre.ClassOutOfScope && row.Covered {
			t.Errorf("%s: out of scope but covered", row.ID)
		}
	}
	if Build().Markdown() != r.Markdown() || Build().Text() != r.Text() {
		t.Error("report output is not deterministic")
	}
}
