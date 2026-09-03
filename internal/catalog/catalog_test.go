package catalog

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/rulepack"
)

// ruleIDRe matches every way the code base names a finding rule:
//
//	RuleID: "X"            (schema.Finding literals)
//	finding("X", ...)      (mcpaudit helper)
//	}, "X",                (detect surface tables: {[]string{...}, "X", ...})
//
// Rule IDs always contain an underscore, which keeps severity and state
// constants ("HIGH", "OBSERVED") out of the match.
var ruleIDRe = regexp.MustCompile(`(?m)(?:RuleID:\s*|\bfinding\(|\},\s*)"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)",?\s*$?`)

// emittingPackages are the Go packages whose findings the catalog mirrors.
var emittingPackages = []string{"detect", "mcpaudit", "provenance", "correlate"}

// TestCatalogMatchesSource fails when a rule ID emitted by the code has no
// catalog entry, or a catalog entry names a rule the code never emits.
func TestCatalogMatchesSource(t *testing.T) {
	inSource := map[string]bool{}
	for _, pkg := range emittingPackages {
		dir := filepath.Join("..", pkg)
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			name := e.Name()
			if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, name))
			if err != nil {
				t.Fatal(err)
			}
			for _, m := range ruleIDRe.FindAllStringSubmatch(string(data), -1) {
				inSource[m[1]] = true
			}
		}
	}
	inCatalog := map[string]bool{}
	for _, r := range Builtin {
		if inCatalog[r.ID] {
			t.Errorf("duplicate catalog entry %s", r.ID)
		}
		inCatalog[r.ID] = true
	}
	var missing, stale []string
	for id := range inSource {
		if !inCatalog[id] {
			missing = append(missing, id)
		}
	}
	for id := range inCatalog {
		if !inSource[id] {
			stale = append(stale, id)
		}
	}
	sort.Strings(missing)
	sort.Strings(stale)
	if len(missing) > 0 {
		t.Errorf("rule IDs emitted in source but absent from catalog: %v", missing)
	}
	if len(stale) > 0 {
		t.Errorf("catalog entries with no emitting code: %v", stale)
	}
}

var attackIDRe = regexp.MustCompile(`^T\d{4}(\.\d{3})?$`)

// TestCatalogMitreDiscipline: HIGH/CRITICAL built-ins carry a MITRE mapping
// unless they are evidence-quality rules, and every ATLAS ID is real.
func TestCatalogMitreDiscipline(t *testing.T) {
	// Rules about evidence integrity or agent topology, not adversary
	// technique; they legitimately have no ATT&CK/ATLAS technique.
	exempt := map[string]bool{"ORPHAN_AGENT": true, "CROSS_SESSION_MESSAGE": true, "TRACE_GAP": true,
		"UNEXPECTED_TASK": true, "UNEXPECTED_AGENT_RESUME": true}
	valid := map[string]bool{"INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
	for _, r := range Builtin {
		if !valid[r.MaxSeverity] {
			t.Errorf("%s: bad max_severity %q", r.ID, r.MaxSeverity)
		}
		if r.Title == "" || r.Summary == "" || r.Surface == "" || r.Package == "" {
			t.Errorf("%s: incomplete catalog entry", r.ID)
		}
		if (r.MaxSeverity == "HIGH" || r.MaxSeverity == "CRITICAL") && r.MitreATTACK == "" && r.MitreATLAS == "" && !exempt[r.ID] {
			t.Errorf("%s: %s built-in rule has no MITRE mapping", r.ID, r.MaxSeverity)
		}
		if r.MitreATLAS != "" && !rulepack.ValidATLAS(r.MitreATLAS) {
			t.Errorf("%s: mitre_atlas %q not in ATLAS %s", r.ID, r.MitreATLAS, rulepack.ATLASVersion)
		}
		if r.MitreATTACK != "" && !attackIDRe.MatchString(r.MitreATTACK) {
			t.Errorf("%s: mitre_attack %q malformed", r.ID, r.MitreATTACK)
		}
	}
}

// TestCatalogMirrorsSourceMappings checks, for the ATLAS IDs that appear next
// to a RuleID in source, that the catalog carries the same ID. It is a
// heuristic (one-line literals only) that catches the common drift case.
func TestCatalogMirrorsSourceMappings(t *testing.T) {
	re := regexp.MustCompile(`RuleID:\s*"([A-Z0-9_]+)"[^\n]*MitreATLAS:\s*"(AML\.T[0-9.]+)"`)
	for _, pkg := range emittingPackages {
		files, _ := filepath.Glob(filepath.Join("..", pkg, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			data, _ := os.ReadFile(f)
			for _, m := range re.FindAllStringSubmatch(string(data), -1) {
				r, ok := ByID(m[1])
				if ok && r.MitreATLAS != m[2] {
					t.Errorf("%s: source maps ATLAS %s, catalog says %q (%s)", m[1], m[2], r.MitreATLAS, f)
				}
			}
		}
	}
}
