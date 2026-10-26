// Package coverage turns the ATLAS relevance inventory
// (internal/mitre/data/atlas-relevance.json) into the coverage report
// behind `agentdfir rules coverage` and docs/atlas-coverage.md, and checks
// the inventory against the rules and chains that actually exist.
//
// The report is deliberately plain about what it measures. "Covered" means
// a rule or chain is mapped to the technique, not that every variant of
// the technique is detected. "Validated" means at least one named test
// exercises one of those rules or chains. Out-of-scope and unobservable
// techniques are listed with the reason, never counted as gaps or as
// coverage.
package coverage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/catalog"
	"github.com/efij/AgentDFIR/v4/internal/chain"
	"github.com/efij/AgentDFIR/v4/internal/mitre"
	"github.com/efij/AgentDFIR/v4/internal/rulepack"
)

// Row is one ATLAS technique in the report.
type Row struct {
	ID         string   `json:"id"`
	Name       string   `json:"name"`
	Tactics    []string `json:"tactics"`
	Class      string   `json:"class"`
	Priority   string   `json:"priority,omitempty"`
	Rules      []string `json:"rules"`
	Chains     []string `json:"chains"`
	Evidence   []string `json:"evidence_sources"`
	Tests      []string `json:"tests"`
	OWASP      []string `json:"owasp"`
	Planned    []string `json:"planned"`
	Limitation string   `json:"limitation"`
	Exception  string   `json:"exception,omitempty"`
	Covered    bool     `json:"covered"`   // at least one rule or chain is mapped
	Validated  bool     `json:"validated"` // covered, and a named test exercises it
}

// Summary counts the inventory.
type Summary struct {
	Techniques   int `json:"techniques"` // in the pinned ATLAS release
	Classified   int `json:"classified"` // inventory entries with a valid class
	Direct       int `json:"direct"`
	Supporting   int `json:"supporting"`
	Unobservable int `json:"unobservable"`
	OutOfScope   int `json:"out_of_scope"`
	P0           int `json:"p0"`
	P1           int `json:"p1"`
	P2           int `json:"p2"`
	Covered      int `json:"covered"`
	Validated    int `json:"validated"`
	Planned      int `json:"planned"`    // entries with rules or chains still being added
	Exceptions   int `json:"exceptions"` // P0 observable entries with a documented reason for no detection
	P0Observable int `json:"p0_observable"`
	P0Covered    int `json:"p0_covered"`
}

// Report is the full coverage report.
type Report struct {
	ATLASVersion  string   `json:"atlas_version"`
	ATTACKVersion string   `json:"attack_version"`
	OWASP         []string `json:"owasp"`
	Summary       Summary  `json:"summary"`
	Techniques    []Row    `json:"techniques"`
}

// Build assembles the report from the embedded inventory.
func Build() Report {
	r := Report{ATLASVersion: mitre.ATLASVersion, ATTACKVersion: mitre.ATTACKVersion}
	for _, l := range mitre.OWASP() {
		r.OWASP = append(r.OWASP, l.Name+" "+l.Version)
	}
	r.Summary.Techniques = len(mitre.ATLAS().Techniques)
	for _, e := range mitre.Relevance() {
		t, _ := mitre.ATLASTechnique(e.ID)
		row := Row{
			ID: e.ID, Name: e.Name, Tactics: nonNil(t.Tactics), Class: e.Class, Priority: e.Priority,
			Rules: nonNil(e.Rules), Chains: nonNil(e.Chains), Evidence: nonNil(e.EvidenceSources),
			Tests: nonNil(e.Tests), OWASP: nonNil(e.OWASP), Planned: nonNil(e.Planned),
			Limitation: e.Rationale, Exception: e.Exception,
		}
		row.Covered = len(e.Rules)+len(e.Chains) > 0
		row.Validated = row.Covered && len(e.Tests) > 0
		s := &r.Summary
		switch e.Class {
		case mitre.ClassDirect:
			s.Direct++
		case mitre.ClassSupporting:
			s.Supporting++
		case mitre.ClassUnobservable:
			s.Unobservable++
		case mitre.ClassOutOfScope:
			s.OutOfScope++
		}
		if validClass(e.Class) {
			s.Classified++
		}
		switch e.Priority {
		case "P0":
			s.P0++
			if e.Observable() {
				s.P0Observable++
				if row.Covered {
					s.P0Covered++
				}
			}
		case "P1":
			s.P1++
		case "P2":
			s.P2++
		}
		if row.Covered {
			s.Covered++
		}
		if row.Validated {
			s.Validated++
		}
		if len(e.Planned) > 0 {
			s.Planned++
		}
		if e.Exception != "" {
			s.Exceptions++
		}
		r.Techniques = append(r.Techniques, row)
	}
	return r
}

func validClass(c string) bool {
	return c == mitre.ClassDirect || c == mitre.ClassSupporting || c == mitre.ClassUnobservable || c == mitre.ClassOutOfScope
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// Universe is every rule and chain AgentDFIR ships, with its primary ATLAS
// mapping: built-in rules (internal/catalog), the embedded rule packs, and
// the built-in chains.
type Universe struct {
	Rules  map[string]string // rule ID -> mitre_atlas ("" when unmapped)
	Chains map[string]string // chain ID -> mitre_atlas
}

// Load collects the universe.
func Load() (Universe, error) {
	u := Universe{Rules: map[string]string{}, Chains: map[string]string{}}
	for _, c := range chain.Builtin {
		u.Chains[c.ID] = c.MitreATLAS
	}
	for _, r := range catalog.Builtin {
		if _, isChain := u.Chains[r.ID]; isChain {
			continue
		}
		u.Rules[r.ID] = r.MitreATLAS
	}
	packs, _, err := rulepack.Embedded()
	if err != nil {
		return u, err
	}
	for _, p := range packs {
		for _, r := range p.Rules {
			if _, dup := u.Rules[r.ID]; !dup {
				u.Rules[r.ID] = r.MitreATLAS
			}
		}
	}
	return u, nil
}

// Validate checks the inventory against the pinned catalogs and the rule
// universe. It does not check test names (that needs the source tree; see
// coverage_test.go) or that planned entries are resolved (an integration
// gate, see TestRelevancePlannedResolved).
func Validate(u Universe) []error {
	var errs []error
	bad := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }
	entries := mitre.Relevance()
	seen := map[string]bool{}
	listed := map[string]map[string]bool{} // technique -> rule/chain IDs listed under it
	for _, e := range entries {
		if seen[e.ID] {
			bad("%s: duplicate entry", e.ID)
		}
		seen[e.ID] = true
		t, ok := mitre.ATLASTechnique(e.ID)
		if !ok {
			bad("%s: not a technique in ATLAS %s", e.ID, mitre.ATLASVersion)
			continue
		}
		if e.Name != t.Name {
			bad("%s: name %q, ATLAS says %q", e.ID, e.Name, t.Name)
		}
		if !validClass(e.Class) {
			bad("%s: class %q", e.ID, e.Class)
		}
		if e.Class == mitre.ClassOutOfScope {
			if e.Priority != "" {
				bad("%s: out_of_scope entries carry no priority", e.ID)
			}
			if len(e.Rules)+len(e.Chains)+len(e.Planned) > 0 {
				bad("%s: out_of_scope entries list no detections", e.ID)
			}
		} else if e.Priority != "P0" && e.Priority != "P1" && e.Priority != "P2" {
			bad("%s: priority %q", e.ID, e.Priority)
		}
		if strings.TrimSpace(e.Rationale) == "" {
			bad("%s: no rationale", e.ID)
		}
		if e.Observable() && len(e.EvidenceSources) == 0 {
			bad("%s: observable but no evidence source", e.ID)
		}
		for _, o := range e.OWASP {
			if !mitre.ValidOWASP(o) {
				bad("%s: unknown OWASP id %s", e.ID, o)
			}
		}
		listed[e.ID] = map[string]bool{}
		for _, id := range e.Rules {
			if _, ok := u.Rules[id]; !ok {
				bad("%s: rule %s does not exist (chains go under chains)", e.ID, id)
			}
			listed[e.ID][id] = true
		}
		for _, id := range e.Chains {
			if _, ok := u.Chains[id]; !ok {
				bad("%s: chain %s does not exist", e.ID, id)
			}
			listed[e.ID][id] = true
		}
		for _, id := range e.Planned {
			if listed[e.ID][id] {
				bad("%s: %s is both shipped and planned; drop it from planned", e.ID, id)
			}
		}
		if e.Priority == "P0" && e.Observable() && len(e.Rules)+len(e.Chains)+len(e.Planned) == 0 && strings.TrimSpace(e.Exception) == "" {
			bad("%s: P0 %s technique with no rule, chain, planned detection or exception", e.ID, e.Class)
		}
		if e.Exception != "" && !(e.Priority == "P0" && e.Observable() && len(e.Rules)+len(e.Chains) == 0) {
			bad("%s: an exception is only for a P0 observable technique with no rule or chain", e.ID)
		}
	}
	for _, t := range mitre.ATLAS().Techniques {
		if !seen[t.ID] {
			bad("%s: no inventory entry", t.ID)
		}
	}
	check := func(kind string, m map[string]string) {
		ids := make([]string, 0, len(m))
		for id := range m {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			a := m[id]
			if a == "" {
				continue
			}
			if !listed[a][id] {
				bad("%s %s maps to %s but is not listed under it in atlas-relevance.json", kind, id, a)
			}
		}
	}
	check("rule", u.Rules)
	check("chain", u.Chains)
	return errs
}
