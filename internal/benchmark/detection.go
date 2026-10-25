package benchmark

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"github.com/efij/AgentDFIR/v3/internal/analysis"
	"github.com/efij/AgentDFIR/v3/internal/catalog"
	"github.com/efij/AgentDFIR/v3/internal/corpus"
	"github.com/efij/AgentDFIR/v3/internal/rulepack"
	"github.com/efij/AgentDFIR/v3/internal/simulate"
)

// RuleStat is one rule's score over every labeled fixture.
//
// A true positive is a rule an attack fixture expects and got; a false
// negative is one it expected and did not get; a false positive is a
// firing on a benign fixture that the fixture's label does not allow
// (building blocks excepted: they are context, not alerts). Firings on an
// attack fixture that its label does not mention are not scored either
// way; they are counted under Unlabeled.
type RuleStat struct {
	Rule      string   `json:"rule"`
	TP        int      `json:"tp"`
	FP        int      `json:"fp"`
	FN        int      `json:"fn"`
	Precision *float64 `json:"precision"` // null when the rule was never expected and never fired falsely
	Recall    *float64 `json:"recall"`    // null when no fixture expects the rule
}

// Detection is the detection-accuracy section.
type Detection struct {
	AttackCases    int        `json:"attack_cases"`
	BenignCases    int        `json:"benign_cases"`
	Scenarios      int        `json:"simulate_scenarios"`
	Rules          []RuleStat `json:"rules"`
	TP             int        `json:"tp"`
	FP             int        `json:"fp"`
	FN             int        `json:"fn"`
	Precision      *float64   `json:"precision"`
	Recall         *float64   `json:"recall"`
	BenignFirings  []string   `json:"benign_firings"`  // "fixture: RULE ×n", unallowed
	AllowedBenign  int        `json:"allowed_benign"`  // benign firings the label allows
	Missed         []string   `json:"missed"`          // "fixture: RULE"
	Unlabeled      []string   `json:"unlabeled"`       // "RULE ×n" on attack fixtures, not scored
	RuleUniverse   int        `json:"rule_universe"`   // built-in rules + embedded pack rules
	BuildingBlocks int        `json:"building_blocks"` // context rules, never scored as alerts
	Uncovered      []string   `json:"uncovered"`       // alert rules no attack fixture expects
}

// fixture is one labeled input.
type fixture struct {
	name    string
	attack  bool
	expect  []string
	allow   map[string]string
	profile string   // directory to collect
	prods   []string // products to collect
	write   func(root string) error
}

func loadFixtures(o Options, work string) ([]fixture, *corpus.Budget, error) {
	root := o.CorpusDir
	if root == "" {
		var err error
		if root, err = corpus.Extract(filepath.Join(work, "corpus")); err != nil {
			return nil, nil, err
		}
	}
	cases, err := corpus.Load(root)
	if err != nil {
		return nil, nil, err
	}
	budget, err := corpus.LoadBudget(filepath.Join(root, "budget.json"))
	if err != nil && !os.IsNotExist(err) {
		return nil, nil, err
	}
	var fx []fixture
	for _, c := range cases {
		fx = append(fx, fixture{name: "corpus/" + c.Kind + "/" + c.Name, attack: c.Kind == "attack",
			expect: c.Expect, allow: c.Allow, profile: c.Dir, prods: []string{"claude-code"}})
	}
	for _, sc := range simulate.Catalog {
		sc := sc
		fx = append(fx, fixture{name: "simulate/" + sc.ID, attack: true, expect: sc.Expect,
			prods: []string{"claude-code", "host-shell"}, write: sc.Run})
	}
	return fx, budget, nil
}

// quickSample keeps a few of each kind: enough to exercise every code
// path of the scoring in `go test`, not enough to be slow.
func quickSample(fx []fixture) []fixture {
	var out []fixture
	seen := map[string]int{}
	for _, f := range fx {
		kind := "benign"
		if f.attack {
			kind = "attack"
			if f.write != nil {
				kind = "scenario"
			}
		}
		if seen[kind] < 2 {
			out = append(out, f)
			seen[kind]++
		}
	}
	return out
}

func runDetection(r *Report, o Options, work string, prov *provenanceChecker) error {
	if err := os.MkdirAll(work, 0o700); err != nil {
		return err
	}
	all, budget, err := loadFixtures(o, work)
	if err != nil {
		return err
	}
	d := &r.Detection
	// Coverage is a property of the labels, so it is computed over every
	// fixture even when only a sample is run.
	expected := map[string]bool{}
	for _, f := range all {
		for _, id := range f.expect {
			expected[id] = true
		}
	}
	universe, err := ruleUniverse()
	if err != nil {
		return err
	}
	d.RuleUniverse = len(universe)
	for _, id := range universe {
		switch {
		case catalog.IsBuildingBlock(id):
			d.BuildingBlocks++
		case !expected[id]:
			d.Uncovered = append(d.Uncovered, id)
		}
	}

	run := all
	if o.Quick {
		run = quickSample(all)
	}
	stats := map[string]*RuleStat{}
	stat := func(id string) *RuleStat {
		s, ok := stats[id]
		if !ok {
			s = &RuleStat{Rule: id}
			stats[id] = s
		}
		return s
	}
	benignFP := map[string]int{}
	unlabeled := map[string]int{}
	for i, f := range run {
		profile := f.profile
		if f.write != nil {
			profile = filepath.Join(work, fmt.Sprintf("profile-%d", i))
			if err := f.write(profile); err != nil {
				return fmt.Errorf("%s: %w", f.name, err)
			}
		}
		a, err := collectAndAnalyze(work, fmt.Sprintf("fx-%d", i), profile, f.prods, analysis.Options{})
		if err != nil {
			r.fail("detection: %s: pipeline failed: %v", f.name, err)
			continue
		}
		prov.check(f.name, a)
		got := map[string]int{}
		for _, fd := range a.findings {
			got[fd.RuleID]++
		}
		if f.attack {
			d.AttackCases++
			if f.write != nil {
				d.AttackCases--
				d.Scenarios++
			}
			want := map[string]bool{}
			for _, id := range f.expect {
				want[id] = true
				if got[id] > 0 {
					stat(id).TP++
				} else {
					stat(id).FN++
					d.Missed = append(d.Missed, f.name+": "+id)
				}
			}
			for id, n := range got {
				if !want[id] && !catalog.IsBuildingBlock(id) {
					unlabeled[id] += n
				}
			}
			continue
		}
		d.BenignCases++
		ids := sortedKeys(got)
		for _, id := range ids {
			n := got[id]
			if _, ok := f.allow[id]; ok {
				d.AllowedBenign += n
				continue
			}
			if catalog.IsBuildingBlock(id) {
				continue
			}
			stat(id).FP += n
			benignFP[id] += n
			d.BenignFirings = append(d.BenignFirings, fmt.Sprintf("%s: %s ×%d", f.name, id, n))
		}
	}
	for _, id := range sortedKeys(stats) {
		s := stats[id]
		s.Precision, s.Recall = ratio(s.TP, s.TP+s.FP), ratio(s.TP, s.TP+s.FN)
		d.TP, d.FP, d.FN = d.TP+s.TP, d.FP+s.FP, d.FN+s.FN
		d.Rules = append(d.Rules, *s)
	}
	d.Precision, d.Recall = ratio(d.TP, d.TP+d.FP), ratio(d.TP, d.TP+d.FN)
	for _, id := range sortedKeys(unlabeled) {
		d.Unlabeled = append(d.Unlabeled, fmt.Sprintf("%s ×%d", id, unlabeled[id]))
	}
	sort.Strings(d.Missed)
	for _, m := range d.Missed {
		r.fail("detection: lost detection %s", m)
	}
	// The corpus carries a false-positive budget per rule; the benchmark
	// holds the same line the build does, and reports anything inside it.
	if budget != nil && !o.Quick {
		total := 0
		for _, id := range sortedKeys(benignFP) {
			total += benignFP[id]
			if benignFP[id] > budget.Rules[id] {
				r.fail("detection: %s produced %d false positive(s) on the benign corpus (budget %d)", id, benignFP[id], budget.Rules[id])
			}
		}
		if total > budget.Total {
			r.fail("detection: %d false positives on the benign corpus (budget %d)", total, budget.Total)
		}
	}
	if d.Missed == nil {
		d.Missed = []string{}
	}
	if d.BenignFirings == nil {
		d.BenignFirings = []string{}
	}
	return nil
}

// ruleUniverse is every rule the binary can emit: the built-in Go rules
// and the rules in the packs embedded in it.
func ruleUniverse() ([]string, error) {
	seen := map[string]bool{}
	for _, r := range catalog.Builtin {
		seen[r.ID] = true
	}
	packs, _, err := rulepack.Embedded()
	if err != nil {
		return nil, err
	}
	for _, p := range packs {
		for _, r := range p.Rules {
			seen[r.ID] = true
		}
	}
	return sortedKeys(seen), nil
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
