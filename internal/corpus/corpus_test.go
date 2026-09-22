package corpus

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/analysis"
	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/products"
	"github.com/efij/AgentDFIR/internal/schema"
)

// analyseCase collects one corpus directory into a real sealed package and
// runs the real analysis pipeline over it. Nothing is mocked: a rule that
// passes here passes in the product.
func analyseCase(t *testing.T, c Case) []schema.Finding {
	t.Helper()
	man, err := products.ManifestAllPlatforms("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := casepkg.New(pkg, "CORPUS-"+c.Name, casepkg.CaseInfo{OperatorOSUser: "corpus"})
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if _, err := collector.Run(b, man, collector.Options{
		ProfileRoot: c.Dir, ConfigRoot: filepath.Join(c.Dir, ".claude"),
		SystemRoot: c.Dir, Product: "claude-code",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	res, err := analysis.Run(pkg, analysis.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res.Findings
}

// TestCorpus is the precision ratchet.
//
// Benign cases must stay under their rule's false-positive budget; attack
// cases must keep producing the rules they name. A change that quietens a
// rule by breaking it fails on the attack side, and a change that adds
// noise fails on the benign side. Run it on its own to see the table:
//
//	go test ./internal/corpus -run TestCorpus -v
func TestCorpus(t *testing.T) {
	cases, err := Load("testdata")
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("no corpus cases")
	}
	budget, err := LoadBudget(filepath.Join("testdata", "budget.json"))
	if err != nil {
		t.Fatal(err)
	}

	res := &Result{FalsePositives: map[string]int{}}
	for _, c := range cases {
		c := c
		t.Run(c.Kind+"/"+c.Name, func(t *testing.T) {
			findings := analyseCase(t, c)
			got := map[string]int{}
			for _, f := range findings {
				got[f.RuleID]++
			}
			switch c.Kind {
			case "benign":
				for rule, n := range got {
					if _, ok := c.Allow[rule]; ok {
						continue
					}
					res.FalsePositives[rule] += n
					res.TotalFP += n
					res.Unexpected = append(res.Unexpected, c.Name+": "+rule)
				}
			case "attack":
				for _, want := range c.Expect {
					if got[want] == 0 {
						res.Missed = append(res.Missed, c.Name+": "+want)
						t.Errorf("lost detection %s\n  this case exists because: %s", want, c.Note)
					}
				}
			}
		})
	}

	t.Log("\n" + res.Report())

	// Per-rule budgets. A rule over budget is a regression even if the
	// total looks fine.
	var over []string
	for rule, n := range res.FalsePositives {
		if n > budget.Rules[rule] {
			over = append(over, fmt.Sprintf("%s: %d (budget %d)", rule, n, budget.Rules[rule]))
		}
	}
	sort.Strings(over)
	for _, o := range over {
		t.Errorf("false-positive budget exceeded — %s", o)
	}
	if res.TotalFP > budget.Total {
		t.Errorf("benign corpus produced %d false positives, budget is %d", res.TotalFP, budget.Total)
	}
	if len(res.Missed) > 0 {
		t.Errorf("attack corpus lost %d detection(s): %s", len(res.Missed), strings.Join(res.Missed, ", "))
	}
}

// TestEveryCaseExplainsItself: a corpus case with no note is unusable —
// whoever hits the failure has to know which real-world shape it stands for.
func TestEveryCaseExplainsItself(t *testing.T) {
	cases, err := Load("testdata")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cases {
		if len(c.Note) < 40 {
			t.Errorf("%s/%s: note is too short to explain the shape", c.Kind, c.Name)
		}
		if c.Kind == "attack" && len(c.Expect) == 0 {
			t.Errorf("attack/%s: expects no rules, so it asserts nothing", c.Name)
		}
		if _, err := os.Stat(filepath.Join(c.Dir, ".claude")); err != nil {
			t.Errorf("%s/%s: no .claude profile to collect", c.Kind, c.Name)
		}
	}
}
