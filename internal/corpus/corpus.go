// Package corpus is the measurement harness for detection precision.
//
// Before this existed there was no way to tell whether a rule change made
// the tool better or worse. `simulate` produced attack scenarios only, no
// test measured a false-positive rate, and the acceptance criterion for a
// precision fix was "run it on my laptop and eyeball the number". Every
// fix was a guess and every regression was invisible.
//
// A corpus case is a directory of files that get collected into a real
// sealed package and analysed by the real pipeline — not a mocked one —
// with an expectation attached:
//
//	benign/  activity that must NOT fire. Every finding is a false positive
//	         and is counted against the rule's budget.
//	attack/  activity that MUST fire. A named rule that stops firing is a
//	         lost detection and fails the build.
//
// The benign cases are synthetic but not invented: each reproduces a shape
// that caused a real false positive on a real machine. They are written
// rather than copied because real transcripts carry live secrets.
package corpus

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Case is one corpus directory plus what it asserts.
type Case struct {
	Name string `json:"name"`
	Kind string `json:"kind"` // "benign" or "attack"
	Note string `json:"note"` // why this shape exists; shown when it fails

	// Expect lists rule IDs an attack case must produce. Ignored for benign.
	Expect []string `json:"expect,omitempty"`
	// Allow lists rule IDs a benign case may legitimately produce, with the
	// reason. Anything else counts as a false positive.
	Allow map[string]string `json:"allow,omitempty"`

	Dir string `json:"-"`
}

// Budget caps how many false positives a rule may produce across the whole
// benign corpus. Zero means the rule must not fire on benign activity at
// all. A rule over budget fails the build.
type Budget struct {
	Rules map[string]int `json:"rules"`
	Total int            `json:"total"`
	Note  string         `json:"note"`
}

// Load reads every case under root ("benign" and "attack" subdirectories).
func Load(root string) ([]Case, error) {
	var cases []Case
	for _, kind := range []string{"benign", "attack"} {
		entries, err := os.ReadDir(filepath.Join(root, kind))
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(root, kind, e.Name())
			c, err := loadCase(dir)
			if err != nil {
				return nil, fmt.Errorf("%s/%s: %w", kind, e.Name(), err)
			}
			c.Name, c.Kind, c.Dir = e.Name(), kind, dir
			cases = append(cases, *c)
		}
	}
	sort.Slice(cases, func(i, j int) bool {
		if cases[i].Kind != cases[j].Kind {
			return cases[i].Kind < cases[j].Kind
		}
		return cases[i].Name < cases[j].Name
	})
	return cases, nil
}

func loadCase(dir string) (*Case, error) {
	data, err := os.ReadFile(filepath.Join(dir, "case.json"))
	if err != nil {
		return nil, err
	}
	var c Case
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.Note == "" {
		return nil, fmt.Errorf("case.json needs a note explaining what this shape is")
	}
	return &c, nil
}

// LoadBudget reads the per-rule false-positive budget.
func LoadBudget(path string) (*Budget, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Budget
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	if b.Rules == nil {
		b.Rules = map[string]int{}
	}
	return &b, nil
}

// Result is what one corpus run measured.
type Result struct {
	FalsePositives map[string]int // rule → count across benign cases
	Missed         []string       // "case: RULE" an attack case expected and did not get
	Unexpected     []string       // "case: RULE" a benign case produced
	TotalFP        int
}

// Report renders a per-rule table, worst first.
func (r *Result) Report() string {
	type row struct {
		rule string
		n    int
	}
	rows := make([]row, 0, len(r.FalsePositives))
	for k, v := range r.FalsePositives {
		rows = append(rows, row{k, v})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].n != rows[j].n {
			return rows[i].n > rows[j].n
		}
		return rows[i].rule < rows[j].rule
	})
	var b strings.Builder
	fmt.Fprintf(&b, "false positives on the benign corpus: %d\n", r.TotalFP)
	for _, x := range rows {
		fmt.Fprintf(&b, "  %5d  %s\n", x.n, x.rule)
	}
	if len(r.Missed) > 0 {
		fmt.Fprintf(&b, "lost detections: %s\n", strings.Join(r.Missed, ", "))
	}
	return b.String()
}
