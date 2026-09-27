package mitigate

import (
	"sort"
	"time"

	"github.com/efij/AgentDFIR/v2/internal/catalog"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// RuleRow is one rule's findings seen through what can be done about them.
type RuleRow struct {
	Rule     string   `json:"rule"`
	Title    string   `json:"title"`
	Severity string   `json:"severity"` // worst severity among its findings
	Mode     Mode     `json:"mode"`
	Total    int      `json:"total"`
	Excluded int      `json:"excluded"`        // marked benign / false positive by the analyst
	Since    *int     `json:"since,omitempty"` // findings after the guardrail went in (nil: none applied)
	SinceTS  string   `json:"since_ts,omitempty"`
	Packs    []string `json:"packs,omitempty"`
	Control  string   `json:"control,omitempty"`
	Steps    []string `json:"steps,omitempty"`
}

// PackRow is one pack's standing on this machine and in this case.
type PackRow struct {
	ID         string   `json:"id"`
	Title      string   `json:"title"`
	Why        string   `json:"why"`
	Cost       string   `json:"cost"`
	Level      Level    `json:"level"`
	Friction   int      `json:"friction"`
	Confidence int      `json:"confidence"`
	DefaultOn  bool     `json:"default_on"`
	ATLAS      []string `json:"atlas"`
	Findings   int      `json:"findings"` // in this case, excluding analyst-cleared ones
	Rules      []string `json:"rules_hit,omitempty"`
	State      string   `json:"state"` // not_applied | in_place | drifted
	AppliedAt  string   `json:"applied_at,omitempty"`
}

// Assessment is the mitigation view of one case.
type Assessment struct {
	Rules     []RuleRow `json:"rules"`
	Packs     []PackRow `json:"packs"`
	LastApply string    `json:"last_apply,omitempty"`
}

var sevRank = map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

// Assess groups findings by rule and mode. cleared(f) reports findings the
// analyst marked benign or false positive: they leave the counts, because
// preventing something the analyst already said was fine is noise.
// states is the verified ledger (Status); nil when nothing was applied or
// the case is from another machine.
func Assess(findings []schema.Finding, cleared func(schema.Finding) bool, states []State) Assessment {
	// earliest in-place apply per rule and per pack
	applied := map[string]time.Time{}
	packState := map[string]string{}
	packAt := map[string]time.Time{}
	var last time.Time
	for _, st := range states {
		if st.State == "reverted" || st.State == "missing" {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, st.Record.TS)
		if err != nil {
			continue
		}
		if ts.After(last) {
			last = ts
		}
		if st.State == "in_place" {
			for _, r := range st.Record.Rules {
				if t, ok := applied[r]; !ok || ts.Before(t) {
					applied[r] = ts
				}
			}
		}
		for _, p := range st.Record.Packs {
			if packState[p] != "drifted" {
				packState[p] = st.State
			}
			if t, ok := packAt[p]; !ok || ts.Before(t) {
				packAt[p] = ts
			}
		}
	}
	rows := map[string]*RuleRow{}
	for _, f := range findings {
		if f.Class == catalog.ClassBuildingBlock || catalog.IsBuildingBlock(f.RuleID) {
			continue
		}
		r := rows[f.RuleID]
		if r == nil {
			r = &RuleRow{Rule: f.RuleID, Title: f.Title, Severity: f.Severity, Mode: ModeOf(f.RuleID), Packs: PacksForRule(f.RuleID), Control: FixControl(f.RuleID)}
			if r.Mode == Manual || r.Mode == None {
				r.Steps = StepsFor(f.RuleID)
			}
			rows[f.RuleID] = r
		}
		if cleared != nil && cleared(f) {
			r.Excluded++
			continue
		}
		r.Total++
		if sevRank[f.Severity] > sevRank[r.Severity] {
			r.Severity = f.Severity
		}
		if at, ok := applied[f.RuleID]; ok {
			if r.Since == nil {
				n := 0
				r.Since = &n
				r.SinceTS = at.Format(time.RFC3339)
			}
			if ft, err := time.Parse(time.RFC3339Nano, f.Timestamp); err == nil && ft.After(at) {
				*r.Since++
			}
		}
	}
	a := Assessment{}
	if !last.IsZero() {
		a.LastApply = last.Format(time.RFC3339)
	}
	for _, r := range rows {
		a.Rules = append(a.Rules, *r)
	}
	sort.Slice(a.Rules, func(i, j int) bool {
		x, y := a.Rules[i], a.Rules[j]
		if sevRank[x.Severity] != sevRank[y.Severity] {
			return sevRank[x.Severity] > sevRank[y.Severity]
		}
		if x.Total != y.Total {
			return x.Total > y.Total
		}
		return x.Rule < y.Rule
	})
	for _, p := range Packs {
		pr := PackRow{ID: p.ID, Title: p.Title, Why: p.Why, Cost: p.Cost, Level: p.Level, Friction: p.Friction,
			Confidence: p.Confidence, DefaultOn: p.DefaultOn, ATLAS: p.ATLAS, State: "not_applied"}
		if s, ok := packState[p.ID]; ok {
			pr.State = s
			pr.AppliedAt = packAt[p.ID].Format(time.RFC3339)
		}
		for _, rid := range p.Rules {
			if r, ok := rows[rid]; ok && r.Total > 0 {
				pr.Findings += r.Total
				pr.Rules = append(pr.Rules, rid)
			}
		}
		a.Packs = append(a.Packs, pr)
	}
	return a
}
