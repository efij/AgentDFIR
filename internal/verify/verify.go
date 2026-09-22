// Package verify decides how much to believe a finding.
//
// Severity answers "how bad is this if it is real". Confidence answers "how
// likely is it to be real". They were the same number, so deleting a build
// directory and deleting a user's SSH key arrived identical, and an analyst
// facing 592 HIGH findings had no way to sort them into the ones worth
// opening.
//
// Every verifier is a pure function over the finding and the events it
// cites. No LLM, no model call, no network: a finding has to be reproducible
// from the sealed package alone, years later, by someone who does not have
// the binary that produced it. That is what makes it evidence rather than an
// opinion.
//
// A verifier may move confidence one step and must say why, in a sentence
// the UI shows verbatim. Severity is never touched.
package verify

import (
	"strings"

	"github.com/efij/AgentDFIR/internal/catalog"
	"github.com/efij/AgentDFIR/internal/schema"
)

// Confidence levels.
const (
	High   = "HIGH"
	Medium = "MEDIUM"
	Low    = "LOW"
)

var rank = map[string]int{Low: 0, Medium: 1, High: 2}
var byRank = []string{Low, Medium, High}

func step(c string, by int) string {
	r, ok := rank[c]
	if !ok {
		r = rank[Medium]
	}
	r += by
	if r < 0 {
		r = 0
	}
	if r > 2 {
		r = 2
	}
	return byRank[r]
}

// Verifier inspects a finding and may adjust confidence.
type Verifier struct {
	Name string
	// Check returns a step (-1, 0 or +1) and the reason for it. An empty
	// reason means the verifier had nothing to say.
	Check func(f schema.Finding, cited []schema.Event) (int, string)
}

// Apply runs every verifier over every finding, in a fixed order, so the
// same package always produces the same confidence.
func Apply(findings []schema.Finding, events []schema.Event) []schema.Finding {
	byID := make(map[string]schema.Event, len(events))
	for _, e := range events {
		byID[e.EventID] = e
	}
	out := make([]schema.Finding, len(findings))
	copy(out, findings)
	for i := range out {
		f := &out[i]
		if catalog.IsBuildingBlock(f.RuleID) {
			f.Class = catalog.ClassBuildingBlock
		}
		if f.Confidence == "" {
			f.Confidence = Medium
		}
		cited := citedEvents(*f, byID)
		for _, v := range Verifiers {
			d, why := v.Check(*f, cited)
			if why == "" {
				continue
			}
			if d != 0 {
				f.Confidence = step(f.Confidence, d)
			}
			f.Reasons = append(f.Reasons, why)
		}
		if f.Timestamp == "" {
			f.Timestamp = earliest(cited)
		}
	}
	return out
}

func citedEvents(f schema.Finding, byID map[string]schema.Event) []schema.Event {
	var out []schema.Event
	for _, s := range f.ChainSteps {
		if e, ok := byID[s.EventID]; ok {
			out = append(out, e)
		}
	}
	return out
}

func earliest(ev []schema.Event) string {
	best := ""
	for _, e := range ev {
		if e.Timestamp == "" {
			continue
		}
		if best == "" || e.Timestamp < best {
			best = e.Timestamp
		}
	}
	return best
}

// Verifiers run in this order. Each is deliberately narrow: a verifier that
// tries to be clever is one nobody can audit.
var Verifiers = []Verifier{
	{Name: "witness", Check: func(_ schema.Finding, ev []schema.Event) (int, string) {
		for _, e := range ev {
			switch e.Corroboration {
			case schema.StateCorroborated:
				return +1, "an independent source on the host confirms this happened"
			case schema.StateContradicted:
				return +1, "an independent source on the host contradicts the transcript"
			}
		}
		return 0, ""
	}},
	{Name: "self-referential", Check: func(f schema.Finding, _ []schema.Event) (int, string) {
		for _, r := range f.EvidenceRefs {
			l := strings.ToLower(r)
			for _, frag := range []string{"signatures", "/rules/", "testdata", "fixtures", "_test.", "agentdfir"} {
				if strings.Contains(l, frag) {
					return -1, "the evidence is a rule list, fixture or test file, which contains these patterns by design"
				}
			}
		}
		return 0, ""
	}},
	{Name: "mirrored-transcript", Check: func(f schema.Finding, _ []schema.Event) (int, string) {
		for _, r := range f.EvidenceRefs {
			if strings.Contains(strings.ToLower(r), "observer-sessions") {
				return -1, "the evidence is a mirrored copy of another session, so the same content is counted more than once"
			}
		}
		return 0, ""
	}},
	{Name: "building-block", Check: func(f schema.Finding, _ []schema.Event) (int, string) {
		if catalog.IsBuildingBlock(f.RuleID) {
			return -1, "this rule describes ordinary agent activity and exists as context for the chain rules"
		}
		return 0, ""
	}},
	{Name: "no-evidence", Check: func(f schema.Finding, _ []schema.Event) (int, string) {
		if len(f.EvidenceRefs) == 0 && len(f.ChainSteps) == 0 {
			return -1, "the finding cites no evidence line"
		}
		return 0, ""
	}},
}

// Group is a set of findings from one rule in one session, which is how an
// analyst actually reads them: 592 HIGH and CRITICAL findings on a real
// machine were 85 groups.
type Group struct {
	RuleID     string   `json:"rule_id"`
	SessionID  string   `json:"session_id,omitempty"`
	Title      string   `json:"title"`
	Severity   string   `json:"severity"`   // worst in the group
	Confidence string   `json:"confidence"` // best in the group
	Count      int      `json:"count"`
	First      string   `json:"first_seen,omitempty"`
	Last       string   `json:"last_seen,omitempty"`
	Members    []string `json:"members"` // evidence refs, capped
	Class      string   `json:"class,omitempty"`
}

var sevRank = map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

// GroupBy collapses findings by rule and session, preserving input order so
// the severity sort that produced them still holds.
func GroupBy(findings []schema.Finding) []Group {
	idx := map[string]*Group{}
	var order []string
	for _, f := range findings {
		k := f.RuleID + "\x00" + f.SessionID
		g, ok := idx[k]
		if !ok {
			g = &Group{RuleID: f.RuleID, SessionID: f.SessionID, Title: f.Title,
				Severity: f.Severity, Confidence: f.Confidence, Class: f.Class}
			idx[k] = g
			order = append(order, k)
		}
		g.Count++
		if sevRank[f.Severity] > sevRank[g.Severity] {
			g.Severity = f.Severity
		}
		if rank[f.Confidence] > rank[g.Confidence] {
			g.Confidence = f.Confidence
		}
		if f.Timestamp != "" {
			if g.First == "" || f.Timestamp < g.First {
				g.First = f.Timestamp
			}
			if g.Last == "" || f.Timestamp > g.Last {
				g.Last = f.Timestamp
			}
		}
		if len(g.Members) < 5 && len(f.EvidenceRefs) > 0 {
			g.Members = append(g.Members, f.EvidenceRefs[0])
		}
	}
	out := make([]Group, 0, len(order))
	for _, k := range order {
		out = append(out, *idx[k])
	}
	return out
}
