package verify

import (
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// TestSeverityIsNeverChanged is the invariant the whole split rests on:
// severity is impact if true, confidence is likelihood it is true, and a
// verifier may only move the second.
func TestSeverityIsNeverChanged(t *testing.T) {
	in := []schema.Finding{
		{RuleID: "SHELL_EXECUTION", Severity: "INFO", EvidenceRefs: []string{"a.jsonl:1"}},
		{RuleID: "CHAIN_SECRET_TO_EXFIL", Severity: "CRITICAL", EvidenceRefs: []string{"b.jsonl:2"}},
	}
	out := Apply(in, nil)
	for i := range out {
		if out[i].Severity != in[i].Severity {
			t.Errorf("%s severity changed %s -> %s", in[i].RuleID, in[i].Severity, out[i].Severity)
		}
		if out[i].Confidence == "" {
			t.Errorf("%s has no confidence", in[i].RuleID)
		}
	}
}

// TestEveryAdjustmentCarriesAReason: a confidence an analyst cannot
// interrogate is worse than none.
func TestEveryAdjustmentCarriesAReason(t *testing.T) {
	out := Apply([]schema.Finding{
		{RuleID: "TOOL_POISONING_INDICATOR", Severity: "HIGH",
			EvidenceRefs: []string{".claude/plugins/cache/runwall/SIGNATURES.md (artifact ab, byte offset 1)"}},
	}, nil)
	f := out[0]
	if f.Confidence != Low {
		t.Errorf("confidence = %s, want %s for a security tool's own rule list", f.Confidence, Low)
	}
	if len(f.Reasons) == 0 {
		t.Fatal("confidence was lowered with no reason given")
	}
	for _, r := range f.Reasons {
		if len(r) < 20 {
			t.Errorf("reason is not a sentence: %q", r)
		}
	}
}

// TestHostWitnessRaisesConfidence: the point of v1.9.0 feeding into v2.0.0.
func TestHostWitnessRaisesConfidence(t *testing.T) {
	ev := []schema.Event{{EventID: "e1", Corroboration: schema.StateCorroborated}}
	out := Apply([]schema.Finding{{
		RuleID: "AGENT_SELF_MODIFICATION", Severity: "HIGH",
		EvidenceRefs: []string{"s.jsonl:9"},
		ChainSteps:   []schema.ChainStep{{EventID: "e1"}},
	}}, ev)
	if out[0].Confidence != High {
		t.Fatalf("confidence = %s, want HIGH when the host confirms it", out[0].Confidence)
	}
}

// TestGroupingCollapsesByRuleAndSession reproduces the shape that turns 592
// findings into 85 rows.
func TestGroupingCollapsesByRuleAndSession(t *testing.T) {
	var in []schema.Finding
	for i := 0; i < 20; i++ {
		in = append(in, schema.Finding{RuleID: "ORPHAN_AGENT", Severity: "HIGH",
			SessionID: "s1", Confidence: Medium, Timestamp: "2026-09-16T10:0" + string(rune('0'+i%10)) + ":00Z",
			EvidenceRefs: []string{"a.jsonl:1"}})
	}
	in = append(in, schema.Finding{RuleID: "ORPHAN_AGENT", Severity: "CRITICAL",
		SessionID: "s2", Confidence: High, EvidenceRefs: []string{"b.jsonl:2"}})

	groups := GroupBy(in)
	if len(groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(groups))
	}
	if groups[0].Count != 20 {
		t.Errorf("first group count = %d, want 20", groups[0].Count)
	}
	if groups[1].Severity != "CRITICAL" || groups[1].Confidence != High {
		t.Errorf("group did not take the worst severity and best confidence: %+v", groups[1])
	}
	if groups[0].First == "" || groups[0].Last == "" {
		t.Error("group has no time span")
	}
	if len(groups[0].Members) > 5 {
		t.Error("member list is unbounded")
	}
}
