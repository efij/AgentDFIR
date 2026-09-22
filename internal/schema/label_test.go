package schema

import "testing"

func TestLabelsCoverEveryState(t *testing.T) {
	states := []string{StateRequested, StateReported, StateObserved, StatePartial,
		StateCorroborated, StateContradicted, StateUnknown}
	for _, s := range states {
		l := Label(s)
		if l == "" || l == s && s != StateUnknown {
			t.Errorf("state %s has no plain label", s)
		}
		if got := StateForLabel(l); got != s {
			t.Errorf("round trip %s -> %s -> %s", s, l, got)
		}
	}
}

// TestLabelPassesUnknownThrough: a pack or a later version may introduce a
// state this build does not know. Swallowing it would hide evidence.
func TestLabelPassesUnknownThrough(t *testing.T) {
	if got := Label("SOMETHING_NEW"); got != "SOMETHING_NEW" {
		t.Errorf("unknown state was rewritten to %q", got)
	}
	if got := Label(""); got != "UNKNOWN" {
		t.Errorf("empty state = %q, want UNKNOWN", got)
	}
}

// TestEnrichedIsNotAState guards the reasoning in label.go: enrichment is
// the action, not the verdict.
func TestEnrichedIsNotAState(t *testing.T) {
	for _, s := range LabelledStates() {
		if s.Label == "ENRICHED" {
			t.Fatal("ENRICHED used as an evidence state; it says nothing about whether the host confirmed or disproved the claim")
		}
	}
}
