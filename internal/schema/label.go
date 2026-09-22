package schema

// Plain-English labels for evidence states.
//
// The stored values stay exactly as they are: `.adfir` is a published
// format, packages exist in the wild, and OCSF/SARIF/STIX exports feed
// other people's systems. What changes is every place a human reads them.
//
// "Corroborated" and "reported" are precise but they are not the words a
// responder reaches for at 3 a.m. These are:
//
//	ASKED            a human asked for it
//	CLAIMED          the model said it happened — narrative, not proof
//	RECORDED         a tool-call record exists in the transcript
//	PARTLY CONFIRMED part of it matched a second source
//	CONFIRMED        an independent source confirms it
//	DISPROVED        an independent source says it did not happen
//
// The feature that produces them is called enrich, or a second witness.
// Note that "enriched" is deliberately NOT one of the labels: enrichment
// is the action, and the label has to say whether the host confirmed or
// disproved the claim, or it carries no information at all.
var stateLabels = map[string]string{
	StateRequested:    "ASKED",
	StateReported:     "CLAIMED",
	StateObserved:     "RECORDED",
	StatePartial:      "PARTLY CONFIRMED",
	StateCorroborated: "CONFIRMED",
	StateContradicted: "DISPROVED",
	StateUnknown:      "UNKNOWN",
}

// Label renders an evidence state for a human. Unknown values pass
// through unchanged so a pack or a future state is never swallowed.
func Label(state string) string {
	if l, ok := stateLabels[state]; ok {
		return l
	}
	if state == "" {
		return "UNKNOWN"
	}
	return state
}

// StateForLabel maps a plain label back to its stored value, so a UI
// filter built from labels still queries the real field. Returns the input
// unchanged when it is already a stored value.
func StateForLabel(label string) string {
	for state, l := range stateLabels {
		if l == label {
			return state
		}
	}
	return label
}

// LabelledStates lists the stored states in reporting order, weakest
// evidence first, with their labels.
func LabelledStates() []struct{ State, Label string } {
	order := []string{StateRequested, StateReported, StateObserved, StatePartial, StateCorroborated, StateContradicted, StateUnknown}
	out := make([]struct{ State, Label string }, 0, len(order))
	for _, s := range order {
		out = append(out, struct{ State, Label string }{s, stateLabels[s]})
	}
	return out
}
