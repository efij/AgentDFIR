package report

import (
	"encoding/json"
	"fmt"

	"github.com/efij/AgentDFIR/v4/internal/redact"
)

// RedactCase returns a redacted deep copy of c for derivative outputs. The
// input is left untouched, and nothing here reads or writes the package:
// redaction applies to what is rendered from evidence, never to evidence.
// Locations in the log name the item (event id, finding rule and index) and
// the field, so a reviewer can see where text was masked without the
// value. A nil Redactor returns c itself.
func RedactCase(c *Case, r *redact.Redactor) (*Case, error) {
	if r == nil || c == nil {
		return c, nil
	}
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	var out Case
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	out.GeneratedAt = c.GeneratedAt
	for i := range out.Events {
		r.Walk(&out.Events[i], "event "+out.Events[i].EventID)
	}
	for i := range out.Findings {
		r.Walk(&out.Findings[i], fmt.Sprintf("finding %s#%d", out.Findings[i].RuleID, i))
	}
	for i := range out.Entities {
		r.Walk(&out.Entities[i], "entity "+out.Entities[i].EntityID)
	}
	r.Walk(&out.Manifest, "manifest")
	r.Walk(&out.CaseInfo, "case")
	r.Walk(&out.Verify, "verify")
	r.Walk(&out.Notes, "notes")
	return &out, nil
}

// RedactCustody masks the custody excerpt the PDF prints.
func RedactCustody(recs []CustodyRecord, r *redact.Redactor) []CustodyRecord {
	if r == nil {
		return recs
	}
	out := make([]CustodyRecord, len(recs))
	copy(out, recs)
	for i := range out {
		r.Walk(&out[i], fmt.Sprintf("custody #%d", out[i].Seq))
	}
	return out
}
