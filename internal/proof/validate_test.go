package proof

import (
	"bytes"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/correlate"
	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/lineage"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// A crafted overlay: escape sequences in vocabulary fields, an
// unparseable timestamp and a short telemetry hash. The report must
// neither pass the escapes to the terminal nor panic.
func TestCraftedOverlayIsNeutralized(t *testing.T) {
	esc := "\x1b]0;pwned\x07\x1b[2J"
	ev := schema.Event{EventID: "e1", EventType: schema.EventToolCall, Tool: "Bash" + esc, Command: "ls", Timestamp: "yesterday" + esc,
		Corroboration: "CORROBORATED" + esc, AgentID: "a", SessionID: "s"}
	g := &lineage.Graph{
		Nodes: []lineage.Node{{ID: "agent:a", Kind: "agent", Label: "a"}, {ID: "tool:e1", Kind: "tool_call", Label: "Bash"},
			{ID: "process:x", Kind: "process" + esc, Label: "p" + esc}},
		Edges: []lineage.Edge{
			{From: "agent:a", To: "tool:e1", Relation: "invoked", State: "OBSERVED", Assurance: "verified" + esc},
			{From: "tool:e1", To: "process:x", Relation: "executed_as" + esc, State: "CORROBORATED", Confidence: "HIGH" + esc,
				Refs: []lineage.Ref{{External: "auditd audit.log:1"}}},
		},
	}
	corr := &correlate.EndpointResult{Records: 1, WindowMS: 3000,
		Health: []endpoint.SourceHealth{{File: "audit.log", SHA256: "abc" + esc, Verdict: "HEALTHY" + esc,
			Drops: []endpoint.DropSignal{{Signal: "rate-limit" + esc, Detail: "d" + esc}}}},
		KindCoverage: []correlate.KindCoverage{{Kind: "process" + esc, Health: "PARTIAL" + esc}},
		Matches:      []correlate.Match{{EventID: "e1", SourceFile: "audit.log", Record: endpoint.Record{Source: "auditd", Ref: "audit.log:1"}}},
		Decisions:    []correlate.CoverageDecision{{EventID: "e1", Needs: "process", Coverage: "healthy" + esc, Reason: "r" + esc}},
	}
	r := Build(Input{CaseID: "C" + esc, Events: []schema.Event{ev}, Correlation: corr, Graph: g}, Options{})
	var buf bytes.Buffer
	WriteText(&buf, r) // must not panic on the short hash
	if out := buf.String(); strings.ContainsRune(out, 0x1b) || strings.ContainsRune(out, 0x07) {
		t.Fatalf("escape sequence reached the terminal:\n%q", out)
	}
	a := r.Actions[0]
	if a.Timestamp != Invalid || a.State != Invalid || a.StateLabel != Invalid || a.Coverage[0].Coverage != Invalid {
		t.Fatalf("action not neutralized: %+v", a)
	}
	if r.Telemetry.Sources[0].SHA256 != "" || r.Telemetry.Sources[0].Verdict != Invalid || r.Telemetry.Coverage[0].Health != Invalid {
		t.Fatalf("telemetry not neutralized: %+v", r.Telemetry)
	}
	for _, s := range a.Chain {
		for _, ref := range s.Refs {
			if ref.TelemetrySHA256 != "" {
				t.Fatalf("short hash kept: %+v", ref)
			}
		}
	}
	if len(r.Notes) == 0 {
		t.Fatal("no note about malformed values")
	}
}

// Valid timestamps are normalized to RFC 3339 UTC.
func TestTimestampNormalized(t *testing.T) {
	r := Build(Input{Events: []schema.Event{{EventID: "e1", EventType: schema.EventToolCall, Tool: "Bash", Command: "ls",
		Timestamp: "2026-08-30T12:00:00+02:00", Corroboration: schema.StateObserved}}}, Options{})
	if r.Actions[0].Timestamp != "2026-08-30T10:00:00Z" || len(r.Notes) != 0 {
		t.Fatalf("%+v %v", r.Actions[0], r.Notes)
	}
}
