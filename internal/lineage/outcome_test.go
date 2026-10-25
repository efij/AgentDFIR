package lineage

import (
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/correlate"
	"github.com/efij/AgentDFIR/v4/internal/endpoint"
)

// Effects shown by a record of them become outcome nodes; every edge says
// how it is known.
func TestOutcomeNodesAndAssurance(t *testing.T) {
	g, err := Build(fixture(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	n := nodeOf(g, "outcome:destination_reached:203.0.113.9")
	if n == nil || n.Kind != KindOutcome || !strings.Contains(n.Label, ":443") {
		t.Fatalf("network outcome: %+v", n)
	}
	o := edgeOf(g, "network:203.0.113.9", n.ID, "resulted_in")
	if o == nil || o.Assurance != AssuranceVerified || len(o.Refs) == 0 || o.Refs[0].External == "" || len(o.Limitations) == 0 {
		t.Fatalf("outcome edge: %+v", o)
	}
	if w := nodeOf(g, "outcome:file_written:/w/notes.txt"); w == nil {
		t.Fatalf("host-witness file outcome missing: %+v", g.Nodes)
	}
	want := map[[3]string]string{
		{"tool:e4", "network:exfil.example", "named_destination"}:             AssuranceInferred,
		{"tool:e4", "process:auditd:audit.log:9", "executed_as"}:              AssuranceCorroborated,
		{"agent:sub1", "tool:e4", "invoked"}:                                  AssuranceVerified,
		{"tool:e5", "file:/w/notes.txt", "wrote"}:                             AssuranceCorroborated,
		{"process:auditd:audit.log:9", "network:203.0.113.9", "connected_to"}: AssuranceVerified,
	}
	for k, a := range want {
		if ed := edgeOf(g, k[0], k[1], k[2]); ed == nil || ed.Assurance != a {
			t.Errorf("%v: %+v, want assurance %s", k, ed, a)
		}
	}
	for _, ed := range g.Edges {
		if ed.Assurance == "" {
			t.Errorf("edge without assurance: %+v", ed)
		}
	}
}

// Coverage and collection health travel onto the edges as limitations.
func TestCoverageLimitationsOnEdges(t *testing.T) {
	in := fixture()
	in.Correlation.WindowMS = 3000
	in.Correlation.KindCoverage = []correlate.KindCoverage{{Kind: "process", CountsAsCoverage: true, Health: endpoint.HealthPartial,
		Windows: []correlate.CoverWindow{{Source: "audit.log", Start: t0, End: t0.Add(time.Hour), Sequenced: true}},
		Partial: []correlate.Interval{{Start: t0.Add(9 * time.Second), End: t0.Add(12 * time.Second), Source: "audit.log", Reason: "sequence gap in auditd/audit.log: 4 missing after 9"}}}}
	g, err := Build(in, Options{})
	if err != nil {
		t.Fatal(err)
	}
	ed := edgeOf(g, "tool:e4", "process:auditd:audit.log:9", "executed_as")
	if ed == nil || !strings.Contains(strings.Join(ed.Limitations, "|"), "process telemetry partial: sequence gap") {
		t.Fatalf("executed_as limitations: %+v", ed)
	}
	nd := edgeOf(g, "tool:e4", "network:exfil.example", "named_destination")
	if nd == nil || !strings.Contains(strings.Join(nd.Limitations, "|"), "no network telemetry") {
		t.Fatalf("named_destination limitations: %+v", nd)
	}
	ls := edgeOf(g, "agent:kid", "tool:e7", "invoked")
	if ls == nil || strings.Contains(strings.Join(ls.Limitations, "|"), "partial") {
		t.Fatalf("e7 is outside the gap: %+v", ls)
	}
}
