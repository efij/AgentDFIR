package gaps

import (
	"bytes"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/correlate"
	"github.com/efij/AgentDFIR/v3/internal/endpoint"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// Calls confirmed by DNS/proxy/auth logs or Windows script-block and
// image-only records are counted under their own source, and the partly
// confirmed ones are counted as partial.
func TestSightingAndEventLogMatchesCountedBySource(t *testing.T) {
	in := baseInput()
	in.Events[3].Corroboration = schema.StatePartial // curl: DNS lookup only
	in.Events[2].Corroboration = schema.StateCorroborated
	in.Events[5].Corroboration = schema.StatePartial // image-only process creation
	in.Correlation = &correlate.EndpointResult{Records: 3, WitnessRecords: 1, Matches: []correlate.Match{
		{EventID: "e4", Witness: correlate.WitnessSighting, Score: 40, WindowMS: 120000, Record: endpoint.Record{Kind: "dns", DestHost: "x.example"}},
		{EventID: "e3", Witness: correlate.WitnessScript, Score: 100, WindowMS: 3000, Record: endpoint.Record{Kind: "script"}},
		{EventID: "e6", Witness: correlate.WitnessProcessImage, Score: 50, WindowMS: 3000, Record: endpoint.Record{Kind: endpoint.KindProcessImage}},
	}}
	r := Build(in, Options{})
	if r.Summary.Verified != 3 || r.Summary.Partial != 2 {
		t.Fatalf("summary: %+v", r.Summary)
	}
	src := map[string]int{}
	for _, s := range r.Witness.Sources {
		src[s.Name] = s.Verified
	}
	if src[srcSightings] != 1 || src[srcEventLog] != 2 || src["endpoint telemetry"] != 0 {
		t.Fatalf("sources: %+v", r.Witness.Sources)
	}
	if !hasItem(r, Known, "1 CONFIRMED, 2 PARTLY CONFIRMED") {
		t.Errorf("known line: %+v", items(r, Known))
	}
	var buf bytes.Buffer
	WriteText(&buf, r)
	if !strings.Contains(buf.String(), "3 confirmed (2 only partly)") {
		t.Errorf("text: %s", buf.String())
	}
}
