package gaps

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/correlate"
	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
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

// Windows event log context kinds are listed as telemetry present and
// kept out of the endpoint telemetry record count.
func TestWindowsContextKindsListed(t *testing.T) {
	in := baseInput()
	in.Correlation = &correlate.EndpointResult{Records: 7, ContextRecords: 4, ContextKinds: map[string]int{"registry": 2, "wmi": 1, "scheduled-task": 1},
		CoverageStart: mustTime("2026-08-30T10:00:00Z"), CoverageEnd: mustTime("2026-08-30T11:00:00Z")}
	r := Build(in, Options{})
	got := map[string]WitnessSource{}
	for _, s := range r.Witness.Sources {
		got[s.Name] = s
	}
	ctx := got["Windows event log context"]
	if ctx.Records != 4 || !strings.Contains(ctx.Note, "registry 2, scheduled-task 1, wmi 1") || got["endpoint telemetry"].Records != 3 {
		t.Fatalf("sources: %+v", r.Witness.Sources)
	}
}

func mustTime(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }

// Per-kind coverage and collection health travel into coverage.json; a
// call left unchecked because its telemetry was PARTIAL says so.
func TestKindCoverageAndHealthListed(t *testing.T) {
	in := baseInput()
	in.Correlation = &correlate.EndpointResult{Records: 2, CoverageStart: mustTime("2026-08-30T10:00:00Z"), CoverageEnd: mustTime("2026-08-30T11:00:00Z"),
		KindCoverage: []correlate.KindCoverage{{Host: "desk-01", Kind: "process", CountsAsCoverage: true, Health: endpoint.HealthPartial}},
		Health:       []endpoint.SourceHealth{{File: "Sysmon.evtx", Gaps: 1, Verdict: endpoint.HealthPartial}},
		Decisions:    []correlate.CoverageDecision{{EventID: "e3", Needs: "process", Coverage: correlate.CoverPartial}}}
	r := Build(in, Options{})
	if len(r.Witness.KindCoverage) != 1 || len(r.Witness.CollectionHealth) != 1 {
		t.Fatalf("witness: %+v", r.Witness)
	}
	if !hasItem(r, Unknown, "Sysmon.evtx is PARTIAL") {
		t.Errorf("items: %+v", items(r, Unknown))
	}
	for _, ac := range r.Witness.Actions {
		if ac.Action == "shell_command" && ac.Reasons[ReasonPartial] != 1 {
			t.Errorf("reasons: %+v", ac)
		}
	}
}
