package gaps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/correlate"
	"github.com/efij/AgentDFIR/v3/internal/endpoint"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/witness"
)

var t0 = time.Date(2026, 10, 2, 13, 0, 0, 0, time.UTC)

func at(d time.Duration) string { return t0.Add(d).Format(time.RFC3339) }

type evOpt func(*schema.Event)

func ev(id string, typ string, d time.Duration, opts ...evOpt) schema.Event {
	e := schema.Event{EventID: id, EventType: typ, Timestamp: at(d), SessionID: "S1", AgentID: "main:S1", Host: "hostx",
		Product: "claude-code", SourceArtifact: "aaaaaaaaaaaaaaaa", SourcePath: ".claude/projects/p/S1.jsonl",
		Corroboration: schema.StateObserved}
	var n int
	fmt.Sscanf(id, "e%d", &n)
	e.SourceLine = n
	for _, o := range opts {
		o(&e)
	}
	return e
}

func cmd(c string) evOpt { return func(e *schema.Event) { e.Command = c; e.Action = "shell_execution"; e.Tool = "Bash" } }
func state(s string) evOpt { return func(e *schema.Event) { e.Corroboration = s } }

func baseInput() Input {
	man := &casepkg.Manifest{CaseID: "C1", Host: "hostx", Artifacts: []casepkg.ArtifactRecord{
		{ArtifactID: "aaaaaaaaaaaaaaaa", SourcePath: "/h/.claude/projects/p/S1.jsonl", LogicalPath: ".claude/projects/p/S1.jsonl", Product: "claude-code",
			Status: casepkg.StatusOK, CollectedUTC: at(5 * time.Hour), ModTimeUTC: at(4 * time.Hour), Round: 2, AcquiredIn: 1},
		{ArtifactID: "bbbbbbbbbbbbbbbb", SourcePath: "/h/.claude/settings.json", LogicalPath: ".claude/settings.json", Product: "claude-code",
			Status: casepkg.StatusOK, CollectedUTC: at(5 * time.Hour), Round: 2, AcquiredIn: 2},
		{SourcePath: "/h/.claude/big.jsonl", LogicalPath: ".claude/big.jsonl", Product: "claude-code", Status: casepkg.StatusSkippedBound},
	}}
	events := []schema.Event{
		ev("e1", schema.EventHumanPrompt, 0),
		ev("e2", schema.EventToolCall, 7*time.Second, cmd("ls -la")),
		ev("e3", schema.EventToolCall, 14*time.Second, cmd("make build")),
		ev("e4", schema.EventToolCall, 21*time.Second, cmd("curl https://x.example/a"), func(e *schema.Event) { e.NetworkDest = "x.example" }),
		// 2h40m of silence, then more activity
		ev("e5", schema.EventToolCall, 2*time.Hour+41*time.Minute, cmd("aws s3 rb s3://bucket --force")),
		ev("e6", schema.EventToolCall, 2*time.Hour+41*time.Minute+7*time.Second, cmd("rm -rf build")),
		ev("e7", schema.EventModelResponse, 2*time.Hour+41*time.Minute+14*time.Second, state(schema.StateReported)),
	}
	return Input{CaseID: "C1", Host: "hostx", Manifest: man, CaseInfo: &casepkg.CaseInfo{Rounds: []casepkg.Round{{Round: 1, ArtifactsOK: 2}, {Round: 2, ArtifactsOK: 1, ArtifactsCarried: 1}}},
		Events: events}
}

func items(r *Report, status string) []Item {
	var out []Item
	for _, it := range r.Items {
		if it.Status == status {
			out = append(out, it)
		}
	}
	return out
}

func hasItem(r *Report, status, sub string) bool {
	for _, it := range items(r, status) {
		if strings.Contains(it.Text, sub) || strings.Contains(it.Collect, sub) {
			return true
		}
	}
	return false
}

func TestTimeGapRelativeToCadence(t *testing.T) {
	r := Build(baseInput(), Options{})
	if len(r.Sessions) != 1 {
		t.Fatalf("sessions: %+v", r.Sessions)
	}
	s := r.Sessions[0]
	if len(s.Gaps) != 1 || s.Gaps[0].Seconds != int64((2*time.Hour+41*time.Minute-21*time.Second)/time.Second) {
		t.Fatalf("gaps: %+v", s.Gaps)
	}
	if s.CadenceSeconds != 7 {
		t.Errorf("median spacing = %v, want 7", s.CadenceSeconds)
	}
	if !strings.Contains(s.Gaps[0].BeforeRef, ":4 ") || !strings.Contains(s.Gaps[0].AfterRef, ":5 ") {
		t.Errorf("gap refs: %+v", s.Gaps[0])
	}
	if !hasItem(r, Unknown, "no transcript records for 2h40m") {
		t.Errorf("no plain-language gap item: %+v", items(r, Unknown))
	}
	// A busy session with the same silence but a slow cadence: a pause of
	// under CadenceFactor × median is not reported.
	in := baseInput()
	for i := range in.Events {
		in.Events[i].Timestamp = at(time.Duration(i) * 10 * time.Minute)
	}
	if r := Build(in, Options{}); r.Summary.TimeGaps != 0 {
		t.Errorf("even 10-minute cadence produced gaps: %+v", r.Sessions[0].Gaps)
	}
}

func TestAcquisitionWindowsAndCarriedForward(t *testing.T) {
	r := Build(baseInput(), Options{})
	if len(r.Acquisition.Rounds) != 2 {
		t.Fatalf("rounds: %+v", r.Acquisition.Rounds)
	}
	var w ProductWindow
	for _, p := range r.Acquisition.Products {
		if p.Product == "claude-code" {
			w = p
		}
	}
	if w.Artifacts != 2 || w.Carried != 1 || w.Fresh != 1 || w.NotAcquired[casepkg.StatusSkippedBound] != 1 {
		t.Fatalf("window: %+v", w)
	}
	if w.EarliestEvidence != at(0) || w.LastCollected != at(5*time.Hour) || w.LagSeconds <= 0 {
		t.Errorf("evidence window: %+v", w)
	}
	if !hasItem(r, VerifyNext, "--max-file-mb") || !hasItem(r, Known, "carried forward") {
		t.Errorf("acquisition items: %+v", r.Items)
	}
}

func TestWitnessCoverageReasonsAndCollectNext(t *testing.T) {
	in := baseInput()
	// Telemetry covers only the first burst; e3 matched, e2 did not and is
	// DISPROVED, e4 (network) sits inside with no match.
	in.Events[2].Corroboration = schema.StateCorroborated
	in.Events[1].Corroboration = schema.StateContradicted
	in.Correlation = &correlate.EndpointResult{Records: 10, CoverageStart: t0, CoverageEnd: t0.Add(time.Minute),
		Matches: []correlate.Match{{EventID: "e3", Witness: "endpoint", Score: 100, WindowMS: 3000, DeltaMS: 1200,
			Record: endpoint.Record{Kind: "process", Time: t0.Add(15 * time.Second)}}}}
	r := Build(in, Options{})
	if r.Summary.Verified != 1 || r.Summary.Disproved != 1 || r.Summary.Unverified != 3 {
		t.Fatalf("summary: %+v", r.Summary)
	}
	reasons := map[string]map[string]int{}
	for _, a := range r.Witness.Actions {
		reasons[a.Action] = a.Reasons
	}
	if reasons["network"][ReasonNoMatch] != 1 {
		t.Errorf("network inside coverage without a match: %+v", reasons)
	}
	if reasons["cloud_command"][ReasonNoTelemetry] != 1 || reasons["shell_command"][ReasonNoTelemetry] != 1 {
		t.Errorf("calls outside coverage: %+v", reasons)
	}
	if len(r.Witness.Activity) != 2 || r.Witness.Activity[0].Coverage != "full" || r.Witness.Activity[1].Coverage != "none" {
		t.Fatalf("activity: %+v", r.Witness.Activity)
	}
	if !hasItem(r, VerifyNext, "Process telemetry (Sysmon event 1, auditd EXECVE, EDR process events) covering 2026-10-02 15:41–15:42 UTC on host hostx would verify 1 shell command(s)") {
		t.Errorf("no concrete collection ask: %+v", items(r, VerifyNext))
	}
	if !hasItem(r, VerifyNext, "Cloud audit logs") {
		t.Errorf("no cloud audit ask: %+v", items(r, VerifyNext))
	}
	if r.Clock.EndpointOffset == nil || r.Clock.EndpointOffset.MedianMS != 1200 {
		t.Errorf("endpoint offset: %+v", r.Clock.EndpointOffset)
	}
	if !hasItem(r, Known, "1 of 5 tool call(s) are CONFIRMED") {
		t.Errorf("known confirmation line: %+v", items(r, Known))
	}
}

func TestNoTelemetryIsAStatedGapNotASilence(t *testing.T) {
	r := Build(baseInput(), Options{})
	if !hasItem(r, VerifyNext, "No endpoint telemetry was imported") || !hasItem(r, VerifyNext, "no host witness") {
		t.Errorf("missing witness asks: %+v", items(r, VerifyNext))
	}
	if r.Witness.NarrativeClaims != 1 {
		t.Errorf("narrative claims: %d", r.Witness.NarrativeClaims)
	}
}

func TestClockConsistency(t *testing.T) {
	in := baseInput()
	// a line stamped after the transcript was collected, and a step back
	in.Events = append(in.Events,
		ev("e8", schema.EventToolResult, 9*time.Hour),
		ev("e9", schema.EventToolResult, time.Hour))
	in.Witness = &witness.Record{GatheredUTC: at(5 * time.Hour), Files: []witness.File{{Path: "/w/out.txt", Exists: true, SHA256: "x", ModTimeUTC: at(-time.Hour)}}}
	in.Events = append(in.Events, ev("e10", schema.EventToolCall, 30*time.Second, state(schema.StateCorroborated), func(e *schema.Event) {
		e.Action, e.File, e.WitnessNote = "write_file", "/w/out.txt", "host witness: out.txt exists"
	}))
	r := Build(in, Options{})
	if r.Clock.FutureEvents != 1 {
		t.Errorf("future events: %d", r.Clock.FutureEvents)
	}
	if len(r.Clock.OutOfOrder) != 1 || r.Clock.OutOfOrder[0].Count < 1 {
		t.Errorf("out of order: %+v", r.Clock.OutOfOrder)
	}
	if len(r.Clock.TranscriptMTime) != 1 {
		t.Errorf("transcript mtime before last record: %+v", r.Clock.TranscriptMTime)
	}
	if len(r.Clock.WitnessFiles) != 1 {
		t.Errorf("witness mtime before write: %+v", r.Clock.WitnessFiles)
	}
	if !hasItem(r, Unknown, "timestamps go backwards") {
		t.Errorf("no out-of-order item")
	}
}

func TestAgentChains(t *testing.T) {
	in := baseInput()
	in.Events = append(in.Events,
		// spawn of a subagent that left no records
		ev("e20", schema.EventAgentSpawn, time.Minute, func(e *schema.Event) { e.TaskID = "ghost"; e.ToolCallID = "toolu_x" }),
		// a result whose call is not in the case
		ev("e21", schema.EventToolResult, time.Minute, func(e *schema.Event) { e.ToolCallID = "toolu_missing" }),
		ev("e22", schema.EventSessionMeta, time.Minute, func(e *schema.Event) { e.Result = "chain_break" }),
		ev("e23", schema.EventToolCall, time.Minute, func(e *schema.Event) { e.AgentID = "child"; e.ParentAgentID = "nobody" }),
	)
	in.Findings = []schema.Finding{{RuleID: "ORPHAN_AGENT", AgentID: "orph", SessionID: "S2", EvidenceRefs: []string{"x.jsonl:1 (artifact a, offset 0)"}},
		{RuleID: "TRANSCRIPT_REWRITTEN", SessionID: "S1", EvidenceRefs: []string{"S1.jsonl:3"}}}
	r := Build(in, Options{})
	c := r.Chains
	if len(c.Orphans) != 1 || len(c.MissingSubagents) != 1 || len(c.SpawnWithoutCall) != 1 || len(c.ResultsWithoutCall) != 1 ||
		len(c.BrokenDAG) != 1 || len(c.UnknownParents) != 1 {
		t.Fatalf("chains: %+v", c)
	}
	if !hasItem(r, VerifyNext, "agent-ghost.jsonl") || !hasItem(r, VerifyNext, "parent transcript holds the spawn record") {
		t.Errorf("chain asks: %+v", items(r, VerifyNext))
	}
	found := false
	for _, s := range r.Integrity {
		if s.Code == "TRANSCRIPT_REWRITTEN" && s.SessionID == "S1" {
			found = true
		}
	}
	if !found {
		t.Errorf("integrity: %+v", r.Integrity)
	}
}

// Same input, same bytes: the report goes into the case and the explorer.
func TestDeterministic(t *testing.T) {
	a, _ := json.Marshal(Build(baseInput(), Options{}))
	for i := 0; i < 5; i++ {
		b, _ := json.Marshal(Build(baseInput(), Options{}))
		if !bytes.Equal(a, b) {
			t.Fatal("coverage output is not deterministic")
		}
	}
}

func TestEmptyAndHostileInput(t *testing.T) {
	r := Build(Input{}, Options{})
	if r.Schema != Schema || r.Items == nil || r.Sessions == nil || len(r.Limits) == 0 {
		t.Fatalf("empty input: %+v", r)
	}
	// garbage timestamps, empty ids, a huge number of tiny gaps: bounded
	var evs []schema.Event
	for i := 0; i < 2000; i++ {
		e := ev(fmt.Sprintf("e%d", i), schema.EventToolCall, time.Duration(i)*time.Hour, cmd("x"))
		if i%7 == 0 {
			e.Timestamp = "not-a-time"
		}
		evs = append(evs, e)
	}
	evs = append(evs, schema.Event{EventType: schema.EventToolCall})
	r = Build(Input{Events: evs}, Options{})
	if len(r.Sessions[0].Gaps) > 20 || !r.Truncated {
		t.Errorf("gaps unbounded: %d (truncated %v)", len(r.Sessions[0].Gaps), r.Truncated)
	}
	var buf bytes.Buffer
	WriteText(&buf, r)
	if !strings.Contains(buf.String(), "UNKNOWN") {
		t.Error("text render missing sections")
	}
}
