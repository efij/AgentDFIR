package benchmark

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// TestQuickBenchmark runs the fast subset end to end: a sample of the
// detection fixtures, and every evidence-state scenario, integrity
// mutation, historical package and robustness case. Performance is never
// measured in `go test`; wall time is not a property of the code alone.
func TestQuickBenchmark(t *testing.T) {
	r, err := Run(Options{Quick: true, Work: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Passed() {
		t.Fatalf("hard checks failed:\n  %s", strings.Join(r.Failures, "\n  "))
	}
	if r.Label != Label || !strings.Contains(r.Label, "SYNTHETIC") {
		t.Fatalf("report not labelled synthetic: %q", r.Label)
	}
	if r.Performance != nil {
		t.Fatal("quick subset measured performance")
	}
	if r.Detection.AttackCases+r.Detection.Scenarios == 0 || r.Detection.BenignCases == 0 {
		t.Fatalf("detection sample is empty: %+v", r.Detection)
	}
	if r.Detection.RuleUniverse < 100 || len(r.Detection.Uncovered) == 0 {
		t.Fatalf("coverage not computed: universe %d, uncovered %d", r.Detection.RuleUniverse, len(r.Detection.Uncovered))
	}
	in := r.Integrity
	if in.Total != len(Mutations()) || in.Detected != in.Total {
		t.Fatalf("mutations detected %d/%d (suite has %d): undetected %v", in.Detected, in.Total, len(Mutations()), in.Undetected)
	}
	if !strings.Contains(in.Reference, "chunked artifact: true") {
		t.Fatalf("reference package does not exercise chunked artifacts: %s", in.Reference)
	}
	if r.Evidence.Total == 0 || r.Evidence.Passed != r.Evidence.Total {
		t.Fatalf("evidence states: %d/%d", r.Evidence.Passed, r.Evidence.Total)
	}
	if r.Provenance.Events == 0 || r.Provenance.Refs == 0 || r.Provenance.Dangling() != 0 {
		t.Fatalf("provenance: %+v", r.Provenance)
	}
	if r.Compat.Total < 5 || r.Compat.OK != r.Compat.Total {
		t.Fatalf("compatibility: %d/%d", r.Compat.OK, r.Compat.Total)
	}
	if r.Robustness.Total == 0 || r.Robustness.Passed != r.Robustness.Total {
		t.Fatalf("robustness: %d/%d", r.Robustness.Passed, r.Robustness.Total)
	}

	var md, js bytes.Buffer
	if err := r.WriteMarkdown(&md); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(md.String(), "SYNTHETIC") || !strings.Contains(md.String(), "not evidence of real-world accuracy") {
		t.Fatal("markdown report does not carry the synthetic label")
	}
	if err := r.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || !strings.Contains(back["label"].(string), "SYNTHETIC") {
		t.Fatalf("json report: %v", err)
	}
}

// TestContractCatchesUnsupportedPromotion: the checker itself must flag
// each kind of violation, or a passing benchmark proves nothing.
func TestContractCatchesUnsupportedPromotion(t *testing.T) {
	events := []schema.Event{
		{EventID: "ok-confirmed", EventType: schema.EventToolCall, Corroboration: schema.StateCorroborated, Summary: "corroborated by auditd process (audit.log:2)"},
		{EventID: "ok-host", EventType: schema.EventToolCall, Corroboration: schema.StateCorroborated, WitnessNote: "the file is on disk with the written content"},
		{EventID: "bad-confirmed", EventType: schema.EventToolCall, Corroboration: schema.StateCorroborated},
		{EventID: "bad-narrative", EventType: schema.EventModelResponse, Corroboration: schema.StateCorroborated, WitnessNote: "x"},
		{EventID: "bad-disproved", EventType: schema.EventToolCall, Corroboration: schema.StateContradicted, Summary: "no matching process in endpoint telemetry"},
		{EventID: "claim", EventType: schema.EventModelResponse, Corroboration: schema.StateReported},
	}
	got := strings.Join(contractViolations(events, false), "\n")
	for _, id := range []string{"bad-confirmed", "bad-narrative", "bad-disproved"} {
		if !strings.Contains(got, id) {
			t.Errorf("%s not flagged:\n%s", id, got)
		}
	}
	for _, id := range []string{"ok-confirmed", "ok-host", "claim"} {
		if strings.Contains(got, id+" ") {
			t.Errorf("%s flagged:\n%s", id, got)
		}
	}
	// With endpoint telemetry given, the contradiction is supported.
	if v := contractViolations(events[4:5], true); len(v) != 0 {
		t.Errorf("endpoint-backed contradiction flagged: %v", v)
	}
}

// TestProvenanceCatchesDanglingReferences: likewise for provenance.
func TestProvenanceCatchesDanglingReferences(t *testing.T) {
	work := t.TempDir()
	profile := filepath.Join(work, "home")
	s := newSession("eeeeeeee-0001-4000-8000-000000000001", t0)
	s.user(0, "hello")
	s.bash(1, "ls", "x")
	if _, err := s.write(profile); err != nil {
		t.Fatal(err)
	}
	pkg, err := collect(work, "p", profile, []string{"claude-code"})
	if err != nil {
		t.Fatal(err)
	}
	ix, err := newPkgIndex(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var art string
	var path string
	for id, a := range ix.byID {
		if strings.HasSuffix(a.LogicalPath, ".jsonl") {
			art, path = id, a.LogicalPath
		}
	}
	if art == "" {
		t.Fatal("transcript not collected")
	}
	a := &analyzed{pkg: pkg,
		events: []schema.Event{
			{EventID: "good", SourceArtifact: art, SourceLine: 2, SourceOffset: int64(len(s.lines[0]) + 1)},
			{EventID: "missing", SourceArtifact: strings.Repeat("0", 64), SourceLine: 1},
			{EventID: "past-end", SourceArtifact: art, SourceLine: 99},
			{EventID: "offset", SourceArtifact: art, SourceLine: 2, SourceOffset: 3},
		},
		findings: []schema.Finding{
			{RuleID: "GOOD", EvidenceRefs: []string{path + ":1 (artifact " + art[:12] + ", offset 0)"}},
			{RuleID: "BAD_ART", EvidenceRefs: []string{"x.jsonl:1 (artifact 000000000000, offset 0)"}},
			{RuleID: "BAD_LINE", EvidenceRefs: []string{path + ":500"}},
			{RuleID: "NOTHING"},
			{RuleID: "CHAIN", ChainSteps: []schema.ChainStep{{Step: "s", EventID: "nope"}}},
		}}
	c := newProvenanceChecker()
	c.check("t", a)
	p := c.result()
	if p.EventsResolved != 1 || p.EventsDanglingArtifact != 1 || p.EventsLineOutOfRange != 1 || p.EventsOffsetMismatch != 1 {
		t.Errorf("events: %+v", p)
	}
	if p.RefsResolved != 1 || p.RefsDangling != 2 || p.FindingsUnreferenced != 1 || p.ChainStepsDangling != 1 {
		t.Errorf("findings: %+v", p)
	}
	if p.Dangling() != 7 {
		t.Errorf("dangling = %d, want 7", p.Dangling())
	}
}

func TestEmbeddedBaselineParses(t *testing.T) {
	b, err := EmbeddedBaseline()
	if err != nil {
		t.Fatal(err)
	}
	if b.Sessions <= 0 || b.AnalyzeMS <= 0 || b.PeakHeapMB <= 0 {
		t.Fatalf("baseline has no numbers: %+v", b)
	}
	data, _ := os.ReadFile("testdata/perf-baseline.json")
	if !bytes.Contains(data, []byte(`"sessions"`)) {
		t.Fatal("baseline file unreadable")
	}
}
