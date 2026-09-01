package detect

// MVP acceptance test (plan §30): the full pipeline against the
// synthetic orphan-agent scenario —
// simulate → collect → verify → normalize → detect —
// asserting every §30 requirement that applies at this phase.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/parsers/claudejsonl"
	"github.com/efij/AgentDFIR/internal/products"
	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/simulate"
)

func runPipeline(t *testing.T) (*claudejsonl.Result, []schema.Finding, string) {
	t.Helper()
	profile := filepath.Join(t.TempDir(), "victim")
	if err := simulate.OrphanAgent(profile); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := casepkg.New(pkg, "MVP-001", casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	man, err := products.Manifest("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Run(b, man, collector.Options{
		ProfileRoot: profile,
		ConfigRoot:  filepath.Join(profile, ".claude"),
		SystemRoot:  profile,
		Product:     "claude-code",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	// §30.2 — hashes preserved and verifiable.
	vres, err := casepkg.Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(vres.Problems) != 0 {
		t.Fatalf("package verification failed: %v", vres.Problems)
	}
	res, err := claudejsonl.ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return res, Run(res), pkg
}

func TestMVPAcceptance(t *testing.T) {
	res, findings, _ := runPipeline(t)

	// §30.3 — both agents reconstructed.
	agents := map[string]bool{}
	for _, e := range res.Entities {
		if e.Kind == "agent" {
			agents[strings.TrimPrefix(e.EntityID, "agent:")] = true
		}
	}
	if !agents["a7c3f19b"] || !agents["adad4e2c"] {
		t.Fatalf("agents not reconstructed: %v", agents)
	}

	// §30.4 — relationship reconstructed: Agent A's spawn is evidenced,
	// and the graph links agents to sessions with evidence-backed edges.
	spawned := res.SpawnEvidence()
	if _, ok := spawned["a7c3f19b"]; !ok {
		t.Fatal("Agent A spawn evidence missing")
	}

	// §30.5 — missing parentage identified for Agent B.
	var orphan *schema.Finding
	for i := range findings {
		if findings[i].RuleID == "ORPHAN_AGENT" && findings[i].AgentID == "adad4e2c" {
			orphan = &findings[i]
		}
	}
	if orphan == nil {
		t.Fatal("ORPHAN_AGENT finding for Agent B missing")
	}
	if orphan.Severity != "HIGH" || orphan.ParentAgentID != "UNKNOWN" {
		t.Fatalf("orphan finding wrong: sev=%s parent=%s", orphan.Severity, orphan.ParentAgentID)
	}
	// Agent A must NOT be flagged as orphan.
	for _, f := range findings {
		if f.RuleID == "ORPHAN_AGENT" && f.AgentID == "a7c3f19b" {
			t.Fatal("legitimately spawned Agent A incorrectly flagged as orphan")
		}
	}

	// §30.6 — unexpected cross-agent communication flagged, HIGH
	// because the sender is unverified.
	var cross *schema.Finding
	for i := range findings {
		if findings[i].RuleID == "CROSS_SESSION_MESSAGE" {
			cross = &findings[i]
		}
	}
	if cross == nil {
		t.Fatal("CROSS_SESSION_MESSAGE finding missing")
	}
	if cross.Severity != "HIGH" {
		t.Fatalf("cross-agent finding severity = %s, want HIGH (orphan sender)", cross.Severity)
	}
	if len(cross.Related) == 0 || !strings.Contains(cross.Related[0], "a7c3f19b") {
		t.Fatalf("cross-agent finding does not name target agent: %v", cross.Related)
	}

	// §30.7 — exact source evidence shown on every finding.
	for _, f := range findings {
		if len(f.EvidenceRefs) == 0 {
			t.Fatalf("finding %s has no evidence refs", f.RuleID)
		}
		for _, ref := range f.EvidenceRefs {
			if !strings.Contains(ref, ".jsonl:") || !strings.Contains(ref, "artifact") {
				t.Fatalf("evidence ref not traceable: %q", ref)
			}
		}
	}

	// §30.8 — model narrative distinguished from tool events: Agent B's
	// "I executed curl" claim is REPORTED; no OBSERVED Bash call exists
	// for Agent B.
	var claimSeen bool
	for _, ev := range res.Events {
		if ev.AgentID == "adad4e2c" {
			if ev.EventType == schema.EventModelResponse && strings.Contains(ev.Summary, "curl") {
				claimSeen = true
				if ev.Corroboration != schema.StateReported {
					t.Fatalf("model claim state = %s, want REPORTED", ev.Corroboration)
				}
			}
			if ev.EventType == schema.EventToolCall && ev.Action == "shell_execution" {
				t.Fatal("no Bash call should exist for Agent B — claim is narrative only")
			}
		}
	}
	if !claimSeen {
		t.Fatal("Agent B's execution claim not parsed")
	}

	// §30.9 — endpoint corroboration explicitly UNKNOWN (valid state).
	if orphan.Endpoint != schema.StateUnknown {
		t.Fatalf("endpoint corroboration = %s, want UNKNOWN", orphan.Endpoint)
	}

	// §30.10 — IR-ready timeline: every event traceable to evidence.
	if len(res.Events) == 0 {
		t.Fatal("no timeline events")
	}
	for _, ev := range res.Events {
		if ev.SourceArtifact == "" || ev.SourceLine == 0 {
			t.Fatalf("event %s not traceable to evidence", ev.EventID)
		}
	}

	// §30 closing rule — findings never auto-escalate to conclusions.
	for _, f := range findings {
		up := strings.ToUpper(f.Title + " " + f.Description)
		for _, banned := range []string{"COMPROMISE", "HIJACK", "EXFILTRATION"} {
			if strings.Contains(up, banned) {
				t.Fatalf("finding auto-escalates to %q without evidence: %s", banned, f.Title)
			}
		}
	}
}

// §30.11 (review addition) — a tampered/truncated transcript must
// surface as TRACE_GAP, downgrading confidence.
func TestTamperedTranscriptYieldsTraceGap(t *testing.T) {
	profile := filepath.Join(t.TempDir(), "victim")
	if err := simulate.OrphanAgent(profile); err != nil {
		t.Fatal(err)
	}
	// Truncate/corrupt one transcript line before collection.
	sess := filepath.Join(profile, ".claude", "projects", "-Users-dev-app", "agent-adad4e2c.jsonl")
	appendLine(t, sess, `{"type":"assistant","broken JSON here`)

	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := casepkg.New(pkg, "MVP-002", casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	man, _ := products.Manifest("claude-code")
	if _, err := collector.Run(b, man, collector.Options{
		ProfileRoot: profile, ConfigRoot: filepath.Join(profile, ".claude"),
		SystemRoot: profile, Product: "claude-code",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	res, err := claudejsonl.ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	findings := Run(res)
	for _, f := range findings {
		if f.RuleID == "TRACE_GAP" {
			return
		}
	}
	t.Fatal("corrupted transcript line did not produce a TRACE_GAP finding")
}

func appendLine(t *testing.T, path, line string) {
	t.Helper()
	f, err := osOpenAppend(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if _, err := f.WriteString(line + "\n"); err != nil {
		t.Fatal(err)
	}
}

func osOpenAppend(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o644)
}
