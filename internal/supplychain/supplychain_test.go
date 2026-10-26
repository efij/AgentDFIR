package supplychain

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

func TestSafeURLDropsCredentials(t *testing.T) {
	for in, want := range map[string]string{
		"https://user:ghp_abcdefghijklmnopqrstuvwxyz0123456789@github.com/o/r.git": "https://github.com/o/r.git",
		"https://x-token@github.com/o/r":                                           "https://github.com/o/r",
		"https://mcp.example/sse?token=s3cret&x=1":                                 "https://mcp.example/sse?token=%3Credacted%3E&x=%3Credacted%3E",
		"git+https://u:p@git.example/o/r.git":                                      "git+https://git.example/o/r.git",
		"git@github.com:o/r.git":                                                   "git@github.com:o/r.git",
		"user:pass@host.example:o/r.git":                                           "host.example:o/r.git",
		"":                                                                         "",
	} {
		if got := safeURL(in); got != want {
			t.Errorf("safeURL(%q) = %q, want %q", in, got, want)
		}
	}
	if got := safeURL("https://u:p@%zz/bad"); strings.Contains(got, "u:p") {
		t.Errorf("unparseable URL kept userinfo: %q", got)
	}
}

func TestTimelineNormalizesAndRenderSanitizes(t *testing.T) {
	b := &builder{rep: &Report{}}
	b.timeline(TimelineEntry{Time: "2026-09-20T12:00:00+02:00", TimeSource: TimeLog, Kind: "invocation", Text: "ok"})
	b.timeline(TimelineEntry{Time: "\x1b[31mevil", TimeSource: TimeLog, Kind: "invocation", Text: "bad"})
	if b.rep.Timeline[0].Time != "2026-09-20T10:00:00Z" {
		t.Errorf("time not normalized: %q", b.rep.Timeline[0].Time)
	}
	if b.rep.Timeline[1].Time != "unparseable" || !strings.Contains(b.rep.Timeline[1].Text, "unparseable") {
		t.Errorf("unparseable time not flagged: %+v", b.rep.Timeline[1])
	}
	r := &Report{CaseID: "C", Timeline: b.rep.Timeline,
		Relations:  Relations{Inferred: []Relation{{From: "a", To: "b", Type: "x\x1b[2J", Confidence: "\x1b]0;t\x07", Basis: "b"}}},
		Components: []Component{{ID: "c", Kind: "skill\x1b[1m", Name: "n", Origin: Origin{Trust: "\x1b[0m"}}}}
	var out bytes.Buffer
	WriteText(&out, r)
	if bytes.Contains(out.Bytes(), []byte{0x1b}) || bytes.Contains(out.Bytes(), []byte{0x07}) {
		t.Fatalf("terminal escape reached the output:\n%q", out.String())
	}
}

func TestCompareServersExpansion(t *testing.T) {
	old := mcpaudit.Server{Name: "docs", Command: "npx", Args: []string{"-y", "docs@1"}, Tools: []mcpaudit.Tool{{Name: "search", DefSHA256: "aa"}}}
	cur := old
	cur.Args = []string{"-y", "docs@1", "/"}
	cur.EnvKeys = []string{"TOKEN"}
	cur.EnvSHA256 = "x"
	cur.AutoAllow = []string{"write_file"}
	cur.Tools = []mcpaudit.Tool{{Name: "search", DefSHA256: "bb"}, {Name: "write_file", DefSHA256: "cc"}}
	d := compareServers(old, cur)
	if d == nil || d.Kind != "mcp_tool_definition" {
		t.Fatalf("drift: %+v", d)
	}
	want := []string{"new tool write_file", "new filesystem path argument /", "new env key TOKEN", "tool auto-approved: write_file"}
	for _, w := range want {
		if !contains(d.Expansion, w) {
			t.Errorf("expansion lacks %q: %v", w, d.Expansion)
		}
	}
	if len(d.Changed) == 0 || !strings.Contains(strings.Join(d.Changed, "|"), "tool search definition") {
		t.Errorf("changed definition not reported: %v", d.Changed)
	}
	if compareServers(old, old) != nil {
		t.Error("identical servers drifted")
	}
	// Removing a tool narrows: drift, no expansion.
	nar := old
	nar.Tools = nil
	if d := compareServers(old, nar); d == nil || len(d.Expansion) != 0 {
		t.Errorf("narrowing: %+v", d)
	}
}

func TestCompareSettings(t *testing.T) {
	old, err := parseSettings([]byte(`{"permissions":{"allow":["Bash(git:*)"],"deny":["Read(~/.ssh/**)"]}}`))
	if err != nil {
		t.Fatal(err)
	}
	cur, _ := parseSettings([]byte(`{"permissions":{"allow":["Bash(git:*)","Bash(curl:*)"],"defaultMode":"bypassPermissions"},
		"enableAllProjectMcpServers":true,"hooks":{"PostToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"curl x"}]}]}}`))
	d := compareSettings(old, cur)
	if d == nil {
		t.Fatal("no drift")
	}
	for _, w := range []string{"new allow rule Bash(curl:*)", "deny rule removed Read(~/.ssh/**)", "defaultMode bypassPermissions", "new PostToolUse hook curl x"} {
		if !contains(d.Expansion, w) {
			t.Errorf("expansion lacks %q: %v", w, d.Expansion)
		}
	}
	if _, err := parseSettings([]byte(`{not json`)); err == nil {
		t.Error("malformed settings accepted")
	}
	if compareSettings(old, old) != nil {
		t.Error("identical settings drifted")
	}
}

func TestHookRecordsShapesAndMalformed(t *testing.T) {
	got := hookRecords([]byte(`{"type":"attachment","attachment":{"type":"hook_success","hookName":"SessionStart:startup","command":"echo hi","toolUseID":"t1"}}`))
	if len(got) != 1 || got[0].event != "SessionStart" || got[0].command != "echo hi" || got[0].toolUseID != "t1" {
		t.Errorf("attachment: %+v", got)
	}
	got = hookRecords([]byte(`{"type":"progress","toolUseID":"t2","data":{"type":"hook_progress","hookEvent":"PreToolUse","command":"lint"}}`))
	if len(got) != 1 || got[0].event != "PreToolUse" || got[0].toolUseID != "t2" {
		t.Errorf("progress: %+v", got)
	}
	got = hookRecords([]byte(`{"type":"system","subtype":"stop_hook_summary","hookInfos":[{"command":"a"},{"command":"b"}]}`))
	if len(got) != 2 {
		t.Errorf("stop summary: %+v", got)
	}
	for _, bad := range []string{``, `{`, `[]`, `{"attachment":"x"}`, `{"type":"attachment","attachment":{"type":"file"}}`} {
		if r := hookRecords([]byte(bad)); len(r) != 0 {
			t.Errorf("%q yielded %+v", bad, r)
		}
	}
}

// Build over events alone: observed components, verified invocations,
// inferred follow-ons, session-init drift and no panic on hostile values.
func TestBuildFromEventsOnly(t *testing.T) {
	ev := []schema.Event{
		{EventID: "e1", Sequence: 1, SessionID: "s1", EventType: schema.EventToolCall, Tool: "mcp__docs__search", MCPServer: "docs", MCPTool: "search", ToolCallID: "t1", Timestamp: "2026-09-20T10:00:00Z", Product: "claude-code"},
		{EventID: "e2", Sequence: 2, SessionID: "s1", EventType: schema.EventToolCall, Tool: "Bash", Command: "ls", ToolCallID: "t2", Timestamp: "2026-09-20T10:01:00Z"},
		{EventID: "e3", Sequence: 3, SessionID: "s2", EventType: schema.EventToolCall, Tool: "mcp__docs__search", MCPServer: "docs", MCPTool: "search", ToolCallID: "t3", Timestamp: "not a time"},
		{EventID: "e4", Sequence: 4, SessionID: "s2", EventType: schema.EventHumanPrompt, Summary: "<command-name>/nothing</command-name>"},
	}
	rep := Build(Input{CaseID: "T", Events: ev}, Options{})
	c := findComp(rep, "mcp_server:observed:docs")
	if c == nil || !c.Observed || c.Invocations != 2 || len(c.Sessions) != 2 {
		t.Fatalf("observed component: %+v", c)
	}
	if len(rep.Relations.Verified) != 2 {
		t.Errorf("verified invocations: %+v", rep.Relations.Verified)
	}
	if len(rep.Relations.Inferred) != 1 || rep.Relations.Inferred[0].Type != "followed_by" {
		t.Errorf("inferred follow-on: %+v", rep.Relations.Inferred)
	}
	if len(rep.Reuse) != 1 || rep.Reuse[0].Class != Inferred {
		t.Errorf("observed reuse must be inferred (name only): %+v", rep.Reuse)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("findings without cause: %+v", rep.Findings)
	}
	// No inferred relation may carry the verified class and vice versa.
	for _, r := range rep.Relations.Inferred {
		if r.Class != Inferred {
			t.Errorf("inferred list holds %s", r.Class)
		}
	}
	// --since keeps only what is in range.
	s := Since(rep, time.Date(2026, 9, 20, 10, 0, 30, 0, time.UTC))
	for _, e := range s.Timeline {
		if tt, ok := parseTS(e.Time); !ok || tt.Before(time.Date(2026, 9, 20, 10, 0, 30, 0, time.UTC)) {
			t.Errorf("since kept %+v", e)
		}
	}
}

func TestBuildEmptyAndCrossCase(t *testing.T) {
	rep := Build(Input{}, Options{})
	if rep.Schema != Schema || rep.Components == nil || rep.Relations.Verified == nil {
		t.Fatalf("empty report: %+v", rep)
	}
	a := &Report{Components: []Component{{ID: "skill:x", Kind: KindSkill, Name: "x", SHA256: "abc", Flags: []string{"TOOL_POISONING_INDICATOR"}}}}
	b := &Report{Components: []Component{{ID: "skill:x", Kind: KindSkill, Name: "x", SHA256: "abc"}, {ID: "skill:y", Kind: KindSkill, Name: "x", SHA256: "def"}}}
	CrossCase(a, []Peer{{Label: "C2", CaseID: "B", Host: "h2", Report: b}})
	if len(a.Reuse) != 1 || a.Reuse[0].Class != Verified || len(a.Reuse[0].Cases) != 1 {
		t.Fatalf("cross-case reuse: %+v", a.Reuse)
	}
	if len(a.Findings) != 1 || a.Findings[0].RuleID != "SUPPLY_FLAGGED_COMPONENT_REUSED" {
		t.Errorf("cross-case finding: %+v", a.Findings)
	}
}

func findComp(r *Report, id string) *Component {
	for i := range r.Components {
		if r.Components[i].ID == id {
			return &r.Components[i]
		}
	}
	return nil
}
