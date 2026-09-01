package claudejsonl

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/products"
	"github.com/efij/AgentDFIR/internal/schema"
)

// buildPkgFromSessions writes session files into a Claude profile,
// collects and seals, and returns the parsed result. Covers the
// remaining plan §28 scenarios with dedicated assertions.
func buildPkgFromSessions(t *testing.T, sessions map[string]string) *Result {
	t.Helper()
	root := t.TempDir()
	for name, content := range sessions {
		p := filepath.Join(root, ".claude", "projects", "-p", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg := filepath.Join(t.TempDir(), "c.adfir")
	b, err := casepkg.New(pkg, "EDGE", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	man, _ := products.Manifest("claude-code")
	if _, err := collector.Run(b, man, collector.Options{
		ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"),
		SystemRoot: root, Product: "claude-code",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	res, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// §28: huge transcript — a single line over the parser bound must not
// crash; it becomes a bounded trace_gap, and other lines still parse.
func TestHugeTranscriptLineBounded(t *testing.T) {
	huge := strings.Repeat("A", MaxLineBytes+100)
	content := `{"type":"user","sessionId":"s","timestamp":"2026-08-30T10:00:00Z","message":{"role":"user","content":"` + huge + `"}}` + "\n" +
		`{"type":"assistant","sessionId":"s","timestamp":"2026-08-30T10:00:01Z","message":{"role":"assistant","content":[{"type":"text","text":"ok"}]}}` + "\n"
	res := buildPkgFromSessions(t, map[string]string{"huge.jsonl": content})
	gap, normal := false, false
	for _, ev := range res.Events {
		if ev.EventType == schema.EventTraceGap {
			gap = true
		}
		if ev.EventType == schema.EventModelResponse {
			normal = true
		}
	}
	if !gap {
		t.Fatal("oversized line did not become a trace_gap")
	}
	if !normal {
		t.Fatal("parser did not recover to parse the following line")
	}
}

// §28: duplicate events — identical lines must each get a distinct
// event_id and sequence (no silent dedupe that would hide replay).
func TestDuplicateEventsRetained(t *testing.T) {
	line := `{"type":"assistant","sessionId":"s","timestamp":"2026-08-30T10:00:00Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}`
	content := line + "\n" + line + "\n"
	res := buildPkgFromSessions(t, map[string]string{"dup.jsonl": content})
	var toolCalls []schema.Event
	for _, ev := range res.Events {
		if ev.EventType == schema.EventToolCall {
			toolCalls = append(toolCalls, ev)
		}
	}
	if len(toolCalls) != 2 {
		t.Fatalf("expected 2 tool-call events, got %d", len(toolCalls))
	}
	if toolCalls[0].EventID == toolCalls[1].EventID {
		t.Fatal("duplicate events share an event_id")
	}
	if toolCalls[0].Sequence == toolCalls[1].Sequence {
		t.Fatal("duplicate events share a sequence number")
	}
}

// §28: clock skew — out-of-order timestamps are preserved verbatim
// (never rewritten); ordering is the timeline's job via sequence.
func TestClockSkewPreservesTimestamps(t *testing.T) {
	content := `{"type":"user","sessionId":"s","timestamp":"2026-08-30T10:05:00Z","message":{"role":"user","content":"later ts first"}}` + "\n" +
		`{"type":"assistant","sessionId":"s","timestamp":"2026-08-30T09:00:00Z","message":{"role":"assistant","content":[{"type":"text","text":"earlier ts second"}]}}` + "\n"
	res := buildPkgFromSessions(t, map[string]string{"skew.jsonl": content})
	if len(res.Events) < 2 {
		t.Fatal("expected 2 events")
	}
	// Timestamps preserved exactly as recorded, in file order.
	if res.Events[0].Timestamp != "2026-08-30T10:05:00Z" ||
		res.Events[1].Timestamp != "2026-08-30T09:00:00Z" {
		t.Fatal("timestamps were altered")
	}
	// Sequence is monotonic regardless of timestamp skew.
	if res.Events[1].Sequence <= res.Events[0].Sequence {
		t.Fatal("sequence not monotonic under clock skew")
	}
}

// §28: multiple users / multiple sessions — events retain their distinct
// session identity and each entity is reconstructed.
func TestMultipleSessionsSeparated(t *testing.T) {
	sessions := map[string]string{}
	for i := 0; i < 3; i++ {
		sid := fmt.Sprintf("sess-%d", i)
		sessions[sid+".jsonl"] = fmt.Sprintf(
			`{"type":"user","sessionId":"%s","timestamp":"2026-08-30T10:0%d:00Z","message":{"role":"user","content":"hi from %s"}}`,
			sid, i, sid) + "\n"
	}
	res := buildPkgFromSessions(t, sessions)
	seen := map[string]bool{}
	for _, e := range res.Entities {
		if e.Kind == "session" {
			seen[e.Label] = true
		}
	}
	for i := 0; i < 3; i++ {
		if !seen[fmt.Sprintf("sess-%d", i)] {
			t.Fatalf("session sess-%d not reconstructed", i)
		}
	}
}
