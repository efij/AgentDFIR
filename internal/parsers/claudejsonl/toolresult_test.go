package claudejsonl

import (
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// Current Claude Code writes toolUseResult as a string for Bash/Read output,
// an array for some tools, and an object only for subagent launches — whose
// agentId lives there, on the result line. A fixed struct rejected the first
// two shapes (1,945 "malformed" trace gaps on one real package) and the
// launch object was read on the wrong line, so every subagent was an orphan.
func TestToolUseResultShapesParseAndLinkSubagents(t *testing.T) {
	parent := `{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-09-01T10:00:00Z","message":{"role":"user","content":"do it"}}
{"type":"assistant","uuid":"a1","parentUuid":"u1","sessionId":"s1","timestamp":"2026-09-01T10:00:01Z","message":{"role":"assistant","model":"m","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls"}}]}}
{"type":"user","uuid":"u2","parentUuid":"a1","sessionId":"s1","timestamp":"2026-09-01T10:00:02Z","toolUseResult":"file.txt\nother.txt","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"file.txt"}]}}
{"type":"assistant","uuid":"a2","parentUuid":"u2","sessionId":"s1","timestamp":"2026-09-01T10:00:03Z","message":{"role":"assistant","model":"m","content":[{"type":"tool_use","id":"t2","name":"Read","input":{"file_path":"x"}}]}}
{"type":"user","uuid":"u3","parentUuid":"a2","sessionId":"s1","timestamp":"2026-09-01T10:00:04Z","toolUseResult":[{"type":"text","text":"x"}],"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t2","content":"x"}]}}
{"type":"assistant","uuid":"a3","parentUuid":"u3","sessionId":"s1","timestamp":"2026-09-01T10:00:05Z","message":{"role":"assistant","model":"m","content":[{"type":"tool_use","id":"t3","name":"Agent","input":{"description":"scan","prompt":"go","run_in_background":true}}]}}
{"type":"user","uuid":"u4","parentUuid":"a3","sessionId":"s1","timestamp":"2026-09-01T10:00:06Z","toolUseResult":{"isAsync":true,"status":"async_launched","agentId":"a00bf68a30ff9a577","description":"scan"},"message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t3","content":"Async agent launched"}]}}
`
	child := `{"type":"user","uuid":"c1","sessionId":"s1","agentId":"a00bf68a30ff9a577","isSidechain":true,"timestamp":"2026-09-01T10:00:07Z","message":{"role":"user","content":"go"}}
{"type":"assistant","uuid":"c2","parentUuid":"c1","sessionId":"s1","agentId":"a00bf68a30ff9a577","isSidechain":true,"timestamp":"2026-09-01T10:00:08Z","message":{"role":"assistant","model":"m","content":[{"type":"text","text":"done"}]}}
`
	res := buildPkgFromSessions(t, map[string]string{
		"s1.jsonl": parent,
		"s1/subagents/agent-a00bf68a30ff9a577.jsonl": child,
	})

	var gaps, results int
	for _, ev := range res.Events {
		switch ev.EventType {
		case schema.EventTraceGap:
			gaps++
			t.Errorf("trace gap on a well-formed line: %s", ev.Summary)
		case schema.EventToolResult:
			results++
		}
	}
	if results != 3 {
		t.Errorf("tool_result events = %d, want 3 (string, array and object toolUseResult all parse)", results)
	}
	if _, ok := res.SpawnEvidence()["a00bf68a30ff9a577"]; !ok {
		t.Errorf("subagent launched via toolUseResult.agentId has no spawn evidence: %v", res.SpawnEvidence())
	}
	// The subagent must be seen as a sidechain agent, so the orphan rule would
	// have considered it — and the evidence above is what clears it.
	found := false
	for _, e := range res.Entities {
		if e.EntityID == "agent:a00bf68a30ff9a577" && e.Attributes["sidechain"] == "true" {
			found = true
		}
	}
	if !found {
		t.Error("subagent entity not recorded as sidechain")
	}
}

func TestSpawnResultOnlyReadsObjects(t *testing.T) {
	for _, raw := range []string{``, `"plain output"`, `["a","b"]`, `42`, `null`} {
		if id, st := spawnResult([]byte(raw)); id != "" || st != "" {
			t.Errorf("spawnResult(%s) = %q,%q; want empty", raw, id, st)
		}
	}
	if id, st := spawnResult([]byte(`{"status":"async_launched","agentId":"abc"}`)); id != "abc" || st != "async_launched" {
		t.Errorf("object form: got %q,%q", id, st)
	}
}
