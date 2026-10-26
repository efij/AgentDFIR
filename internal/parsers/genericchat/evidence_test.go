package genericchat

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/schema"
)

func TestGenericToolCallEvidence(t *testing.T) {
	sec := "xoxb-" + strings.Repeat("7", 12)
	storage := clineStorageRel(t)
	res := collectAndParse(t, "cline", storage, map[string]string{
		storage + "/tasks/task-9/api_conversation_history.json": `[
			{"role":"user","content":[{"type":"text","text":"read the config"}]},
			{"role":"assistant","content":[{"type":"tool_use","id":"tu1","name":"read_file","input":{"path":"/srv/app/config.yml","token":"` + sec + `"}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu1","content":"key: value"}]},
			{"role":"assistant","content":[{"type":"tool_use","id":"tu2","name":"read_file","input":{"path":"/missing"}}]},
			{"role":"user","content":[{"type":"tool_result","tool_use_id":"tu2","is_error":true,"content":"ENOENT"}]}
		]`,
	})
	var c1, r1, r2 schema.Event
	for _, e := range res.Events {
		switch {
		case e.EventType == schema.EventToolCall && e.ToolCallID == "tu1":
			c1 = e
		case e.EventType == schema.EventToolResult && e.ToolCallID == "tu1":
			r1 = e
		case e.EventType == schema.EventToolResult && e.ToolCallID == "tu2":
			r2 = e
		}
	}
	if c1.ArgKeys != "path,token" || c1.SafeArgs["path"] != "/srv/app/config.yml" || len(c1.SafeArgs) != 1 || c1.ArgsDigest == "" {
		t.Errorf("call: keys %q safe %v", c1.ArgKeys, c1.SafeArgs)
	}
	if r1.ResultStatus != "ok" || r1.ResultDigest == "" || c1.ResultRef != r1.EventID || r1.ResultRef != c1.EventID {
		t.Errorf("result: %q refs %q/%q", r1.ResultStatus, c1.ResultRef, r1.ResultRef)
	}
	if r2.ResultStatus != "error" {
		t.Errorf("is_error result: %q", r2.ResultStatus)
	}
	if c1.ApprovalState != "" || r1.ApprovalState != "" {
		t.Error("approval set without a record")
	}
	js, _ := json.Marshal(res.Events)
	if strings.Contains(string(js), sec) {
		t.Error("secret argument reached the events")
	}
}

func TestOpenAIStyleArgumentsDigested(t *testing.T) {
	res := collectAndParse(t, "copilot-cli", ".copilot", map[string]string{
		".copilot/history-session-state/sess-cp2.json": `{
			"sessionId": "sess-cp2",
			"chatMessages": [
				{"role":"assistant","content":"","tool_calls":[{"id":"c1","function":{"name":"fetch","arguments":"{\"url\":\"https://example.org/a/b?q=1\",\"method\":\"GET\"}"}}]}
			]
		}`,
	})
	for _, e := range res.Events {
		if e.EventType != schema.EventToolCall {
			continue
		}
		if e.SafeArgs["url"] != "https://example.org" || e.SafeArgs["method"] != "GET" || e.ArgKeys != "method,url" {
			t.Fatalf("openai-style: keys %q safe %v", e.ArgKeys, e.SafeArgs)
		}
		return
	}
	t.Fatal("no tool call")
}
