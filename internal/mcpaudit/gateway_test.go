package mcpaudit

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/internal/schema"
)

func TestGatewayCorrelation(t *testing.T) {
	events := []schema.Event{
		// matched by call id
		{EventType: schema.EventToolCall, Action: "mcp_call", MCPServer: "gateway", MCPTool: "jira.create", ToolCallID: "c1", Timestamp: "2026-08-30T10:00:00Z", SessionID: "s1", AgentID: "main:s1", SourcePath: "p.jsonl", SourceLine: 1},
		// matched by tool + time (no id on gateway side)
		{EventType: schema.EventToolCall, Action: "mcp_call", MCPServer: "gateway", MCPTool: "docs.search", Timestamp: "2026-08-30T10:00:10Z", SessionID: "s1", AgentID: "main:s1", SourcePath: "p.jsonl", SourceLine: 2},
		// transcript-only → CONTRADICTED
		{EventType: schema.EventToolCall, Action: "mcp_call", MCPServer: "gateway", MCPTool: "github.push", Timestamp: "2026-08-30T10:00:20Z", SessionID: "s1", AgentID: "main:s1", SourcePath: "p.jsonl", SourceLine: 3},
		// direct server not routed via gateway → ignored when --gateway-server given
		{EventType: schema.EventToolCall, Action: "mcp_call", MCPServer: "local-fs", MCPTool: "read", Timestamp: "2026-08-30T10:00:30Z", SessionID: "s1", AgentID: "main:s1", SourcePath: "p.jsonl", SourceLine: 4},
		// not an MCP call
		{EventType: schema.EventToolCall, Tool: "Bash", Command: "ls", Timestamp: "2026-08-30T10:00:40Z"},
	}
	log := filepath.Join(t.TempDir(), "gw.jsonl")
	lines := `{"ts":"2026-08-30T10:00:00Z","call_id":"c1","tool":"jira.create","backend":"jira-mcp","status":200,"latency_ms":120,"actor":"dev","decision":"allow"}
{"ts":1788084011,"tool":"docs.search","backend":"docs-mcp","status":"ok","latency_ms":80,"decision":"allow"}
{"ts":"2026-08-30T10:01:00Z","call_id":"c9","tool":"payments.refund","backend":"pay-mcp","status":200,"latency_ms":50,"actor":"dev","decision":"allow"}
{"ts":"2026-08-30T10:01:05Z","tool":"admin.delete_user","backend":"iam-mcp","status":403,"latency_ms":5,"actor":"dev","decision":"deny"}
{"ts":"2026-08-30T10:01:10Z","tool":"docs.search","backend":"docs-mcp","status":502,"latency_ms":3000,"error":"upstream timeout"}
{"ts":"2026-08-30T10:01:11Z","tool":"docs.search","backend":"docs-mcp","status":502,"latency_ms":3000,"error":"upstream timeout"}
{"ts":"2026-08-30T10:01:12Z","tool":"docs.search","backend":"docs-mcp","status":"timeout","latency_ms":3000}
not json at all
`
	if err := os.WriteFile(log, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	recs, unparsed, err := LoadGatewayLog(log, DefaultGatewayMap)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 7 || unparsed != 1 {
		t.Fatalf("records=%d unparsed=%d", len(recs), unparsed)
	}
	if recs[1].Time.Format("2006-01-02T15:04:05Z") != "2026-08-30T10:00:11Z" {
		t.Fatalf("epoch seconds not parsed: %v", recs[1].Time)
	}
	sum, f := CorrelateGateway(events, recs, []string{"gateway"}, 3)
	if sum.Matched != 2 || sum.AgentOnly != 1 || sum.Denied != 1 || sum.Errors != 3 {
		t.Fatalf("summary: %+v", sum)
	}
	// gateway-only: payments.refund (allow, unlogged) + admin.delete_user (denied) + 3 error docs.search
	if sum.GatewayOnly != 5 {
		t.Fatalf("gateway-only: %+v", sum)
	}
	by := byRule(f)
	if n := len(by["MCP_GATEWAY_UNLOGGED_CALL"]); n != 1 || !containsStr(by["MCP_GATEWAY_UNLOGGED_CALL"][0].Description, "payments.refund") {
		// error records carry no decision → they are also "allow/empty"; ensure only the clean allowed call is flagged
		t.Fatalf("UNLOGGED: %d %+v", n, by["MCP_GATEWAY_UNLOGGED_CALL"])
	}
	if n := len(by["MCP_GATEWAY_CONTRADICTED_CALL"]); n != 1 || by["MCP_GATEWAY_CONTRADICTED_CALL"][0].Status != schema.StateContradicted || !containsStr(by["MCP_GATEWAY_CONTRADICTED_CALL"][0].Description, "github.push") {
		t.Fatalf("CONTRADICTED: %+v", by["MCP_GATEWAY_CONTRADICTED_CALL"])
	}
	if len(by["MCP_GATEWAY_DENIED_CALL"]) != 1 || len(by["MCP_GATEWAY_BACKEND_ERRORS"]) != 1 {
		t.Fatalf("denied=%d backend_errors=%d", len(by["MCP_GATEWAY_DENIED_CALL"]), len(by["MCP_GATEWAY_BACKEND_ERRORS"]))
	}
	if sum.P95LatencyMS != 3000 || sum.Backends["docs-mcp"] != 4 {
		t.Fatalf("latency/backends: %+v", sum)
	}
	// Without --gateway-server every MCP call is expected at the gateway → local-fs read becomes contradicted too.
	_, f2 := CorrelateGateway(events, recs, nil, 3)
	if n := len(byRule(f2)["MCP_GATEWAY_CONTRADICTED_CALL"]); n != 2 {
		t.Fatalf("all-servers mode contradicted=%d", n)
	}
	// Custom field map.
	custom := filepath.Join(t.TempDir(), "gw2.jsonl")
	_ = os.WriteFile(custom, []byte(`{"time":"2026-08-30T10:00:00Z","requestId":"c1","toolName":"jira.create","upstream":"jira-mcp","code":200,"durationMs":9,"verdict":"ALLOW"}`+"\n"), 0o600)
	m := GatewayMap{Timestamp: "time", CallID: "requestId", Tool: "toolName", Backend: "upstream", Status: "code", LatencyMS: "durationMs", Decision: "verdict"}
	r2, _, err := LoadGatewayLog(custom, m)
	if err != nil || len(r2) != 1 || r2[0].Backend != "jira-mcp" || r2[0].Decision != "allow" || r2[0].LatencyMS != 9 {
		t.Fatalf("custom map: %v %+v", err, r2)
	}
}

func containsStr(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
