package mcpaudit

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/schema"
)

// MCP gateway adapter. Organizations that front all MCP traffic with a
// gateway have a second, independent witness for every tool call. This
// adapter ingests the gateway's own log (JSON lines, any field names via
// GatewayMap) and correlates it with the agent-side transcript so each
// call can be CORROBORATED, flagged as unlogged on one side, or judged
// operationally (denied by policy, backend failing).

// GatewayMap names the gateway log fields. Defaults cover the common
// shape; override with --gateway-map for a vendor's export.
type GatewayMap struct {
	Timestamp string `json:"ts"`         // RFC 3339 or epoch s/ms
	CallID    string `json:"call_id"`    // request/correlation id (matches transcript tool_call_id when present)
	Tool      string `json:"tool"`       // tool name as the agent called it
	Backend   string `json:"backend"`    // upstream MCP server the gateway routed to
	Status    string `json:"status"`     // HTTP-ish status or "ok"/"error"
	LatencyMS string `json:"latency_ms"` // numeric
	Actor     string `json:"actor"`      // user/agent identity seen by the gateway
	Decision  string `json:"decision"`   // allow | deny | blocked | …
	Error     string `json:"error"`
}

// DefaultGatewayMap is the field naming assumed when no map is given.
var DefaultGatewayMap = GatewayMap{Timestamp: "ts", CallID: "call_id", Tool: "tool", Backend: "backend",
	Status: "status", LatencyMS: "latency_ms", Actor: "actor", Decision: "decision", Error: "error"}

// GatewayRecord is one normalized gateway log line.
type GatewayRecord struct {
	Time      time.Time
	CallID    string
	Tool      string
	Backend   string
	Status    string
	LatencyMS int
	Actor     string
	Decision  string
	Error     string
	Line      int
}

// GatewaySummary is the operational view.
type GatewaySummary struct {
	Records      int            `json:"records"`
	Backends     map[string]int `json:"backends"`
	Denied       int            `json:"denied"`
	Errors       int            `json:"errors"`
	Matched      int            `json:"matched_with_transcript"`
	GatewayOnly  int            `json:"gateway_only"`
	AgentOnly    int            `json:"transcript_only"`
	P95LatencyMS int            `json:"p95_latency_ms"`
	Unparsed     int            `json:"unparsed_lines"`
}

// LoadGatewayLog reads a JSONL gateway log with the given field map.
func LoadGatewayLog(path string, m GatewayMap) ([]GatewayRecord, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	var out []GatewayRecord
	unparsed, line := 0, 0
	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" {
			continue
		}
		var doc map[string]any
		if err := json.Unmarshal([]byte(raw), &doc); err != nil {
			unparsed++
			continue
		}
		r := GatewayRecord{Line: line}
		r.Time = parseTime(doc[m.Timestamp])
		r.CallID = str(doc[m.CallID])
		r.Tool = str(doc[m.Tool])
		r.Backend = str(doc[m.Backend])
		r.Status = str(doc[m.Status])
		r.Actor = str(doc[m.Actor])
		r.Decision = strings.ToLower(str(doc[m.Decision]))
		r.Error = str(doc[m.Error])
		if v, ok := doc[m.LatencyMS].(float64); ok {
			r.LatencyMS = int(v)
		} else if s := str(doc[m.LatencyMS]); s != "" {
			r.LatencyMS, _ = strconv.Atoi(s)
		}
		if r.Tool == "" && r.CallID == "" {
			unparsed++
			continue
		}
		out = append(out, r)
	}
	return out, unparsed, sc.Err()
}

func str(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

func parseTime(v any) time.Time {
	switch t := v.(type) {
	case string:
		for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
			if ts, err := time.Parse(layout, t); err == nil {
				return ts.UTC()
			}
		}
		if n, err := strconv.ParseFloat(t, 64); err == nil {
			return parseTime(n)
		}
	case float64:
		if t > 1e11 {
			return time.UnixMilli(int64(t)).UTC()
		}
		return time.Unix(int64(t), 0).UTC()
	}
	return time.Time{}
}

// mcpCall is the agent-side view of one MCP tool call.
type mcpCall struct {
	ev   schema.Event
	time time.Time
	tool string
}

// CorrelateGateway matches gateway records against transcript MCP calls.
// gatewayServers restricts which transcript servers are expected to be
// visible to the gateway (nil = all MCP calls). Window is ±2 s when no
// call id links the two sides.
func CorrelateGateway(events []schema.Event, records []GatewayRecord, gatewayServers []string, errorThreshold int) (GatewaySummary, []schema.Finding) {
	if errorThreshold <= 0 {
		errorThreshold = 3
	}
	sum := GatewaySummary{Backends: map[string]int{}}
	sum.Records = len(records)
	var findings []schema.Finding

	// Agent-side calls.
	var calls []mcpCall
	viaGateway := func(server string) bool {
		if len(gatewayServers) == 0 {
			return true
		}
		for _, g := range gatewayServers {
			if strings.EqualFold(g, server) {
				return true
			}
		}
		return false
	}
	for _, ev := range events {
		if ev.EventType != schema.EventToolCall {
			continue
		}
		isMCP := ev.Action == "mcp_call" || ev.MCPServer != "" || strings.HasPrefix(ev.Tool, "mcp__")
		if !isMCP || !viaGateway(ev.MCPServer) {
			continue
		}
		tool := ev.MCPTool
		if tool == "" {
			tool = ev.Tool
			if i := strings.LastIndex(tool, "__"); i >= 0 {
				tool = tool[i+2:]
			}
		}
		calls = append(calls, mcpCall{ev: ev, time: parseTime(ev.Timestamp), tool: tool})
	}

	matchedCall := make([]bool, len(calls))
	byID := map[string]int{}
	for i, c := range calls {
		if c.ev.ToolCallID != "" {
			byID[c.ev.ToolCallID] = i
		}
	}
	var latencies []int
	errorsByBackend := map[string]int{}
	for _, r := range records {
		if r.Backend != "" {
			sum.Backends[r.Backend]++
		}
		if r.LatencyMS > 0 {
			latencies = append(latencies, r.LatencyMS)
		}
		if r.Decision == "deny" || r.Decision == "denied" || r.Decision == "blocked" || r.Decision == "reject" || r.Decision == "rejected" {
			sum.Denied++
			findings = append(findings, schema.Finding{
				RuleID: "MCP_GATEWAY_DENIED_CALL", Severity: "MEDIUM", Title: "MCP Call Denied by Gateway Policy",
				Description:  fmt.Sprintf("Gateway refused tool %q (backend %q, actor %q) at %s. The agent attempted something policy forbids; check whether it retried or routed around.", r.Tool, r.Backend, r.Actor, r.Time.Format(time.RFC3339)),
				EvidenceRefs: []string{fmt.Sprintf("gateway-log:%d", r.Line)},
				Status:       schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1548",
				FalsePositive: "Policy tuning produces denials of benign calls; frequency and target matter.",
			})
		}
		isErr := r.Error != "" || strings.HasPrefix(r.Status, "5") || strings.EqualFold(r.Status, "error") || strings.EqualFold(r.Status, "timeout")
		if isErr {
			sum.Errors++
			errorsByBackend[r.Backend]++
		}
		// Match to transcript.
		idx := -1
		if r.CallID != "" {
			if i, ok := byID[r.CallID]; ok {
				idx = i
			}
		}
		if idx < 0 && !r.Time.IsZero() {
			best := -1
			var bestDelta time.Duration
			for i, c := range calls {
				if matchedCall[i] || c.time.IsZero() || !strings.EqualFold(c.tool, r.Tool) {
					continue
				}
				d := c.time.Sub(r.Time)
				if d < 0 {
					d = -d
				}
				if d <= 2*time.Second && (best < 0 || d < bestDelta) {
					best, bestDelta = i, d
				}
			}
			idx = best
		}
		if idx >= 0 {
			matchedCall[idx] = true
			sum.Matched++
			continue
		}
		sum.GatewayOnly++
		// Only calls the gateway actually served are forensically
		// significant as "unlogged": a denied or failed request delivered
		// nothing to any model. Those still count in Denied/Errors.
		if (r.Decision == "" || r.Decision == "allow" || r.Decision == "allowed") && !isErr {
			findings = append(findings, schema.Finding{
				RuleID: "MCP_GATEWAY_UNLOGGED_CALL", Severity: "HIGH", Title: "Gateway Saw an MCP Call the Transcript Does Not Contain",
				Description:  fmt.Sprintf("Gateway served tool %q (backend %q, actor %q) at %s with no matching tool call in the collected transcripts. Either the transcript was edited/truncated, the call came from an uncollected session or host, or a tool invoked the gateway outside the agent's logging.", r.Tool, r.Backend, r.Actor, r.Time.Format(time.RFC3339)),
				EvidenceRefs: []string{fmt.Sprintf("gateway-log:%d", r.Line)},
				Status:       schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1070",
				FalsePositive: "Clock skew beyond ±2 s, or sessions not collected; widen collection before concluding tampering.",
			})
		}
	}
	for i, c := range calls {
		if matchedCall[i] {
			continue
		}
		sum.AgentOnly++
		findings = append(findings, schema.Finding{
			RuleID: "MCP_GATEWAY_CONTRADICTED_CALL", Severity: "HIGH", Title: "Transcript MCP Call Never Reached the Gateway",
			Description: fmt.Sprintf("Transcript records a call to tool %q via server %q at %s, but the gateway log has no corresponding request. The agent may have bypassed the gateway (direct server, local stdio copy) or the transcript entry is fabricated.", c.tool, c.ev.MCPServer, c.ev.Timestamp),
			SessionID:   c.ev.SessionID, AgentID: c.ev.AgentID,
			EvidenceRefs: []string{fmt.Sprintf("%s:%d (artifact %s, offset %d)", c.ev.SourcePath, c.ev.SourceLine, short(c.ev.SourceArtifact), c.ev.SourceOffset)},
			Status:       schema.StateContradicted, Endpoint: schema.StateContradicted, MitreATTACK: "T1562",
			FalsePositive: "Gateway log window shorter than the session, or a server legitimately not routed through the gateway (use --gateway-server).",
		})
	}
	backends := make([]string, 0, len(errorsByBackend))
	for b := range errorsByBackend {
		backends = append(backends, b)
	}
	sort.Strings(backends)
	for _, b := range backends {
		if n := errorsByBackend[b]; n >= errorThreshold {
			findings = append(findings, schema.Finding{
				RuleID: "MCP_GATEWAY_BACKEND_ERRORS", Severity: "LOW", Title: "MCP Backend Failing Behind the Gateway",
				Description:  fmt.Sprintf("Backend %q returned %d error/timeout responses in the log window. Agents retry failed tools and often fall back to riskier alternatives (shell, direct network).", b, n),
				EvidenceRefs: []string{"gateway-log (backend " + b + ")"},
				Status:       schema.StateObserved, Endpoint: schema.StateObserved,
				FalsePositive: "Transient outages; correlate with agent behavior after the failures.",
			})
		}
	}
	if len(latencies) > 0 {
		sort.Ints(latencies)
		idx := (len(latencies)*95+99)/100 - 1 // ceil(0.95n) - 1
		if idx < 0 {
			idx = 0
		}
		sum.P95LatencyMS = latencies[idx]
	}
	return sum, findings
}
