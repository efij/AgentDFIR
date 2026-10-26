package analysis

import (
	"encoding/json"
	"os"

	"github.com/efij/AgentDFIR/v4/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// annotateGateway writes the MCP gateway log's evidence (allow/deny
// decisions, serverInfo versions, tools/list definition digests) onto the
// transcript calls it matches, before the overlay is written back, so the
// detections that stream events.jsonl read it. It returns how many events
// changed. A log that cannot be read changes nothing here; the MCP audit
// stage reports the error.
func annotateGateway(o *Options, events []schema.Event) int {
	m := mcpaudit.DefaultGatewayMap
	if o.GatewayMap != "" {
		if data, err := os.ReadFile(o.GatewayMap); err == nil {
			_ = json.Unmarshal(data, &m)
		}
	}
	recs, _, err := mcpaudit.LoadGatewayLog(o.GatewayLog, m)
	if err != nil {
		return 0
	}
	defs, err := mcpaudit.LoadGatewayDefs(o.GatewayLog, m)
	if err != nil {
		defs = nil
	}
	return mcpaudit.AnnotateGateway(events, recs, defs, o.GatewayServers)
}
