package mcpaudit

import (
	"encoding/json"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/parsers/linereader"
	"github.com/efij/AgentDFIR/v4/internal/schema"
	"github.com/efij/AgentDFIR/v4/internal/toolargs"
)

// Gateways that log JSON-RPC responses record what each MCP server said
// it was (the initialize result's serverInfo) and which tools it offered
// (tools/list results). Those are the runtime identity of a server, as
// opposed to the configuration that launched it, and they are what lets a
// tool call be tied to the definition in force when it was made.
//
// LoadGatewayDefs reads them from the same log LoadGatewayLog reads, and
// AnnotateGateway writes them, with the gateway's allow/deny decision,
// onto the transcript calls the gateway saw.

// Bounds on what one gateway log contributes.
const (
	maxGatewayLine     = 8 << 20
	maxDefsPerBackend  = 4096
	maxToolsPerListing = 1024
)

// gatewayDef is one serverInfo or tools/list response the gateway logged.
type gatewayDef struct {
	time    time.Time
	line    int
	version string            // serverInfo name/version, when an initialize result
	tools   map[string]string // tool name → definition digest, when a tools/list result
}

// GatewayDefs holds the server identities and tool definitions a gateway
// log recorded, per backend.
type GatewayDefs struct {
	byBackend map[string][]gatewayDef
}

// Backends returns how many backends have recorded definitions.
func (d *GatewayDefs) Backends() int {
	if d == nil {
		return 0
	}
	return len(d.byBackend)
}

// LoadGatewayDefs reads the initialize and tools/list results from a JSONL
// gateway log. A response is read from "result" or "response.result" of a
// line; the backend and time come from the map's fields. Lines over the
// size bound or not JSON are skipped (LoadGatewayLog counts them).
func LoadGatewayDefs(path string, m GatewayMap) (*GatewayDefs, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	defs := &GatewayDefs{byBackend: map[string][]gatewayDef{}}
	lr := linereader.New(f, maxGatewayLine)
	for {
		ln, err := lr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return defs, err
		}
		if ln.Overflow {
			continue
		}
		var doc map[string]json.RawMessage
		if json.Unmarshal(ln.Bytes, &doc) != nil {
			continue
		}
		result := doc["result"]
		if len(result) == 0 {
			var resp struct {
				Result json.RawMessage `json:"result"`
			}
			if json.Unmarshal(doc["response"], &resp) == nil {
				result = resp.Result
			}
		}
		if len(result) == 0 {
			continue
		}
		var res struct {
			ServerInfo json.RawMessage              `json:"serverInfo"`
			Tools      []map[string]json.RawMessage `json:"tools"`
		}
		if json.Unmarshal(result, &res) != nil {
			continue
		}
		def := gatewayDef{line: ln.Number}
		if len(res.ServerInfo) > 0 {
			def.version = toolargs.ServerVersion(res.ServerInfo)
		}
		if res.Tools != nil {
			def.tools = map[string]string{}
			for i, t := range res.Tools {
				if i >= maxToolsPerListing {
					break
				}
				var name string
				if json.Unmarshal(t["name"], &name) != nil || name == "" {
					continue
				}
				if d := toolargs.ToolDefDigest(t); d != "" {
					def.tools[name] = d
				}
			}
		}
		if def.version == "" && def.tools == nil {
			continue
		}
		var generic map[string]any
		_ = json.Unmarshal(ln.Bytes, &generic)
		def.time = parseTime(generic[m.Timestamp])
		backend := str(generic[m.Backend])
		if len(defs.byBackend[backend]) >= maxDefsPerBackend {
			continue
		}
		defs.byBackend[backend] = append(defs.byBackend[backend], def)
	}
	for b := range defs.byBackend {
		l := defs.byBackend[b]
		sort.SliceStable(l, func(i, j int) bool { return l[i].time.Before(l[j].time) })
	}
	return defs, nil
}

// lookup returns the value pick reads from the backend's newest
// definition of the right kind (pick's second result) recorded at or
// before t: a tool missing from the newest listing has no definition, even
// if an older listing had one. Definitions without a time are used only
// when no timed one applies and they all agree.
func (d *GatewayDefs) lookup(backend string, t time.Time, pick func(gatewayDef) (string, bool)) string {
	if d == nil {
		return ""
	}
	l := d.byBackend[backend]
	if !t.IsZero() {
		found, best := false, ""
		for _, def := range l {
			if def.time.IsZero() || def.time.After(t) {
				continue
			}
			if v, ok := pick(def); ok {
				found, best = true, v
			}
		}
		if found {
			return best
		}
	}
	best, seen := "", false
	for _, def := range l {
		if !def.time.IsZero() {
			continue
		}
		v, ok := pick(def)
		if !ok {
			continue
		}
		if seen && best != v {
			return "" // unordered and contradictory: no answer
		}
		best, seen = v, true
	}
	return best
}

// backendFor finds the backend name the defs use for a transcript server,
// case-insensitively, when the gateway record gave none.
func (d *GatewayDefs) backendFor(server string) string {
	if d == nil || server == "" {
		return ""
	}
	if _, ok := d.byBackend[server]; ok {
		return server
	}
	names := make([]string, 0, len(d.byBackend))
	for b := range d.byBackend {
		names = append(names, b)
	}
	sort.Strings(names)
	for _, b := range names {
		if strings.EqualFold(b, server) {
			return b
		}
	}
	return ""
}

// gatewayApproval maps a gateway decision to an approval state: a policy
// allow is an automatic approval, a deny/block/reject is a denial. Other
// or empty decisions record nothing.
func gatewayApproval(decision string) string {
	switch decision {
	case "allow", "allowed", "permit", "permitted":
		return "auto_approved"
	case "deny", "denied", "blocked", "block", "reject", "rejected":
		return "denied"
	}
	return ""
}

// AnnotateGateway writes the gateway's evidence onto the transcript MCP
// calls it matches (same matching as CorrelateGateway): ApprovalState from
// the gateway decision, MCPServerVersion from the backend's last
// initialize result before the call, and ToolDefDigest from the backend's
// last tools/list result before the call that lists the tool. A denial
// from either side is kept; a recorded state is never replaced by an
// allow. It returns how many events changed.
func AnnotateGateway(events []schema.Event, records []GatewayRecord, defs *GatewayDefs, gatewayServers []string) int {
	calls := gatewayCalls(events, gatewayServers)
	match := matchGateway(calls, records)
	recFor := make([]int, len(calls))
	for i := range recFor {
		recFor[i] = -1
	}
	for ri, ci := range match {
		if ci >= 0 && recFor[ci] < 0 {
			recFor[ci] = ri
		}
	}
	changed := 0
	for ci, c := range calls {
		ev := &events[c.idx]
		before := *ev
		backend := ""
		t := c.time
		if ri := recFor[ci]; ri >= 0 {
			r := records[ri]
			backend = r.Backend
			if t.IsZero() {
				t = r.Time
			}
			switch a := gatewayApproval(r.Decision); {
			case a == "denied":
				ev.ApprovalState = a
			case a != "" && ev.ApprovalState == "":
				ev.ApprovalState = a
			}
		}
		if defs.Backends() > 0 {
			if _, ok := defs.byBackend[backend]; !ok || backend == "" {
				backend = defs.backendFor(c.ev.MCPServer)
			}
			if backend != "" {
				if v := defs.lookup(backend, t, func(d gatewayDef) (string, bool) { return d.version, d.version != "" }); v != "" && ev.MCPServerVersion == "" {
					ev.MCPServerVersion = v
				}
				tool := c.tool
				if d := defs.lookup(backend, t, func(d gatewayDef) (string, bool) { return d.tools[tool], d.tools != nil }); d != "" && ev.ToolDefDigest == "" {
					ev.ToolDefDigest = d
				}
			}
		}
		if ev.ApprovalState != before.ApprovalState || ev.MCPServerVersion != before.MCPServerVersion || ev.ToolDefDigest != before.ToolDefDigest {
			changed++
		}
	}
	return changed
}
