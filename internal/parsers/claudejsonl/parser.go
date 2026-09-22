// Package claudejsonl parses Claude Code session transcripts (JSONL)
// out of a sealed .adfir package into normalized events, entities and
// relationships.
//
// Evidence-vs-claims rule (plan §12): assistant narrative text becomes
// REPORTED events; tool_use / tool_result records become OBSERVED
// events. Nothing here is treated as endpoint-corroborated.
//
// All evidence is hostile: lines are size-bounded, malformed lines
// become trace_gap events (never silently skipped), and extracted
// summaries are truncated and later sanitized before display.
package claudejsonl

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/parsers/linereader"
	"github.com/efij/AgentDFIR/v2/internal/parsers/segment"
	"github.com/efij/AgentDFIR/v2/internal/schema"
	"github.com/efij/AgentDFIR/v2/internal/version"
)

// MaxLineBytes bounds a single transcript line (archive-bomb defense).
const MaxLineBytes = 8 << 20 // 8 MiB

// Result is the normalized output for one package.
type Result = schema.Normalized

// transcriptLine is the (tolerant) shape of one Claude Code JSONL line.
type transcriptLine struct {
	Type        string          `json:"type"`
	UUID        string          `json:"uuid"`
	ParentUUID  string          `json:"parentUuid"`
	SessionID   string          `json:"sessionId"`
	AgentID     string          `json:"agentId"`
	Timestamp   string          `json:"timestamp"`
	IsSidechain bool            `json:"isSidechain"`
	Version     string          `json:"version"`
	CWD         string          `json:"cwd"`
	Message     json.RawMessage `json:"message"`
	// ToolUseResult is whatever the client attached to a tool result: an
	// object for spawns (carrying the child's agentId on current builds), but
	// a plain string for most Bash/Read output and an array for some tools.
	// It was a fixed struct once, and json.Unmarshal rejected every line
	// whose value was not an object — on a real package 1,945 ordinary
	// tool-result lines became "malformed" trace gaps and every parentUuid
	// chain through them read as tampering. Decoded leniently by
	// spawnResult instead.
	ToolUseResult json.RawMessage `json:"toolUseResult"`

	// Cowork's audit.jsonl is the Agent SDK's stream-json dialect of the
	// same transcript: snake_case keys, an HMAC per line, and system/result
	// records that the CLI transcript does not write. Read into their own
	// fields and folded into the camelCase ones by normalize().
	SessionIDSnake     string          `json:"session_id"`
	ParentToolUseID    string          `json:"parent_tool_use_id"`
	ToolUseResultSnake json.RawMessage `json:"tool_use_result"`
	AuditTimestamp     string          `json:"_audit_timestamp"`
	AuditHMAC          string          `json:"_audit_hmac"`
	Subtype            string          `json:"subtype"`
	Model              string          `json:"model"`
	PermissionMode     string          `json:"permissionMode"`
	CLIVersion         string          `json:"claude_code_version"`
	NumTurns           int             `json:"num_turns"`
	IsError            bool            `json:"is_error"`
	TotalCostUSD       float64         `json:"total_cost_usd"`
	PermissionDenials  json.RawMessage `json:"permission_denials"`
	MCPServers         json.RawMessage `json:"mcp_servers"`
}

// normalize folds the stream-json spellings into the transcript fields so
// one handleLine serves both dialects.
func (tl *transcriptLine) normalize() {
	if tl.SessionID == "" {
		tl.SessionID = tl.SessionIDSnake
	}
	if tl.Timestamp == "" {
		tl.Timestamp = tl.AuditTimestamp
	}
	if len(tl.ToolUseResult) == 0 {
		tl.ToolUseResult = tl.ToolUseResultSnake
	}
	if tl.Version == "" {
		tl.Version = tl.CLIVersion
	}
}

// inSubagent reports whether the line was exchanged inside a subagent: the
// CLI transcript flags it with isSidechain, the audit log with the
// parent_tool_use_id of the launching call. Only the former marks the
// agent entity as a sidechain (the audit log's lines all run under the main
// agent id, and marking that as a sidechain made every Cowork main agent
// an orphan); both decide whether a user-role text is a human prompt or a
// message from the parent agent.
func (tl *transcriptLine) inSubagent() bool {
	return tl.IsSidechain || tl.ParentToolUseID != ""
}

// spawnResult reads the child agent id and status out of a toolUseResult
// when, and only when, it is an object. Strings and arrays are ordinary
// tool output and yield nothing.
func spawnResult(raw json.RawMessage) (agentID, status string) {
	b := bytes.TrimSpace(raw)
	if len(b) == 0 || b[0] != '{' {
		return "", ""
	}
	var r struct {
		AgentID string `json:"agentId"`
		Status  string `json:"status"`
	}
	if json.Unmarshal(b, &r) != nil {
		return "", ""
	}
	return r.AgentID, r.Status
}

// isSpawnTool reports whether a tool name spawns a subagent.
//
// Claude Code renamed this tool from Task to Agent. Matching only "Task"
// produced zero agent_spawn events on a real 206,896-event package, so
// every subagent in it was reported as an orphan with no verified parent —
// 275 HIGH findings, all false.
func isSpawnTool(name string) bool {
	return name == "Task" || name == "Agent"
}

type messageBody struct {
	Role    string          `json:"role"`
	Model   string          `json:"model"`
	Content json.RawMessage `json:"content"`
}

type contentItem struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	ID        string          `json:"id"`    // tool_use id
	Name      string          `json:"name"`  // tool name
	Input     json.RawMessage `json:"input"` // tool input
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"` // tool_result payload
	AgentID   string          `json:"agentId"` // present on some Task results
}

// IDFormat renders an event id from its sequence number. The incremental
// overlay needs it to renumber a cached artifact's events when an earlier
// artifact changed size.
const IDFormat = "evt-%06d"

// ParsePackage parses every claude.sessions artifact in a sealed package.
func ParsePackage(pkgDir string) (*Result, error) { return parseWith(pkgDir, nil, nil) }

// StreamPackage parses and emits every event to sink instead of
// accumulating them, returning only entities/relationships. Bounds memory
// by entity count rather than event count.
func StreamPackage(pkgDir string, sink func(schema.Event)) (*Result, error) {
	return parseWith(pkgDir, sink, nil)
}

// StreamPackageCached is StreamPackage with an overlay cache: artifacts the
// cache already holds are replayed instead of re-read. See the segment
// package for why that is safe.
func StreamPackageCached(pkgDir string, sink func(schema.Event), cache segment.Cache) (*Result, error) {
	return parseWith(pkgDir, sink, cache)
}

func parseWith(pkgDir string, sink func(schema.Event), cache segment.Cache) (*Result, error) {
	man, err := casepkg.ReadManifest(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	store := casepkg.NewStore(pkgDir, man)
	res := &Result{}
	p := &parser{res: res, sink: sink, caseID: man.CaseID, host: man.Host,
		entities: map[string]schema.Entity{}, spawned: map[string]string{}}
	for _, a := range man.Current() {
		if a.Status != casepkg.StatusOK {
			continue
		}
		stem := ruleStem(a.CollectorRule)
		p.product = productFor(a)
		if sidecarRules[stem] && strings.HasSuffix(a.LogicalPath, ".json") {
			// Cowork session metadata: not a transcript, one JSON document.
			// Small, and its events depend only on itself, so it goes
			// through the same cache protocol as a transcript.
			if err := p.cached(cache, a, func() error { return p.parseSidecar(store, a, stem) }); err != nil {
				return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
			}
			continue
		}
		if !transcriptRules[stem] || !strings.HasSuffix(a.LogicalPath, ".jsonl") {
			continue
		}
		base := p.seq
		if cache != nil {
			rp, err := cache.Begin(a, base)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
			}
			if rp != nil {
				// The cache has already written this artifact's events.
				// Advance past them and replay the graph calls through the
				// same merge a fresh parse would have used.
				p.seq = base + rp.Events
				for _, e := range rp.Entities {
					p.addEntity(e)
				}
				for _, r := range rp.Relationships {
					p.addRel(r)
				}
				continue
			}
			p.rec = &segment.Recorder{}
		}
		if err := p.parseTranscript(store, a); err != nil {
			return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
		}
		if cache != nil {
			if err := cache.End(a, base, p.seq-base, p.rec.Entities, p.rec.Relationships); err != nil {
				return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
			}
			p.rec = nil
		}
	}
	p.finish()
	return res, nil
}

type parser struct {
	sink     func(schema.Event)
	res      *Result
	caseID   string
	host     string
	seq      int
	entities map[string]schema.Entity
	// spawned maps agent IDs to the event_id of their observed spawn.
	spawned map[string]string
	// rec, when set, captures the entity and relationship calls made while
	// reading the current artifact so the overlay can replay them later.
	rec *segment.Recorder
	// product is the product id stamped on events from the current
	// artifact: claude-code for CLI transcripts, claude-cowork for the
	// desktop app's sessions. Same format, different evidence source.
	product string
	// audit counters for the current audit.jsonl artifact.
	auditLines, auditSigned int
}

// transcriptRules are the collector rules whose .jsonl artifacts are
// Claude transcripts; sidecarRules hold Cowork's per-session JSON metadata.
var (
	transcriptRules = map[string]bool{"claude.sessions": true, "cowork.sessions": true, "cowork.audit": true}
	sidecarRules    = map[string]bool{"cowork.session_meta": true, "cowork.desktop_sessions": true}
)

// ruleStem strips the per-platform suffix from a collector rule id
// (cowork.audit_macos → cowork.audit).
func ruleStem(rule string) string {
	for _, suf := range []string{"_macos", "_linux", "_windows"} {
		if strings.HasSuffix(rule, suf) {
			return strings.TrimSuffix(rule, suf)
		}
	}
	return rule
}

func productFor(a casepkg.ArtifactRecord) string {
	if a.Product == "claude-cowork" || strings.HasPrefix(a.CollectorRule, "cowork.") {
		return "claude-cowork"
	}
	return "claude-code"
}

// cached runs parse for one artifact under the overlay cache protocol:
// replay if the cache has it, otherwise parse and record.
func (p *parser) cached(cache segment.Cache, a casepkg.ArtifactRecord, parse func() error) error {
	base := p.seq
	if cache != nil {
		rp, err := cache.Begin(a, base)
		if err != nil {
			return err
		}
		if rp != nil {
			p.seq = base + rp.Events
			for _, e := range rp.Entities {
				p.addEntity(e)
			}
			for _, r := range rp.Relationships {
				p.addRel(r)
			}
			return nil
		}
		p.rec = &segment.Recorder{}
	}
	if err := parse(); err != nil {
		return err
	}
	if cache != nil {
		if err := cache.End(a, base, p.seq-base, p.rec.Entities, p.rec.Relationships); err != nil {
			return err
		}
		p.rec = nil
	}
	return nil
}

func (p *parser) parseTranscript(store *casepkg.Store, art casepkg.ArtifactRecord) error {
	f, err := store.Open(art.ArtifactID)
	if err != nil {
		return err
	}
	defer f.Close()

	p.auditLines, p.auditSigned = 0, 0
	// Cowork's audit log opens under the Cowork session id (the first user
	// message, before the CLI starts) and switches to the CLI session id
	// from the init record on. One file, two ids, by design — which is
	// exactly what AGENT_IDENTITY_MISMATCH looks for, and it fired on every
	// Cowork session. The CLI id is the one the in-VM transcript uses, so
	// the file is read under it: a cheap first pass finds it.
	primary := ""
	if ruleStem(art.CollectorRule) == "cowork.audit" {
		primary = auditPrimarySession(store, art)
	}
	uuids := map[string]bool{}
	type parentRef struct {
		parent string
		off    int64
		line   int
		sess   string
	}
	var parents []parentRef
	lastSession := ""

	lr := linereader.New(f, MaxLineBytes)
	for {
		ln, err := lr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			p.emit(schema.Event{
				EventType: schema.EventTraceGap, ActorType: schema.ActorSystem,
				Result: "read_aborted", Summary: "transcript read aborted: " + err.Error(),
			}, art, ln.Offset, ln.Number)
			break
		}
		if ln.Overflow {
			// Oversized line: record a bounded gap, keep parsing the rest.
			p.emit(schema.Event{
				EventType: schema.EventTraceGap, ActorType: schema.ActorSystem,
				Result:  "oversized_line",
				Summary: fmt.Sprintf("transcript line exceeded %d-byte bound (%d bytes); skipped", MaxLineBytes, ln.OverBytes),
			}, art, ln.Offset, ln.Number)
			continue
		}
		var tl transcriptLine
		if err := json.Unmarshal(ln.Bytes, &tl); err != nil {
			p.emit(schema.Event{
				EventType: schema.EventTraceGap, ActorType: schema.ActorSystem,
				Result:  "malformed_line",
				Summary: fmt.Sprintf("unparseable transcript line (%d bytes): %v", len(ln.Bytes), err),
			}, art, ln.Offset, ln.Number)
			continue
		}
		tl.normalize()
		if primary != "" && tl.SessionID != "" && tl.SessionID != primary {
			tl.SessionID = primary
		}
		if tl.AuditHMAC != "" {
			p.auditSigned++
		}
		p.auditLines++
		if tl.UUID != "" {
			uuids[tl.UUID] = true
		}
		if tl.ParentUUID != "" && !danglingByDesign(tl.Type) {
			parents = append(parents, parentRef{tl.ParentUUID, ln.Offset, ln.Number, tl.SessionID})
		}
		if tl.SessionID != "" {
			lastSession = tl.SessionID
		}
		p.handleLine(tl, art, ln.Offset, ln.Number)
	}
	// Dangling parentUuid references = broken conversation DAG (splicing,
	// deletion, or fabrication). Emitted as evidence for SESSION_TAMPERING.
	for _, pr := range parents {
		if !uuids[pr.parent] {
			p.emit(schema.Event{
				EventType: schema.EventSessionMeta, ActorType: schema.ActorSystem,
				SessionID: pr.sess, AgentID: "main:" + pr.sess,
				Result:        "chain_break",
				Summary:       fmt.Sprintf("parentUuid %.8s… references a record not present in this transcript", pr.parent),
				Corroboration: schema.StateObserved,
			}, art, pr.off, pr.line)
		}
	}
	if p.auditSigned > 0 {
		// Cowork signs every audit line with an HMAC keyed by the session's
		// .audit-key. The scheme is not public, so the signatures are
		// recorded, not verified: an analyst with the key can check them,
		// and a line without one in a signed file is worth a look.
		p.emit(schema.Event{
			EventType: schema.EventSessionMeta, ActorType: schema.ActorSystem,
			SessionID: lastSession, AgentID: "main:" + lastSession,
			Result:        "audit_signed",
			Summary:       fmt.Sprintf("%d of %d audit lines carry an HMAC (scheme not verified)", p.auditSigned, p.auditLines),
			Corroboration: schema.StateObserved,
		}, art, 0, 0)
	}
	return nil
}

func (p *parser) handleLine(tl transcriptLine, art casepkg.ArtifactRecord, off int64, line int) {
	agentID := tl.AgentID
	if agentID == "" {
		agentID = "main:" + tl.SessionID
	}
	p.touchSession(tl, agentID)

	base := schema.Event{
		Timestamp: tl.Timestamp, TimestampSrc: "transcript",
		SessionID: tl.SessionID, AgentID: agentID,
		ProductVersion: tl.Version,
	}

	var msg messageBody
	if len(tl.Message) > 0 {
		_ = json.Unmarshal(tl.Message, &msg)
	}

	switch tl.Type {
	case "user":
		items, text := contentItems(msg.Content)
		emittedToolResult := false
		for _, it := range items {
			if it.Type == "tool_result" {
				ev := base
				ev.EventType = schema.EventToolResult
				ev.ActorType = schema.ActorAgent
				ev.ToolCallID = it.ToolUseID
				ev.Corroboration = schema.StateObserved
				ev.Summary = trim(flatText(it.Content), 200)
				p.emit(ev, art, off, line)
				emittedToolResult = true
				// The child id of an Agent/Task launch arrives on the RESULT
				// line — in the content item on older builds, in the top-level
				// toolUseResult on current ones ({"status":"async_launched",
				// "agentId":…}). Spawn evidence is read from agent_spawn
				// events, so it must become one here; recording it in the
				// parser map alone left 275 real subagents reported as
				// orphans with no verified parent.
				child, status := it.AgentID, ""
				if child == "" {
					child, status = spawnResult(tl.ToolUseResult)
				}
				if child != "" {
					sp := base
					sp.EventType = schema.EventAgentSpawn
					sp.ActorType = schema.ActorAgent
					sp.ToolCallID = it.ToolUseID
					sp.TaskID = child
					sp.Corroboration = schema.StateObserved
					sp.Summary = "subagent " + child + " launched"
					if status != "" {
						sp.Summary += " (" + status + ")"
					}
					p.spawned[child] = fmt.Sprintf("evt-%06d", p.seq)
					p.emit(sp, art, off, line)
				}
			}
		}
		if !emittedToolResult {
			ev := base
			if tl.inSubagent() {
				// Prompt delivered TO a subagent by its parent.
				ev.EventType = schema.EventAgentMessage
				ev.ActorType = schema.ActorAgent
			} else {
				ev.EventType = schema.EventHumanPrompt
				ev.ActorType = schema.ActorHuman
			}
			ev.Corroboration = schema.StateObserved
			ev.Summary = trim(text, 200)
			p.emit(ev, art, off, line)
		}
	case "assistant":
		items, text := contentItems(msg.Content)
		if text != "" {
			ev := base
			ev.EventType = schema.EventModelResponse
			ev.ActorType = schema.ActorModel
			ev.Model = msg.Model
			// Model narrative: a CLAIM, never proof of execution.
			ev.Corroboration = schema.StateReported
			ev.Summary = trim(text, 200)
			p.emit(ev, art, off, line)
		}
		for _, it := range items {
			if it.Type != "tool_use" {
				continue
			}
			ev := base
			ev.EventType = schema.EventToolCall
			ev.ActorType = schema.ActorAgent
			ev.Model = msg.Model
			ev.Tool = it.Name
			ev.ToolCallID = it.ID
			ev.Corroboration = schema.StateObserved
			p.decorateToolCall(&ev, it)
			p.emit(ev, art, off, line)

			if isSpawnTool(it.Name) {
				sp := base
				sp.EventType = schema.EventAgentSpawn
				sp.ActorType = schema.ActorAgent
				sp.ToolCallID = it.ID
				sp.Corroboration = schema.StateObserved
				sp.Summary = "subagent spawn requested via " + it.Name + " tool"
				// The child id arrives in one of three places depending on
				// the client version: the tool input, the top-level
				// toolUseResult, or the content item on the result.
				child := inputField(it.Input, "agentId")
				if child == "" {
					child, _ = spawnResult(tl.ToolUseResult)
				}
				if child == "" {
					child = it.AgentID
				}
				if child != "" {
					sp.TaskID = child
					p.spawned[child] = fmt.Sprintf("evt-%06d", p.seq)
				}
				p.emit(sp, art, off, line)
			}
		}
	case "system", "summary", "progress", "result", "rate_limit_event":
		ev := base
		ev.EventType = schema.EventSessionMeta
		ev.ActorType = schema.ActorSystem
		ev.Result = tl.Type
		if tl.Subtype != "" {
			ev.Result += ":" + trim(tl.Subtype, 40)
		}
		ev.Corroboration = schema.StateObserved
		switch {
		case tl.Type == "system" && tl.Subtype == "init":
			// The SDK's init record: what the session was allowed to do.
			ev.Model = tl.Model
			ev.Summary = trim(strings.TrimSpace(fmt.Sprintf("model=%s permissionMode=%s cwd=%s version=%s mcp_servers=%d",
				tl.Model, tl.PermissionMode, tl.CWD, tl.Version, jsonLen(tl.MCPServers))), 300)
		case tl.Type == "result":
			ev.Summary = trim(fmt.Sprintf("turns=%d error=%v cost_usd=%.4f permission_denials=%d",
				tl.NumTurns, tl.IsError, tl.TotalCostUSD, jsonLen(tl.PermissionDenials)), 300)
		}
		p.emit(ev, art, off, line)
	default:
		ev := base
		ev.EventType = schema.EventSessionMeta
		ev.ActorType = schema.ActorSystem
		ev.Result = "unknown_type:" + trim(tl.Type, 40)
		ev.Corroboration = schema.StateObserved
		p.emit(ev, art, off, line)
	}
}

// decorateToolCall extracts forensically relevant fields per tool.
func (p *parser) decorateToolCall(ev *schema.Event, it contentItem) {
	switch {
	case it.Name == "Bash":
		ev.Command = trim(inputField(it.Input, "command"), 300)
		ev.Action = "shell_execution"
	case it.Name == "Read" || it.Name == "Write" || it.Name == "Edit" || it.Name == "MultiEdit" || it.Name == "NotebookEdit":
		ev.File = inputField(it.Input, "file_path")
		if ev.File == "" {
			ev.File = inputField(it.Input, "notebook_path")
		}
		switch it.Name {
		case "MultiEdit", "NotebookEdit":
			ev.Action = "edit_file"
		default:
			ev.Action = strings.ToLower(it.Name) + "_file"
		}
	case it.Name == "SendMessage":
		ev.Action = "inter_agent_message"
		ev.Summary = "to=" + trim(inputField(it.Input, "to"), 80)
	case isSpawnTool(it.Name):
		ev.Action = "spawn_subagent"
		ev.Summary = trim(inputField(it.Input, "description"), 120)
	case strings.HasPrefix(it.Name, "mcp__"):
		parts := strings.SplitN(it.Name, "__", 3)
		if len(parts) == 3 {
			ev.MCPServer = parts[1]
			ev.MCPTool = parts[2]
		}
		ev.Action = "mcp_call"
	}
}

func (p *parser) touchSession(tl transcriptLine, agentID string) {
	if tl.SessionID != "" {
		p.addEntity(schema.Entity{
			EntityID: "session:" + tl.SessionID, Kind: "session",
			Label: tl.SessionID, Product: p.product,
		})
	}
	attrs := map[string]string{}
	if tl.IsSidechain {
		attrs["sidechain"] = "true"
	}
	p.addEntity(schema.Entity{
		EntityID: "agent:" + agentID, Kind: "agent",
		Label: agentID, Product: p.product, Attributes: attrs,
	})
	if tl.SessionID != "" {
		p.addRel(schema.Relationship{
			From: "agent:" + agentID, To: "session:" + tl.SessionID,
			Type: "belongs_to", Corroboration: schema.StateObserved,
		})
	}
}

func (p *parser) emit(ev schema.Event, art casepkg.ArtifactRecord, off int64, line int) {
	ev.EventID = fmt.Sprintf(IDFormat, p.seq)
	ev.CaseID = p.caseID
	ev.SchemaVersion = version.SchemaVersion
	ev.Sequence = p.seq
	ev.Host = p.host
	ev.User = art.User
	ev.Vendor = "anthropic"
	ev.Product = p.product
	if ev.Product == "" {
		ev.Product = "claude-code"
	}
	ev.SourceArtifact = art.ArtifactID
	ev.SourcePath = art.LogicalPath
	ev.SourceOffset = off
	ev.SourceLine = line
	if ev.Corroboration == "" {
		ev.Corroboration = schema.StateUnknown
	}
	p.seq++
	if p.sink != nil {
		p.sink(ev)
	} else {
		p.res.Events = append(p.res.Events, ev)
	}

	// Evidence-backed relationships for notable events.
	switch ev.EventType {
	case schema.EventToolCall:
		p.addEntity(schema.Entity{EntityID: "tool:" + ev.Tool, Kind: "tool", Label: ev.Tool})
		p.addRel(schema.Relationship{
			From: "agent:" + ev.AgentID, To: "tool:" + ev.Tool, Type: "invoked",
			DerivedFrom: []string{ev.EventID}, Corroboration: ev.Corroboration,
		})
		if ev.MCPServer != "" {
			p.addEntity(schema.Entity{EntityID: "mcp:" + ev.MCPServer, Kind: "mcp_server", Label: ev.MCPServer})
			p.addRel(schema.Relationship{
				From: "tool:" + ev.Tool, To: "mcp:" + ev.MCPServer, Type: "invoked",
				DerivedFrom: []string{ev.EventID}, Corroboration: ev.Corroboration,
			})
		}
	}
}

func (p *parser) finish() {
	// Deterministic entity order.
	keys := make([]string, 0, len(p.entities))
	for k := range p.entities {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p.res.Entities = append(p.res.Entities, p.entities[k])
	}
}

func (p *parser) addEntity(e schema.Entity) {
	if p.rec != nil {
		p.rec.Entity(e)
	}
	if old, ok := p.entities[e.EntityID]; ok {
		// Merge attributes; keep first label.
		for k, v := range e.Attributes {
			if old.Attributes == nil {
				old.Attributes = map[string]string{}
			}
			old.Attributes[k] = v
		}
		p.entities[e.EntityID] = old
		return
	}
	p.entities[e.EntityID] = e
}

func (p *parser) addRel(r schema.Relationship) {
	if p.rec != nil {
		p.rec.Rel(r)
	}
	for _, ex := range p.res.Relationships {
		if ex.From == r.From && ex.To == r.To && ex.Type == r.Type {
			return
		}
	}
	p.res.Relationships = append(p.res.Relationships, r)
}

// contentItems handles message.content being either a plain string or an
// array of typed items; returns items plus concatenated text.
func contentItems(raw json.RawMessage) ([]contentItem, string) {
	if len(raw) == 0 {
		return nil, ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return nil, s
	}
	var items []contentItem
	if err := json.Unmarshal(raw, &items); err != nil {
		return nil, ""
	}
	var texts []string
	for _, it := range items {
		if it.Type == "text" && it.Text != "" {
			texts = append(texts, it.Text)
		}
	}
	return items, strings.Join(texts, "\n")
}

func flatText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var items []contentItem
	if err := json.Unmarshal(raw, &items); err == nil {
		var texts []string
		for _, it := range items {
			if it.Text != "" {
				texts = append(texts, it.Text)
			}
		}
		return strings.Join(texts, "\n")
	}
	return ""
}

// jsonLen counts the elements of a JSON array (or keys of an object); 0
// for anything else.
func jsonLen(raw json.RawMessage) int {
	if len(raw) == 0 {
		return 0
	}
	var arr []json.RawMessage
	if json.Unmarshal(raw, &arr) == nil {
		return len(arr)
	}
	var obj map[string]json.RawMessage
	if json.Unmarshal(raw, &obj) == nil {
		return len(obj)
	}
	return 0
}

func inputField(raw json.RawMessage, key string) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	return ""
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	// Truncate on a rune boundary.
	cut := n
	for cut > 0 && !isRuneStart(s[cut]) {
		cut--
	}
	return s[:cut] + "…"
}

func isRuneStart(b byte) bool { return b&0xC0 != 0x80 }

// Live parses individual transcript lines as they are tailed from a
// running session (real-time detection). Events are delivered to sink;
// entity/relationship bookkeeping is kept but not returned.
type Live struct{ p *parser }

// NewLive creates a line parser for live tailing of Claude Code transcripts.
func NewLive(host string, sink func(schema.Event)) *Live {
	return NewLiveProduct("claude-code", host, sink)
}

// NewLiveProduct is NewLive for another product that writes the same
// transcript format (Cowork).
func NewLiveProduct(product, host string, sink func(schema.Event)) *Live {
	return &Live{p: &parser{res: &Result{}, sink: sink, caseID: "live", host: host, product: product,
		entities: map[string]schema.Entity{}, spawned: map[string]string{}}}
}

// Line feeds one raw JSONL line; malformed lines become trace_gap events.
func (l *Live) Line(path string, raw []byte, off int64, line int) {
	art := casepkg.ArtifactRecord{ArtifactID: "live", LogicalPath: path, CollectorRule: "claude.sessions", ArtifactType: "agent_session"}
	var tl transcriptLine
	if err := json.Unmarshal(raw, &tl); err != nil {
		l.p.emit(schema.Event{EventType: schema.EventTraceGap, ActorType: schema.ActorSystem, Result: "unparsed",
			Summary: "malformed transcript line", Corroboration: schema.StateObserved}, art, off, line)
		return
	}
	tl.normalize()
	l.p.handleLine(tl, art, off, line)
}

// auditPrimarySession returns the session id of the first system record in
// an audit log (the CLI session), or the most frequent id when there is
// none. Bounded by the same line limit as the parse itself.
func auditPrimarySession(store *casepkg.Store, art casepkg.ArtifactRecord) string {
	f, err := store.Open(art.ArtifactID)
	if err != nil {
		return ""
	}
	defer f.Close()
	counts := map[string]int{}
	lr := linereader.New(f, MaxLineBytes)
	for {
		ln, err := lr.Next()
		if err != nil {
			break
		}
		if ln.Overflow {
			continue
		}
		var probe struct {
			Type      string `json:"type"`
			SessionID string `json:"session_id"`
		}
		if json.Unmarshal(ln.Bytes, &probe) != nil || probe.SessionID == "" {
			continue
		}
		if probe.Type == "system" {
			return probe.SessionID
		}
		counts[probe.SessionID]++
	}
	best, n := "", 0
	for id, c := range counts {
		if c > n || c == n && id < best {
			best, n = id, c
		}
	}
	return best
}

// danglingByDesign reports record types whose parentUuid routinely points
// outside the transcript.
//
// Every dangling parent used to be reported as a broken conversation DAG.
// On real transcripts they come from attachment, queue-operation and system
// records — Claude Code's own bookkeeping — which produced 49
// SESSION_TAMPERING findings on one machine and not one of them was a
// spliced transcript.
func danglingByDesign(recType string) bool {
	switch recType {
	case "attachment", "queue-operation", "system", "summary", "progress", "result", "rate_limit_event":
		return true
	}
	return false
}
