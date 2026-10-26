// Package codexjsonl parses OpenAI Codex CLI rollout transcripts
// (~/.codex/sessions/**.jsonl) from a sealed .adfir package into the
// unified schema.
//
// Rollout lines look like:
//
//	{"timestamp":"…","type":"session_meta","payload":{"id":"…","cwd":"…","cli_version":"…"}}
//	{"timestamp":"…","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"…"}]}}
//	{"timestamp":"…","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{…}","call_id":"…"}}
//	{"timestamp":"…","type":"response_item","payload":{"type":"function_call_output","call_id":"…","output":"…"}}
//	{"timestamp":"…","type":"event_msg","payload":{"type":"agent_message","message":"…"}}
//
// The same evidence-vs-claims discipline applies: assistant text is
// REPORTED; function/tool call records are OBSERVED. Malformed lines
// become trace_gap events.
package codexjsonl

import (
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/parsers/linereader"
	"github.com/efij/AgentDFIR/v5/internal/parsers/segment"
	"github.com/efij/AgentDFIR/v5/internal/schema"
	"github.com/efij/AgentDFIR/v5/internal/toolargs"
	"github.com/efij/AgentDFIR/v5/internal/version"
)

// MaxLineBytes bounds one transcript line (archive-bomb defense).
const MaxLineBytes = 8 << 20

// Result mirrors the claude parser's output shape.
type Result = schema.Normalized

type rolloutLine struct {
	Timestamp string          `json:"timestamp"`
	Type      string          `json:"type"`
	Payload   json.RawMessage `json:"payload"`
}

type payload struct {
	// session_meta
	ID         string `json:"id"`
	CWD        string `json:"cwd"`
	CLIVersion string `json:"cli_version"`
	// response_item
	Type      string          `json:"type"`
	Role      string          `json:"role"`
	Content   json.RawMessage `json:"content"`
	Name      string          `json:"name"`
	Arguments string          `json:"arguments"`
	Input     string          `json:"input"` // custom_tool_call carries its argument here, not in arguments
	CallID    string          `json:"call_id"`
	Output    json.RawMessage `json:"output"`
	Action    json.RawMessage `json:"action"`
	// event_msg
	Message string `json:"message"`
	// turn_context: the policy the agent ran under for this turn. The
	// desktop app writes one per turn; it is the only place in the rollout
	// that says whether the sandbox was on and what approvals were required.
	TurnID         string          `json:"turn_id"`
	ApprovalPolicy string          `json:"approval_policy"`
	SandboxPolicy  json.RawMessage `json:"sandbox_policy"`
	Model          string          `json:"model"`
}

// IDFormat renders an event id from its sequence number; the incremental
// overlay needs it to renumber a cached artifact's events.
const IDFormat = "evt-x-%06d"

// ParsePackage parses every codex session artifact in a sealed package.
func ParsePackage(pkgDir string) (*Result, error) { return parseWith(pkgDir, nil, nil) }

// StreamPackage parses and emits every event to sink instead of
// accumulating them, returning only entities/relationships. Bounds memory
// by entity count rather than event count.
func StreamPackage(pkgDir string, sink func(schema.Event)) (*Result, error) {
	return parseWith(pkgDir, sink, nil)
}

// StreamPackageCached is StreamPackage with an overlay cache: artifacts the
// cache already holds are replayed instead of re-read.
func StreamPackageCached(pkgDir string, sink func(schema.Event), cache segment.Cache) (*Result, error) {
	return parseWith(pkgDir, sink, cache)
}

func parseWith(pkgDir string, sink func(schema.Event), cache segment.Cache) (*Result, error) {
	man, err := casepkg.ReadManifest(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	store := casepkg.NewStore(pkgDir, man)
	// sink is what makes this a streaming parse. It was missing here and
	// present in every other parser, so StreamPackage built its events in an
	// in-memory slice that the streaming caller discards: Codex CLI sessions
	// have been absent from normalized/events.jsonl, and therefore from
	// every rule that reads it, since streaming normalization was
	// introduced. ParsePackage passes a nil sink and returned them
	// correctly, which is why no test caught it.
	p := &parser{res: &Result{}, sink: sink, caseID: man.CaseID, host: man.Host,
		entities: map[string]schema.Entity{}}
	for _, a := range man.Current() {
		if a.Status != casepkg.StatusOK ||
			(a.CollectorRule != "codex.sessions" && a.CollectorRule != "codex.archived_sessions") ||
			!strings.HasSuffix(a.LogicalPath, ".jsonl") {
			continue
		}
		base := p.seq
		if cache != nil {
			rp, err := cache.Begin(a, base)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
			}
			if rp != nil {
				// The cache already wrote this artifact's events; advance
				// past them and replay the graph calls through the same
				// merge a fresh parse would have used.
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
	p.finishEntities()
	return p.res, nil
}

type parser struct {
	sink     func(schema.Event)
	res      *Result
	caseID   string
	host     string
	seq      int
	entities map[string]schema.Entity
	session  string // current session id (from session_meta or filename)
	version  string
	// rec, when set, captures this artifact's entity and relationship
	// calls so the overlay can replay them without re-reading the file.
	rec *segment.Recorder
	// pair links calls and outputs inside one artifact; nil when tailing.
	pair *toolargs.Pairer
	// policy is the approval policy the last turn_context of this
	// artifact recorded (Codex writes one per turn).
	policy string
}

func (p *parser) parseTranscript(store *casepkg.Store, art casepkg.ArtifactRecord) error {
	f, err := store.Open(art.ArtifactID)
	if err != nil {
		return err
	}
	defer f.Close()
	p.policy = ""
	if p.pair == nil {
		p.pair = toolargs.NewPairer(p.deliver)
	}
	defer p.pair.End()

	// Default session identity: transcript filename stem.
	base := filepath.Base(art.LogicalPath)
	p.session = strings.TrimSuffix(base, ".jsonl")
	p.version = ""

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
			p.emit(schema.Event{
				EventType: schema.EventTraceGap, ActorType: schema.ActorSystem,
				Result:  "oversized_line",
				Summary: fmt.Sprintf("rollout line exceeded %d-byte bound (%d bytes); skipped", MaxLineBytes, ln.OverBytes),
			}, art, ln.Offset, ln.Number)
			continue
		}
		var rl rolloutLine
		if err := json.Unmarshal(ln.Bytes, &rl); err != nil {
			p.emit(schema.Event{
				EventType: schema.EventTraceGap, ActorType: schema.ActorSystem,
				Result:  "malformed_line",
				Summary: fmt.Sprintf("unparseable rollout line (%d bytes): %v", len(ln.Bytes), err),
			}, art, ln.Offset, ln.Number)
			continue
		}
		p.handleLine(rl, art, ln.Offset, ln.Number)
	}
	return nil
}

func (p *parser) handleLine(rl rolloutLine, art casepkg.ArtifactRecord, off int64, line int) {
	var pl payload
	if len(rl.Payload) > 0 {
		_ = json.Unmarshal(rl.Payload, &pl)
	}
	base := schema.Event{
		Timestamp: rl.Timestamp, TimestampSrc: "transcript",
		SessionID: p.session, AgentID: "main:" + p.session,
		ProductVersion: p.version,
	}

	switch rl.Type {
	case "session_meta":
		if pl.ID != "" {
			p.session = pl.ID
			base.SessionID = pl.ID
			base.AgentID = "main:" + pl.ID
		}
		p.version = pl.CLIVersion
		base.ProductVersion = pl.CLIVersion
		base.EventType = schema.EventSessionMeta
		base.ActorType = schema.ActorSystem
		base.Result = "session_meta"
		base.Summary = trim("cwd="+pl.CWD, 160)
		base.Corroboration = schema.StateObserved
		p.emit(base, art, off, line)
		p.touchSession(base.SessionID, base.AgentID)
	case "response_item":
		p.touchSession(base.SessionID, base.AgentID)
		switch pl.Type {
		case "message":
			text := contentText(pl.Content)
			ev := base
			ev.Summary = trim(text, 200)
			ev.InputModality = contentModality(pl.Content)
			if pl.Role == "user" {
				ev.EventType = schema.EventHumanPrompt
				ev.ActorType = schema.ActorHuman
				ev.Corroboration = schema.StateObserved
			} else {
				ev.EventType = schema.EventModelResponse
				ev.ActorType = schema.ActorModel
				ev.Corroboration = schema.StateReported // narrative, not proof
			}
			p.emit(ev, art, off, line)
		case "function_call", "custom_tool_call":
			ev := base
			ev.EventType = schema.EventToolCall
			ev.ActorType = schema.ActorAgent
			ev.Tool = pl.Name
			ev.ToolCallID = pl.CallID
			ev.Corroboration = schema.StateObserved
			if pl.Name == "shell" || pl.Name == "container.exec" {
				ev.Action = "shell_execution"
				ev.Command = trim(shellCommand(pl.Arguments), 300)
				ev.KeepFull(shellCommand(pl.Arguments))
			} else if strings.Contains(pl.Name, "__") {
				parts := strings.SplitN(pl.Name, "__", 2)
				ev.MCPServer = parts[0]
				ev.MCPTool = parts[1]
				ev.Action = "mcp_call"
			} else if pl.Input != "" {
				// custom_tool_call (exec, apply_patch, …) carries a single
				// string argument: a script or a patch. Keep enough of it to
				// read what was asked.
				ev.Summary = trim(pl.Input, 300)
				if pl.Name == "exec" {
					ev.Action = "shell_execution"
					ev.Command = trim(pl.Input, 300)
					ev.KeepFull(pl.Input)
				}
			}
			if pl.Type == "custom_tool_call" {
				toolargs.Apply(&ev, []byte(pl.Input))
			} else {
				toolargs.Apply(&ev, []byte(pl.Arguments))
			}
			ev.ApprovalState = p.autoApproval()
			p.emit(ev, art, off, line)
			p.linkTool(ev)
		case "local_shell_call":
			ev := base
			ev.EventType = schema.EventToolCall
			ev.ActorType = schema.ActorAgent
			ev.Tool = "local_shell"
			ev.ToolCallID = pl.CallID
			ev.Action = "shell_execution"
			ev.Command = trim(actionCommand(pl.Action), 300)
			ev.KeepFull(actionCommand(pl.Action))
			ev.Corroboration = schema.StateObserved
			toolargs.Apply(&ev, pl.Action)
			ev.ApprovalState = p.autoApproval()
			p.emit(ev, art, off, line)
			p.linkTool(ev)
		case "function_call_output", "custom_tool_call_output":
			// custom_tool_call_output is what the desktop app writes for the
			// result of exec / apply_patch. It was unhandled, so the OBSERVED
			// output side of every such call — what the command actually
			// printed — fell into the generic response_item bucket and no
			// rule that reads tool results ever saw it.
			ev := base
			ev.EventType = schema.EventToolResult
			ev.ActorType = schema.ActorAgent
			ev.ToolCallID = pl.CallID
			ev.Corroboration = schema.StateObserved
			ev.Summary = trim(flatOutput(pl.Output), 200)
			ev.ResultDigest = toolargs.Digest(pl.Output)
			ev.ResultStatus = outputStatus(pl.Output)
			if ev.ResultStatus == "denied" {
				ev.ApprovalState = "denied"
			}
			ev.InputModality = contentModality(pl.Output)
			p.emit(ev, art, off, line)
		case "reasoning":
			ev := base
			ev.EventType = schema.EventModelResponse
			ev.ActorType = schema.ActorModel
			ev.Result = "reasoning"
			ev.Corroboration = schema.StateReported
			p.emit(ev, art, off, line)
		default:
			ev := base
			ev.EventType = schema.EventSessionMeta
			ev.ActorType = schema.ActorSystem
			ev.Result = "response_item:" + trim(pl.Type, 40)
			ev.Corroboration = schema.StateObserved
			p.emit(ev, art, off, line)
		}
	case "turn_context":
		// The policy this turn ran under. "approval=never sandbox=danger-
		// full-access" on a turn that then ran a destructive command is the
		// difference between a supervised agent and an unsupervised one,
		// and it is written nowhere else in the rollout.
		ev := base
		ev.EventType = schema.EventSessionMeta
		ev.ActorType = schema.ActorSystem
		ev.Result = "turn_context"
		ev.TaskID = pl.TurnID
		ev.Model = pl.Model
		ev.Summary = trim(policySummary(pl.ApprovalPolicy, pl.SandboxPolicy, pl.CWD, pl.Model), 200)
		ev.Corroboration = schema.StateObserved
		if pol := trim(pl.ApprovalPolicy, 40); pol != "" {
			ev.PermissionMode = pol
			if p.policy != "" && p.policy != pol {
				// The approval policy changed between turns: the line
				// where it did is its own event.
				pc := base
				pc.EventType = schema.EventPermissionChange
				pc.ActorType = schema.ActorSystem
				pc.Result = "permission_change"
				pc.PermissionFrom, pc.PermissionMode = p.policy, pol
				pc.TaskID = pl.TurnID
				pc.Summary = "approval policy " + p.policy + " → " + pol
				pc.Corroboration = schema.StateObserved
				p.emit(pc, art, off, line)
			}
			p.policy = pol
		}
		p.emit(ev, art, off, line)
		p.touchSession(base.SessionID, base.AgentID)
	case "event_msg":
		ev := base
		switch pl.Type {
		case "user_message":
			ev.EventType = schema.EventHumanPrompt
			ev.ActorType = schema.ActorHuman
			ev.Corroboration = schema.StateObserved
		case "agent_message":
			ev.EventType = schema.EventModelResponse
			ev.ActorType = schema.ActorModel
			ev.Corroboration = schema.StateReported
		default:
			ev.EventType = schema.EventSessionMeta
			ev.ActorType = schema.ActorSystem
			ev.Result = "event_msg:" + trim(pl.Type, 40)
			ev.Corroboration = schema.StateObserved
		}
		ev.Summary = trim(pl.Message, 200)
		p.emit(ev, art, off, line)
	default:
		ev := base
		ev.EventType = schema.EventSessionMeta
		ev.ActorType = schema.ActorSystem
		ev.Result = "unknown_type:" + trim(rl.Type, 40)
		ev.Corroboration = schema.StateObserved
		p.emit(ev, art, off, line)
	}
}

func (p *parser) emit(ev schema.Event, art casepkg.ArtifactRecord, off int64, line int) {
	ev.EventID = fmt.Sprintf(IDFormat, p.seq)
	ev.CaseID = p.caseID
	ev.SchemaVersion = version.SchemaVersion
	ev.Sequence = p.seq
	ev.Host = p.host
	ev.User = art.User
	ev.Vendor = "openai"
	ev.Product = "codex-cli"
	ev.SourceArtifact = art.ArtifactID
	ev.SourcePath = art.LogicalPath
	ev.SourceOffset = off
	ev.SourceLine = line
	if ev.Corroboration == "" {
		ev.Corroboration = schema.StateUnknown
	}
	p.seq++
	if p.pair != nil {
		p.pair.Push(ev)
	} else {
		p.deliver(ev)
	}
}

// deliver hands one finished event to the sink or the result.
func (p *parser) deliver(ev schema.Event) {
	if p.sink != nil {
		p.sink(ev)
	} else {
		p.res.Events = append(p.res.Events, ev)
	}
}

func (p *parser) touchSession(sessionID, agentID string) {
	if sessionID == "" {
		return
	}
	p.addEntity(schema.Entity{EntityID: "session:" + sessionID, Kind: "session",
		Label: sessionID, Product: "codex-cli"})
	p.addEntity(schema.Entity{EntityID: "agent:" + agentID, Kind: "agent",
		Label: agentID, Product: "codex-cli"})
	p.addRel(schema.Relationship{From: "agent:" + agentID, To: "session:" + sessionID,
		Type: "belongs_to", Corroboration: schema.StateObserved})
}

func (p *parser) linkTool(ev schema.Event) {
	p.addEntity(schema.Entity{EntityID: "tool:" + ev.Tool, Kind: "tool", Label: ev.Tool})
	p.addRel(schema.Relationship{From: "agent:" + ev.AgentID, To: "tool:" + ev.Tool,
		Type: "invoked", DerivedFrom: []string{ev.EventID}, Corroboration: ev.Corroboration})
	if ev.MCPServer != "" {
		p.addEntity(schema.Entity{EntityID: "mcp:" + ev.MCPServer, Kind: "mcp_server", Label: ev.MCPServer})
		p.addRel(schema.Relationship{From: "tool:" + ev.Tool, To: "mcp:" + ev.MCPServer,
			Type: "invoked", DerivedFrom: []string{ev.EventID}, Corroboration: ev.Corroboration})
	}
}

func (p *parser) addEntity(e schema.Entity) {
	if p.rec != nil {
		p.rec.Entity(e)
	}
	if _, ok := p.entities[e.EntityID]; !ok {
		p.entities[e.EntityID] = e
	}
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

func (p *parser) finishEntities() {
	keys := make([]string, 0, len(p.entities))
	for k := range p.entities {
		keys = append(keys, k)
	}
	// deterministic order
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[j] < keys[i] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}
	for _, k := range keys {
		p.res.Entities = append(p.res.Entities, p.entities[k])
	}
}

// contentText extracts text from a response_item message content array
// ({"type":"input_text"/"output_text","text":"…"}).
func contentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var items []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return ""
	}
	var texts []string
	for _, it := range items {
		if it.Text != "" {
			texts = append(texts, it.Text)
		}
	}
	return strings.Join(texts, "\n")
}

// shellCommand extracts the command from function_call arguments JSON:
// {"command":["bash","-lc","ls"]} or {"command":"ls"}.
func shellCommand(args string) string {
	var m map[string]any
	if err := json.Unmarshal([]byte(args), &m); err != nil {
		return trim(args, 200)
	}
	switch v := m["command"].(type) {
	case string:
		return v
	case []any:
		var parts []string
		for _, x := range v {
			if s, ok := x.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}
	return trim(args, 200)
}

// policySummary renders a turn's approval and sandbox policy in one line.
// The sandbox is an object ({"type":"danger-full-access"} or
// {"type":"workspace-write","writable_roots":[…]}); only its type is kept.
func policySummary(approval string, sandbox json.RawMessage, cwd, model string) string {
	var parts []string
	if approval != "" {
		parts = append(parts, "approval="+approval)
	}
	if len(sandbox) > 0 {
		var sb struct {
			Type string `json:"type"`
		}
		if json.Unmarshal(sandbox, &sb) == nil && sb.Type != "" {
			parts = append(parts, "sandbox="+sb.Type)
		}
	}
	if model != "" {
		parts = append(parts, "model="+model)
	}
	if cwd != "" {
		parts = append(parts, "cwd="+cwd)
	}
	return strings.Join(parts, " ")
}

func actionCommand(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var a struct {
		Command []string `json:"command"`
	}
	if err := json.Unmarshal(raw, &a); err == nil && len(a.Command) > 0 {
		return strings.Join(a.Command, " ")
	}
	return ""
}

func flatOutput(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s
	}
	var o struct {
		Output string `json:"output"`
	}
	if err := json.Unmarshal(raw, &o); err == nil && o.Output != "" {
		return o.Output
	}
	// custom_tool_call_output: [{"type":"input_text","text":"…"}, …]
	return contentText(raw)
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}

// Live parses individual rollout lines as they are tailed (real-time).
type Live struct{ p *parser }

// NewLive creates a line parser for live tailing.
func NewLive(host string, sink func(schema.Event)) *Live {
	return &Live{p: &parser{res: &Result{}, sink: sink, caseID: "live", host: host, entities: map[string]schema.Entity{}}}
}

// Line feeds one raw JSONL line.
func (l *Live) Line(path string, raw []byte, off int64, line int) {
	art := casepkg.ArtifactRecord{ArtifactID: "live", LogicalPath: path, CollectorRule: "codex.sessions", ArtifactType: "agent_session"}
	var rl rolloutLine
	if err := json.Unmarshal(raw, &rl); err != nil {
		return
	}
	l.p.handleLine(rl, art, off, line)
}

// autoApproval is the approval the recorded turn policy grants a call:
// approval_policy "never" runs every command without asking. Other
// policies decide per call, and the rollout does not record those
// decisions, so the state stays empty.
func (p *parser) autoApproval() string {
	if p.policy == "never" {
		return "auto_approved"
	}
	return ""
}

// Texts Codex writes as the output of a call the user declined.
var declinedOutputs = []string{"exec command rejected by user", "patch rejected by user"}

// outputStatus is the outcome a function_call_output records: "denied"
// for Codex's own rejected-by-user output, "ok" / "error" from the exit
// code in the exec metadata ({"output":…,"metadata":{"exit_code":N}}).
// Anything else records no outcome and yields "".
func outputStatus(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return ""
	}
	t := strings.TrimSpace(s)
	for _, d := range declinedOutputs {
		if strings.HasPrefix(t, d) {
			return "denied"
		}
	}
	if !strings.HasPrefix(t, "{") {
		return ""
	}
	var o struct {
		Metadata *struct {
			ExitCode *int `json:"exit_code"`
		} `json:"metadata"`
	}
	if json.Unmarshal([]byte(t), &o) != nil || o.Metadata == nil || o.Metadata.ExitCode == nil {
		return ""
	}
	if *o.Metadata.ExitCode == 0 {
		return "ok"
	}
	return "error"
}

// contentModality names the first non-text input in a content array
// (input_image, input_file, input_audio).
func contentModality(raw json.RawMessage) string {
	b := strings.TrimSpace(string(raw))
	if !strings.HasPrefix(b, "[") {
		return ""
	}
	var items []struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(raw, &items) != nil {
		return ""
	}
	for _, it := range items {
		switch it.Type {
		case "input_image", "image":
			return "image"
		case "input_file", "file", "document":
			return "document"
		case "input_audio", "audio":
			return "audio"
		}
	}
	return ""
}
