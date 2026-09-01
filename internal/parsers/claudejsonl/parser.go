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
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/parsers/linereader"
	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/version"
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

// ParsePackage parses every claude.sessions artifact in a sealed package.
func ParsePackage(pkgDir string) (*Result, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var man casepkg.Manifest
	if err := json.Unmarshal(data, &man); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	res := &Result{}
	p := &parser{res: res, caseID: man.CaseID, host: man.Host,
		entities: map[string]schema.Entity{}, spawned: map[string]string{}}
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK || a.CollectorRule != "claude.sessions" ||
			!strings.HasSuffix(a.LogicalPath, ".jsonl") {
			continue
		}
		blob := filepath.Join(pkgDir, "raw", a.ArtifactID)
		if err := p.parseTranscript(blob, a); err != nil {
			return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
		}
	}
	p.finish()
	return res, nil
}

type parser struct {
	res      *Result
	caseID   string
	host     string
	seq      int
	entities map[string]schema.Entity
	// spawned maps agent IDs to the event_id of their observed spawn.
	spawned map[string]string
}

func (p *parser) parseTranscript(blobPath string, art casepkg.ArtifactRecord) error {
	f, err := os.Open(blobPath)
	if err != nil {
		return err
	}
	defer f.Close()

	uuids := map[string]bool{}
	type parentRef struct {
		parent string
		off    int64
		line   int
		sess   string
	}
	var parents []parentRef

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
		if tl.UUID != "" {
			uuids[tl.UUID] = true
		}
		if tl.ParentUUID != "" {
			parents = append(parents, parentRef{tl.ParentUUID, ln.Offset, ln.Number, tl.SessionID})
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
				if it.AgentID != "" {
					p.spawned[it.AgentID] = fmt.Sprintf("evt-%06d", p.seq)
				}
				p.emit(ev, art, off, line)
				emittedToolResult = true
			}
		}
		if !emittedToolResult {
			ev := base
			if tl.IsSidechain {
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

			if it.Name == "Task" {
				sp := base
				sp.EventType = schema.EventAgentSpawn
				sp.ActorType = schema.ActorAgent
				sp.ToolCallID = it.ID
				sp.Corroboration = schema.StateObserved
				sp.Summary = "subagent spawn requested via Task tool"
				if child := inputField(it.Input, "agentId"); child != "" {
					sp.TaskID = child
					p.spawned[child] = fmt.Sprintf("evt-%06d", p.seq)
				}
				p.emit(sp, art, off, line)
			}
		}
	case "system", "summary", "progress":
		ev := base
		ev.EventType = schema.EventSessionMeta
		ev.ActorType = schema.ActorSystem
		ev.Result = tl.Type
		ev.Corroboration = schema.StateObserved
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
	case it.Name == "Read" || it.Name == "Write" || it.Name == "Edit":
		ev.File = inputField(it.Input, "file_path")
		ev.Action = strings.ToLower(it.Name) + "_file"
	case it.Name == "SendMessage":
		ev.Action = "inter_agent_message"
		ev.Summary = "to=" + trim(inputField(it.Input, "to"), 80)
	case it.Name == "Task":
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
			Label: tl.SessionID, Product: "claude-code",
		})
	}
	attrs := map[string]string{}
	if tl.IsSidechain {
		attrs["sidechain"] = "true"
	}
	p.addEntity(schema.Entity{
		EntityID: "agent:" + agentID, Kind: "agent",
		Label: agentID, Product: "claude-code", Attributes: attrs,
	})
	if tl.SessionID != "" {
		p.addRel(schema.Relationship{
			From: "agent:" + agentID, To: "session:" + tl.SessionID,
			Type: "belongs_to", Corroboration: schema.StateObserved,
		})
	}
}

func (p *parser) emit(ev schema.Event, art casepkg.ArtifactRecord, off int64, line int) {
	ev.EventID = fmt.Sprintf("evt-%06d", p.seq)
	ev.CaseID = p.caseID
	ev.SchemaVersion = version.SchemaVersion
	ev.Sequence = p.seq
	ev.Host = p.host
	ev.User = art.User
	ev.Vendor = "anthropic"
	ev.Product = "claude-code"
	ev.SourceArtifact = art.ArtifactID
	ev.SourcePath = art.LogicalPath
	ev.SourceOffset = off
	ev.SourceLine = line
	if ev.Corroboration == "" {
		ev.Corroboration = schema.StateUnknown
	}
	p.seq++
	p.res.Events = append(p.res.Events, ev)

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
