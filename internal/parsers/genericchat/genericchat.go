// Package genericchat normalizes session evidence from the remaining
// supported AI agent products — Gemini CLI, Cursor, Copilot CLI, Cline,
// Roo Code and OpenClaw — into the unified schema. One tolerant engine
// handles the message shapes these products persist:
//
//   - Gemini API style:      {"role":"user|model","parts":[{"text"|"functionCall"|"functionResponse"}]}
//   - Anthropic style:       {"role":"user|assistant","content":[{"type":"text|tool_use|tool_result"}]}
//   - OpenAI chat style:     {"role","content":"…","tool_calls":[{"function":{"name","arguments"}}]}
//   - Plain messages:        {"role","content":"…"} / {"role","text":"…"}
//   - Cursor store.db:       binary SQLite — JSON message fragments are
//     string-carved (classic forensic carving); such events carry
//     result="carved" so analysts can weigh them accordingly.
//
// Evidence-vs-claims discipline is identical everywhere: user input and
// tool-call records are OBSERVED; assistant/model narrative is REPORTED.
// Malformed inputs become trace_gap events, never silent skips.
package genericchat

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/version"
)

// MaxFileBytes bounds a whole session file read (hostile evidence).
const MaxFileBytes = 32 << 20

// productCfg maps collector-rule prefixes to product identity.
type productCfg struct {
	rulePrefix string
	product    string
	vendor     string
}

var productTable = []productCfg{
	{"gemini.", "gemini-cli", "google"},
	{"cursor.", "cursor-cli", "anysphere"},
	{"copilot.", "copilot-cli", "github"},
	{"cline.", "cline", "cline"},
	{"roo.", "roo-code", "roo"},
	{"openclaw.", "openclaw", "openclaw"},
	{"opencode.", "opencode", "sst"},
	{"copilotchat.", "copilot-chat-vscode", "github"},
	{"aider.", "aider", "aider"},
	{"warp.", "warp", "warp"},
}

// sessionCategories are the artifact types this parser consumes.
var sessionCategories = map[string]bool{"agent_session": true, "prompt_history": true}

// ParsePackage parses every matching session artifact in a sealed package.
func ParsePackage(pkgDir string) (*schema.Normalized, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var man casepkg.Manifest
	if err := json.Unmarshal(data, &man); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	p := &parser{res: &schema.Normalized{}, caseID: man.CaseID, host: man.Host,
		entities: map[string]schema.Entity{}}
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK || !sessionCategories[a.ArtifactType] {
			continue
		}
		cfg := productFor(a.CollectorRule)
		if cfg == nil {
			continue // claude/codex have dedicated parsers
		}
		if err := p.parseArtifact(pkgDir, a, cfg); err != nil {
			return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
		}
	}
	p.finishEntities()
	return p.res, nil
}

func productFor(rule string) *productCfg {
	for i := range productTable {
		if strings.HasPrefix(rule, productTable[i].rulePrefix) {
			return &productTable[i]
		}
	}
	return nil
}

type parser struct {
	res      *schema.Normalized
	caseID   string
	host     string
	seq      int
	entities map[string]schema.Entity
}

// parseArtifact dispatches on file shape.
func (p *parser) parseArtifact(pkgDir string, art casepkg.ArtifactRecord, cfg *productCfg) error {
	blob := filepath.Join(pkgDir, "raw", art.ArtifactID)
	st, err := os.Stat(blob)
	if err != nil {
		return err
	}
	if st.Size() > MaxFileBytes {
		p.gap(art, cfg, 0, 1, fmt.Sprintf("session file exceeds %d-byte bound; preserved unparsed", MaxFileBytes))
		return nil
	}
	data, err := os.ReadFile(blob)
	if err != nil {
		return err
	}
	base := filepath.Base(art.LogicalPath)
	sessionID := sessionIDFor(art.LogicalPath)

	switch {
	case strings.HasPrefix(art.CollectorRule, "copilotchat."):
		return p.parseVSCodeChat(data, art, cfg, sessionID)
	case art.CollectorRule == "aider.chat_history":
		return p.parseAiderMarkdown(data, art, cfg)
	case art.CollectorRule == "aider.input_history":
		return p.parseAiderInput(data, art, cfg)
	case strings.HasSuffix(base, ".db") || isBinary(data):
		// Cursor store.db and friends: forensic string-carving.
		msgs := CarveMessages(data)
		if len(msgs) == 0 {
			p.gap(art, cfg, 0, 1, "binary store contained no carvable message fragments")
			return nil
		}
		for _, m := range msgs {
			p.emitMessage(m.msg, art, cfg, sessionID, m.offset, 0, "carved")
		}
		return nil
	case strings.HasSuffix(base, ".jsonl"):
		return p.parseJSONL(data, art, cfg, sessionID)
	case base == "logs.json":
		return p.parseGeminiLogs(data, art, cfg)
	case base == "ui_messages.json":
		return p.parseClineUI(data, art, cfg, sessionID)
	default: // *.json
		return p.parseJSONDoc(data, art, cfg, sessionID)
	}
}

// parseJSONDoc handles a JSON document that is an array of messages or
// an object wrapping one ({"messages":[…]}, {"history":[…]}, …).
func (p *parser) parseJSONDoc(data []byte, art casepkg.ArtifactRecord, cfg *productCfg, sessionID string) error {
	msgs, ok := extractMessageArray(data)
	if !ok {
		// A single message object (OpenCode stores one message per file).
		var probe struct {
			Role string `json:"role"`
			Type string `json:"type"`
		}
		if err := json.Unmarshal(data, &probe); err == nil && (probe.Role != "" || probe.Type != "") {
			p.emitMessage(json.RawMessage(data), art, cfg, sessionID, 0, 1, "")
			return nil
		}
		p.gap(art, cfg, 0, 1, "unrecognized session JSON shape; preserved unparsed")
		return nil
	}
	for i, raw := range msgs {
		p.emitMessage(raw, art, cfg, sessionID, 0, i+1, "")
	}
	return nil
}

// parseJSONL handles line-per-message transcripts (OpenClaw and others).
func (p *parser) parseJSONL(data []byte, art casepkg.ArtifactRecord, cfg *productCfg, sessionID string) error {
	var offset int64
	lineNo := 0
	for _, line := range strings.Split(string(data), "\n") {
		lineNo++
		start := offset
		offset += int64(len(line)) + 1
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !json.Valid([]byte(trimmed)) {
			p.gap(art, cfg, start, lineNo, "malformed transcript line")
			continue
		}
		p.emitMessage(json.RawMessage(trimmed), art, cfg, sessionID, start, lineNo, "")
	}
	return nil
}

// parseGeminiLogs handles ~/.gemini/tmp/<hash>/logs.json:
// [{"sessionId","messageId","type":"user","message","timestamp"}].
func (p *parser) parseGeminiLogs(data []byte, art casepkg.ArtifactRecord, cfg *productCfg) error {
	var entries []struct {
		SessionID string `json:"sessionId"`
		Type      string `json:"type"`
		Message   string `json:"message"`
		Timestamp string `json:"timestamp"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		p.gap(art, cfg, 0, 1, "unrecognized logs.json shape")
		return nil
	}
	for i, e := range entries {
		ev := p.base(art, cfg, e.SessionID)
		ev.Timestamp = e.Timestamp
		ev.EventType = schema.EventHumanPrompt
		ev.ActorType = schema.ActorHuman
		ev.Corroboration = schema.StateObserved
		if e.Type != "" && e.Type != "user" {
			ev.EventType = schema.EventSessionMeta
			ev.ActorType = schema.ActorSystem
			ev.Result = "log:" + trim(e.Type, 40)
		}
		ev.Summary = trim(e.Message, 200)
		p.emit(ev, art, 0, i+1)
	}
	return nil
}

// parseClineUI handles Cline/Roo ui_messages.json:
// [{"ts":…,"type":"say|ask","say":"…","text":"…"}]. These are UI echoes;
// they are normalized as low-detail events (the full API history file is
// the richer source).
func (p *parser) parseClineUI(data []byte, art casepkg.ArtifactRecord, cfg *productCfg, sessionID string) error {
	var entries []struct {
		TS   int64  `json:"ts"`
		Type string `json:"type"`
		Say  string `json:"say"`
		Ask  string `json:"ask"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		p.gap(art, cfg, 0, 1, "unrecognized ui_messages.json shape")
		return nil
	}
	for i, e := range entries {
		ev := p.base(art, cfg, sessionID)
		ev.Timestamp = msToRFC3339(e.TS)
		ev.EventType = schema.EventSessionMeta
		ev.ActorType = schema.ActorSystem
		ev.Result = strings.TrimSpace("ui:" + e.Type + ":" + e.Say + e.Ask)
		ev.Summary = trim(e.Text, 160)
		ev.Corroboration = schema.StateObserved
		p.emit(ev, art, 0, i+1)
	}
	return nil
}

// ---- unified message normalization ----

// message is the tolerant union of the message shapes we accept.
type message struct {
	Role      string           `json:"role"`
	Parts     []part           `json:"parts"`   // gemini
	Content   json.RawMessage  `json:"content"` // anthropic array | plain string
	Text      string           `json:"text"`
	Timestamp string           `json:"timestamp"`
	ToolCalls []openaiToolCall `json:"tool_calls"` // openai
	SessionID string           `json:"sessionID"`  // opencode message files
	Type      string           `json:"type"`       // opencode part files
	Tool      string           `json:"tool"`       // opencode tool part
	State     *struct {
		Input json.RawMessage `json:"input"`
	} `json:"state"`
}

type part struct {
	Text         string `json:"text"`
	FunctionCall *struct {
		Name string          `json:"name"`
		Args json.RawMessage `json:"args"`
	} `json:"functionCall"`
	FunctionResponse *struct {
		Name string `json:"name"`
	} `json:"functionResponse"`
}

type openaiToolCall struct {
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type anthropicItem struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
}

// emitMessage normalizes one message object into events.
func (p *parser) emitMessage(raw json.RawMessage, art casepkg.ArtifactRecord, cfg *productCfg,
	sessionID string, offset int64, line int, method string) {

	var m message
	if err := json.Unmarshal(raw, &m); err != nil ||
		(m.Role == "" && m.Text == "" && len(m.Parts) == 0 && m.Type == "") {
		p.gap(art, cfg, offset, line, "unrecognized message shape")
		return
	}
	if m.SessionID != "" {
		sessionID = m.SessionID
	}
	// Role-less part objects (OpenCode stores parts as separate files).
	if m.Role == "" && m.Type != "" {
		ev := p.base(art, cfg, sessionID)
		ev.Timestamp = m.Timestamp
		ev.Result = strings.TrimSpace(method + " part:" + trim(m.Type, 30))
		switch m.Type {
		case "tool":
			ev.EventType = schema.EventToolCall
			ev.ActorType = schema.ActorAgent
			ev.Tool = m.Tool
			ev.Corroboration = schema.StateObserved
			if m.State != nil {
				if cmd := commandArg(m.State.Input); cmd != "" {
					ev.Command = trim(cmd, 300)
					ev.Action = "shell_execution"
				}
			}
			p.emit(ev, art, offset, line)
			p.linkTool(ev)
		case "text":
			ev.EventType = schema.EventSessionMeta
			ev.ActorType = schema.ActorSystem
			ev.Summary = trim(m.Text, 200)
			ev.Corroboration = schema.StateObserved
			p.emit(ev, art, offset, line)
		default:
			ev.EventType = schema.EventSessionMeta
			ev.ActorType = schema.ActorSystem
			ev.Corroboration = schema.StateObserved
			p.emit(ev, art, offset, line)
		}
		return
	}
	isModel := m.Role == "model" || m.Role == "assistant"
	mk := func() schema.Event {
		ev := p.base(art, cfg, sessionID)
		ev.Timestamp = m.Timestamp
		ev.Result = method
		return ev
	}

	emitted := false

	// Gemini parts.
	for _, pt := range m.Parts {
		switch {
		case pt.FunctionCall != nil:
			ev := mk()
			ev.EventType = schema.EventToolCall
			ev.ActorType = schema.ActorAgent
			ev.Tool = pt.FunctionCall.Name
			ev.Corroboration = schema.StateObserved
			if cmd := commandArg(pt.FunctionCall.Args); cmd != "" {
				ev.Command = trim(cmd, 300)
				ev.Action = "shell_execution"
			}
			p.emit(ev, art, offset, line)
			p.linkTool(ev)
			emitted = true
		case pt.FunctionResponse != nil:
			ev := mk()
			ev.EventType = schema.EventToolResult
			ev.ActorType = schema.ActorAgent
			ev.Tool = pt.FunctionResponse.Name
			ev.Corroboration = schema.StateObserved
			p.emit(ev, art, offset, line)
			emitted = true
		case pt.Text != "":
			p.emitText(mk, pt.Text, isModel, art, offset, line)
			emitted = true
		}
	}

	// Anthropic-style content array (Cline/Roo) or plain string content.
	if len(m.Content) > 0 {
		var items []anthropicItem
		if err := json.Unmarshal(m.Content, &items); err == nil {
			for _, it := range items {
				switch it.Type {
				case "tool_use":
					ev := mk()
					ev.EventType = schema.EventToolCall
					ev.ActorType = schema.ActorAgent
					ev.Tool = it.Name
					ev.ToolCallID = it.ID
					ev.Corroboration = schema.StateObserved
					if cmd := commandArg(it.Input); cmd != "" {
						ev.Command = trim(cmd, 300)
						ev.Action = "shell_execution"
					}
					p.emit(ev, art, offset, line)
					p.linkTool(ev)
					emitted = true
				case "tool_result":
					ev := mk()
					ev.EventType = schema.EventToolResult
					ev.ActorType = schema.ActorAgent
					ev.ToolCallID = it.ToolUseID
					ev.Corroboration = schema.StateObserved
					p.emit(ev, art, offset, line)
					emitted = true
				default:
					if it.Text != "" {
						p.emitText(mk, it.Text, isModel, art, offset, line)
						emitted = true
					}
				}
			}
		} else {
			var s string
			if err := json.Unmarshal(m.Content, &s); err == nil && s != "" {
				p.emitText(mk, s, isModel, art, offset, line)
				emitted = true
			}
		}
	}

	// OpenAI-style tool calls (Copilot).
	for _, tc := range m.ToolCalls {
		ev := mk()
		ev.EventType = schema.EventToolCall
		ev.ActorType = schema.ActorAgent
		ev.Tool = tc.Function.Name
		ev.ToolCallID = tc.ID
		ev.Corroboration = schema.StateObserved
		if cmd := commandArg(json.RawMessage(tc.Function.Arguments)); cmd != "" {
			ev.Command = trim(cmd, 300)
			ev.Action = "shell_execution"
		}
		p.emit(ev, art, offset, line)
		p.linkTool(ev)
		emitted = true
	}

	if !emitted && m.Text != "" {
		p.emitText(mk, m.Text, isModel, art, offset, line)
		emitted = true
	}
	if !emitted {
		ev := mk()
		ev.EventType = schema.EventSessionMeta
		ev.ActorType = schema.ActorSystem
		ev.Result = strings.TrimSpace(method + " empty:" + trim(m.Role, 20))
		ev.Corroboration = schema.StateObserved
		p.emit(ev, art, offset, line)
	}
}

// emitText emits narrative/prompt text with the evidence-vs-claims split,
// and additionally extracts Cline's XML-style tool invocations from
// assistant text (<execute_command><command>…</command></execute_command>).
func (p *parser) emitText(mk func() schema.Event, text string, isModel bool,
	art casepkg.ArtifactRecord, offset int64, line int) {
	ev := mk()
	ev.Summary = trim(text, 200)
	if isModel {
		ev.EventType = schema.EventModelResponse
		ev.ActorType = schema.ActorModel
		ev.Corroboration = schema.StateReported // narrative, not proof
	} else {
		ev.EventType = schema.EventHumanPrompt
		ev.ActorType = schema.ActorHuman
		ev.Corroboration = schema.StateObserved
	}
	p.emit(ev, art, offset, line)

	if isModel {
		if cmd := xmlCommand(text); cmd != "" {
			tc := mk()
			tc.EventType = schema.EventToolCall
			tc.ActorType = schema.ActorAgent
			tc.Tool = "execute_command"
			tc.Action = "shell_execution"
			tc.Command = trim(cmd, 300)
			tc.Corroboration = schema.StateObserved
			p.emit(tc, art, offset, line)
			p.linkTool(tc)
		}
	}
}

// ---- helpers ----

func (p *parser) base(art casepkg.ArtifactRecord, cfg *productCfg, sessionID string) schema.Event {
	p.touchSession(cfg, sessionID)
	return schema.Event{
		TimestampSrc: "transcript",
		SessionID:    sessionID,
		AgentID:      "main:" + sessionID,
		Vendor:       cfg.vendor,
		Product:      cfg.product,
	}
}

func (p *parser) emit(ev schema.Event, art casepkg.ArtifactRecord, off int64, line int) {
	ev.EventID = fmt.Sprintf("evt-g-%06d", p.seq)
	ev.CaseID = p.caseID
	ev.SchemaVersion = version.SchemaVersion
	ev.Sequence = p.seq
	ev.Host = p.host
	ev.User = art.User
	ev.SourceArtifact = art.ArtifactID
	ev.SourcePath = art.LogicalPath
	ev.SourceOffset = off
	ev.SourceLine = line
	if ev.Corroboration == "" {
		ev.Corroboration = schema.StateUnknown
	}
	p.seq++
	p.res.Events = append(p.res.Events, ev)
}

func (p *parser) gap(art casepkg.ArtifactRecord, cfg *productCfg, off int64, line int, why string) {
	ev := p.base(art, cfg, sessionIDFor(art.LogicalPath))
	ev.EventType = schema.EventTraceGap
	ev.ActorType = schema.ActorSystem
	ev.Result = "unparsed"
	ev.Summary = why
	ev.Corroboration = schema.StateObserved
	p.emit(ev, art, off, line)
}

func (p *parser) touchSession(cfg *productCfg, sessionID string) {
	if sessionID == "" {
		return
	}
	p.addEntity(schema.Entity{EntityID: "session:" + sessionID, Kind: "session",
		Label: sessionID, Product: cfg.product})
	p.addEntity(schema.Entity{EntityID: "agent:main:" + sessionID, Kind: "agent",
		Label: "main:" + sessionID, Product: cfg.product})
	p.addRel(schema.Relationship{From: "agent:main:" + sessionID, To: "session:" + sessionID,
		Type: "belongs_to", Corroboration: schema.StateObserved})
}

func (p *parser) linkTool(ev schema.Event) {
	if ev.Tool == "" {
		return
	}
	p.addEntity(schema.Entity{EntityID: "tool:" + ev.Tool, Kind: "tool", Label: ev.Tool})
	p.addRel(schema.Relationship{From: "agent:" + ev.AgentID, To: "tool:" + ev.Tool,
		Type: "invoked", DerivedFrom: []string{ev.EventID}, Corroboration: ev.Corroboration})
}

func (p *parser) addEntity(e schema.Entity) {
	if _, ok := p.entities[e.EntityID]; !ok {
		p.entities[e.EntityID] = e
	}
}

func (p *parser) addRel(r schema.Relationship) {
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
	sort.Strings(keys)
	for _, k := range keys {
		p.res.Entities = append(p.res.Entities, p.entities[k])
	}
}

// extractMessageArray accepts a bare array or common wrapper keys.
func extractMessageArray(data []byte) ([]json.RawMessage, bool) {
	var arr []json.RawMessage
	if err := json.Unmarshal(data, &arr); err == nil {
		return arr, true
	}
	var wrap map[string]json.RawMessage
	if err := json.Unmarshal(data, &wrap); err != nil {
		return nil, false
	}
	for _, key := range []string{"messages", "chatMessages", "history", "conversation", "events"} {
		if raw, ok := wrap[key]; ok {
			if err := json.Unmarshal(raw, &arr); err == nil {
				return arr, true
			}
		}
	}
	return nil, false
}

// commandArg pulls a shell command out of tool arguments.
func commandArg(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return ""
	}
	for _, key := range []string{"command", "cmd", "script"} {
		switch v := m[key].(type) {
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
	}
	return ""
}

// xmlCommand extracts Cline-style XML tool text:
// <execute_command>…<command>CMD</command>…</execute_command>.
func xmlCommand(text string) string {
	i := strings.Index(text, "<execute_command>")
	if i < 0 {
		return ""
	}
	rest := text[i:]
	a := strings.Index(rest, "<command>")
	b := strings.Index(rest, "</command>")
	if a < 0 || b < 0 || b <= a {
		return ""
	}
	return strings.TrimSpace(rest[a+len("<command>") : b])
}

// sessionIDFor derives a stable session identity from the logical path:
// the filename stem, or the parent directory for generically-named files.
func sessionIDFor(logicalPath string) string {
	base := filepath.Base(logicalPath)
	stem := strings.TrimSuffix(base, filepath.Ext(base))
	switch base {
	case "logs.json", "ui_messages.json", "api_conversation_history.json", "store.db":
		if dir := filepath.Base(filepath.Dir(logicalPath)); dir != "." && dir != "/" {
			return dir
		}
	}
	return stem
}

// isBinary reports whether data looks like a binary blob (NUL bytes in
// the head) rather than text JSON.
func isBinary(data []byte) bool {
	n := len(data)
	if n > 512 {
		n = 512
	}
	for i := 0; i < n; i++ {
		if data[i] == 0 {
			return true
		}
	}
	return false
}

func msToRFC3339(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return timeUnixMilli(ms)
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
