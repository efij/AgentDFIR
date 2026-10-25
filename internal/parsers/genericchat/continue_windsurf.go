package genericchat

// Continue (continue.dev) and Windsurf (Codeium) session stores.
//
// Continue writes one JSON document per session under ~/.continue/sessions:
//
//	{"sessionId","title","workspaceDirectory","mode","chatModelTitle",
//	 "history":[{"message":{"role":"user|assistant|thinking|system|tool",
//	             "content": "…" | [{"type":"text","text"}…],
//	             "toolCalls":[{"id","type":"function","function":{"name","arguments"}}],
//	             "toolCallId"},
//	           "contextItems":[{"name","description","uri":{"type","value"},"id":{"providerTitle"}}],
//	           "toolCallState":{…}, "toolCallStates":[{"toolCallId","toolCall","status","output"}]}]}
//
// plus sessions.json, an index of {sessionId,title,dateCreated,workspaceDirectory}.
// History items are wrapped ({"message":{…}}), which is why the generic
// message engine cannot read them as they are. Tool calls are RECORDED as
// tool_call events (OBSERVED: the product's own record of the call), and
// the state Continue kept for each call (done, errored, canceled) as its
// tool_result. Assistant narrative is REPORTED.
//
// Windsurf's Cascade conversations (~/.codeium/windsurf/cascade/*.pb) and
// auto-generated memories (memories/*.pb) are protobuf with no published
// schema, and current builds encrypt them. They are collected and sealed;
// this file reports each one's metadata and says, per file, that its
// content is UNSUPPORTED and why. Nothing is carved out of them: bytes
// that happen to look like text in an encrypted blob are not evidence.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// Collector rules with dedicated handling here.
const (
	ruleContinueSessions = "continue.sessions"
	ruleWindsurfCascade  = "windsurf.cascade"
	ruleWindsurfMemories = "windsurf.memories"
)

// opaqueHeadBytes is how much of an opaque store is read to characterize
// it (entropy); the rest stays sealed and unread.
const opaqueHeadBytes = 64 << 10

type continueSession struct {
	SessionID          string          `json:"sessionId"`
	Title              string          `json:"title"`
	WorkspaceDirectory string          `json:"workspaceDirectory"`
	Mode               string          `json:"mode"`
	ChatModelTitle     string          `json:"chatModelTitle"`
	History            json.RawMessage `json:"history"`
}

type continueToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"` // JSON-encoded string, or an object in some builds
	} `json:"function"`
}

type continueToolState struct {
	ToolCallID string           `json:"toolCallId"`
	ToolCall   continueToolCall `json:"toolCall"`
	Status     string           `json:"status"`
	Output     []struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	} `json:"output"`
}

type continueItem struct {
	Message *struct {
		Role       string             `json:"role"`
		Content    json.RawMessage    `json:"content"`
		ToolCalls  []continueToolCall `json:"toolCalls"`
		ToolCallID string             `json:"toolCallId"`
	} `json:"message"`
	ContextItems []struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		URI         *struct {
			Type  string `json:"type"`
			Value string `json:"value"`
		} `json:"uri"`
		ID struct {
			ProviderTitle string `json:"providerTitle"`
		} `json:"id"`
	} `json:"contextItems"`
	ToolCallState  *continueToolState  `json:"toolCallState"`
	ToolCallStates []continueToolState `json:"toolCallStates"`
}

// parseContinueSession normalizes one ~/.continue/sessions/<id>.json.
func (p *parser) parseContinueSession(data []byte, art casepkg.ArtifactRecord, cfg *productCfg, fallbackID string) error {
	var s continueSession
	if err := json.Unmarshal(data, &s); err != nil {
		p.gap(art, cfg, 0, 1, "Continue session is not valid JSON: "+trim(err.Error(), 120))
		return nil
	}
	var items []json.RawMessage
	if len(s.History) > 0 && json.Unmarshal(s.History, &items) != nil {
		p.gap(art, cfg, 0, 1, "Continue session history is not an array; preserved unparsed")
		return nil
	}
	sid := s.SessionID
	if sid == "" {
		sid = fallbackID
	}
	cwd := fileURIPath(s.WorkspaceDirectory)

	meta := p.base(art, cfg, sid)
	meta.EventType, meta.ActorType = schema.EventSessionMeta, schema.ActorSystem
	meta.Result = "session_meta"
	meta.Cwd = cwd
	meta.Model = s.ChatModelTitle
	meta.Corroboration = schema.StateObserved
	var parts []string
	for _, kv := range [][2]string{{"title", trim(s.Title, 80)}, {"workspace", cwd}, {"mode", s.Mode}, {"model", s.ChatModelTitle}} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	parts = append(parts, fmt.Sprintf("items=%d", len(items)))
	meta.Summary = trim(strings.Join(parts, " "), 300)
	p.emit(meta, art, 0, 0)

	locs := continueItemLocs(data, len(items))
	for i, raw := range items {
		loc := locs[i]
		var it continueItem
		if err := json.Unmarshal(raw, &it); err != nil || it.Message == nil {
			p.gap(art, cfg, loc.off, loc.line, "unrecognized Continue history item")
			continue
		}
		p.continueItem(it, art, cfg, sid, cwd, loc)
	}
	return nil
}

// srcLoc is where a history item starts in the session file: its line and
// the byte offset of that line, the schema's source_line/source_offset.
type srcLoc struct {
	off  int64
	line int
}

// continueItemLocs finds the start of each element of the top-level
// "history" array. Items it cannot place (a file the decoder disagrees
// with) cite line 1, the whole document, rather than a wrong line.
func continueItemLocs(data []byte, n int) []srcLoc {
	locs := make([]srcLoc, n)
	for i := range locs {
		locs[i] = srcLoc{0, 1}
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return locs
	}
	for dec.More() {
		k, err := dec.Token()
		if err != nil {
			return locs
		}
		if k != "history" {
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				return locs
			}
			continue
		}
		if t, err := dec.Token(); err != nil || t != json.Delim('[') {
			return locs
		}
		for i := 0; i < n && dec.More(); i++ {
			start := int(dec.InputOffset())
			for start < len(data) && (data[start] == ',' || data[start] == ' ' || data[start] == '\t' || data[start] == '\r' || data[start] == '\n') {
				start++
			}
			lineStart := bytes.LastIndexByte(data[:start], '\n') + 1
			locs[i] = srcLoc{int64(lineStart), bytes.Count(data[:start], []byte{'\n'}) + 1}
			var skip json.RawMessage
			if dec.Decode(&skip) != nil {
				return locs
			}
		}
		return locs
	}
	return locs
}

func (p *parser) continueItem(it continueItem, art casepkg.ArtifactRecord, cfg *productCfg, sid, cwd string, loc srcLoc) {
	line := loc.line
	msg := it.Message
	mk := func() schema.Event {
		ev := p.base(art, cfg, sid)
		ev.Cwd = cwd
		return ev
	}
	text := continueText(msg.Content)
	switch msg.Role {
	case "user":
		ev := mk()
		ev.EventType, ev.ActorType = schema.EventHumanPrompt, schema.ActorHuman
		ev.Corroboration = schema.StateObserved
		ev.Summary = trim(text, 200)
		p.emit(ev, art, loc.off, line)
	case "assistant", "thinking":
		if text != "" {
			ev := mk()
			ev.EventType, ev.ActorType = schema.EventModelResponse, schema.ActorModel
			ev.Corroboration = schema.StateReported // narrative, not proof
			if msg.Role == "thinking" {
				ev.Result = "thinking"
			}
			ev.Summary = trim(text, 200)
			p.emit(ev, art, loc.off, line)
		}
	case "tool":
		ev := mk()
		ev.EventType, ev.ActorType = schema.EventToolResult, schema.ActorAgent
		ev.Corroboration = schema.StateObserved
		ev.ToolCallID = msg.ToolCallID
		ev.Summary = trim(text, 200)
		p.emit(ev, art, loc.off, line)
	case "system":
		ev := mk()
		ev.EventType, ev.ActorType = schema.EventSessionMeta, schema.ActorSystem
		ev.Corroboration = schema.StateObserved
		ev.Result = "system_message"
		ev.Summary = trim(text, 200)
		p.emit(ev, art, loc.off, line)
	default:
		ev := mk()
		ev.EventType, ev.ActorType = schema.EventSessionMeta, schema.ActorSystem
		ev.Corroboration = schema.StateObserved
		ev.Result = "role:" + trim(msg.Role, 30)
		p.emit(ev, art, loc.off, line)
	}

	// Context the user (or a provider) attached to the turn: files, URLs,
	// docs, MCP resources. Names and locations only.
	for _, c := range it.ContextItems {
		ev := mk()
		ev.EventType, ev.ActorType = schema.EventSessionMeta, schema.ActorSystem
		ev.Corroboration = schema.StateObserved
		ev.Result = "context_item"
		s := strings.TrimSpace(c.ID.ProviderTitle + " " + c.Name)
		if c.URI != nil && c.URI.Value != "" {
			s += " " + c.URI.Value
		}
		ev.Summary = trim(s, 200)
		p.emit(ev, art, loc.off, line)
	}

	// Tool calls: the per-call states carry the outcome; fall back to the
	// message's tool calls for builds that do not keep states.
	states := it.ToolCallStates
	if it.ToolCallState != nil {
		states = append([]continueToolState{*it.ToolCallState}, states...)
	}
	seen := map[string]bool{}
	for _, st := range states {
		tc := st.ToolCall
		if tc.ID == "" {
			tc.ID = st.ToolCallID
		}
		if tc.ID != "" && seen[tc.ID] {
			continue
		}
		seen[tc.ID] = true
		call := mk()
		p.continueToolCall(&call, tc)
		p.emit(call, art, loc.off, line)
		p.linkTool(call)
		if st.Status != "" {
			res := mk()
			res.EventType, res.ActorType = schema.EventToolResult, schema.ActorAgent
			res.Corroboration = schema.StateObserved
			res.Tool, res.ToolCallID, res.Result = call.Tool, call.ToolCallID, st.Status
			if len(st.Output) > 0 {
				res.Summary = trim(fmt.Sprintf("%d output item(s): %s", len(st.Output), st.Output[0].Name), 200)
			}
			p.emit(res, art, loc.off, line)
		}
	}
	for _, tc := range msg.ToolCalls {
		if tc.ID != "" && seen[tc.ID] {
			continue
		}
		seen[tc.ID] = true
		call := mk()
		p.continueToolCall(&call, tc)
		p.emit(call, art, loc.off, line)
		p.linkTool(call)
	}
}

// continueToolCall fills a tool_call event from a Continue tool call,
// mapping the built-in tools onto the fields rules read.
func (p *parser) continueToolCall(ev *schema.Event, tc continueToolCall) {
	ev.EventType, ev.ActorType = schema.EventToolCall, schema.ActorAgent
	ev.Corroboration = schema.StateObserved
	ev.Tool = tc.Function.Name
	ev.ToolCallID = tc.ID
	args := argsObject(tc.Function.Arguments)
	str := func(keys ...string) string {
		for _, k := range keys {
			if v, ok := args[k].(string); ok && v != "" {
				return v
			}
		}
		return ""
	}
	switch strings.TrimPrefix(tc.Function.Name, "builtin_") {
	case "run_terminal_command":
		cmd := str("command", "cmd")
		ev.Command = trim(cmd, 300)
		ev.KeepFull(cmd)
		ev.Action = "shell_execution"
	case "read_file", "read_file_range", "read_currently_open_file", "view_subdirectory", "ls":
		ev.File = str("filepath", "filePath", "path", "dirPath")
		ev.Action = "read_file"
	case "create_new_file":
		ev.File = str("filepath", "filePath", "path")
		ev.Action = "write_file"
	case "edit_existing_file", "single_find_and_replace", "multi_edit":
		ev.File = str("filepath", "filePath", "path")
		ev.Action = "edit_file"
	case "fetch_url_content":
		ev.NetworkDest = str("url")
		ev.Summary = trim(ev.NetworkDest, 200)
	case "search_web":
		ev.Action = "web_search"
		ev.Summary = trim(str("query"), 200)
	case "grep_search", "file_glob_search":
		ev.Summary = trim(str("query", "pattern"), 200)
	default:
		if len(tc.Function.Arguments) > 0 {
			ev.Summary = trim("args="+argsText(tc.Function.Arguments), 300)
		}
	}
}

// argsObject decodes tool arguments given as a JSON-encoded string or an
// object; anything else is an empty map.
func argsObject(raw json.RawMessage) map[string]any {
	var m map[string]any
	if json.Unmarshal(raw, &m) == nil {
		return m
	}
	var s string
	if json.Unmarshal(raw, &s) == nil && json.Unmarshal([]byte(s), &m) == nil {
		return m
	}
	return map[string]any{}
}

func argsText(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return string(raw)
}

// continueText flattens message content: a string, or parts of which the
// text ones are kept (image parts are named, never decoded).
func continueText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var parts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &parts) != nil {
		return ""
	}
	var out []string
	for _, pt := range parts {
		switch {
		case pt.Text != "":
			out = append(out, pt.Text)
		case pt.Type != "":
			out = append(out, "["+pt.Type+"]")
		}
	}
	return strings.Join(out, "\n")
}

// parseContinueIndex reads ~/.continue/sessions/sessions.json: one
// session_meta per listed session, dated by its dateCreated.
func (p *parser) parseContinueIndex(data []byte, art casepkg.ArtifactRecord, cfg *productCfg) error {
	var entries []struct {
		SessionID          string          `json:"sessionId"`
		Title              string          `json:"title"`
		DateCreated        json.RawMessage `json:"dateCreated"`
		WorkspaceDirectory string          `json:"workspaceDirectory"`
	}
	if err := json.Unmarshal(data, &entries); err != nil {
		p.gap(art, cfg, 0, 1, "unrecognized Continue sessions.json shape")
		return nil
	}
	for i, e := range entries {
		if e.SessionID == "" {
			continue
		}
		ev := p.base(art, cfg, e.SessionID)
		ev.EventType, ev.ActorType = schema.EventSessionMeta, schema.ActorSystem
		ev.Corroboration = schema.StateObserved
		ev.Result = "session_index"
		ev.Timestamp = flexibleTime(e.DateCreated)
		if ev.Timestamp != "" {
			ev.TimestampSrc = "metadata"
		}
		ev.Cwd = fileURIPath(e.WorkspaceDirectory)
		ev.Summary = trim("title="+e.Title, 200)
		p.emit(ev, art, 0, i+1)
	}
	return nil
}

// flexibleTime reads epoch milliseconds (number or numeric string) or an
// RFC 3339 string.
func flexibleTime(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		s = strings.TrimSpace(string(raw))
	}
	if s == "" || s == "null" {
		return ""
	}
	if ms, err := strconv.ParseInt(s, 10, 64); err == nil {
		if ms <= 0 || ms > 1e14 {
			return ""
		}
		return msToRFC3339(ms)
	}
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t.UTC().Format(time.RFC3339Nano)
	}
	return ""
}

// fileURIPath turns file:///Users/x/repo into /Users/x/repo.
func fileURIPath(s string) string {
	if strings.HasPrefix(s, "file://") {
		return strings.TrimPrefix(s, "file://")
	}
	return s
}

// parseOpaqueStore reports a Windsurf Cascade or memory store: name, size,
// modification time and why its content is not decoded. It reads at most
// opaqueHeadBytes to measure entropy.
func (p *parser) parseOpaqueStore(store *casepkg.Store, art casepkg.ArtifactRecord, cfg *productCfg) error {
	id := strings.TrimSuffix(filepath.Base(art.LogicalPath), filepath.Ext(art.LogicalPath))
	kind := "Cascade conversation store"
	if art.CollectorRule == ruleWindsurfMemories {
		kind = "Cascade memory store"
	}
	var head []byte
	if rc, err := store.Open(art.ArtifactID); err == nil {
		head, _ = io.ReadAll(io.LimitReader(rc, opaqueHeadBytes))
		rc.Close()
	}
	reason, result := opaqueReason(head)
	ev := p.base(art, cfg, "cascade:"+id)
	ev.EventType, ev.ActorType = schema.EventSessionMeta, schema.ActorSystem
	ev.Corroboration = schema.StateObserved
	ev.Result = result
	if art.ModTimeUTC != "" {
		ev.Timestamp, ev.TimestampSrc = art.ModTimeUTC, "file_mtime"
	}
	ev.Summary = trim(fmt.Sprintf("Windsurf %s %s (%d bytes, modified %s): content UNSUPPORTED — %s; preserved sealed",
		kind, filepath.Base(art.LogicalPath), art.Size, orUnknown(art.ModTimeUTC), reason), 400)
	p.emit(ev, art, 0, 0)
	return nil
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// opaqueReason characterizes an undecoded store from its first bytes.
func opaqueReason(head []byte) (reason, result string) {
	if len(head) == 0 {
		return "empty or unreadable", "unsupported:empty"
	}
	h := entropy(head)
	if h >= 7.5 {
		return fmt.Sprintf("appears encrypted (%.2f bits/byte over the first %d bytes); no published schema or key", h, len(head)),
			"unsupported:encrypted"
	}
	return fmt.Sprintf("protobuf with no published schema (%.2f bits/byte); not decoded", h), "unsupported:undocumented_format"
}

// entropy is the Shannon entropy of b in bits per byte.
func entropy(b []byte) float64 {
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	var h float64
	n := float64(len(b))
	for _, c := range counts {
		if c == 0 {
			continue
		}
		q := float64(c) / n
		h -= q * math.Log2(q)
	}
	return h
}
