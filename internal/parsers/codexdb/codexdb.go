// Package codexdb parses the SQLite stores the Codex desktop app and
// current Codex CLI keep beside the rollout transcripts:
//
//	~/.codex/state_*.sqlite          threads: cwd, model, sandbox and approval
//	                                 policy, git origin/branch, source (app,
//	                                 CLI, exec), spawn edges between threads
//	~/.codex/thread_history_*.sqlite thread_items: every user message, agent
//	                                 message, command execution, file change,
//	                                 MCP call and web search, as JSON rows
//
// Rollout JSONL is still the primary transcript. Where a thread's rollout
// is in the package, this parser adds only what the rollout does not
// carry: the thread row (policy, git, source) and spawn edges. Where the
// rollout is missing — pruned, never written (history_mode without a
// rollout), or outside the collection — the item rows become the
// transcript, so the thread does not vanish from the case.
//
// The same evidence-vs-claims discipline applies: agent text is REPORTED;
// command, file-change and MCP rows are OBSERVED. Timestamps come from the
// database (timestamp_source="database").
package codexdb

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/parsers/segment"
	"github.com/efij/AgentDFIR/v2/internal/parsers/sqlitero"
	"github.com/efij/AgentDFIR/v2/internal/schema"
	"github.com/efij/AgentDFIR/v2/internal/version"
)

// Collector rules whose artifacts this parser reads.
const (
	RuleState   = "codex.state_db"
	RuleHistory = "codex.thread_history_db"
)

// MaxDBBytes bounds one database image held in memory while it is walked.
const MaxDBBytes = 512 << 20

// IDFormat renders an event id from its sequence number.
const IDFormat = "evt-xd-%06d"

// Result mirrors the other parsers' output shape.
type Result = schema.Normalized

// ParsePackage parses every Codex database artifact in a sealed package.
func ParsePackage(pkgDir string) (*Result, error) { return parseWith(pkgDir, nil) }

// StreamPackage parses and emits every event to sink instead of
// accumulating them.
func StreamPackage(pkgDir string, sink func(schema.Event)) (*Result, error) {
	return parseWith(pkgDir, sink)
}

// StreamPackageCached has the signature the overlay expects. The cache is
// deliberately not used: which rows this parser turns into events depends
// on which rollouts are in the package, so an artifact's contribution can
// change when the artifact itself did not. Replaying a cached segment
// would then be wrong, and a full walk of a 60 MB store takes well under
// a second.
func StreamPackageCached(pkgDir string, sink func(schema.Event), _ segment.Cache) (*Result, error) {
	return parseWith(pkgDir, sink)
}

func parseWith(pkgDir string, sink func(schema.Event)) (*Result, error) {
	man, err := casepkg.ReadManifest(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	store := casepkg.NewStore(pkgDir, man)
	p := &parser{res: &Result{}, sink: sink, caseID: man.CaseID, host: man.Host,
		entities: map[string]schema.Entity{}, rollouts: map[string]bool{}}

	current := man.Current()
	byPath := map[string]casepkg.ArtifactRecord{}
	for _, a := range current {
		if a.Status != casepkg.StatusOK {
			continue
		}
		byPath[a.LogicalPath] = a
		if a.CollectorRule == "codex.sessions" || a.CollectorRule == "codex.archived_sessions" {
			p.rollouts[a.LogicalPath] = true
		}
	}
	// State first, so thread rows precede their items in the event stream.
	for _, rule := range []string{RuleState, RuleHistory} {
		for _, a := range current {
			if a.Status != casepkg.StatusOK || a.CollectorRule != rule || !strings.HasSuffix(a.LogicalPath, ".sqlite") {
				continue
			}
			wal, hasWAL := byPath[a.LogicalPath+"-wal"]
			var walArt *casepkg.ArtifactRecord
			if hasWAL {
				walArt = &wal
			}
			if err := p.parseDB(store, a, walArt, rule); err != nil {
				return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
			}
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
	rollouts map[string]bool // logical paths of rollout artifacts in the package
}

// hasRollout reports whether the package holds a rollout transcript for a
// thread. Rollout files are named rollout-<timestamp>-<thread id>.jsonl.
func (p *parser) hasRollout(threadID string) bool {
	if threadID == "" {
		return false
	}
	for path := range p.rollouts {
		if strings.Contains(path, threadID) {
			return true
		}
	}
	return false
}

func (p *parser) readAll(store *casepkg.Store, art casepkg.ArtifactRecord) ([]byte, error) {
	if art.Size > MaxDBBytes {
		return nil, fmt.Errorf("database is %d bytes, over the %d-byte parse bound", art.Size, MaxDBBytes)
	}
	f, err := store.Open(art.ArtifactID)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, MaxDBBytes+1))
}

func (p *parser) parseDB(store *casepkg.Store, art casepkg.ArtifactRecord, walArt *casepkg.ArtifactRecord, rule string) error {
	data, err := p.readAll(store, art)
	if err != nil {
		p.gap(art, "read_failed", "database not readable: "+err.Error())
		return nil
	}
	var wal []byte
	if walArt != nil {
		if wal, err = p.readAll(store, *walArt); err != nil {
			p.gap(art, "wal_unreadable", "write-ahead log not readable, database read as checkpointed: "+err.Error())
			wal = nil
		}
	}
	db, err := sqlitero.Open(data, wal)
	if err != nil {
		p.gap(art, "malformed_database", "database not parseable: "+err.Error())
		return nil
	}
	switch rule {
	case RuleState:
		p.threads(db, art)
		p.spawnEdges(db, art)
	case RuleHistory:
		p.items(db, art)
	}
	return nil
}

func (p *parser) gap(art casepkg.ArtifactRecord, result, summary string) {
	p.emit(schema.Event{EventType: schema.EventTraceGap, ActorType: schema.ActorSystem,
		Result: result, Summary: trim(summary, 200), Corroboration: schema.StateObserved}, art, 0, 0)
}

// threads emits one session_meta per thread row: the policy and
// provenance the rollout only carries per turn, if at all.
func (p *parser) threads(db *sqlitero.DB, art casepkg.ArtifactRecord) {
	t, err := db.Table("threads")
	if err != nil {
		return
	}
	col := func(row []any, name string) string {
		if i := t.Index(name); i >= 0 && i < len(row) {
			return sqlitero.Str(row[i])
		}
		return ""
	}
	num := func(row []any, name string) int64 {
		if i := t.Index(name); i >= 0 && i < len(row) {
			return sqlitero.Int(row[i])
		}
		return 0
	}
	_ = db.Each(t, func(rowid int64, row []any) error {
		id := col(row, "id")
		if id == "" {
			return nil
		}
		ev := schema.Event{
			Timestamp: tsFrom(num(row, "created_at_ms"), num(row, "created_at")), TimestampSrc: "database",
			SessionID: id, AgentID: "main:" + id,
			EventType: schema.EventSessionMeta, ActorType: schema.ActorSystem,
			Result: "thread_meta", Model: col(row, "model"),
			ProductVersion: col(row, "cli_version"), Corroboration: schema.StateObserved,
		}
		var parts []string
		for _, kv := range [][2]string{
			{"source", col(row, "source")}, {"approval", col(row, "approval_mode")},
			{"sandbox", policyType(col(row, "sandbox_policy"))}, {"model", col(row, "model")},
			{"cwd", col(row, "cwd")}, {"git", col(row, "git_origin_url")}, {"branch", col(row, "git_branch")},
			{"agent", col(row, "agent_nickname")}, {"role", col(row, "agent_role")},
		} {
			if kv[1] != "" {
				parts = append(parts, kv[0]+"="+kv[1])
			}
		}
		if num(row, "archived") != 0 {
			parts = append(parts, "archived")
		}
		if !p.hasRollout(id) {
			parts = append(parts, "rollout=absent")
		}
		if title := col(row, "title"); title != "" {
			parts = append(parts, "title="+trim(title, 60))
		}
		ev.Summary = trim(strings.Join(parts, " "), 300)
		p.emit(ev, art, rowid, 0)
		attrs := map[string]string{}
		for _, k := range []string{"source", "approval_mode", "model", "cwd", "git_origin_url"} {
			if v := col(row, k); v != "" {
				attrs[k] = v
			}
		}
		if sb := policyType(col(row, "sandbox_policy")); sb != "" {
			attrs["sandbox_policy"] = sb
		}
		p.touchSession(id, "main:"+id, attrs)
		return nil
	})
}

// spawnEdges emits an agent_spawn per parent→child thread edge, the way
// the Claude parser does for Agent/Task launches, so ORPHAN_AGENT and the
// agent tree see Codex sub-threads.
func (p *parser) spawnEdges(db *sqlitero.DB, art casepkg.ArtifactRecord) {
	t, err := db.Table("thread_spawn_edges")
	if err != nil {
		return
	}
	pi, ci, si := t.Index("parent_thread_id"), t.Index("child_thread_id"), t.Index("status")
	if pi < 0 || ci < 0 {
		return
	}
	_ = db.Each(t, func(rowid int64, row []any) error {
		parent, child := sqlitero.Str(row[pi]), sqlitero.Str(row[ci])
		if parent == "" || child == "" {
			return nil
		}
		status := ""
		if si >= 0 && si < len(row) {
			status = sqlitero.Str(row[si])
		}
		ev := schema.Event{
			SessionID: parent, AgentID: "main:" + parent, TaskID: child,
			EventType: schema.EventAgentSpawn, ActorType: schema.ActorAgent,
			Summary: "sub-thread " + child + " spawned", Corroboration: schema.StateObserved,
		}
		if status != "" {
			ev.Summary += " (" + status + ")"
			ev.Result = status
		}
		p.emit(ev, art, rowid, 0)
		p.touchSession(parent, "main:"+parent, nil)
		p.touchSession(child, "main:"+child, nil)
		p.addRel(schema.Relationship{From: "agent:main:" + parent, To: "agent:main:" + child,
			Type: "spawned", DerivedFrom: []string{ev.EventID}, Corroboration: schema.StateObserved})
		return nil
	})
}

// item is the tolerant shape of a thread_items.item_json row.
type item struct {
	Type    string          `json:"type"`
	ID      string          `json:"id"`
	Text    string          `json:"text"`
	Content json.RawMessage `json:"content"`
	Phase   string          `json:"phase"`
	Status  string          `json:"status"`
	// commandExecution
	Command   string `json:"command"`
	CWD       string `json:"cwd"`
	ExitCode  *int   `json:"exitCode"`
	ProcessID string `json:"processId"`
	// fileChange
	Changes []struct {
		Path string          `json:"path"`
		Kind json.RawMessage `json:"kind"`
	} `json:"changes"`
	// mcpToolCall
	Server     string          `json:"server"`
	Tool       string          `json:"tool"`
	Arguments  json.RawMessage `json:"arguments"`
	AppContext *struct {
		AppName    string `json:"appName"`
		ActionName string `json:"actionName"`
	} `json:"appContext"`
	// webSearch
	Query  string `json:"query"`
	Action *struct {
		Type string `json:"type"`
		URL  string `json:"url"`
	} `json:"action"`
	// reasoning
	Summary []string `json:"summary"`
}

// items turns thread_items rows into events for threads that have no
// rollout in the package.
func (p *parser) items(db *sqlitero.DB, art casepkg.ArtifactRecord) {
	t, err := db.Table("thread_items")
	if err != nil {
		return
	}
	ti, ji, ci, oi, tyi := t.Index("thread_id"), t.Index("item_json"), t.Index("created_at_ms"), t.Index("rollout_ordinal"), t.Index("item_type")
	if ti < 0 || ji < 0 {
		return
	}
	type row struct {
		rowid   int64
		thread  string
		ordinal int64
		ts      int64
		typ     string
		raw     string
	}
	var rows []row
	skip := map[string]bool{}
	_ = db.Each(t, func(rowid int64, v []any) error {
		thread := sqlitero.Str(v[ti])
		if thread == "" {
			return nil
		}
		has, seen := skip[thread]
		if !seen {
			has = p.hasRollout(thread)
			skip[thread] = has
		}
		if has {
			return nil
		}
		r := row{rowid: rowid, thread: thread, raw: sqlitero.Str(v[ji])}
		if ci >= 0 {
			r.ts = sqlitero.Int(v[ci])
		}
		if oi >= 0 {
			r.ordinal = sqlitero.Int(v[oi])
		}
		if tyi >= 0 {
			r.typ = sqlitero.Str(v[tyi])
		}
		rows = append(rows, r)
		return nil
	})
	// B-tree order is (thread, turn, item) by primary key; the transcript
	// order an analyst expects is thread, then rollout ordinal.
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].thread != rows[j].thread {
			return rows[i].thread < rows[j].thread
		}
		return rows[i].ordinal < rows[j].ordinal
	})
	for _, r := range rows {
		var it item
		if err := json.Unmarshal([]byte(r.raw), &it); err != nil {
			p.emit(schema.Event{EventType: schema.EventTraceGap, ActorType: schema.ActorSystem,
				SessionID: r.thread, AgentID: "main:" + r.thread, Result: "malformed_row",
				Summary:       fmt.Sprintf("unparseable thread_items row (%d bytes): %v", len(r.raw), err),
				Corroboration: schema.StateObserved}, art, r.rowid, int(r.ordinal))
			continue
		}
		if it.Type == "" {
			it.Type = r.typ
		}
		p.touchSession(r.thread, "main:"+r.thread, nil)
		p.item(it, r.thread, tsFrom(r.ts, 0), art, r.rowid, int(r.ordinal))
	}
}

func (p *parser) item(it item, thread, ts string, art casepkg.ArtifactRecord, rowid int64, ordinal int) {
	base := schema.Event{Timestamp: ts, TimestampSrc: "database",
		SessionID: thread, AgentID: "main:" + thread, ToolCallID: it.ID}
	switch it.Type {
	case "userMessage":
		ev := base
		ev.EventType, ev.ActorType = schema.EventHumanPrompt, schema.ActorHuman
		ev.Corroboration = schema.StateObserved
		ev.Summary = trim(contentText(it.Content), 200)
		p.emit(ev, art, rowid, ordinal)
	case "agentMessage":
		ev := base
		ev.EventType, ev.ActorType = schema.EventModelResponse, schema.ActorModel
		ev.Corroboration = schema.StateReported // narrative, not proof
		ev.Result = it.Phase
		ev.Summary = trim(it.Text, 200)
		p.emit(ev, art, rowid, ordinal)
	case "reasoning", "plan":
		ev := base
		ev.EventType, ev.ActorType = schema.EventModelResponse, schema.ActorModel
		ev.Corroboration = schema.StateReported
		ev.Result = it.Type
		text := it.Text
		if text == "" {
			text = strings.Join(it.Summary, " ")
		}
		ev.Summary = trim(text, 200)
		p.emit(ev, art, rowid, ordinal)
	case "commandExecution":
		ev := base
		ev.EventType, ev.ActorType = schema.EventToolCall, schema.ActorAgent
		ev.Corroboration = schema.StateObserved
		ev.Tool, ev.Action = "shell", "shell_execution"
		ev.Command = trim(it.Command, 300)
		ev.Result = it.Status
		ev.Summary = trim("cwd="+it.CWD, 200)
		p.emit(ev, art, rowid, ordinal)
		p.linkTool(ev)
		// The row also records how it ended; that is the result side of the
		// same call, and rules pair the two by tool_call_id.
		res := base
		res.EventType, res.ActorType = schema.EventToolResult, schema.ActorAgent
		res.Corroboration = schema.StateObserved
		res.Result = it.Status
		if it.ExitCode != nil {
			res.Summary = fmt.Sprintf("exit=%d", *it.ExitCode)
		}
		if it.ProcessID != "" {
			res.Summary = strings.TrimSpace(res.Summary + " pid=" + it.ProcessID)
		}
		p.emit(res, art, rowid, ordinal)
	case "fileChange":
		ev := base
		ev.EventType, ev.ActorType = schema.EventToolCall, schema.ActorAgent
		ev.Corroboration = schema.StateObserved
		ev.Tool, ev.Action = "apply_patch", "write_file"
		ev.Result = it.Status
		var paths []string
		for _, c := range it.Changes {
			if c.Path != "" {
				paths = append(paths, c.Path)
			}
		}
		if len(paths) > 0 {
			ev.File = paths[0]
		}
		ev.Summary = trim(fmt.Sprintf("%d file(s): %s", len(paths), strings.Join(paths, ", ")), 300)
		p.emit(ev, art, rowid, ordinal)
		p.linkTool(ev)
	case "mcpToolCall":
		ev := base
		ev.EventType, ev.ActorType = schema.EventToolCall, schema.ActorAgent
		ev.Corroboration = schema.StateObserved
		ev.MCPServer, ev.MCPTool = it.Server, it.Tool
		ev.Tool = it.Server + "__" + it.Tool
		ev.Action = "mcp_call"
		ev.Result = it.Status
		var parts []string
		if it.AppContext != nil && it.AppContext.AppName != "" {
			parts = append(parts, "app="+it.AppContext.AppName+"/"+it.AppContext.ActionName)
		}
		if len(it.Arguments) > 0 {
			parts = append(parts, "args="+string(it.Arguments))
		}
		ev.Summary = trim(strings.Join(parts, " "), 300)
		p.emit(ev, art, rowid, ordinal)
		p.linkTool(ev)
	case "webSearch":
		ev := base
		ev.EventType, ev.ActorType = schema.EventToolCall, schema.ActorAgent
		ev.Corroboration = schema.StateObserved
		ev.Tool, ev.Action = "web_search", "web_search"
		if it.Action != nil && it.Action.URL != "" {
			ev.NetworkDest = it.Action.URL
		}
		ev.Summary = trim(it.Query, 200)
		p.emit(ev, art, rowid, ordinal)
		p.linkTool(ev)
	case "imageGeneration":
		ev := base
		ev.EventType, ev.ActorType = schema.EventToolCall, schema.ActorAgent
		ev.Corroboration = schema.StateObserved
		ev.Tool, ev.Action = "image_generation", "image_generation"
		ev.Result = it.Status
		p.emit(ev, art, rowid, ordinal)
		p.linkTool(ev)
	default:
		ev := base
		ev.EventType, ev.ActorType = schema.EventSessionMeta, schema.ActorSystem
		ev.Corroboration = schema.StateObserved
		ev.Result = "item:" + trim(it.Type, 40)
		p.emit(ev, art, rowid, ordinal)
	}
}

func (p *parser) emit(ev schema.Event, art casepkg.ArtifactRecord, rowid int64, ordinal int) {
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
	ev.SourceOffset = rowid // the row, not a byte offset: databases have no lines
	ev.SourceLine = ordinal
	if ev.Timestamp != "" && ev.TimestampSrc == "" {
		ev.TimestampSrc = "database"
	}
	if ev.Corroboration == "" {
		ev.Corroboration = schema.StateUnknown
	}
	p.seq++
	if p.sink != nil {
		p.sink(ev)
	} else {
		p.res.Events = append(p.res.Events, ev)
	}
}

func (p *parser) touchSession(sessionID, agentID string, attrs map[string]string) {
	if sessionID == "" {
		return
	}
	p.addEntity(schema.Entity{EntityID: "session:" + sessionID, Kind: "session",
		Label: sessionID, Product: "codex-cli", Attributes: attrs})
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
	if ex, ok := p.entities[e.EntityID]; ok {
		// Merge attributes; the first label wins.
		if len(e.Attributes) > 0 {
			if ex.Attributes == nil {
				ex.Attributes = map[string]string{}
			}
			for k, v := range e.Attributes {
				if _, dup := ex.Attributes[k]; !dup {
					ex.Attributes[k] = v
				}
			}
			p.entities[e.EntityID] = ex
		}
		return
	}
	if len(e.Attributes) == 0 {
		e.Attributes = nil
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

// tsFrom renders a database timestamp: milliseconds when the store has
// them, whole seconds otherwise, empty when neither is set.
func tsFrom(ms, sec int64) string {
	switch {
	case ms > 0:
		return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
	case sec > 0:
		return time.Unix(sec, 0).UTC().Format("2006-01-02T15:04:05Z")
	}
	return ""
}

// policyType reads the "type" of a JSON policy object such as
// {"type":"danger-full-access"}; other strings are returned as-is.
func policyType(s string) string {
	if !strings.HasPrefix(strings.TrimSpace(s), "{") {
		return s
	}
	var o struct {
		Type string `json:"type"`
	}
	if json.Unmarshal([]byte(s), &o) == nil {
		return o.Type
	}
	return trim(s, 40)
}

// contentText flattens a userMessage content array
// ([{"type":"text","text":"…"}]) or a plain string.
func contentText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var items []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &items) != nil {
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
