package claudejsonl

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// Cowork — the Claude desktop app's agent mode — runs Claude Code inside a
// VM and keeps, per session, two transcripts and one metadata document:
//
//	local_<id>/audit.jsonl                        stream-json audit log, HMAC per line
//	local_<id>/.claude/projects/**/<cli>.jsonl    the CLI transcript from inside the VM
//	local_<id>.json                               the sidecar: title, model, VM cwd, the
//	                                              folders the user shared, the egress
//	                                              allowlist, remote MCP servers, account
//
// The transcripts are handled by the regular line parser. This file turns
// the sidecar into session_meta events, because the sidecar is where the
// session's blast radius is written down: which host folders the agent
// could touch and which domains it could reach. The desktop app's plain
// Claude Code tab keeps a smaller sidecar under claude-code-sessions/ with
// the permission mode and every permission the user granted for good.

// MaxSidecarBytes bounds one metadata document.
const MaxSidecarBytes = 4 << 20

type coworkSidecar struct {
	SessionID            string          `json:"sessionId"`
	CLISessionID         string          `json:"cliSessionId"`
	ProcessName          string          `json:"processName"`
	VMProcessName        string          `json:"vmProcessName"`
	CWD                  string          `json:"cwd"`
	OriginCWD            string          `json:"originCwd"`
	CreatedAt            int64           `json:"createdAt"`
	LastActivityAt       int64           `json:"lastActivityAt"`
	Model                string          `json:"model"`
	IsArchived           bool            `json:"isArchived"`
	Title                string          `json:"title"`
	PermissionMode       string          `json:"permissionMode"`
	InitialMessage       string          `json:"initialMessage"`
	UserSelectedFolders  []string        `json:"userSelectedFolders"`
	EgressAllowedDomains []string        `json:"egressAllowedDomains"`
	RemoteMCPServers     json.RawMessage `json:"remoteMcpServersConfig"`
	MemoryEnabled        *bool           `json:"memoryEnabled"`
	SpaceID              string          `json:"spaceId"`
	AccountName          string          `json:"accountName"`
	EmailAddress         string          `json:"emailAddress"`
	HostLoopMode         bool            `json:"hostLoopMode"`
	CompletedTurns       int             `json:"completedTurns"`
	TranscriptGone       bool            `json:"transcriptUnavailable"`
	AlwaysAllowed        json.RawMessage `json:"alwaysAllowedReasons"`
	PermissionUpdates    json.RawMessage `json:"sessionPermissionUpdates"`
}

// coworkSessionID is the id the audit log uses: the sidecar's sessionId
// without its "local_" prefix.
func coworkSessionID(sc coworkSidecar) string {
	return strings.TrimPrefix(sc.SessionID, "local_")
}

func (p *parser) parseSidecar(store *casepkg.Store, art casepkg.ArtifactRecord, stem string) error {
	if art.Size > MaxSidecarBytes {
		p.emit(schema.Event{EventType: schema.EventTraceGap, ActorType: schema.ActorSystem,
			Result: "oversized_document", Corroboration: schema.StateObserved,
			Summary: fmt.Sprintf("session metadata is %d bytes, over the %d-byte bound; skipped", art.Size, MaxSidecarBytes)}, art, 0, 0)
		return nil
	}
	data, err := store.ReadAll(art.ArtifactID, MaxSidecarBytes)
	if err != nil {
		return err
	}
	var sc coworkSidecar
	if err := json.Unmarshal(data, &sc); err != nil {
		p.emit(schema.Event{EventType: schema.EventTraceGap, ActorType: schema.ActorSystem,
			Result: "malformed_document", Corroboration: schema.StateObserved,
			Summary: trim(fmt.Sprintf("unparseable session metadata (%d bytes): %v", len(data), err), 200)}, art, 0, 0)
		return nil
	}
	if sc.SessionID == "" {
		return nil // scheduled-tasks.json and friends share the directory
	}
	sess := coworkSessionID(sc)
	agent := "main:" + sess
	base := schema.Event{
		Timestamp: msTime(sc.CreatedAt), TimestampSrc: "metadata",
		SessionID: sess, AgentID: agent, Model: sc.Model,
		EventType: schema.EventSessionMeta, ActorType: schema.ActorSystem,
		Corroboration: schema.StateObserved,
	}

	attrs := map[string]string{}
	if sc.Model != "" {
		attrs["model"] = sc.Model
	}
	if sc.PermissionMode != "" {
		attrs["permission_mode"] = sc.PermissionMode
	}
	if sc.CLISessionID != "" {
		attrs["cli_session"] = sc.CLISessionID
	}
	if sc.EmailAddress != "" {
		attrs["account"] = sc.EmailAddress
	}

	var parts []string
	kind := "cowork_session"
	if stem == "cowork.desktop_sessions" {
		kind = "desktop_session"
	}
	for _, kv := range [][2]string{
		{"title", trim(sc.Title, 80)}, {"model", sc.Model}, {"permissionMode", sc.PermissionMode},
		{"cwd", sc.CWD}, {"origin", sc.OriginCWD}, {"vm", firstNonEmpty(sc.VMProcessName, sc.ProcessName)},
		{"cli_session", sc.CLISessionID}, {"account", sc.EmailAddress},
	} {
		if kv[1] != "" {
			parts = append(parts, kv[0]+"="+kv[1])
		}
	}
	if kind == "cowork_session" {
		parts = append(parts, fmt.Sprintf("folders=%d egress_domains=%d remote_mcp=%d",
			len(sc.UserSelectedFolders), len(sc.EgressAllowedDomains), jsonLen(sc.RemoteMCPServers)))
		if sc.MemoryEnabled != nil {
			parts = append(parts, fmt.Sprintf("memory=%v", *sc.MemoryEnabled))
		}
		if sc.HostLoopMode {
			parts = append(parts, "host_loop=true")
		}
	} else {
		parts = append(parts, fmt.Sprintf("turns=%d always_allowed=%d permission_updates=%d",
			sc.CompletedTurns, jsonLen(sc.AlwaysAllowed), jsonLen(sc.PermissionUpdates)))
		if sc.TranscriptGone {
			parts = append(parts, "transcript=unavailable")
		}
	}
	if sc.IsArchived {
		parts = append(parts, "archived")
	}
	if sc.LastActivityAt > 0 {
		parts = append(parts, "last_activity="+msTime(sc.LastActivityAt))
	}
	ev := base
	ev.Result = kind
	ev.Summary = trim(strings.Join(parts, " "), 400)
	p.emit(ev, art, 0, 0)

	p.addEntity(schema.Entity{EntityID: "session:" + sess, Kind: "session", Label: sess,
		Product: p.product, Attributes: attrs})
	p.addEntity(schema.Entity{EntityID: "agent:" + agent, Kind: "agent", Label: agent, Product: p.product})
	p.addRel(schema.Relationship{From: "agent:" + agent, To: "session:" + sess,
		Type: "belongs_to", DerivedFrom: []string{ev.EventID}, Corroboration: schema.StateObserved})
	if sc.CLISessionID != "" && sc.CLISessionID != sess {
		// The transcript inside the VM runs under the CLI session id. Tie
		// it to the Cowork session so the tree shows one session, not two.
		p.addEntity(schema.Entity{EntityID: "session:" + sc.CLISessionID, Kind: "session",
			Label: sc.CLISessionID, Product: p.product, Attributes: map[string]string{"cowork_session": sess}})
		p.addRel(schema.Relationship{From: "agent:main:" + sc.CLISessionID, To: "session:" + sess,
			Type: "belongs_to", DerivedFrom: []string{ev.EventID}, Corroboration: schema.StateObserved})
	}

	// Each shared host folder and each allowed egress domain is its own
	// event, so rules that read File and NetworkDest see them the way they
	// see a tool call's file or destination.
	for _, dir := range sc.UserSelectedFolders {
		e := base
		e.Result = "selected_folder"
		e.File = dir
		e.Summary = "host folder shared with the session: " + trim(dir, 200)
		p.emit(e, art, 0, 0)
	}
	for _, dom := range sc.EgressAllowedDomains {
		e := base
		e.Result = "egress_allowed"
		e.NetworkDest = dom
		e.Summary = "egress allowed: " + trim(dom, 200)
		p.emit(e, art, 0, 0)
	}
	if sc.InitialMessage != "" {
		e := base
		e.EventType, e.ActorType = schema.EventHumanPrompt, schema.ActorHuman
		e.Result = "initial_message"
		e.Summary = trim(sc.InitialMessage, 200)
		p.emit(e, art, 0, 0)
	}
	return nil
}

func msTime(ms int64) string {
	if ms <= 0 {
		return ""
	}
	return time.UnixMilli(ms).UTC().Format("2006-01-02T15:04:05.000Z")
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
