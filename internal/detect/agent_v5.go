// v5 P0 agent rules: questions the structured tool-call fields of the event
// format (arg_keys, safe_args, tool_def_digest, mcp_server_version,
// approval_state, permission_from) make answerable.
//
// Every rule here stays silent when the fields it reads are empty: a parser
// that does not fill a field is missing evidence, and missing evidence is
// never reported as a clean result. Raw arguments are read only where a rule
// must (the credential rule), straight from the sealed source line, and are
// reduced to a fingerprint before anything leaves the function. Dedupe
// verdicts and limits are in docs/detection-v5.md.
package detect

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// runV5Rules evaluates the v5 P0 rules over the shared event index. man may
// be nil: the rules that need collected files (tool definitions, the sealed
// transcript lines) are then skipped.
func runV5Rules(ix *eventIndex, pkgDir string, man *casepkg.Manifest) []schema.Finding {
	var out []schema.Finding
	out = append(out, mcpToolIdentityDrift(ix)...)
	out = append(out, permissionStateDrift(ix)...)
	out = append(out, planModeResourceChange(ix)...)
	if man != nil {
		store := casepkg.NewStore(pkgDir, man)
		out = append(out, mcpArgumentBehaviorMismatch(ix, loadToolDefs(store, man))...)
		out = append(out, credentialToExternalTool(ix, pkgDir, man, store)...)
	}
	return out
}

// mcpName returns the configured server name and tool name of an event.
// The client's mcp__server__tool spelling is the fallback when the parser
// left MCPServer/MCPTool empty.
func mcpName(e schema.Event) (server, tool string) {
	if e.MCPServer != "" {
		return e.MCPServer, e.MCPTool
	}
	if strings.HasPrefix(e.Tool, "mcp__") {
		if p := strings.SplitN(e.Tool, "__", 3); len(p) == 3 {
			return p[1], p[2]
		}
	}
	return "", ""
}

func isMCPCall(e schema.Event) bool {
	if e.EventType != schema.EventToolCall {
		return false
	}
	s, _ := mcpName(e)
	return s != "" || e.Action == "mcp_call"
}

// normDigest compares digests written with or without an algorithm prefix.
func normDigest(d string) string {
	d = strings.ToLower(strings.TrimSpace(d))
	d = strings.TrimPrefix(d, "sha256:")
	if len(d) > 128 {
		d = d[:128]
	}
	return d
}

func shortDigest(d string) string {
	if len(d) > 12 {
		return d[:12] + "…"
	}
	return d
}

// ---------------------------------------------------------------------------
// MCP_TOOL_IDENTITY_DRIFT

// maxDriftValues bounds the distinct values remembered per server or tool;
// maxDriftKeys bounds the servers and tools tracked.
const (
	maxDriftValues = 8
	maxDriftKeys   = 4096
)

type driftSeen struct {
	vals  []string
	first []schema.Event // event where each value was first recorded
}

// MCP_TOOL_IDENTITY_DRIFT — one configured MCP server name answered calls
// with different serverInfo versions, or one of its tools ran under
// different definition digests, within the case. MCP_SERVER_CHANGED and
// MCP_TOOL_DEFINITION_CHANGED compare configuration against a baseline, and
// SUPPLY_MCP_TOOL_DRIFT_EXPANSION compares snapshots for added capability;
// this rule reads the runtime records on the calls themselves, and reports
// any change, not only a capability gain.
func mcpToolIdentityDrift(ix *eventIndex) []schema.Finding {
	versions, defs := map[string]*driftSeen{}, map[string]*driftSeen{}
	var vOrder, dOrder []string
	note := func(m map[string]*driftSeen, order *[]string, key, val string, e schema.Event) {
		d := m[key]
		if d == nil {
			if len(m) >= maxDriftKeys {
				return
			}
			d = &driftSeen{}
			m[key] = d
			*order = append(*order, key)
		}
		for _, v := range d.vals {
			if v == val {
				return
			}
		}
		if len(d.vals) < maxDriftValues {
			d.vals = append(d.vals, val)
			d.first = append(d.first, e)
		}
	}
	for _, e := range ix.events {
		srv, tool := mcpName(e)
		if srv == "" {
			continue
		}
		if v := strings.TrimSpace(e.MCPServerVersion); v != "" {
			note(versions, &vOrder, srv, trimTo(v, 80), e)
		}
		if d := normDigest(e.ToolDefDigest); d != "" && tool != "" {
			note(defs, &dOrder, srv+"\x00"+tool, d, e)
		}
	}
	var out []schema.Finding
	emit := func(d *driftSeen, what, subject string, show func(string) string) {
		if len(d.vals) < 2 {
			return
		}
		var list, refs, related []string
		sessions := map[string]bool{}
		for k, v := range d.vals {
			e := d.first[k]
			sessions[e.SessionID] = true
			list = append(list, fmt.Sprintf("%q from %s", show(v), e.Timestamp))
			if len(refs) < 4 {
				refs = append(refs, ref(e))
			}
			related = append(related, fmt.Sprintf("%s %s first recorded at %s", what, show(v), ref(e)))
		}
		changed := d.first[1]
		conf := "MEDIUM"
		reasons := []string{"each value is the one recorded on the call events themselves; the definitions behind the digests are not compared here"}
		if len(sessions) == 1 {
			conf = "HIGH"
			reasons = append(reasons, "the change happened inside one session, where a server upgrade between launches cannot explain it")
		} else {
			reasons = append(reasons, "the values come from different sessions, so an upgrade between launches is a possible explanation")
		}
		// Evidence order: where it changed first, then where it started.
		refs[0], refs[1] = refs[1], refs[0]
		out = append(out, schema.Finding{
			RuleID: "MCP_TOOL_IDENTITY_DRIFT", Severity: "HIGH",
			Title: "MCP Server or Tool Identity Changed Between Calls",
			Description: fmt.Sprintf("%s recorded %d different %ss in this case: %s. The code answering calls under this configured name changed between calls; a server approved once and swapped later is the rug-pull shape.",
				subject, len(d.vals), what, strings.Join(list, ", ")),
			SessionID: changed.SessionID, AgentID: changed.AgentID,
			Related: related, EvidenceRefs: refs,
			Status: schema.StateObserved, Endpoint: schema.StateUnknown,
			MitreATTACK: "T1195.002", MitreATLAS: "AML.T0109",
			Confidence: conf, Reasons: reasons, Timestamp: changed.Timestamp,
			FalsePositive: "A server upgrade the owner made (an unpinned npx/uvx launch picks up new releases between sessions) produces the same drift. A version or digest change is not compromise on its own: diff the two definitions and ask who changed the server.",
		})
	}
	for _, k := range vOrder {
		emit(versions[k], "server version", fmt.Sprintf("MCP server %q", k), func(v string) string { return v })
	}
	for _, k := range dOrder {
		p := strings.SplitN(k, "\x00", 2)
		emit(defs[k], "tool definition digest", fmt.Sprintf("Tool %q of MCP server %q", p[1], p[0]), shortDigest)
	}
	return out
}

// ---------------------------------------------------------------------------
// AGENT_PERMISSION_STATE_DRIFT

// approvedPlanRe is the client's own record that the person approved a plan
// presented through ExitPlanMode. Completion alone is not approval.
var approvedPlanRe = regexp.MustCompile(`(?i)\b(user has )?approved (your|the) plan\b`)

// planExitApproved reports whether e is the recorded approval of a plan exit.
func planExitApproved(ix *eventIndex, e schema.Event) bool {
	if e.EventType != schema.EventToolResult || e.Result == "error" || refusal(e) != "" {
		return false
	}
	call, ok := ix.callOf(e)
	return ok && call.Tool == "ExitPlanMode" && approvedPlanRe.MatchString(e.Summary)
}

// recordedApproval reports whether e records a person's decision: a prompt
// they typed, an approval the evidence states, or an approved plan exit.
func recordedApproval(ix *eventIndex, e schema.Event) bool {
	switch {
	case e.EventType == schema.EventHumanPrompt && isInstruction(e):
		return true
	case e.ApprovalState == "approved":
		return true
	}
	return planExitApproved(ix, e)
}

// promptOnSameLine reports whether a change event e shares its source
// line with a prompt the person typed: the parser emits the
// permission_change event of a line before the line's own events, so the
// prompt that records the person's decision follows it in order. next is
// the agent's events after e.
func promptOnSameLine(ix *eventIndex, next []int, e schema.Event) bool {
	if e.EventType != schema.EventPermissionChange || e.SourceArtifact == "" {
		return false
	}
	for n, i := range next {
		x := ix.events[i]
		if n >= 8 || x.SourceArtifact != e.SourceArtifact || x.SourceLine != e.SourceLine {
			return false
		}
		if x.EventType == schema.EventHumanPrompt && isInstruction(x) {
			return true
		}
	}
	return false
}

// AGENT_PERMISSION_STATE_DRIFT — the recorded permission mode widened in the
// middle of a session (plan → default, default → acceptEdits/auto, …) and
// nothing in the evidence records a person approving it: the line carrying
// the new mode is not a prompt they typed, no approval is recorded on it,
// and no approved plan exit sits between the last line in the old mode and
// the first line in the new one. A move into bypassPermissions is
// AGENT_TOOL_PERMISSION_ESCALATION's and is not repeated here; static
// grants at rest are PERMISSION_ESCALATION / PERMISSION_BYPASS_ENABLED.
func permissionStateDrift(ix *eventIndex) []schema.Finding {
	var out []schema.Finding
	for _, a := range ix.agents {
		last, lastEv := "", schema.Event{}
		acc := false // a recorded approval since the last line in the old mode
		n := 0
		// ceiling is the widest mode the session already held. Returning
		// to it (bypass → default → acceptEdits) widens nothing the
		// session had not been given before.
		ceiling, session := -1, ""
		list := ix.byAgent[a]
		for k, i := range list {
			e := ix.events[i]
			if e.SessionID != session {
				// A new session starts from its own launch mode.
				session, ceiling = e.SessionID, -1
			}
			own := recordedApproval(ix, e) || promptOnSameLine(ix, list[k+1:], e)
			to := e.PermissionMode
			if to == "" {
				acc = acc || own
				continue
			}
			from, explicit := last, false
			if e.PermissionFrom != "" {
				from, explicit = e.PermissionFrom, true
			}
			r, ranked := permissionRank[to]
			fr, franked := permissionRank[from]
			if from != to && ranked && franked && r > fr && r > ceiling && to != "bypassPermissions" &&
				e.ApprovalState != "denied" && !(acc || own) && n < 5 {
				n++
				conf := "LOW"
				reasons := []string{"the change is inferred from the modes recorded on consecutive transcript lines"}
				if explicit {
					conf = "MEDIUM"
					reasons = []string{"the evidence records the previous and the new mode on the change itself"}
				}
				reasons = append(reasons, "no prompt, approval record or approved plan exit is recorded between the last line in the old mode and this one")
				related := []string{}
				if lastEv.EventID != "" {
					related = append(related, "previous mode recorded at: "+ref(lastEv))
				}
				out = append(out, schema.Finding{
					RuleID: "AGENT_PERMISSION_STATE_DRIFT", Severity: "MEDIUM",
					Title: "Permission Mode Widened With No Recorded Approval",
					Description: fmt.Sprintf("The permission mode moved from %q to %q in the middle of this session, and the evidence records no approval for the change. Calls after it needed fewer per-call approvals.",
						from, to),
					SessionID: e.SessionID, AgentID: e.AgentID,
					Related: related, EvidenceRefs: []string{ref(e)},
					Status: schema.StateObserved, Endpoint: schema.StateUnknown,
					MitreATTACK: "T1548", MitreATLAS: "AML.T0081",
					Confidence: conf, Reasons: reasons, Timestamp: e.Timestamp,
					FalsePositive: "A missing approval record is not an unauthorized change: a person can switch modes with a key press while the agent is working, and only the next line they type records it. Ask who was at the keyboard.",
				})
			}
			// A prompt typed in the old mode came before the change and
			// approves nothing; an approved plan exit recorded on the last
			// old-mode line is what the change follows from.
			// A denied change never took effect, so it raises nothing.
			if r, ok := permissionRank[to]; ok && r > ceiling && e.ApprovalState != "denied" {
				ceiling = r
			}
			last, lastEv = to, e
			acc = e.ApprovalState == "approved" || planExitApproved(ix, e)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AGENT_UNAUTHORIZED_RESOURCE_CHANGE

// planFileRe is where the client lets the agent write its plan while in plan
// mode; writing it is the purpose of the mode, not a change to the project.
var planFileRe = regexp.MustCompile(`(^|/)\.claude/plans/[^/]+$`)

// changesState reports whether a tool call writes, deletes or executes
// something. MCP calls are left out: whether the client lets a read-only MCP
// tool run in plan mode depends on annotations this rule does not see.
func changesState(e schema.Event) bool {
	if e.EventType != schema.EventToolCall {
		return false
	}
	switch {
	case e.Tool == "Write" || e.Tool == "Edit" || e.Tool == "MultiEdit" || e.Tool == "NotebookEdit" ||
		e.Action == "write_file" || e.Action == "edit_file" || e.Action == "apply_patch":
		return !planFileRe.MatchString(strings.ReplaceAll(e.File, `\`, "/"))
	case e.Command != "":
		return !IsReadOnlyCommand(e.FullCommand())
	}
	return false
}

// AGENT_UNAUTHORIZED_RESOURCE_CHANGE — a write, delete or command ran to
// completion while the session's recorded permission mode was plan, a mode
// in which the client allows read-only tools only. The other half of the
// proposed rule, a call matching a collected permissions.deny pattern, is
// AGENT_PERMISSION_BOUNDARY_CROSSING and is not repeated.
func planModeResourceChange(ix *eventIndex) []schema.Finding {
	var out []schema.Finding
	for _, a := range ix.agents {
		mode, modeEv := "", schema.Event{}
		n := 0
		for _, i := range ix.byAgent[a] {
			e := ix.events[i]
			if e.PermissionMode != "" {
				mode, modeEv = e.PermissionMode, e
			}
			if planExitApproved(ix, e) {
				mode = "" // left plan mode; the next line records the new one
				continue
			}
			if mode != "plan" || !changesState(e) || n >= 20 {
				continue
			}
			res, ok := ix.completed(e)
			if !ok {
				continue // refused, failed or no result: the boundary held or is unknown
			}
			if res.PermissionMode != "" && res.PermissionMode != "plan" {
				continue // the mode changed before the result was written
			}
			n++
			conf := "MEDIUM"
			reasons := []string{"the mode is the last one the client recorded in this session before the call"}
			if e.PermissionMode == "plan" || res.PermissionMode == "plan" {
				conf = "HIGH"
				reasons = []string{"the client recorded plan mode on the call or on its result"}
			}
			reasons = append(reasons, "the recorded result is neither an error nor a refusal")
			out = append(out, schema.Finding{
				RuleID: "AGENT_UNAUTHORIZED_RESOURCE_CHANGE", Severity: "HIGH",
				Title: "Agent Changed Something While in Plan Mode",
				Description: fmt.Sprintf("The %s completed while the recorded permission mode was \"plan\", in which the client allows read-only tools only. Either the mode record is wrong, the client did not enforce it, or something ran the tool around it.",
					describeCall(e)),
				SessionID: e.SessionID, AgentID: e.AgentID,
				Related:      []string{"plan mode recorded at: " + ref(modeEv), "result: " + ref(res)},
				EvidenceRefs: []string{ref(e), ref(res)},
				Status:       e.Corroboration, Endpoint: schema.StateUnknown,
				MitreATTACK: "T1548", MitreATLAS: "AML.T0053",
				Confidence: conf, Reasons: reasons, Timestamp: e.Timestamp,
				FalsePositive: "Client versions differ in what plan mode allows, and a mode switch the transcript records late (a key press mid-turn) makes a legitimate call look like this. Read the lines around the call.",
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// MCP_ARGUMENT_BEHAVIOR_MISMATCH

// Bounds on reading cached MCP tool declarations.
const (
	maxToolDefBytes = 8 << 20
	maxToolDefs     = 4096
	maxToolDefNodes = 200000
)

// toolDef is one captured MCP tool declaration, reduced to what the rule
// compares: declared argument names and the behaviour annotations.
type toolDef struct {
	name        string
	digest      string          // sha256 of the canonical declaration
	props       map[string]bool // declared argument names; nil when the schema lists none
	open        bool            // additionalProperties is true or a schema
	readOnly    int8            // readOnlyHint: -1 absent, 0 false, 1 true
	destructive int8            // destructiveHint: -1 absent, 0 false, 1 true
	art         casepkg.ArtifactRecord
}

// loadToolDefs reads the MCP tool declarations clients cache in their
// configuration and state files. A file that does not parse contributes
// nothing.
func loadToolDefs(store *casepkg.Store, man *casepkg.Manifest) []toolDef {
	var out []toolDef
	for _, a := range man.Current() {
		if a.Status != casepkg.StatusOK || a.ArtifactID == "" || a.Size > maxToolDefBytes ||
			!isType(a, "product_config", "product_state", "debug_logs", "managed_config") {
			continue
		}
		data, err := store.ReadAll(a.ArtifactID, maxToolDefBytes)
		if err != nil || !bytes.Contains(data, []byte("inputSchema")) {
			continue
		}
		for _, d := range parseToolDefs(data) {
			if len(out) >= maxToolDefs {
				return out
			}
			d.art = a
			out = append(out, d)
		}
	}
	return out
}

// parseToolDefs walks a JSON document (or JSON lines) for objects shaped
// like MCP tool declarations ({name, inputSchema, annotations?}). The
// digest is computed the way mcpaudit fingerprints a declaration, so the two
// agree on what "the same definition" means.
func parseToolDefs(data []byte) []toolDef {
	var docs []any
	var doc any
	if json.Unmarshal(data, &doc) == nil {
		docs = append(docs, doc)
	} else {
		for _, line := range bytes.Split(data, []byte("\n")) {
			var d any
			if len(docs) < 10000 && json.Unmarshal(bytes.TrimSpace(line), &d) == nil {
				docs = append(docs, d)
			}
		}
	}
	var out []toolDef
	nodes := 0
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		nodes++
		if depth > 12 || nodes > maxToolDefNodes || len(out) >= maxToolDefs {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			if name, _ := t["name"].(string); name != "" {
				if sch, ok := t["inputSchema"].(map[string]any); ok {
					out = append(out, toolDefFrom(name, t, sch))
				}
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k], depth+1)
			}
		case []any:
			for _, e := range t {
				walk(e, depth+1)
			}
		}
	}
	for _, d := range docs {
		walk(d, 0)
	}
	return out
}

func toolDefFrom(name string, m, sch map[string]any) toolDef {
	d := toolDef{name: name, readOnly: -1, destructive: -1}
	if canon, err := json.Marshal(m); err == nil { // map keys marshal sorted
		sum := sha256.Sum256(canon)
		d.digest = hex.EncodeToString(sum[:])
	}
	if p, ok := sch["properties"].(map[string]any); ok {
		d.props = make(map[string]bool, len(p))
		for k := range p {
			d.props[k] = true
		}
	}
	switch ap := sch["additionalProperties"].(type) {
	case bool:
		d.open = ap
	case map[string]any:
		d.open = true
	}
	hint := func(an map[string]any, k string) int8 {
		switch an[k] {
		case true:
			return 1
		case false:
			return 0
		}
		return -1
	}
	if an, ok := m["annotations"].(map[string]any); ok {
		d.readOnly, d.destructive = hint(an, "readOnlyHint"), hint(an, "destructiveHint")
	}
	return d
}

// toolDefIndex resolves the declaration a call ran under.
type toolDefIndex struct {
	byDigest map[string]toolDef
	byName   map[string][]toolDef // distinct declarations per tool name
}

func newToolDefIndex(defs []toolDef) *toolDefIndex {
	ti := &toolDefIndex{byDigest: map[string]toolDef{}, byName: map[string][]toolDef{}}
	for _, d := range defs {
		if _, dup := ti.byDigest[d.digest]; dup {
			continue
		}
		ti.byDigest[d.digest] = d
		ti.byName[d.name] = append(ti.byName[d.name], d)
	}
	return ti
}

// resolve returns the declaration for a call: by the digest the call
// recorded when there is one (and only that), otherwise by tool name when
// every captured declaration of that name is the same.
func (ti *toolDefIndex) resolve(e schema.Event, tool string) (toolDef, bool, bool) {
	if d := normDigest(e.ToolDefDigest); d != "" {
		td, ok := ti.byDigest[d]
		return td, true, ok && td.name == tool
	}
	c := ti.byName[tool]
	if len(c) != 1 {
		return toolDef{}, false, false // none captured, or several that disagree
	}
	return c[0], false, true
}

// writeMethods are HTTP methods that change something on the far side.
var writeMethods = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// effectKind classifies what an event did: "delete", "write", "network
// send", "exec", or "" for a read or something it cannot tell.
func effectKind(c schema.Event) string {
	a := strings.ToLower(c.Action)
	has := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(a, s) {
				return true
			}
		}
		return false
	}
	method := strings.ToUpper(c.SafeArgs["method"])
	switch {
	case has("delete", "remove", "unlink", "destroy", "drop") || method == "DELETE":
		return "delete"
	case c.Command != "" && len(DeleteTargets(c.FullCommand())) > 0:
		return "delete"
	case c.Tool == "Write" || c.Tool == "Edit" || c.Tool == "MultiEdit" || c.Tool == "NotebookEdit" ||
		a == "write_file" || a == "edit_file" || a == "apply_patch" || has("write", "create", "modify", "rename", "put_", "patch"):
		return "write"
	case c.NetworkDest != "" && (has("upload", "send", "post", "publish") || writeMethods[method]):
		return "network send"
	case c.Command != "" && !IsReadOnlyCommand(c.FullCommand()):
		return "exec"
	}
	return ""
}

// pathLike reports whether an allowlisted argument value names a file.
func pathLike(v string) (string, bool) {
	v = strings.TrimPrefix(strings.TrimSpace(v), "file://")
	v = strings.ReplaceAll(v, `\`, "/")
	switch {
	case strings.HasPrefix(v, "/"), strings.HasPrefix(v, "~/"), len(v) > 2 && v[1] == ':' && v[2] == '/':
		return path.Clean(v), true
	}
	return "", false
}

// MCP_ARGUMENT_BEHAVIOR_MISMATCH — an MCP call did not match the tool's
// captured declaration: it carried argument names the input schema does
// not declare, or the tool is annotated read-only (or non-destructive) and
// an effect of the forbidden kind was observed inside the same call: an
// event linked to the call by its id (a subagent or gateway record of it),
// or an event on a path named in the call's allowlisted arguments recorded
// between the call and its result. The proposed v4 family
// MCP_SCHEMA_BEHAVIOR_DIVERGENCE had no evidence source; the v5 fields are
// that source.
func mcpArgumentBehaviorMismatch(ix *eventIndex, defs []toolDef) []schema.Finding {
	if len(defs) == 0 {
		return nil
	}
	ti := newToolDefIndex(defs)
	linked := map[string][]int{} // tool call id → events recorded as part of that call
	byPath := map[string][]int{} // file or resource → events touching it
	paths := 0
	for i, e := range ix.events {
		if e.ParentToolCallID != "" && len(linked[e.ParentToolCallID]) < 64 {
			linked[e.ParentToolCallID] = append(linked[e.ParentToolCallID], i)
		}
		if e.ToolCallID != "" && e.EventType != schema.EventToolCall && e.EventType != schema.EventToolResult &&
			len(linked[e.ToolCallID]) < 64 {
			linked[e.ToolCallID] = append(linked[e.ToolCallID], i)
		}
		for _, p := range []string{e.File, e.ResourceID} {
			if cp, ok := pathLike(p); ok && paths < 1<<16 && len(byPath[cp]) < 64 {
				byPath[cp] = append(byPath[cp], i)
				paths++
			}
		}
	}
	var out []schema.Finding
	for _, e := range ix.events {
		if !isMCPCall(e) {
			continue
		}
		srv, tool := mcpName(e)
		if tool == "" {
			continue
		}
		def, exact, ok := ti.resolve(e, tool)
		if !ok {
			continue
		}
		var parts, reasons, related []string
		refs := []string{ref(e)}
		conf := "LOW"
		if exact {
			conf = "MEDIUM"
			reasons = append(reasons, "the declaration is the one whose digest the call recorded")
		} else {
			reasons = append(reasons, "the declaration is matched by tool name; it is the only one captured for that name, but the call recorded no digest to prove it was in force")
		}
		related = append(related, "declaration: "+artRef(def.art, 0))

		// Undeclared argument names (names only; values are never read).
		if def.props != nil && !def.open && e.ArgKeys != "" {
			var extra []string
			for _, k := range strings.Split(e.ArgKeys, ",") {
				if k = strings.TrimSpace(k); k != "" && !def.props[k] && len(extra) < 8 {
					extra = append(extra, trimTo(k, 40))
				}
			}
			if len(extra) > 0 {
				parts = append(parts, fmt.Sprintf("was called with argument(s) its captured input schema does not declare (%s)", strings.Join(extra, ", ")))
				reasons = append(reasons, "argument names come from the call's recorded arg_keys")
			}
		}

		// Forbidden effect inside the same call.
		var forbid func(string) bool
		var hint string
		switch {
		case def.readOnly == 1:
			forbid, hint = func(k string) bool { return k != "" }, "readOnlyHint=true"
		case def.destructive == 0:
			forbid, hint = func(k string) bool { return k == "delete" }, "destructiveHint=false"
		}
		if forbid != nil {
			res, hasRes := ix.resultOf(e)
			var cands []int
			byID := len(linked[e.ToolCallID])
			if e.ToolCallID != "" {
				cands = append(cands, linked[e.ToolCallID]...)
			}
			if hasRes {
				keys := make([]string, 0, len(e.SafeArgs))
				for k := range e.SafeArgs {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					if cp, ok := pathLike(e.SafeArgs[k]); ok {
						cands = append(cands, byPath[cp]...)
					}
				}
			}
			for n, ci := range cands {
				c := ix.events[ci]
				if c.EventID == e.EventID || (hasRes && c.EventID == res.EventID) {
					continue
				}
				if n >= byID && !duringCall(e, res, c) {
					continue // path match outside the call's window
				}
				k := effectKind(c)
				if !forbid(k) {
					continue
				}
				how := "linked to the call by its id"
				if n >= byID {
					how = "on a path named in the call's arguments, between the call and its result"
				} else if exact {
					conf = "HIGH"
				}
				parts = append(parts, fmt.Sprintf("is annotated %s, yet a %s was observed inside the same call (%s, %s)", hint, k, describeCall(c), how))
				reasons = append(reasons, "the effect is "+how)
				refs = append(refs, ref(c))
				break
			}
		}
		if len(parts) == 0 {
			continue
		}
		out = append(out, schema.Finding{
			RuleID: "MCP_ARGUMENT_BEHAVIOR_MISMATCH", Severity: "HIGH",
			Title: "MCP Call Did Not Match the Tool's Declaration",
			Description: fmt.Sprintf("Tool %q of MCP server %q %s. What the tool declared and what the call did differ.",
				tool, srv, strings.Join(parts, "; and ")),
			SessionID: e.SessionID, AgentID: e.AgentID,
			Related: related, EvidenceRefs: refs,
			Status: e.Corroboration, Endpoint: schema.StateUnknown,
			MitreATTACK: "T1195.002", MitreATLAS: "AML.T0110.001",
			Confidence: conf, Reasons: reasons, Timestamp: e.Timestamp,
			FalsePositive: "A mismatch is not compromise: annotations are hints the server author writes, schemas go stale after an upgrade, and clients add bookkeeping arguments. Compare the declaration with the server's source before drawing a conclusion.",
		})
	}
	return out
}

// duringCall reports whether c was recorded between call and its result:
// by timestamp when all three have one, otherwise by recorded order within
// one session.
func duringCall(call, res, c schema.Event) bool {
	tc, ok1 := parseTS(call.Timestamp)
	tr, ok2 := parseTS(res.Timestamp)
	tx, ok3 := parseTS(c.Timestamp)
	if ok1 && ok2 && ok3 {
		return !tx.Before(tc) && !tx.After(tr)
	}
	return c.SessionID == call.SessionID && c.Sequence > call.Sequence && c.Sequence < res.Sequence
}

// ---------------------------------------------------------------------------
// AGENT_CREDENTIAL_TO_EXTERNAL_TOOL

// Bounds on re-reading sealed transcript lines. They bound the work done,
// not only the output: every call the rule could not examine is counted and
// reported in one INFO finding (see credLimitation), never dropped silently.
const (
	maxArgLine      = 4 << 20 // one source line
	maxArgJSONNodes = 200000  // nodes walked in one parsed line
	maxCredFindings = 200
)

// Package variables so tests can lower them.
var (
	maxArgLineReads = 20000    // distinct source lines read
	maxArgBytes     = 64 << 20 // bytes read, parsed and fingerprinted, rule-wide
)

// externalToolCall reports the calls whose arguments leave the host: MCP
// tools and the web fetch/search tools. Shell commands are the command
// rules' and CHAIN_SECRET_TO_EXFIL's.
func externalToolCall(e schema.Event) bool {
	if e.EventType != schema.EventToolCall {
		return false
	}
	return isMCPCall(e) || e.Tool == "WebFetch" || e.Tool == "WebSearch" || e.Action == "web_search"
}

// sourceLine re-reads the sealed line at (art, off), bounded by maxArgLine.
func sourceLine(store *casepkg.Store, art string, off int64) []byte {
	rc, err := store.OpenAt(art, off)
	if err != nil {
		return nil
	}
	defer rc.Close()
	br := bufio.NewReaderSize(io.LimitReader(rc, maxArgLine), 64<<10)
	var out []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		out = append(out, chunk...)
		if err != nil || !isPrefix {
			break
		}
	}
	return out
}

// callArgs finds the arguments of tool call id inside one source line. See
// callArgsAll.
func callArgs(line []byte, id string) []byte {
	if id == "" {
		return nil
	}
	return callArgsAll(line, map[string]bool{id: true})[id]
}

// callArgsAll parses one source line once and returns the arguments of every
// wanted tool call on it: the object whose id / call_id / tool_use_id is the
// call id and that carries input, arguments or params. Anything else on the
// line (the model's text, other calls) is not returned. A call id absent
// from the result is not on the line, or the line does not parse.
func callArgsAll(line []byte, want map[string]bool) map[string][]byte {
	found := map[string][]byte{}
	if len(line) == 0 || len(want) == 0 {
		return found
	}
	var doc any
	if json.Unmarshal(line, &doc) != nil {
		return found
	}
	idOf := func(v any) string {
		switch x := v.(type) {
		case string:
			return x
		case float64:
			return strconv.FormatFloat(x, 'f', -1, 64)
		}
		return ""
	}
	nodes := 0
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		nodes++
		if len(found) == len(want) || depth > 16 || nodes > maxArgJSONNodes {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			for _, k := range []string{"id", "call_id", "tool_use_id", "callId"} {
				id := idOf(t[k])
				if !want[id] {
					continue
				}
				if _, done := found[id]; done {
					continue // first occurrence wins
				}
				for _, ak := range []string{"input", "arguments", "params", "args"} {
					a, ok := t[ak]
					if !ok {
						continue
					}
					if s, isStr := a.(string); isStr {
						found[id] = []byte(s)
					} else if b, err := json.Marshal(a); err == nil {
						found[id] = b
					}
					return
				}
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k], depth+1)
			}
		case []any:
			for _, e := range t {
				walk(e, depth+1)
			}
		}
	}
	walk(doc, 0)
	return found
}

// credLimitation is the INFO finding that says the rule stopped before
// examining every external tool call. Fewer findings than calls is then a
// cap, not a clean result.
func credLimitation(skipped int, why string, first schema.Event) schema.Finding {
	return schema.Finding{
		RuleID: "AGENT_CREDENTIAL_TO_EXTERNAL_TOOL", Severity: "INFO",
		Title:       "Credential Check of External Tool Calls Incomplete",
		Description: fmt.Sprintf("%d external tool call(s) were not (fully) checked for credentials in their arguments: %s. Absence of findings for them is missing evidence, not a clean result.", skipped, why),
		SessionID:   first.SessionID, AgentID: first.AgentID,
		EvidenceRefs: []string{ref(first)},
		Status:       first.Corroboration, Endpoint: schema.StateUnknown,
		Reasons:       []string{"a work bound of the rule was reached (limitation, not an indicator)"},
		Timestamp:     first.Timestamp,
		FalsePositive: "Informational: records an analysis limit on a large or hostile case.",
	}
}

// AGENT_CREDENTIAL_TO_EXTERNAL_TOOL — a credential sits in the arguments of
// an MCP or web tool call. The arguments are re-read from the sealed source
// line, fingerprinted with the POTENTIAL_SECRET_EXPOSURE patterns and
// placeholder rules, and dropped; only the fingerprint is reported. When the
// same fingerprint appears earlier in the collected transcripts, the finding
// names where: that is the credential's way into the call.
// CHAIN_SECRET_TO_EXFIL and CHAIN_CROSS_TOOL_EXFIL link a credential read to
// a later upload by time; this rule sees the credential in the call itself.
//
// Calls are grouped by source line, so each line is read and parsed once
// however many calls point at it. The number of lines, the bytes read and
// parsed across the rule, and the findings are all capped; calls left
// unexamined by any cap are reported by credLimitation.
func credentialToExternalTool(ix *eventIndex, pkgDir string, man *casepkg.Manifest, store *casepkg.Store) []schema.Finding {
	type lineKey struct {
		art string
		off int64
	}
	var order []lineKey
	groups := map[lineKey][]schema.Event{}
	for _, e := range ix.events {
		if !externalToolCall(e) || e.SourceArtifact == "" || e.ToolCallID == "" {
			continue
		}
		k := lineKey{e.SourceArtifact, e.SourceOffset}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
		}
		groups[k] = append(groups[k], e)
	}
	if len(order) == 0 {
		return nil
	}
	type spot struct {
		art casepkg.ArtifactRecord
		off int64
	}
	seen := map[string][]spot{}
	cur, per := caseSecretSightings(pkgDir, man, store)
	for i, a := range cur {
		for _, s := range per[i] {
			if len(seen[s.FP]) < 8 {
				seen[s.FP] = append(seen[s.FP], spot{a, s.Off})
			}
		}
	}
	var out []schema.Finding
	budget := maxArgBytes
	skipped, why := 0, ""
	var firstSkipped schema.Event
	skip := func(e schema.Event) {
		if skipped == 0 {
			firstSkipped = e
		}
		skipped++
	}
	capWhy := fmt.Sprintf("the rule stopped at its cap of %d findings", maxCredFindings)
	for gi, k := range order {
		switch {
		case len(out) >= maxCredFindings:
			why = capWhy
		case gi >= maxArgLineReads:
			why = fmt.Sprintf("the rule stopped after re-reading %d source lines", maxArgLineReads)
		case budget <= 0:
			why = fmt.Sprintf("the rule stopped after reading and parsing %d bytes of arguments", maxArgBytes)
		}
		if why != "" {
			for _, rest := range order[gi:] {
				for _, e := range groups[rest] {
					skip(e)
				}
			}
			break
		}
		line := sourceLine(store, k.art, k.off)
		budget -= len(line)
		evs := groups[k]
		want := make(map[string]bool, len(evs))
		for _, e := range evs {
			want[e.ToolCallID] = true
		}
		all := callArgsAll(line, want)
		// Fingerprint each call id once per line, however many events
		// point at it, and charge the budget once.
		fps := make(map[string][]SecretFingerprint, len(all))
		for _, e := range evs {
			if len(out) >= maxCredFindings {
				why = capWhy
				skip(e)
				continue
			}
			args := all[e.ToolCallID]
			if args == nil {
				continue // the line is unreadable or does not hold this call: no evidence, no finding
			}
			got, done := fps[e.ToolCallID]
			if !done {
				if budget <= 0 {
					why = fmt.Sprintf("the rule stopped after reading and parsing %d bytes of arguments", maxArgBytes)
					skip(e)
					continue
				}
				budget -= len(args)
				got = SecretFingerprints(args)
				fps[e.ToolCallID] = got
			}
			for _, fp := range got {
				if len(out) >= maxCredFindings {
					why = capWhy
					skip(e) // fingerprints of this call left unreported
					break
				}
				hexFP := strings.TrimPrefix(fp.Fingerprint, "sha256:")
				var origin *spot
				for si, sp := range seen[hexFP] {
					inLine := sp.art.ArtifactID == e.SourceArtifact && sp.off >= e.SourceOffset && sp.off < e.SourceOffset+int64(len(line))
					later := sp.art.ArtifactID == e.SourceArtifact && sp.off >= e.SourceOffset+int64(len(line))
					if !inLine && !later {
						origin = &seen[hexFP][si]
						break
					}
				}
				srv, tool := mcpName(e)
				target := e.Tool + " call"
				if srv != "" {
					target = fmt.Sprintf("call to tool %q of MCP server %q", tool, srv)
				}
				conf := "MEDIUM"
				where := "No earlier copy of it was found in the collected transcripts."
				reasons := []string{"the value was fingerprinted from this call's own arguments in the sealed source line; the value itself is not stored"}
				var related []string
				if origin != nil {
					conf = "HIGH"
					where = fmt.Sprintf("The same credential appears earlier in the case at %s.", artRef(origin.art, origin.off))
					reasons = append(reasons, "the same fingerprint was found earlier in the collected transcripts")
					related = append(related, "earlier sighting: "+artRef(origin.art, origin.off))
				}
				out = append(out, schema.Finding{
					RuleID: "AGENT_CREDENTIAL_TO_EXTERNAL_TOOL", Severity: "CRITICAL",
					Title: "Credential Passed in an External Tool Call's Arguments",
					Description: fmt.Sprintf("The arguments of a %s carry a %s with fingerprint %s…. %s The credential was handed to a tool that runs outside the agent. Value: [REDACTED]",
						target, fp.Type, fp.Fingerprint, where),
					SessionID: e.SessionID, AgentID: e.AgentID,
					Related: related, EvidenceRefs: []string{ref(e)},
					Status: e.Corroboration, Endpoint: schema.StateUnknown,
					MitreATTACK: "T1567", MitreATLAS: "AML.T0086",
					Confidence: conf, Reasons: reasons, Timestamp: e.Timestamp,
					FalsePositive: "Giving a tool the credential it is meant to use (a deploy server called with its own API key) is intended use. A credential in the arguments is not proof it was exfiltrated: who operates the server, and whether the credential belongs to it, decides.",
				})
			}
		}
	}
	if skipped > 0 {
		out = append(out, credLimitation(skipped, why, firstSkipped))
	}
	return out
}
