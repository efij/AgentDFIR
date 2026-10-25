package accountability

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/detect"
	"github.com/efij/AgentDFIR/v3/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v3/internal/provenance"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// caseAuth is the authority picture of the whole case, computed once:
// the permission-bearing files as captured, how they changed between
// rounds, the MCP servers in play, and the case-wide bypass findings.
type caseAuth struct {
	configs    []ConfigState
	changed    []ConfigChange
	mcp        []string
	indicators []Indicator
	headless   []Indicator // AI_CLI_HEADLESS_BYPASS launches, with the prompt text they carried
	launchCmds []string    // the full commands of those launches
}

// permissionFileRe recognizes files that decide what an agent may do.
var permissionFileRe = regexp.MustCompile(`(?i)(\.claude/settings(\.local)?\.json$|managed-settings\.json$|\.codex/config\.toml$|\.gemini/settings\.json$|\.cursor/(mcp\.json|cli-config\.json)$|\.copilot/config\.json$|\.claude\.json$|\.mcp\.json$|opencode\.json$|\.claude/hooks/)`)

// caseAuthority reads every captured permission file and the case-wide
// authority findings.
func caseAuthority(pkg string, man *casepkg.Manifest, st *casepkg.Store, events []schema.Event, findings []schema.Finding) *caseAuth {
	a := &caseAuth{}
	// Every record, every round, so a file that changed between rounds
	// shows both states.
	byPath := map[string][]ConfigState{}
	for _, rec := range man.Artifacts {
		if rec.Status != casepkg.StatusOK || rec.ArtifactID == "" || rec.Size > 4<<20 {
			continue
		}
		if !permissionFileRe.MatchString(rec.LogicalPath) {
			continue
		}
		if rec.ArtifactType != "product_config" && rec.ArtifactType != "managed_config" && rec.ArtifactType != "agent_instructions" && rec.ArtifactType != "agent_definitions" {
			continue
		}
		data, err := st.ReadAll(rec.ArtifactID, 4<<20)
		if err != nil {
			continue
		}
		cs := ConfigState{Path: rec.LogicalPath, Product: rec.Product, ArtifactID: rec.ArtifactID, Round: rec.Round, CollectedUTC: rec.CollectedUTC}
		if cs.Round == 0 {
			cs.Round = 1
		}
		parseConfig(&cs, data)
		byPath[rec.LogicalPath] = append(byPath[rec.LogicalPath], cs)
	}
	var paths []string
	for p := range byPath {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		states := byPath[p]
		sort.SliceStable(states, func(i, j int) bool { return states[i].Round < states[j].Round })
		// Newest state is the one shown; a different content address in
		// an earlier round is a change worth showing on its own.
		last := states[len(states)-1]
		for i := 1; i < len(states); i++ {
			if states[i].ArtifactID != states[i-1].ArtifactID {
				a.changed = append(a.changed, ConfigChange{Path: p, Before: states[i-1], After: states[i]})
			}
		}
		a.configs = append(a.configs, last)
	}
	sort.SliceStable(a.configs, func(i, j int) bool {
		if a.configs[i].Round != a.configs[j].Round {
			return a.configs[i].Round < a.configs[j].Round
		}
		return a.configs[i].Path < a.configs[j].Path
	})

	if inv, _, err := mcpaudit.ScanPackage(pkg); err == nil && inv != nil {
		seen := map[string]bool{}
		for _, s := range inv.Servers {
			k := s.Name + " (" + s.Host + ", " + s.Scope
			if s.Disabled {
				k += ", disabled"
			}
			if len(s.AutoAllow) > 0 {
				k += ", auto-allow"
			}
			k += ")"
			if !seen[k] {
				seen[k] = true
				a.mcp = append(a.mcp, k)
			}
		}
		sort.Strings(a.mcp)
	}

	for _, f := range findings {
		switch f.RuleID {
		case "AI_CLI_HEADLESS_BYPASS", "NESTED_AGENT_PERMISSION_BYPASS":
			ind := Indicator{RuleID: f.RuleID, Text: f.Description, SessionID: f.SessionID, Timestamp: f.Timestamp}
			if len(f.EvidenceRefs) > 0 {
				ind.Evidence = f.EvidenceRefs[0]
			}
			a.headless = append(a.headless, ind)
			a.indicators = append(a.indicators, ind)
		case "PERMISSION_BYPASS_ENABLED", "MCP_AUTO_APPROVE", "MCP_WILDCARD_TOOL_PERMISSION", "MCP_ALL_PROJECT_SERVERS_TRUSTED",
			"MCP_AUTO_APPROVE_ALL", "MCP_WILDCARD_PERMISSIONS", "PERMISSION_ESCALATION", "REPO_AGENT_PERMISSION_WEAKENING":
			ind := Indicator{RuleID: f.RuleID, Text: f.Description, SessionID: f.SessionID, Timestamp: f.Timestamp}
			if len(f.EvidenceRefs) > 0 {
				ind.Evidence = f.EvidenceRefs[0]
			}
			a.indicators = append(a.indicators, ind)
		}
	}
	// The launch commands themselves, to tie a headless launch to the
	// session it started (the prompt travels in the command line).
	for _, ev := range events {
		if c := ev.FullCommand(); c != "" && looksLikeAgentLaunch(c) {
			a.launchCmds = append(a.launchCmds, c)
		}
	}
	return a
}

func looksLikeAgentLaunch(cmd string) bool {
	l := strings.ToLower(cmd)
	return strings.Contains(l, "--dangerously-skip-permissions") || strings.Contains(l, "--yolo") ||
		strings.Contains(l, "--dangerously-bypass-approvals-and-sandbox") || strings.Contains(l, "--permission-mode bypasspermissions") ||
		strings.Contains(l, "--trust-all-tools") || strings.Contains(l, "--allow-all-tools")
}

// parseConfig fills the permission fields of one captured file. JSON
// settings are read structurally; anything else is scanned for the bypass
// markers the PERMISSION_BYPASS_ENABLED rule uses.
func parseConfig(cs *ConfigState, data []byte) {
	for _, m := range detect.BypassMarkers {
		if strings.Contains(string(data), m) {
			cs.BypassMarkers = append(cs.BypassMarkers, m)
		}
	}
	base := path.Base(cs.Path)
	if !strings.HasSuffix(base, ".json") {
		if strings.HasSuffix(base, ".toml") {
			for _, line := range strings.Split(string(data), "\n") {
				t := strings.TrimSpace(line)
				if strings.HasPrefix(t, "approval_policy") || strings.HasPrefix(t, "sandbox_mode") {
					cs.Hooks = append(cs.Hooks, t) // Codex: the two switches that matter, shown verbatim
				}
			}
		}
		return
	}
	var doc map[string]json.RawMessage
	if json.Unmarshal(mcpaudit.StripJSONC(data), &doc) != nil {
		cs.Note = "not valid JSON; scanned for bypass markers only"
		return
	}
	var perms struct {
		DefaultMode              string   `json:"defaultMode"`
		Allow                    []string `json:"allow"`
		Deny                     []string `json:"deny"`
		Ask                      []string `json:"ask"`
		DisableBypassPermissions string   `json:"disableBypassPermissionsMode"`
	}
	if raw, ok := doc["permissions"]; ok && json.Unmarshal(raw, &perms) == nil {
		cs.DefaultMode, cs.Allow, cs.Deny, cs.Ask, cs.DisableBypassMode = perms.DefaultMode, perms.Allow, perms.Deny, perms.Ask, perms.DisableBypassPermissions
	}
	var hooks map[string][]struct {
		Matcher string `json:"matcher"`
		Hooks   []struct {
			Type    string `json:"type"`
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if raw, ok := doc["hooks"]; ok && json.Unmarshal(raw, &hooks) == nil {
		var names []string
		for ev := range hooks {
			names = append(names, ev)
		}
		sort.Strings(names)
		for _, ev := range names {
			for _, grp := range hooks[ev] {
				for _, h := range grp.Hooks {
					s := ev
					if grp.Matcher != "" {
						s += "[" + grp.Matcher + "]"
					}
					if h.Command != "" {
						s += ": " + trimTo(h.Command, 120)
					} else if h.Type != "" {
						s += ": " + h.Type
					}
					cs.Hooks = append(cs.Hooks, s)
				}
			}
		}
	}
	var b bool
	if raw, ok := doc["enableAllProjectMcpServers"]; ok && json.Unmarshal(raw, &b) == nil {
		cs.EnableAllProjectMCP = b
	}
	if raw, ok := doc["enabledMcpjsonServers"]; ok {
		_ = json.Unmarshal(raw, &cs.EnabledProjectServers)
	}
}

// sessionAuthority is the authority column for one action: the case-wide
// picture plus what this session itself shows — its recorded permission
// mode, a headless bypass launch that carried this session's prompt, and
// any write the agent made to a permission file earlier in the session.
func sessionAuthority(a *caseAuth, events []schema.Event, idxs []int, at int, trig provenance.Trigger) Authority {
	out := Authority{Configs: a.configs, Changed: a.changed, MCPServers: a.mcp, Indicators: a.indicators}
	ev := events[at]
	// The transcript's own init record: "permissionMode=…".
	for _, i := range idxs {
		if i > at {
			break
		}
		e := events[i]
		if e.EventType == schema.EventSessionMeta && strings.Contains(e.Summary, "permissionMode=") {
			rest := e.Summary[strings.Index(e.Summary, "permissionMode=")+len("permissionMode="):]
			if j := strings.IndexByte(rest, ' '); j >= 0 {
				rest = rest[:j]
			}
			if rest != "" {
				out.SessionPermissionMode = rest
			}
		}
	}
	// A headless launch whose command line carries this session's first
	// prompt started this session with permissions bypassed.
	if first := firstPrompt(events, idxs); first != "" {
		key := strings.ToLower(trimTo(first, 48))
		key = strings.TrimSuffix(key, "…")
		for _, c := range a.launchCmds {
			if len(key) >= 20 && strings.Contains(strings.ToLower(strings.ReplaceAll(c, "'", "\"")), strings.ReplaceAll(key, "'", "\"")) {
				ind := Indicator{RuleID: "AI_CLI_HEADLESS_BYPASS", Text: "This session was started non-interactively with permission prompts disabled: " + trimTo(c, 160)}
				for _, h := range a.headless {
					if strings.Contains(h.Text, "--dangerously") || strings.Contains(h.Text, "yolo") || h.Evidence != "" {
						ind.Evidence = h.Evidence
						break
					}
				}
				out.HeadlessLaunch = &ind
				break
			}
		}
	}
	// Agent writes to permission files earlier in the same session.
	pos := sort.SearchInts(idxs, at)
	for k := 0; k < pos; k++ {
		e := events[idxs[k]]
		if e.EventType != schema.EventToolCall || e.File == "" {
			continue
		}
		if (e.Action == "write_file" || e.Action == "edit_file") && permissionFileRe.MatchString(filepathToSlash(e.File)) {
			out.AgentWrites = append(out.AgentWrites, Indicator{Text: fmt.Sprintf("the agent wrote %s via %s before this action", e.File, e.Tool),
				Evidence: provenance.EvidenceRef(e), SessionID: e.SessionID, Timestamp: e.Timestamp})
		}
	}
	out.Statement = authorityStatement(out, ev)
	return out
}

func filepathToSlash(p string) string { return strings.ReplaceAll(p, "\\", "/") }

func firstPrompt(events []schema.Event, idxs []int) string {
	for _, i := range idxs {
		if events[i].EventType == schema.EventHumanPrompt {
			return events[i].Summary
		}
	}
	return ""
}

// authorityStatement is the sentence a reader gets.
func authorityStatement(a Authority, ev schema.Event) string {
	var parts []string
	switch {
	case a.HeadlessLaunch != nil:
		parts = append(parts, "permission prompts were disabled for this session at launch")
	case a.SessionPermissionMode != "":
		parts = append(parts, "the session ran in permission mode "+a.SessionPermissionMode)
	}
	bypass := 0
	allow := 0
	for _, c := range a.Configs {
		if len(c.BypassMarkers) > 0 || c.DefaultMode == "bypassPermissions" {
			bypass++
		}
		for _, x := range c.Allow {
			if strings.Contains(x, "*") || x == "Bash" {
				allow++
			}
		}
	}
	if bypass > 0 {
		parts = append(parts, fmt.Sprintf("%d captured configuration file(s) disable permission prompting or sandboxing", bypass))
	}
	if allow > 0 {
		parts = append(parts, fmt.Sprintf("%d wildcard allow rule(s) in captured settings", allow))
	}
	if len(a.AgentWrites) > 0 {
		parts = append(parts, fmt.Sprintf("the agent itself wrote to a permission file %d time(s) earlier in this session", len(a.AgentWrites)))
	}
	if len(a.Changed) > 0 {
		parts = append(parts, fmt.Sprintf("%d permission file(s) changed between collection rounds", len(a.Changed)))
	}
	if len(parts) == 0 {
		if len(a.Configs) == 0 {
			return "No permission-bearing configuration was captured and the transcript records no permission mode; what was allowed is not in the evidence."
		}
		return fmt.Sprintf("As captured, %d configuration file(s) with no bypass markers; no permission mode recorded in the transcript.", len(a.Configs))
	}
	s := strings.Join(parts, "; ")
	return strings.ToUpper(s[:1]) + s[1:] + "."
}

func trimTo(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
