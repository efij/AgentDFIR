package detect

import (
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/accounts"
	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/shellshape"
)

// maxSettingsBytes bounds one settings file read; maxDenyRules bounds the
// rules taken from all of them. Settings are small; a larger file is not a
// settings file a client would load.
const (
	maxSettingsBytes = 1 << 20
	maxDenyRules     = 512
)

// denyRule is one entry of permissions.deny in a collected settings file.
type denyRule struct {
	raw     string // as written, e.g. Bash(rm -rf:*)
	tool    string
	arg     string
	art     casepkg.ArtifactRecord
	profile string // login profile the file belongs to (accounts.Key)
	managed bool   // managed settings apply to every profile
	mtime   time.Time
	hasTime bool
	argRe   *regexp.Regexp // compiled path or command pattern; nil = tool-wide
	prefix  string         // Bash "cmd:*" prefix form
}

// isSettingsArtifact reports the collected files a client reads deny rules
// from: the user settings and the managed (policy) settings.
func isSettingsArtifact(a casepkg.ArtifactRecord) (managed, ok bool) {
	if a.Status != casepkg.StatusOK || a.ArtifactID == "" || !strings.HasSuffix(a.LogicalPath, ".json") {
		return false, false
	}
	base := path.Base(a.LogicalPath)
	switch {
	case a.CollectorRule == "claude.settings":
		return false, true
	case strings.HasPrefix(a.CollectorRule, "claude.managed_settings") && strings.Contains(base, "settings"):
		return true, true
	}
	return false, false
}

// loadDenyRules reads permissions.deny from every collected settings file.
// A file that is not JSON contributes nothing: the client refuses to load
// it too, so it denied nothing.
func loadDenyRules(store *casepkg.Store, man *casepkg.Manifest) []denyRule {
	var out []denyRule
	for _, a := range man.Current() {
		managed, ok := isSettingsArtifact(a)
		if !ok || a.Size > maxSettingsBytes {
			continue
		}
		f, err := store.Open(a.ArtifactID)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxSettingsBytes))
		f.Close()
		if err != nil {
			continue
		}
		var doc struct {
			Permissions struct {
				Deny []json.RawMessage `json:"deny"`
			} `json:"permissions"`
		}
		if json.Unmarshal(data, &doc) != nil {
			continue
		}
		mt, hasT := parseTS(a.ModTimeUTC)
		for _, raw := range doc.Permissions.Deny {
			var s string
			if json.Unmarshal(raw, &s) != nil || strings.TrimSpace(s) == "" || len(out) >= maxDenyRules {
				continue
			}
			r, ok := parseDenyRule(strings.TrimSpace(s))
			if !ok {
				continue
			}
			r.art, r.managed, r.mtime, r.hasTime = a, managed, mt, hasT
			r.profile = accounts.Key(a.LogicalPath, a.Product)
			out = append(out, r)
		}
	}
	return out
}

// parseDenyRule splits "Tool" or "Tool(argument)" and compiles the
// argument. Forms this reader does not model (WebFetch domains, which the
// transcript events do not carry) are dropped rather than guessed at.
func parseDenyRule(s string) (denyRule, bool) {
	r := denyRule{raw: s, tool: s}
	if i := strings.IndexByte(s, '('); i > 0 && strings.HasSuffix(s, ")") {
		r.tool, r.arg = s[:i], strings.TrimSpace(s[i+1:len(s)-1])
	}
	if r.tool == "" || strings.ContainsAny(r.tool, " ()") {
		return r, false
	}
	if r.arg == "" || r.arg == "*" {
		r.arg = ""
		return r, true
	}
	switch r.tool {
	case "Bash":
		switch {
		case strings.HasSuffix(r.arg, ":*"):
			r.prefix = strings.TrimSuffix(r.arg, ":*")
		case strings.Contains(r.arg, "*"):
			re, err := regexp.Compile(`^` + strings.ReplaceAll(regexp.QuoteMeta(r.arg), `\*`, `.*`) + `$`)
			if err != nil {
				return r, false
			}
			r.argRe = re
		default:
			r.argRe = regexp.MustCompile(`^` + regexp.QuoteMeta(r.arg) + `$`)
		}
		return r, true
	case "Read", "Edit", "Write", "MultiEdit", "NotebookEdit":
		re, err := regexp.Compile(pathGlob(r.arg))
		if err != nil {
			return r, false
		}
		r.argRe = re
		return r, true
	}
	return r, false
}

// pathGlob turns a gitignore-style permission path into a regexp matched
// against the absolute path in the event. The anchor (~/, //, ./, /) cannot
// be resolved without the session's home and project root, so the pattern
// matches as a path suffix: broader than the client's own matching, which
// is why these findings never claim more than MEDIUM confidence.
func pathGlob(p string) string {
	for _, pre := range []string{"//", "~/", "./", "/"} {
		if strings.HasPrefix(p, pre) {
			p = p[len(pre):]
			break
		}
	}
	var b strings.Builder
	b.WriteString(`(^|/)`)
	for i := 0; i < len(p); i++ {
		switch {
		case strings.HasPrefix(p[i:], "**/"):
			b.WriteString(`(.*/)?`)
			i += 2
		case strings.HasPrefix(p[i:], "**"):
			b.WriteString(`.*`)
			i++
		case p[i] == '*':
			b.WriteString(`[^/]*`)
		case p[i] == '?':
			b.WriteString(`[^/]`)
		default:
			b.WriteString(regexp.QuoteMeta(p[i : i+1]))
		}
	}
	b.WriteString(`$`)
	return b.String()
}

// spawnAliases: the delegation tool was renamed; a rule naming either
// covers both.
var spawnAliases = map[string]bool{"Task": true, "Agent": true}

// toolCovered reports whether the rule's tool part names the event's tool.
func (r denyRule) toolCovered(e schema.Event) bool {
	switch {
	case strings.HasPrefix(r.tool, "mcp__"):
		t := strings.TrimSuffix(r.tool, "*")
		t = strings.TrimSuffix(t, "__")
		return e.Tool == t || strings.HasPrefix(e.Tool, t+"__")
	case r.tool == "Edit":
		return e.Tool == "Edit" || e.Tool == "MultiEdit" || e.Tool == "Write" || e.Tool == "NotebookEdit"
	case spawnAliases[r.tool]:
		return spawnAliases[e.Tool]
	}
	return e.Tool == r.tool
}

// matches reports whether the rule covers the event.
func (r denyRule) matches(e schema.Event) bool {
	if !r.toolCovered(e) {
		return false
	}
	if r.arg == "" {
		return true
	}
	if r.tool == "Bash" {
		cmd := e.FullCommand()
		cands := []string{strings.TrimSpace(cmd)}
		for _, st := range shellshape.Stages(cmd) {
			cands = append(cands, strings.TrimSpace(st.Text))
		}
		for _, c := range cands {
			if r.prefix != "" && (c == r.prefix || strings.HasPrefix(c, r.prefix+" ")) {
				return true
			}
			if r.argRe != nil && r.argRe.MatchString(c) {
				return true
			}
		}
		return false
	}
	return r.argRe != nil && e.File != "" && r.argRe.MatchString(e.File)
}

// applies reports whether the rule's settings file governs the event: the
// same login profile, or a managed file and a Claude client.
func (r denyRule) applies(e schema.Event) bool {
	if r.managed {
		return strings.HasPrefix(e.Product, "claude") || strings.HasPrefix(accounts.Key(e.SourcePath, e.Product), ".claude")
	}
	return r.profile == accounts.Key(e.SourcePath, e.Product)
}

// AGENT_PERMISSION_BOUNDARY_CROSSING — a deny rule in the collected
// settings covers a tool call, and the call completed: its recorded result
// is neither an error nor a refusal. The client enforces deny rules in
// every permission mode, so either the rule did not exist yet, the client
// did not enforce it, or something ran the tool around it. When the
// governed tool is the delegation tool (Task/Agent) the finding says so:
// that is delegation outside the recorded authorization.
//
// Settings are what was collected, not what was in force at the time. The
// file's mtime is the only clue to when the rule appeared, and confidence
// follows it.
func permissionBoundaryCrossing(ix *eventIndex, rules []denyRule) []schema.Finding {
	if len(rules) == 0 {
		return nil
	}
	var out []schema.Finding
	perRule := map[string]int{}
	for _, e := range ix.events {
		if e.EventType != schema.EventToolCall || e.Tool == "" {
			continue
		}
		for _, r := range rules {
			if !r.applies(e) || !r.matches(e) {
				continue
			}
			res, ok := ix.completed(e)
			if !ok {
				break // refused, failed or no result: the boundary held or is unknown
			}
			key := r.art.ArtifactID + "\x00" + r.raw
			if perRule[key] >= 20 {
				break
			}
			perRule[key]++
			conf := "LOW"
			reason := "the settings file was modified after this call, so the deny rule may have been added later"
			if t, ok := parseTS(e.Timestamp); ok && r.hasTime && !r.mtime.After(t) {
				conf = "MEDIUM"
				reason = "the settings file was last modified before this call, so the deny rule most likely existed when it ran"
			}
			what := "tool call"
			if spawnAliases[e.Tool] {
				what = "subagent delegation"
			}
			out = append(out, schema.Finding{
				RuleID: "AGENT_PERMISSION_BOUNDARY_CROSSING", Severity: "HIGH",
				Title: "Tool Ran Although a Deny Rule Covers It",
				Description: fmt.Sprintf("Deny rule %q in %s covers this %s (%s), and the call completed: its recorded result is not an error or a refusal. Deny rules apply in every permission mode.",
					r.raw, r.art.LogicalPath, what, describeCall(e)),
				SessionID: e.SessionID, AgentID: e.AgentID,
				Related:      []string{"deny rule: " + artRef(r.art, 0), "result: " + ref(res)},
				EvidenceRefs: []string{ref(e), ref(res)},
				Status:       e.Corroboration, Endpoint: schema.StateUnknown,
				MitreATTACK: "T1548", // Abuse Elevation Control Mechanism
				Confidence:  conf, Reasons: []string{reason, "deny paths are matched as suffixes, which is broader than the client's own matching"},
				Timestamp:     e.Timestamp,
				FalsePositive: "The rule was added after the call (compare the settings file's history), or a project-level setting outside the collection changed it. A suffix match on a relative path rule can cover a file the client would not.",
			})
			break
		}
	}
	return out
}
