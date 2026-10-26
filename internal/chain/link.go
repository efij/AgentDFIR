package chain

// Links. Scope and window alone let two unrelated events in one session
// complete a chain. A link names a value consecutive steps must share — the
// same file, destination, tool call, MCP tool, target or agent — so a match
// says why its steps belong together, not only that they happened in order.

import (
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/netdest"
	"github.com/efij/AgentDFIR/v5/internal/redact"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// Link kinds. The artifact kinds join on something the steps touched; the
// identity kinds (session, agent) join on who acted. Case scope needs an
// artifact kind as the chain's link, so a cross-agent chain always names
// the shared artifact.
const (
	LinkFile       = "file"
	LinkNetDest    = "network_destination"
	LinkToolCallID = "tool_call_id"
	LinkMCPTool    = "mcp_tool"
	LinkMCPServer  = "mcp_server"
	LinkTarget     = "target"
	LinkSkill      = "skill"
	LinkSession    = "session"
	LinkAgent      = "agent"
)

var artifactLinks = map[string]bool{LinkFile: true, LinkNetDest: true, LinkToolCallID: true, LinkMCPTool: true, LinkMCPServer: true, LinkTarget: true, LinkSkill: true}

func validLink(k string) bool { return artifactLinks[k] || k == LinkSession || k == LinkAgent }

// maxLinkValues bounds the values one event contributes to a join; a
// hostile command naming thousands of paths still costs a constant.
const maxLinkValues = 16

// maxLinkScan bounds how much of a command line is searched for targets.
const maxLinkScan = 8192

var (
	skillDirRe   = regexp.MustCompile(`(?i)(?:^|/)skills/([^/]+)/`)
	cloudURIRe   = regexp.MustCompile(`(?i)\b(s3|gs|az|abfss?|wasbs?)://([^\s'"/;|&<>()]+)`)
	cmdPathRe    = regexp.MustCompile(`(?:^|[\s'"=])((?:/|~/)[^\s'";|&<>()*?$]+)`)
	fileArgKeys  = []string{"file_path", "path", "notebook_path", "filename", "file"}
	urlArgKeys   = []string{"url", "uri", "host", "endpoint"}
	resArgKeys   = []string{"resource_id", "resource", "arn", "bucket"}
	skillArgKeys = []string{"skill", "command", "name"}
	envAssignRe  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*=`)
)

// linkValues returns the normalized values an event offers for one link
// kind, sorted and unique. Empty means the event cannot take part in that
// join: missing data never links.
func linkValues(kind string, e schema.Event) []string {
	var out []string
	add := func(v string) {
		if v != "" && len(out) < maxLinkValues {
			out = append(out, v)
		}
	}
	switch kind {
	case LinkFile:
		for _, p := range filePaths(e) {
			add(p)
		}
	case LinkNetDest:
		if h := destHost(e.NetworkDest); h != "" {
			add(h)
		}
		for _, h := range netdest.Extract(clip(e.FullCommand())) {
			add(netdest.Host(h))
		}
	case LinkToolCallID:
		add(strings.TrimSpace(e.ToolCallID))
	case LinkMCPTool:
		if srv, tool := mcpIdentity(e); srv != "" && tool != "" {
			add(srv + "/" + tool)
		}
	case LinkMCPServer:
		if srv, _ := mcpIdentity(e); srv != "" {
			add(srv)
		}
	case LinkTarget:
		add(strings.TrimSpace(e.ResourceID))
		for _, k := range resArgKeys {
			add(strings.TrimSpace(e.SafeArgs[k]))
		}
		for _, p := range filePaths(e) {
			add(p)
		}
		if h := destHost(e.NetworkDest); h != "" {
			add(h)
		}
		for _, k := range urlArgKeys {
			add(destHost(e.SafeArgs[k]))
		}
		cmd := clip(e.FullCommand())
		for _, m := range cloudURIRe.FindAllStringSubmatch(cmd, maxLinkValues) {
			add(strings.ToLower(m[1]) + "://" + strings.ToLower(m[2]))
		}
		for _, m := range cmdPathRe.FindAllStringSubmatch(cmd, maxLinkValues) {
			add(normPath(m[1]))
		}
		for _, h := range netdest.Extract(cmd) {
			add(netdest.Host(h))
		}
	case LinkSkill:
		for _, p := range filePaths(e) {
			if m := skillDirRe.FindStringSubmatch(p); m != nil {
				add(strings.ToLower(m[1]))
			}
		}
		if strings.EqualFold(e.Tool, "Skill") {
			for _, k := range skillArgKeys {
				v := strings.TrimPrefix(strings.TrimSpace(e.SafeArgs[k]), "/")
				if i := strings.LastIndex(v, ":"); i >= 0 {
					v = v[i+1:]
				}
				add(strings.ToLower(v))
			}
		}
	case LinkSession:
		add(e.SessionID)
	case LinkAgent:
		if e.SessionID != "" || e.AgentID != "" {
			add(actor(e))
		}
	}
	return uniq(out)
}

func actor(e schema.Event) string { return e.SessionID + "\x00" + e.AgentID }

// method is how an action was carried out: the tool, and for shell calls
// the program run. `rm` refused and `find -delete` allowed are two methods.
func method(e schema.Event) string {
	return methodWith(nil, e)
}

// methodWith builds the method, masking each raw part before it is
// lowercased: lowercasing first can carry a secret past case-sensitive
// patterns, and a masked part keeps its marker intact.
func methodWith(red *redact.Redactor, e schema.Event) string {
	low := func(v string) string {
		if red != nil {
			if m := red.String(v, "chain_link"); m != v {
				return m
			}
		}
		return strings.ToLower(v)
	}
	m := low(e.Tool)
	if f := firstProgramRaw(e.Command); f != "" {
		return m + ":" + low(f)
	}
	return m + ":" + low(e.MCPTool)
}

func firstProgramRaw(cmd string) string {
	for _, tok := range strings.Fields(clip(cmd)) {
		if envAssignRe.MatchString(tok) {
			continue // VAR=value prefix, whatever the value holds
		}
		switch tok {
		case "sudo", "doas", "env", "nohup", "time", "exec", "command":
			continue
		}
		return path.Base(tok)
	}
	return ""
}

func filePaths(e schema.Event) []string {
	var out []string
	if p := normPath(e.File); p != "" {
		out = append(out, p)
	}
	for _, k := range fileArgKeys {
		if p := normPath(e.SafeArgs[k]); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// normPath cleans a path for comparison: forward slashes, no trailing
// slash, no "." or ".." segments. The root, single-component paths (/tmp,
// /etc) and devices never link: everything touches them.
func normPath(p string) string {
	p = strings.TrimSpace(strings.Trim(p, `"'`))
	if p == "" || len(p) > 4096 {
		return ""
	}
	p = path.Clean(strings.ReplaceAll(p, `\`, "/"))
	if p == "." || p == "/" || p == "~" || strings.HasPrefix(p, "/dev/") || strings.HasPrefix(p, "/proc/") {
		return ""
	}
	if strings.Count(strings.Trim(p, "/~"), "/") < 1 && strings.HasPrefix(p, "/") {
		return ""
	}
	return p
}

func destHost(d string) string {
	d = strings.TrimSpace(d)
	if d == "" {
		return ""
	}
	if strings.Contains(d, "://") {
		if h, ok := netdest.URLHost(d); ok {
			return netdest.Host(h)
		}
		return ""
	}
	if i := strings.IndexAny(d, "/ "); i >= 0 {
		d = d[:i]
	}
	return strings.ToLower(netdest.Host(d))
}

func mcpIdentity(e schema.Event) (string, string) {
	srv, tool := strings.ToLower(e.MCPServer), strings.ToLower(e.MCPTool)
	if strings.HasPrefix(strings.ToLower(e.Tool), "mcp__") {
		parts := strings.SplitN(strings.ToLower(e.Tool)[len("mcp__"):], "__", 2)
		if srv == "" {
			srv = parts[0]
		}
		if tool == "" && len(parts) == 2 {
			tool = parts[1]
		}
	}
	return srv, tool
}

func clip(s string) string {
	if len(s) > maxLinkScan {
		return s[:maxLinkScan]
	}
	return s
}

func uniq(v []string) []string {
	if len(v) < 2 {
		return v
	}
	sort.Strings(v)
	out := v[:1]
	for _, x := range v[1:] {
		if x != out[len(out)-1] {
			out = append(out, x)
		}
	}
	return out
}

func intersect(a, b []string) []string {
	var out []string
	for _, x := range a {
		for _, y := range b {
			if x == y {
				out = append(out, x)
				break
			}
		}
	}
	return out
}

// joinState carries what step i-1 shared with step i-2, so a run of steps
// joined on one kind keeps sharing the same value rather than drifting
// (file A → file A,B → file B is not one shared file).
type joinState struct {
	kind   string
	shared []string
}

// related checks the relational constraints between the previous matched
// event and a candidate for step s. It returns the shared values (nil for
// unlinked steps) and whether the candidate qualifies.
func related(kind string, s *Step, prev, cur schema.Event, st joinState) ([]string, bool) {
	if s.DifferentAgent && actor(prev) == actor(cur) {
		return nil, false
	}
	if s.DifferentMethod && method(prev) == method(cur) {
		return nil, false
	}
	if kind == "" {
		return nil, true
	}
	pv := st.shared
	if st.kind != kind {
		pv = linkValues(kind, prev)
	}
	if len(pv) == 0 {
		return nil, false
	}
	shared := intersect(pv, linkValues(kind, cur))
	return shared, len(shared) > 0
}

// linkSentence describes one join for an analyst: the kind and the shared
// value, shortened and with anything secret-shaped masked. The full value
// is redacted before it is shortened, so a cut can never hide a secret from
// the patterns, and the finished sentence (method and agent text included)
// goes through the redactor once more before it is stored.
func linkSentence(red *redact.Redactor, kind string, from, to int, shared []string, s *Step, prev, cur schema.Event) string {
	var parts []string
	if kind != "" && len(shared) > 0 {
		v := shared[0]
		if red != nil {
			v = red.String(v, "chain_link")
		}
		v = display(kind, v)
		noun := map[string]string{LinkFile: "the file", LinkNetDest: "the destination", LinkToolCallID: "the tool call",
			LinkMCPTool: "the MCP tool", LinkMCPServer: "the MCP server", LinkTarget: "the target", LinkSkill: "the skill",
			LinkSession: "the session", LinkAgent: "the agent"}[kind]
		parts = append(parts, "steps "+strconv.Itoa(from)+"→"+strconv.Itoa(to)+" share "+noun+" "+v)
	}
	if s.DifferentAgent {
		parts = append(parts, "step "+strconv.Itoa(to)+" is a different agent ("+short(agentName(red, cur), 40)+") from step "+strconv.Itoa(from)+" ("+short(agentName(red, prev), 40)+")")
	}
	if s.DifferentMethod {
		parts = append(parts, "step "+strconv.Itoa(to)+" used a different method ("+short(methodWith(red, cur), 40)+") from step "+strconv.Itoa(from)+" ("+short(methodWith(red, prev), 40)+")")
	}
	out := strings.Join(parts, "; ")
	if red != nil {
		out = red.String(out, "chain_link")
	}
	return out
}

// agentName labels an actor, masking the raw IDs before any shortening.
func agentName(red *redact.Redactor, e schema.Event) string {
	a, sid := e.AgentID, e.SessionID
	if red != nil {
		a, sid = red.String(a, "chain_link"), red.String(sid, "chain_link")
	}
	if a == "" {
		a = "main"
	}
	return a + " in session " + short(sid, 12)
}

// display shortens a link value: the last path components, the host, an ID
// prefix. Full paths carry user names; the evidence reference has the rest.
func display(kind, v string) string {
	switch kind {
	case LinkFile, LinkTarget:
		if strings.Contains(v, "/") && !strings.Contains(v, "://") {
			segs := strings.Split(strings.Trim(v, "/"), "/")
			if len(segs) > 3 {
				v = ".../" + strings.Join(segs[len(segs)-3:], "/")
			}
		}
		return short(v, 80)
	case LinkToolCallID:
		return short(v, 16)
	case LinkAgent:
		if i := strings.IndexByte(v, 0); i >= 0 {
			a := v[i+1:]
			if a == "" {
				a = "main"
			}
			return a + " in session " + short(v[:i], 12)
		}
	case LinkSession:
		return short(v, 12)
	}
	return short(v, 80)
}

// short cuts s to at most n bytes plus an ellipsis, on a rune boundary,
// and never inside a redaction marker: a marker the cut would split is
// dropped whole rather than left as a fragment.
func short(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && cut < len(s) && (s[cut]&0xC0) == 0x80 {
		cut--
	}
	for off := 0; off < cut; {
		i := strings.Index(s[off:], redactMarkerOpen)
		if i < 0 || off+i >= cut {
			break
		}
		i += off
		j := strings.IndexByte(s[i:], ']')
		if j < 0 || i+j >= cut {
			cut = i // the cut lands inside this marker (or its opening)
			break
		}
		off = i + j + 1
	}
	return s[:cut] + "…"
}

const redactMarkerOpen = "[REDACTED:"
