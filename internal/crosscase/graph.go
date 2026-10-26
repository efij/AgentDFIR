package crosscase

// The cross-case activity graph (`correlate-cases --graph`).
//
// The shared-item comparison above says what two cases have in common.
// The graph says how their agent activity connects, and how sure that
// connection is. Every entity stays in its own case: a session recorded in
// C1 and a session with the same id recorded in C2 are two nodes, and the
// edge between them names the identifier that joins them, the evidence on
// each side, a confidence and how the two sides sit in time.
//
// Joins are graded once, here:
//
//	strong   the same session or agent id; a delegation reference (a
//	         parent tool call / parent agent id in one case naming a tool
//	         call, task or agent recorded in another); the same tool call
//	         id; a full commit id; a file's content hash; the same cloud
//	         principal acting on the same resource id
//	moderate the same cloud principal alone; the same execution
//	         environment
//	weak     the same destination, the same file name, similar prompt
//	         text, a remote agent launch followed in time by a session
//	         with no identifier tying them
//
// Weak edges are reported so an analyst sees them. They never make two
// actions the same agent and never raise a finding on their own. A strong
// join whose timestamps contradict its direction is kept, marked with the
// time relation, and downgraded to moderate.
//
// The two cross-case findings read strong joins only:
//
//	AGENT_CROSS_HOST_ACTIVITY          strong-joined agent activity on two
//	                                   or more distinct hosts / execution
//	                                   environments
//	CHAIN_CROSS_HOST_AGENT_PROPAGATION an agent launched or delegated
//	                                   remotely in one case, the linked
//	                                   session active in another within a
//	                                   bounded window, then a consequential
//	                                   action there

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/efij/AgentDFIR/v4/internal/catalog"
	"github.com/efij/AgentDFIR/v4/internal/detect"
	"github.com/efij/AgentDFIR/v4/internal/lineage"
	"github.com/efij/AgentDFIR/v4/internal/netdest"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// GraphSchema identifies the graph document (the `graph` member of the
// correlate-cases report).
const GraphSchema = "agentdfir.crosscase-graph/1"

// Node kinds, in reporting order.
const (
	NodeCase        = "case"
	NodeHost        = "host"
	NodeExecEnv     = "exec_env"
	NodeSession     = "agent_session"
	NodeAgent       = "agent"
	NodeMCPTool     = "mcp_tool"
	NodePrincipal   = "cloud_principal"
	NodeResource    = "cloud_resource"
	NodeCommit      = "git_commit"
	NodeFile        = "file"
	NodeDestination = "destination"
)

var nodeRank = map[string]int{NodeCase: 0, NodeHost: 1, NodeExecEnv: 2, NodeSession: 3, NodeAgent: 4, NodeMCPTool: 5,
	NodePrincipal: 6, NodeResource: 7, NodeCommit: 8, NodeFile: 9, NodeDestination: 10}

// Confidence grades.
const (
	Strong   = "strong"
	Moderate = "moderate"
	Weak     = "weak"
)

var confRank = map[string]int{Strong: 0, Moderate: 1, Weak: 2}

// Time relations of an edge's from side to its to side.
const (
	RelBefore  = "before"
	RelAfter   = "after"
	RelOverlap = "overlap"
	RelUnknown = "unknown"
)

// Join key types.
const (
	JoinSessionID         = "session_id"
	JoinAgentID           = "agent_id"
	JoinDelegation        = "delegation_ref"
	JoinToolCallID        = "tool_call_id"
	JoinSessionInCommand  = "session_id_in_command"
	JoinCommit            = "git_commit"
	JoinCommitAbbrev      = "git_commit_abbreviated"
	JoinFileHash          = "file_sha256"
	JoinPrincipalResource = "principal_resource"
	JoinPrincipal         = "principal"
	JoinExecEnv           = "exec_env"
	JoinDestination       = "destination"
	JoinFilename          = "filename"
	JoinPrompt            = "prompt_similarity"
	JoinLaunchTiming      = "launch_timing"
)

// agentJoins are the strong joins that tie agent activity in two cases
// together: the inputs to AGENT_CROSS_HOST_ACTIVITY.
var agentJoins = map[string]bool{JoinSessionID: true, JoinAgentID: true, JoinDelegation: true, JoinToolCallID: true, JoinSessionInCommand: true}

// Cross-case finding rule ids.
const (
	RuleCrossHostActivity    = "AGENT_CROSS_HOST_ACTIVITY"
	RuleCrossHostPropagation = "CHAIN_CROSS_HOST_AGENT_PROPAGATION"
)

// GraphOptions bound the graph and set the propagation window.
type GraphOptions struct {
	MaxNodes      int           // default 20,000
	MaxEdges      int           // default 50,000
	MaxPerJoin    int           // edges of one join key type per case pair; default 2,000
	MaxKeys       int           // distinct identifiers of one kind indexed per case; default 50,000
	Window        time.Duration // launch → linked activity → consequential action; default 60 min
	Skew          time.Duration // clock tolerance between hosts; default 2 min
	IncludeCommon bool          // also join allowlisted destinations
}

func (o *GraphOptions) defaults() {
	if o.MaxNodes <= 0 {
		o.MaxNodes = 20000
	}
	if o.MaxEdges <= 0 {
		o.MaxEdges = 50000
	}
	if o.MaxPerJoin <= 0 {
		o.MaxPerJoin = 2000
	}
	if o.MaxKeys <= 0 {
		o.MaxKeys = 50000
	}
	if o.Window <= 0 {
		o.Window = 60 * time.Minute
	}
	if o.Skew <= 0 {
		o.Skew = 2 * time.Minute
	}
}

// GraphCase is one case as the graph reads it.
type GraphCase struct {
	Label      string
	Path       string
	CaseID     string
	Host       string
	Unverified bool
	Events     []schema.Event
	Findings   []schema.Finding
	Files      []FileHash // collected artifacts by content hash
}

// FileHash is one collected artifact by its content hash.
type FileHash struct {
	SHA256 string
	Path   string
	Size   int64
}

// Graph is the typed multi-case activity graph.
type Graph struct {
	Schema     string         `json:"schema"`
	Unverified bool           `json:"includes_unverified_cases"`
	Cases      []GraphCaseRef `json:"cases"`
	Nodes      []Node         `json:"nodes"`
	Edges      []Edge         `json:"edges"`
	Findings   []CrossFinding `json:"findings"`
	Summary    GraphSummary   `json:"summary"`
	Options    GraphLimits    `json:"limits"`
	Truncated  bool           `json:"truncated"`
	Omitted    map[string]int `json:"omitted,omitempty"`
	Notes      []string       `json:"notes"`
	Caveats    []string       `json:"caveats"`
}

// GraphCaseRef names one input case and whether its seal verified.
type GraphCaseRef struct {
	Label      string `json:"label"`
	CaseID     string `json:"case_id"`
	Host       string `json:"host"`
	Unverified bool   `json:"unverified,omitempty"`
}

// GraphLimits are the bounds the graph was built with.
type GraphLimits struct {
	MaxNodes      int `json:"max_nodes"`
	MaxEdges      int `json:"max_edges"`
	MaxPerJoin    int `json:"max_edges_per_join"`
	WindowSeconds int `json:"propagation_window_seconds"`
	SkewSeconds   int `json:"clock_skew_seconds"`
}

// GraphSummary counts what the graph holds.
type GraphSummary struct {
	Nodes        map[string]int `json:"nodes_by_kind"`
	JoinEdges    map[string]int `json:"join_edges_by_confidence"`
	ContextEdges int            `json:"context_edges"`
	Findings     int            `json:"findings"`
}

// Node is one entity in one case.
type Node struct {
	ID         string            `json:"id"`
	Kind       string            `json:"kind"`
	Case       string            `json:"case"`
	Label      string            `json:"label"`
	FirstSeen  string            `json:"first_seen,omitempty"`
	LastSeen   string            `json:"last_seen,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Unverified bool              `json:"from_unverified_case,omitempty"`
}

// Edge is one link. A join edge connects entities in two cases; a context
// edge places an entity inside its own case (case → host → session …).
type Edge struct {
	Kind       string       `json:"kind"`
	From       string       `json:"from"`
	To         string       `json:"to"`
	JoinKey    string       `json:"join_key,omitempty"`   // empty on context edges
	JoinValue  string       `json:"join_value,omitempty"` // the identifier, masked
	Confidence string       `json:"confidence"`
	Reason     string       `json:"confidence_reason"`
	Time       TimeRelation `json:"time_relation"`
	Evidence   []SideRef    `json:"evidence"`
	Unverified bool         `json:"from_unverified_case,omitempty"`
}

// TimeRelation is how the from side's activity sits against the to
// side's: before (it ended before the other began), after, overlap, or
// unknown when either side has no timestamp.
type TimeRelation struct {
	Relation string `json:"relation"`
	FromTime string `json:"from_time,omitempty"`
	ToTime   string `json:"to_time,omitempty"`
}

// SideRef is the evidence for one side of an edge: the case and the
// sealed source of the event (or collected artifact).
type SideRef struct {
	Case string `json:"case"`
	lineage.Ref
	JSONPath string `json:"source_json_path,omitempty"`
}

// String renders "C1: path:line (artifact …, offset …) event …".
func (r SideRef) String() string {
	s := r.Case + ": " + r.Path
	if r.Line > 0 {
		s += fmt.Sprintf(":%d", r.Line)
	}
	if r.ArtifactID != "" {
		s += " (artifact " + short12(r.ArtifactID)
		if r.Offset > 0 || r.Line > 0 {
			s += fmt.Sprintf(", offset %d", r.Offset)
		}
		s += ")"
	}
	if r.JSONPath != "" {
		s += " " + r.JSONPath
	}
	if r.EventID != "" {
		s += " event " + r.EventID
	}
	return s
}

// CrossFinding is a finding that only exists across cases. The embedded
// Finding carries the usual fields; evidence references are prefixed with
// the case label.
type CrossFinding struct {
	schema.Finding
	Cases      []string  `json:"cases"`
	Joins      []JoinRef `json:"joins"`
	Limits     []string  `json:"limits"`
	Unverified bool      `json:"from_unverified_case,omitempty"`
}

// JoinRef names one edge that justifies a finding.
type JoinRef struct {
	JoinKey    string `json:"join_key"`
	JoinValue  string `json:"join_value"`
	From       string `json:"from"`
	To         string `json:"to"`
	Confidence string `json:"confidence"`
	Relation   string `json:"time_relation"`
}

const (
	maxIDLen        = 256
	minSessionIDLen = 8
	minToolCallLen  = 12
	minCommitLen    = 12
	minFileSize     = 64
	maxPrompts      = 300
	maxPromptTokens = 400
	maxFindingRefs  = 12
	maxFindingJoins = 20
	maxLaunches     = 500
)

// ---- per-case index

// span is where and when one identifier appears in one case.
type span struct {
	first, last time.Time
	ev          int // index of the first event (or -1)
	session     string
	count       int
}

func (s *span) add(t time.Time) {
	s.count++
	if t.IsZero() {
		return
	}
	if s.first.IsZero() || t.Before(s.first) {
		s.first = t
	}
	if t.After(s.last) {
		s.last = t
	}
}

type launch struct {
	ev      int
	t       time.Time
	session string
	cli     string
	target  string // remote host named by the command, masked
	resume  string // session id named by the command
	how     string // the remote verb (ssh, kubectl exec …)
}

type prompt struct {
	ev     int
	tokens map[string]bool
}

type cidx struct {
	c        *GraphCase
	host     string // lower-cased
	byID     map[string]int
	sessions map[string]*span
	agents   map[string]*span
	calls    map[string]*span // tool call ids
	tasks    map[string]*span // task ids
	envs     map[string]*span // exec envs
	princ    map[string]*span
	pairs    map[string]*span // principal \x00 resource
	commits  map[string]*span
	dests    map[string]*span
	names    map[string]*span
	files    map[string]FileHash
	prompts  []prompt
	launches []launch
	sessEnv  map[string]string // session → exec env
	parentTC []int             // events carrying ParentToolCallID
	parentAg []int             // events carrying ParentAgentID
	bySess   map[string][]int  // session → event indices, in input order
	sev      map[string]string // session|agent → worst P0-class finding rule
	common   int
}

// cleanID accepts an identifier from evidence: trimmed, 1..256 bytes, no
// control characters. Anything else is not used as a join key.
func cleanID(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if s == "" || len(s) > maxIDLen {
		return "", false
	}
	for _, r := range s {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return "", false
		}
	}
	return s, true
}

func (x *cidx) put(m map[string]*span, key string, t time.Time, ev int, session string, g *gbuild) *span {
	k, ok := cleanID(key)
	if !ok {
		if key != "" {
			g.omit("unusable_identifiers", 1)
		}
		return nil
	}
	return x.putClean(m, k, t, ev, session, g)
}

// putClean records a key that is already clean (or composed of clean parts
// joined by a control-character separator, which cleanID would refuse).
func (x *cidx) putClean(m map[string]*span, k string, t time.Time, ev int, session string, g *gbuild) *span {
	s := m[k]
	if s == nil {
		if len(m) >= g.o.MaxKeys {
			g.omit("identifiers_over_bound", 1)
			return nil
		}
		s = &span{ev: ev, session: session}
		m[k] = s
	}
	s.add(t)
	return s
}

func index(c *GraphCase, g *gbuild) *cidx {
	x := &cidx{c: c, host: strings.ToLower(strings.TrimSpace(c.Host)), byID: map[string]int{},
		sessions: map[string]*span{}, agents: map[string]*span{}, calls: map[string]*span{}, tasks: map[string]*span{},
		envs: map[string]*span{}, princ: map[string]*span{}, pairs: map[string]*span{}, commits: map[string]*span{},
		dests: map[string]*span{}, names: map[string]*span{}, files: map[string]FileHash{},
		sessEnv: map[string]string{}, bySess: map[string][]int{}, sev: map[string]string{}}
	for i := range c.Events {
		e := &c.Events[i]
		if e.EventID != "" {
			if _, dup := x.byID[e.EventID]; !dup {
				x.byID[e.EventID] = i
			}
		}
		t, _ := parseTS(e.Timestamp)
		sid, _ := cleanID(e.SessionID)
		if sid != "" {
			if len(x.bySess[sid]) < 100000 {
				x.bySess[sid] = append(x.bySess[sid], i)
			}
			// An index or metadata record naming a session is not a
			// recording of it.
			if e.EventType != schema.EventSessionMeta {
				x.put(x.sessions, sid, t, i, sid, g)
			}
		}
		if e.AgentID != "" && !strings.HasPrefix(e.AgentID, "main:") {
			x.put(x.agents, e.AgentID, t, i, sid, g)
		}
		if e.ToolCallID != "" && (e.EventType == schema.EventToolCall || e.EventType == schema.EventAgentSpawn) {
			x.put(x.calls, e.ToolCallID, t, i, sid, g)
		}
		if e.TaskID != "" {
			x.put(x.tasks, e.TaskID, t, i, sid, g)
		}
		if e.ExecEnv != "" {
			if s := x.put(x.envs, e.ExecEnv, t, i, sid, g); s != nil && sid != "" {
				if _, ok := x.sessEnv[sid]; !ok {
					x.sessEnv[sid], _ = cleanID(e.ExecEnv)
				}
			}
		}
		if e.Principal != "" {
			x.put(x.princ, e.Principal, t, i, sid, g)
			if e.ResourceID != "" {
				p, ok1 := cleanID(e.Principal)
				r, ok2 := cleanID(e.ResourceID)
				if ok1 && ok2 {
					x.putClean(x.pairs, p+"\x00"+r, t, i, sid, g)
				}
			}
		}
		if e.ParentToolCallID != "" {
			x.parentTC = append(x.parentTC, i)
		}
		if e.ParentAgentID != "" && e.ParentAgentID != "UNKNOWN" {
			x.parentAg = append(x.parentAg, i)
		}
		if e.File != "" {
			if b := path.Base(strings.ReplaceAll(e.File, `\`, "/")); len(b) >= 3 && b != "." && b != "/" {
				x.put(x.names, b, t, i, sid, g)
			}
		}
		switch e.EventType {
		case schema.EventHumanPrompt:
			if len(x.prompts) < maxPrompts {
				if tok := promptTokens(e.Summary); len(tok) >= 6 {
					x.prompts = append(x.prompts, prompt{ev: i, tokens: tok})
				}
			}
		case schema.EventToolCall:
			cmd := e.FullCommand()
			x.indexCommand(i, e, cmd, t, sid, g)
		case schema.EventToolResult:
			for _, m := range commitOutRe.FindAllStringSubmatch(e.Summary, 4) {
				x.put(x.commits, strings.ToLower(m[1]), t, i, sid, g)
			}
		}
	}
	for _, f := range c.Files {
		h := strings.ToLower(strings.TrimSpace(f.SHA256))
		if len(h) != 64 || f.Size < minFileSize || !isHex(h) {
			continue
		}
		if len(x.files) >= g.o.MaxKeys {
			g.omit("identifiers_over_bound", 1)
			break
		}
		if _, ok := x.files[h]; !ok {
			x.files[h] = f
		}
	}
	for _, f := range c.Findings {
		if (f.Severity != "HIGH" && f.Severity != "CRITICAL") || catalog.IsBuildingBlock(f.RuleID) || f.Class == catalog.ClassBuildingBlock {
			continue
		}
		for _, k := range []string{"s:" + f.SessionID, "a:" + f.AgentID} {
			if len(k) > 2 && x.sev[k] == "" {
				x.sev[k] = f.RuleID
			}
		}
	}
	return x
}

func (x *cidx) indexCommand(i int, e *schema.Event, cmd string, t time.Time, sid string, g *gbuild) {
	if cmd == "" {
		return
	}
	dests := netdest.Extract(cmd)
	if e.NetworkDest != "" {
		dests = append(dests, e.NetworkDest)
	}
	for _, d := range dests {
		h := strings.ToLower(netdest.Host(d))
		if h == "" || isLoopback(h) {
			continue
		}
		if !g.o.IncludeCommon && netdest.IsAllowed(h, nil) {
			x.common++
			continue
		}
		x.put(x.dests, h, t, i, sid, g)
	}
	for _, m := range gitCmdRe.FindAllStringSubmatch(cmd, 8) {
		for _, c := range commitRe.FindAllString(m[2], 4) {
			if strings.Trim(c, "0123456789") != "" {
				x.put(x.commits, strings.ToLower(c), t, i, sid, g)
			}
		}
	}
	if l, ok := remoteLaunch(cmd); ok && len(x.launches) < maxLaunches {
		l.ev, l.t, l.session = i, t, sid
		x.launches = append(x.launches, l)
	} else if ok {
		g.omit("remote_launches", 1)
	}
}

// ---- command shapes

var (
	// gitCmdRe and commitRe follow internal/reconstruct's git hand-off
	// reading: a git verb that names or moves commits, then hex ids.
	gitCmdRe = regexp.MustCompile(`(?:^|[\s;&|(])git\s+(?:-C\s+\S+\s+)?(push|pull|fetch|checkout|switch|clone|cherry-pick|reset|merge|rebase|show|revert|commit|tag|log)\b([^;&|\n]*)`)
	commitRe = regexp.MustCompile(`\b[0-9a-fA-F]{7,40}\b`)
	// commitOutRe is git commit's own output line: "[branch 1a2b3c4] msg".
	commitOutRe = regexp.MustCompile(`\[[\w./-]+(?: \(root-commit\))? ([0-9a-f]{7,40})\]`)

	// remoteRe is a command that runs something on another machine or in
	// another execution environment.
	remoteRe = regexp.MustCompile(`(?:^|[\s;&|(])(ssh|gcloud\s+compute\s+ssh|aws\s+ssm\s+(?:send-command|start-session)|az\s+(?:vm\s+run-command\s+invoke|ssh\s+vm)|kubectl\s+exec|docker\s+exec|podman\s+exec|gcloud\s+run\s+jobs\s+execute|aws\s+ecs\s+run-task)\b`)
	// agentRe is an agent CLI named after the remote verb (often inside
	// the quoted remote command).
	agentRe = regexp.MustCompile(`(?:^|[\s;&|/("'])(claude|codex|gemini|cursor-agent|copilot|opencode|aider)(?:\s|$|["';])`)
	// resumeRe is a session id handed to the agent CLI (as in
	// internal/reconstruct).
	resumeRe = regexp.MustCompile(`(?:--resume|--session-id|-r|\bresume)(?:\s+|=)["']?([0-9A-Za-z][0-9A-Za-z_-]{7,})`)
)

// sshOptArg are ssh options that take a value.
var sshOptArg = map[string]bool{"-i": true, "-p": true, "-l": true, "-o": true, "-J": true, "-F": true, "-b": true, "-c": true,
	"-D": true, "-E": true, "-e": true, "-I": true, "-L": true, "-m": true, "-O": true, "-Q": true, "-R": true, "-S": true, "-W": true, "-w": true}

// remoteLaunch reports an agent CLI started on another machine: a remote
// verb followed, in the same command, by an agent CLI name.
func remoteLaunch(cmd string) (launch, bool) {
	if len(cmd) > schema.MaxCommandFull {
		cmd = cmd[:schema.MaxCommandFull]
	}
	loc := remoteRe.FindStringSubmatchIndex(cmd)
	if loc == nil {
		return launch{}, false
	}
	rest := cmd[loc[1]:]
	m := agentRe.FindStringSubmatch(rest)
	if m == nil {
		return launch{}, false
	}
	l := launch{cli: m[1], how: strings.Join(strings.Fields(cmd[loc[2]:loc[3]]), " ")}
	if r := resumeRe.FindStringSubmatch(rest); r != nil {
		l.resume = r[1]
	}
	if l.how == "ssh" {
		skip := false
		for _, w := range strings.Fields(rest) {
			switch {
			case skip:
				skip = false
			case sshOptArg[w]:
				skip = true
			case strings.HasPrefix(w, "-"):
			default:
				h := w
				if j := strings.LastIndexByte(h, '@'); j >= 0 {
					h = h[j+1:]
				}
				l.target = detect.MaskSecrets(strings.Trim(h, `"'`))
			}
			if l.target != "" {
				break
			}
		}
	}
	return l, true
}

// consequential reports a recorded action with an effect: a shell
// command, a file write or edit, an MCP call, a spawned agent, or a cloud
// action on a named resource. A denied action had none.
func consequential(e *schema.Event) bool {
	if e.EventType != schema.EventToolCall && e.EventType != schema.EventAgentSpawn {
		return false
	}
	if e.ResultStatus == "denied" || e.ApprovalState == "denied" {
		return false
	}
	switch e.Action {
	case "shell_execution", "shell", "write_file", "edit_file", "apply_patch", "mcp_call", "spawn_subagent":
		return true
	}
	return e.EventType == schema.EventAgentSpawn || e.ResourceID != "" || e.Command != ""
}

func promptTokens(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ToLower(s), func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) }) {
		if len(w) >= 3 && len(out) < maxPromptTokens {
			out[w] = true
		}
	}
	return out
}

func jaccard(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	n := 0
	for k := range a {
		if b[k] {
			n++
		}
	}
	return float64(n) / float64(len(a)+len(b)-n)
}

func isHex(s string) bool {
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// ---- builder

type gbuild struct {
	o       GraphOptions
	cases   []*cidx
	byLabel map[string]*cidx
	nodes   map[string]*Node
	edges   []Edge
	ekeys   map[string]bool
	perJoin map[string]int
	omitted map[string]int
	notes   []string
}

func (g *gbuild) omit(k string, n int) {
	if g.omitted == nil {
		g.omitted = map[string]int{}
	}
	g.omitted[k] += n
}

// BuildGraph computes the graph from in-memory cases. Cases are taken in
// order; their labels must be unique.
func BuildGraph(cases []GraphCase, o GraphOptions) *Graph {
	o.defaults()
	g := &gbuild{o: o, byLabel: map[string]*cidx{}, nodes: map[string]*Node{}, ekeys: map[string]bool{}, perJoin: map[string]int{}}
	out := &Graph{Schema: GraphSchema, Cases: []GraphCaseRef{}, Nodes: []Node{}, Edges: []Edge{}, Findings: []CrossFinding{}, Notes: []string{},
		Options: GraphLimits{MaxNodes: o.MaxNodes, MaxEdges: o.MaxEdges, MaxPerJoin: o.MaxPerJoin, WindowSeconds: int(o.Window / time.Second), SkewSeconds: int(o.Skew / time.Second)}}
	for i := range cases {
		c := &cases[i]
		if _, dup := g.byLabel[c.Label]; dup {
			g.notes = append(g.notes, "duplicate case label "+c.Label+" ignored")
			continue
		}
		x := index(c, g)
		g.cases = append(g.cases, x)
		g.byLabel[c.Label] = x
		out.Cases = append(out.Cases, GraphCaseRef{Label: c.Label, CaseID: c.CaseID, Host: c.Host, Unverified: c.Unverified})
		if c.Unverified {
			out.Unverified = true
		}
		if x.common > 0 {
			g.notes = append(g.notes, fmt.Sprintf("%s: %d reference(s) to allowlisted destinations not joined (use --include-common)", c.Label, x.common))
		}
	}
	for i := 0; i < len(g.cases); i++ {
		for j := i + 1; j < len(g.cases); j++ {
			g.pair(g.cases[i], g.cases[j])
		}
	}
	for _, a := range g.cases {
		for _, b := range g.cases {
			if a != b {
				g.delegations(a, b)
			}
		}
	}
	findings := g.propagation()
	findings = append(findings, g.crossHost()...)
	g.finish(out, findings)
	return out
}

// ---- nodes

func nodeID(kind, label, key string) string { return kind + ":" + label + ":" + key }

func (g *gbuild) node(kind string, x *cidx, key, label string, s *span) string {
	key = detect.MaskSecrets(key)
	id := nodeID(kind, x.c.Label, key)
	n := g.nodes[id]
	if n == nil {
		n = &Node{ID: id, Kind: kind, Case: x.c.Label, Label: detect.MaskSecrets(label), Unverified: x.c.Unverified}
		g.nodes[id] = n
	}
	if s != nil {
		if !s.first.IsZero() && (n.FirstSeen == "" || rfc(s.first) < n.FirstSeen) {
			n.FirstSeen = rfc(s.first)
		}
		if !s.last.IsZero() && rfc(s.last) > n.LastSeen {
			n.LastSeen = rfc(s.last)
		}
	}
	return id
}

func (g *gbuild) attr(id, k, v string) {
	if n := g.nodes[id]; n != nil && v != "" {
		if n.Attributes == nil {
			n.Attributes = map[string]string{}
		}
		n.Attributes[k] = detect.MaskSecrets(v)
	}
}

// place returns the node an agent session runs in: its execution
// environment when the evidence names one, else the case's host; both
// hang off the case node by context edges.
func (g *gbuild) place(x *cidx, sid string) string {
	cid := g.node(NodeCase, x, x.c.Label, x.c.Label+" ("+x.c.CaseID+")", nil)
	g.attr(cid, "path", x.c.Path)
	hostKey := x.host
	if hostKey == "" {
		hostKey = "unknown"
	}
	hid := g.node(NodeHost, x, hostKey, "host "+orUnknownStr(x.c.Host), nil)
	g.attr(hid, "note", "a host name is not a unique machine identifier")
	g.context("collected_from", cid, hid, x, -1, "the case manifest names this host")
	if env := x.sessEnv[sid]; env != "" {
		eid := g.node(NodeExecEnv, x, env, "execution environment "+env, x.envs[env])
		g.context("hosts", hid, eid, x, x.envs[env].ev, "the event records this execution environment")
		return eid
	}
	return hid
}

func (g *gbuild) sessionNode(x *cidx, sid string) string {
	s := x.sessions[sid]
	if s == nil {
		s = &span{ev: -1}
		if idx := x.bySess[sid]; len(idx) > 0 {
			s.ev = idx[0]
		}
	}
	id := g.node(NodeSession, x, sid, "session "+sid, s)
	if s.ev >= 0 {
		g.attr(id, "product", x.c.Events[s.ev].Product)
	}
	g.context("ran", g.place(x, sid), id, x, s.ev, "the session's events are recorded in this case")
	return id
}

// sessionOrPlace is the session node, or the host / environment node
// when the record carries no session id.
func (g *gbuild) sessionOrPlace(x *cidx, sid string) string {
	if sid == "" {
		return g.place(x, "")
	}
	return g.sessionNode(x, sid)
}

func (g *gbuild) agentNode(x *cidx, aid string) string {
	s := x.agents[aid]
	id := g.node(NodeAgent, x, aid, "agent "+aid, s)
	if s != nil {
		g.context("contains", g.sessionOrPlace(x, s.session), id, x, s.ev, "the agent's events carry this session id")
	}
	return id
}

// entityNode places a non-agent entity under the session it was first
// recorded in (or directly under its case).
func (g *gbuild) entityNode(kind string, x *cidx, key, label string, s *span, rel string) string {
	id := g.node(kind, x, key, label, s)
	if s != nil && s.session != "" {
		g.context(rel, g.sessionNode(x, s.session), id, x, s.ev, "recorded on an event of this session")
	} else {
		cid := g.node(NodeCase, x, x.c.Label, x.c.Label+" ("+x.c.CaseID+")", nil)
		g.context(rel, cid, id, x, -1, "collected in this case")
	}
	return id
}

// ---- edges

func (g *gbuild) ref(x *cidx, ev int) SideRef {
	if ev < 0 || ev >= len(x.c.Events) {
		return SideRef{Case: x.c.Label}
	}
	e := &x.c.Events[ev]
	return SideRef{Case: x.c.Label, Ref: lineage.Ref{ArtifactID: e.SourceArtifact, Path: detect.MaskSecrets(e.SourcePath), Line: e.SourceLine, Offset: e.SourceOffset, EventID: e.EventID},
		JSONPath: e.SourceJSONPath}
}

func (g *gbuild) context(kind, from, to string, x *cidx, ev int, reason string) {
	k := kind + "\x00" + from + "\x00" + to
	if g.ekeys[k] {
		return
	}
	g.ekeys[k] = true
	ref := g.ref(x, ev)
	if ev < 0 {
		ref = SideRef{Case: x.c.Label, Ref: lineage.Ref{Path: "case.json / MANIFEST"}}
	}
	g.edges = append(g.edges, Edge{Kind: kind, From: from, To: to, Confidence: Strong, Reason: reason,
		Time: TimeRelation{Relation: RelUnknown}, Evidence: []SideRef{ref}, Unverified: x.c.Unverified})
}

// join adds a cross-case edge. a and b are the two sides, already ordered
// from → to by the caller.
func (g *gbuild) join(kind, joinKey, value string, a *cidx, from string, sa *span, evA int, b *cidx, to string, sb *span, evB int, conf, reason string) *Edge {
	pk := joinKey + "\x00" + a.c.Label + "\x00" + b.c.Label
	if a.c.Label > b.c.Label {
		pk = joinKey + "\x00" + b.c.Label + "\x00" + a.c.Label
	}
	k := kind + "\x00" + from + "\x00" + to + "\x00" + joinKey + "\x00" + value
	if g.ekeys[k] {
		return nil
	}
	if g.perJoin[pk] >= g.o.MaxPerJoin {
		g.omit("edges_"+joinKey, 1)
		return nil
	}
	g.perJoin[pk]++
	g.ekeys[k] = true
	e := Edge{Kind: kind, From: from, To: to, JoinKey: joinKey, JoinValue: detect.MaskSecrets(value), Confidence: conf, Reason: reason,
		Time: relate(sa, sb), Evidence: []SideRef{g.ref(a, evA), g.ref(b, evB)}, Unverified: a.c.Unverified || b.c.Unverified}
	if e.Unverified {
		e.Reason += "; includes a case whose seal did not verify"
	}
	g.edges = append(g.edges, e)
	return &g.edges[len(g.edges)-1]
}

func relate(a, b *span) TimeRelation {
	r := TimeRelation{Relation: RelUnknown}
	if a == nil || b == nil {
		return r
	}
	if !a.first.IsZero() {
		r.FromTime = rfc(a.first)
	}
	if !b.first.IsZero() {
		r.ToTime = rfc(b.first)
	}
	if a.first.IsZero() || b.first.IsZero() {
		return r
	}
	switch {
	case a.last.Before(b.first):
		r.Relation = RelBefore
	case b.last.Before(a.first):
		r.Relation = RelAfter
	default:
		r.Relation = RelOverlap
	}
	return r
}

// order puts the side that was active first on the left: unknown times
// sort after known ones, ties by case label.
func order(a *cidx, sa *span, b *cidx, sb *span) (*cidx, *span, *cidx, *span) {
	ta, tb := time.Time{}, time.Time{}
	if sa != nil {
		ta = sa.first
	}
	if sb != nil {
		tb = sb.first
	}
	switch {
	case !ta.IsZero() && !tb.IsZero() && !ta.Equal(tb):
		if tb.Before(ta) {
			return b, sb, a, sa
		}
	case ta.IsZero() != tb.IsZero():
		if ta.IsZero() {
			return b, sb, a, sa
		}
	}
	return a, sa, b, sb
}

func spanEv(s *span) int {
	if s == nil {
		return -1
	}
	return s.ev
}

// pair computes the symmetric joins between two cases.
func (g *gbuild) pair(a, b *cidx) {
	samePlace := a.host != "" && a.host == b.host
	for _, sid := range sortedKeys(a.sessions) {
		sb := b.sessions[sid]
		if sb == nil || len(sid) < minSessionIDLen {
			continue
		}
		sa := a.sessions[sid]
		x, xs, y, ys := order(a, sa, b, sb)
		// A remote launch that names this session gives the join a
		// direction: launched in x, continued in y.
		conf, reason := Strong, fmt.Sprintf("the same session id is recorded in %s and %s", x.c.Label, y.c.Label)
		if l, lc := g.namedLaunch(sid, a, b); l != nil {
			far := b
			if lc == b {
				far = a
			}
			if lc != x {
				x, xs, y, ys = y, ys, x, xs
			}
			fs := far.sessions[sid]
			if !l.t.IsZero() && !fs.last.IsZero() && fs.last.Before(l.t.Add(-g.o.Skew)) {
				conf = Moderate
				reason = fmt.Sprintf("timestamps contradict the hand-off: %s names this session in a remote launch at %s, but every record of it in %s ends by %s",
					lc.c.Label, rfc(l.t), far.c.Label, rfc(fs.last))
			}
		}
		e := g.join("same_session", JoinSessionID, sid, x, g.sessionNode(x, sid), xs, spanEv(xs), y, g.sessionNode(y, sid), ys, spanEv(ys), conf, reason)
		if e != nil && conf == Strong && e.Time.Relation == RelOverlap {
			e.Confidence = Moderate
			e.Reason += "; the two recordings overlap in time, so they may be copies of the same evidence (a synced or copied home directory) rather than a continuation"
		}
		if e != nil && samePlace {
			e.Reason += "; both cases name the same host, so they may be two collections of one machine"
		}
	}
	for _, aid := range sortedKeys(a.agents) {
		sb := b.agents[aid]
		if sb == nil || len(aid) < minSessionIDLen {
			continue
		}
		x, xs, y, ys := order(a, a.agents[aid], b, sb)
		e := g.join("same_agent", JoinAgentID, aid, x, g.agentNode(x, aid), xs, spanEv(xs), y, g.agentNode(y, aid), ys, spanEv(ys), Strong,
			fmt.Sprintf("the same agent id is recorded in %s and %s", x.c.Label, y.c.Label))
		if e != nil && e.Time.Relation == RelOverlap {
			e.Confidence = Moderate
			e.Reason += "; the two recordings overlap in time, so they may be copies of the same evidence"
		}
	}
	for _, id := range sortedKeys(a.calls) {
		sb := b.calls[id]
		if sb == nil || len(id) < minToolCallLen || isDigits(id) {
			continue
		}
		x, xs, y, ys := order(a, a.calls[id], b, sb)
		e := g.join("same_tool_call", JoinToolCallID, id, x, g.sessionOrPlace(x, xs.session), xs, xs.ev, y, g.sessionOrPlace(y, ys.session), ys, ys.ev, Strong,
			fmt.Sprintf("the same tool call id is recorded in %s and %s", x.c.Label, y.c.Label))
		if e != nil {
			g.mcpContext(x, xs)
			g.mcpContext(y, ys)
		}
	}
	for _, c := range sortedKeys(a.commits) {
		sb := b.commits[c]
		var cb string
		if sb != nil {
			cb = c
		} else {
			// an abbreviated id in one case and the full id in the other
			for _, d := range sortedKeys(b.commits) {
				if len(c) >= 7 && len(d) >= 7 && c != d && (strings.HasPrefix(c, d) || strings.HasPrefix(d, c)) {
					sb, cb = b.commits[d], d
					break
				}
			}
		}
		if sb == nil {
			continue
		}
		sa := a.commits[c]
		x, xs, y, ys := order(a, sa, b, sb)
		xk, yk := c, cb
		if x != a {
			xk, yk = cb, c
		}
		key, conf := JoinCommit, Strong
		reason := fmt.Sprintf("commit %s is named in %s and %s", short(c), x.c.Label, y.c.Label)
		if len(c) < minCommitLen || len(cb) < minCommitLen {
			key, conf = JoinCommitAbbrev, Weak
			reason = "an abbreviated commit id (fewer than 12 hex digits) can collide across repositories"
		}
		g.join("same_commit", key, c, x, g.entityNode(NodeCommit, x, xk, "commit "+xk, xs, "named_commit"), xs, xs.ev,
			y, g.entityNode(NodeCommit, y, yk, "commit "+yk, ys, "named_commit"), ys, ys.ev, conf, reason)
	}
	for _, h := range sortedKeys(a.files) {
		fb, ok := b.files[h]
		if !ok {
			continue
		}
		fa := a.files[h]
		na := g.entityNode(NodeFile, a, "sha256:"+h, path.Base(fa.Path)+" (sha256:"+short(h)+")", nil, "collected")
		g.attr(na, "path", fa.Path)
		nb := g.entityNode(NodeFile, b, "sha256:"+h, path.Base(fb.Path)+" (sha256:"+short(h)+")", nil, "collected")
		g.attr(nb, "path", fb.Path)
		e := g.join("same_content", JoinFileHash, "sha256:"+h, a, na, nil, -1, b, nb, nil, -1, Strong,
			fmt.Sprintf("a collected file in %s and one in %s have the same SHA-256", a.c.Label, b.c.Label))
		if e != nil {
			e.Evidence[0].Path, e.Evidence[0].ArtifactID = detect.MaskSecrets(fa.Path), h
			e.Evidence[1].Path, e.Evidence[1].ArtifactID = detect.MaskSecrets(fb.Path), h
		}
	}
	paired := map[string]bool{}
	for _, k := range sortedKeys(a.pairs) {
		sb := b.pairs[k]
		if sb == nil {
			continue
		}
		p, r, _ := strings.Cut(k, "\x00")
		paired[p] = true
		x, xs, y, ys := order(a, a.pairs[k], b, sb)
		g.join("same_principal_resource", JoinPrincipalResource, p+" → "+r,
			x, g.resourceNode(x, p, r, xs), xs, xs.ev, y, g.resourceNode(y, p, r, ys), ys, ys.ev, Strong,
			fmt.Sprintf("the same cloud principal acted on the same resource id in %s and %s", x.c.Label, y.c.Label))
	}
	for _, p := range sortedKeys(a.princ) {
		sb := b.princ[p]
		if sb == nil || paired[p] {
			continue
		}
		x, xs, y, ys := order(a, a.princ[p], b, sb)
		g.join("same_principal", JoinPrincipal, p, x, g.entityNode(NodePrincipal, x, p, "principal "+p, xs, "acted_as"), xs, xs.ev,
			y, g.entityNode(NodePrincipal, y, p, "principal "+p, ys, "acted_as"), ys, ys.ev, Moderate,
			"the same cloud principal, but no common resource: a principal is shared by every workload that assumes it")
	}
	for _, env := range sortedKeys(a.envs) {
		sb := b.envs[env]
		if sb == nil {
			continue
		}
		x, xs, y, ys := order(a, a.envs[env], b, sb)
		g.join("same_exec_env", JoinExecEnv, env, x, g.envNode(x, env), xs, xs.ev, y, g.envNode(y, env), ys, ys.ev, Moderate,
			"the same execution environment identifier; environment names (container, VM) can be reused")
	}
	// Weak joins: reported, never sufficient alone.
	for _, d := range sortedKeys(a.dests) {
		sb := b.dests[d]
		if sb == nil {
			continue
		}
		x, xs, y, ys := order(a, a.dests[d], b, sb)
		g.join("same_destination", JoinDestination, d, x, g.entityNode(NodeDestination, x, d, d, xs, "named_destination"), xs, xs.ev,
			y, g.entityNode(NodeDestination, y, d, d, ys, "named_destination"), ys, ys.ev, Weak,
			"the same destination or address is named in both cases; many unrelated hosts reach the same destinations")
	}
	for _, n := range sortedKeys(a.names) {
		sb := b.names[n]
		if sb == nil {
			continue
		}
		x, xs, y, ys := order(a, a.names[n], b, sb)
		g.join("same_filename", JoinFilename, n, x, g.entityNode(NodeFile, x, "name:"+n, n, xs, "named_file"), xs, xs.ev,
			y, g.entityNode(NodeFile, y, "name:"+n, n, ys, "named_file"), ys, ys.ev, Weak,
			"the same file name, not the same content: names repeat across machines")
	}
	g.prompts(a, b)
}

func (g *gbuild) resourceNode(x *cidx, p, r string, s *span) string {
	pid := g.entityNode(NodePrincipal, x, p, "principal "+p, s, "acted_as")
	id := g.node(NodeResource, x, r, "resource "+r, s)
	g.context("acted_on", pid, id, x, s.ev, "the event records this principal acting on this resource")
	return id
}

func (g *gbuild) envNode(x *cidx, env string) string {
	s := x.envs[env]
	hostKey := x.host
	if hostKey == "" {
		hostKey = "unknown"
	}
	hid := g.node(NodeHost, x, hostKey, "host "+orUnknownStr(x.c.Host), nil)
	id := g.node(NodeExecEnv, x, env, "execution environment "+env, s)
	g.context("hosts", hid, id, x, s.ev, "the event records this execution environment")
	return id
}

func (g *gbuild) mcpContext(x *cidx, s *span) {
	if s == nil || s.ev < 0 {
		return
	}
	e := &x.c.Events[s.ev]
	if e.MCPServer == "" && e.MCPTool == "" {
		return
	}
	key := e.MCPServer + "/" + e.MCPTool
	if _, ok := cleanID(key); !ok {
		return
	}
	id := g.node(NodeMCPTool, x, key, "MCP "+key, s)
	if e.MCPServerVersion != "" {
		g.attr(id, "server_version", e.MCPServerVersion)
	}
	g.context("called", g.sessionOrPlace(x, s.session), id, x, s.ev, "the tool call names this MCP server and tool")
}

func (g *gbuild) prompts(a, b *cidx) {
	n := 0
	for _, pa := range a.prompts {
		for _, pb := range b.prompts {
			j := jaccard(pa.tokens, pb.tokens)
			if j < 0.8 {
				continue
			}
			if n++; n > 50 {
				g.omit("edges_"+JoinPrompt, 1)
				continue
			}
			ea, eb := &a.c.Events[pa.ev], &b.c.Events[pb.ev]
			sa, sb := a.sessions[ea.SessionID], b.sessions[eb.SessionID]
			if sa == nil || sb == nil {
				continue
			}
			ta, _ := parseTS(ea.Timestamp)
			tb, _ := parseTS(eb.Timestamp)
			s1, s2 := &span{first: ta, last: ta}, &span{first: tb, last: tb}
			x, xs, y, ys := order(a, s1, b, s2)
			xe, ye := pa.ev, pb.ev
			if x != a {
				xe, ye = pb.ev, pa.ev
			}
			g.join("similar_prompt", JoinPrompt, fmt.Sprintf("jaccard %.2f", j), x, g.sessionNode(x, x.c.Events[xe].SessionID), xs, xe,
				y, g.sessionNode(y, y.c.Events[ye].SessionID), ys, ye, Weak,
				"similar prompt wording (word overlap); people reuse prompts, so this never ties two sessions together. The text is not copied here")
		}
	}
}

// namedLaunch finds a remote launch in a or b naming session sid.
func (g *gbuild) namedLaunch(sid string, a, b *cidx) (*launch, *cidx) {
	for _, x := range []*cidx{a, b} {
		for i := range x.launches {
			if x.launches[i].resume == sid {
				return &x.launches[i], x
			}
		}
	}
	return nil, nil
}

// delegations joins a child recorded in b to the parent tool call, task
// or agent recorded in a.
func (g *gbuild) delegations(a, b *cidx) {
	for _, i := range b.parentTC {
		e := &b.c.Events[i]
		ref, ok := cleanID(e.ParentToolCallID)
		if !ok || len(ref) < minSessionIDLen || b.calls[ref] != nil || b.tasks[ref] != nil {
			continue // the parent call is recorded in b itself
		}
		pa := a.calls[ref]
		what := "tool call"
		if pa == nil {
			pa, what = a.tasks[ref], "task"
		}
		if pa == nil {
			continue
		}
		g.delegationEdge(a, pa, b, i, ref, "parent tool call id names a "+what+" recorded in "+a.c.Label)
	}
	for _, i := range b.parentAg {
		e := &b.c.Events[i]
		ref, ok := cleanID(e.ParentAgentID)
		if !ok || len(ref) < minSessionIDLen || strings.HasPrefix(ref, "main:") && b.sessions[strings.TrimPrefix(ref, "main:")] != nil {
			continue
		}
		if b.agents[ref] != nil {
			continue // the parent is recorded in b itself
		}
		pa := a.agents[ref]
		what := "agent"
		if pa == nil {
			pa, what = a.tasks[ref], "task"
		}
		if pa == nil {
			if s := a.sessions[strings.TrimPrefix(ref, "main:")]; s != nil && strings.HasPrefix(ref, "main:") {
				pa, what = s, "main agent"
			}
		}
		if pa == nil {
			continue
		}
		g.delegationEdge(a, pa, b, i, ref, "parent agent id names a "+what+" recorded in "+a.c.Label)
	}
}

func (g *gbuild) delegationEdge(a *cidx, pa *span, b *cidx, i int, ref, why string) {
	e := &b.c.Events[i]
	sid, _ := cleanID(e.SessionID)
	sb := b.sessions[sid]
	if sb == nil {
		t, _ := parseTS(e.Timestamp)
		sb = &span{first: t, last: t, ev: i, session: sid}
	}
	conf, reason := Strong, "delegation: the "+why
	if !pa.first.IsZero() && !sb.last.IsZero() && sb.last.Before(pa.first.Add(-g.o.Skew)) {
		conf = Moderate
		reason += fmt.Sprintf("; timestamps contradict it: every record of the child in %s ends by %s, before the parent was recorded at %s",
			b.c.Label, rfc(sb.last), rfc(pa.first))
	}
	from, to := g.sessionOrPlace(a, pa.session), g.sessionOrPlace(b, sid)
	g.join("delegated_to", JoinDelegation, ref, a, from, pa, pa.ev, b, to, sb, i, conf, reason)
}

// ---- findings

type stepRef struct {
	x  *cidx
	ev int
}

// propagation finds CHAIN_CROSS_HOST_AGENT_PROPAGATION: a remote agent
// launch (or a delegation reference) in one case, the linked session
// active in another inside the window, then a consequential action there.
func (g *gbuild) propagation() []CrossFinding {
	var out []CrossFinding
	seen := map[string]bool{}
	for _, a := range g.cases {
		for li := range a.launches {
			l := &a.launches[li]
			linked := false
			for _, b := range g.cases {
				if b == a {
					continue
				}
				// Sessions tied to the launch by an identifier: the session id
				// named in the command, or a child naming the launch's tool
				// call as its parent.
				ties := map[string]string{}
				if l.resume != "" && b.sessions[l.resume] != nil {
					ties[l.resume] = JoinSessionInCommand
				}
				lev := &a.c.Events[l.ev]
				if tc, ok := cleanID(lev.ToolCallID); ok && len(tc) >= minSessionIDLen {
					for _, i := range b.parentTC {
						if strings.TrimSpace(b.c.Events[i].ParentToolCallID) == tc {
							if s, _ := cleanID(b.c.Events[i].SessionID); s != "" && ties[s] == "" {
								ties[s] = JoinDelegation
							}
						}
					}
				}
				for _, sid := range sortedKeys(ties) {
					linked = true
					sb := b.sessions[sid]
					if sb == nil {
						continue
					}
					ls := &span{first: l.t, last: l.t}
					conf, reason := Strong, fmt.Sprintf("%s in %s launches %s on another machine naming session %s", l.how, a.c.Label, l.cli, sid)
					if ties[sid] == JoinDelegation {
						reason = fmt.Sprintf("%s in %s launches %s on another machine; a record in %s names that tool call as its parent", l.how, a.c.Label, l.cli, b.c.Label)
					}
					arrive, act := g.window(b, sid, l.t)
					if !l.t.IsZero() && !sb.last.IsZero() && sb.last.Before(l.t.Add(-g.o.Skew)) {
						conf = Moderate
						reason += fmt.Sprintf("; timestamps contradict it: every record of the session in %s ends by %s, before the launch at %s", b.c.Label, rfc(sb.last), rfc(l.t))
					} else if arrive < 0 && !l.t.IsZero() {
						reason += "; no record of the session falls inside the propagation window"
					}
					e := g.join("launched", ties[sid], sid, a, g.sessionOrPlace(a, l.session), ls, l.ev, b, g.sessionNode(b, sid), sb, spanEv(sb), conf, reason)
					if e != nil && l.target != "" {
						e.Reason += "; the command targets " + l.target
						if b.host != "" && !strings.EqualFold(firstLabel(l.target), firstLabel(b.host)) {
							e.Reason += " (" + b.c.Label + " names host " + b.c.Host + ")"
						}
					}
					if e == nil || conf != Strong || l.t.IsZero() || arrive < 0 || act < 0 || g.samePlace(a, l.session, b, sid) {
						continue
					}
					k := fmt.Sprintf("%s|%d|%s|%s", a.c.Label, l.ev, b.c.Label, sid)
					if seen[k] {
						continue
					}
					seen[k] = true
					out = append(out, g.propFinding(a, b, sid, stepRef{a, l.ev}, stepRef{b, arrive}, stepRef{b, act},
						fmt.Sprintf("remote agent launch (%s … %s)", l.how, l.cli), e))
				}
			}
			if !linked && !l.t.IsZero() {
				g.launchTiming(a, l)
			}
		}
	}
	// Delegation references with no remote command in the evidence.
	for _, e := range g.edges {
		if e.Kind != "delegated_to" || e.Confidence != Strong {
			continue
		}
		a, b := g.byLabel[e.Evidence[0].Case], g.byLabel[e.Evidence[1].Case]
		pi, ok1 := a.byID[e.Evidence[0].EventID]
		ci, ok2 := b.byID[e.Evidence[1].EventID]
		if !ok1 || !ok2 {
			continue
		}
		pev, cev := &a.c.Events[pi], &b.c.Events[ci]
		t, ok := parseTS(pev.Timestamp)
		sid, _ := cleanID(cev.SessionID)
		if !ok || sid == "" || g.samePlace(a, pev.SessionID, b, sid) {
			continue
		}
		k := fmt.Sprintf("%s|%d|%s|%s", a.c.Label, pi, b.c.Label, sid)
		if seen[k] {
			continue
		}
		arrive, act := g.window(b, sid, t)
		if arrive < 0 || act < 0 {
			continue
		}
		seen[k] = true
		ec := e
		out = append(out, g.propFinding(a, b, sid, stepRef{a, pi}, stepRef{b, arrive}, stepRef{b, act}, "delegation recorded in "+a.c.Label, &ec))
	}
	return out
}

// launchTiming adds a weak edge from a remote agent launch that no
// identifier ties to a session, to the first session that starts in
// another case shortly after it. Order in time only.
func (g *gbuild) launchTiming(a *cidx, l *launch) {
	for _, b := range g.cases {
		if b == a {
			continue
		}
		var best string
		var bt time.Time
		for _, sid := range sortedKeys(b.sessions) {
			s := b.sessions[sid]
			if s.first.IsZero() || s.first.Before(l.t.Add(-g.o.Skew)) || s.first.Sub(l.t) > g.o.Window {
				continue
			}
			if best == "" || s.first.Before(bt) {
				best, bt = sid, s.first
			}
		}
		if best == "" {
			continue
		}
		g.join("launched", JoinLaunchTiming, best, a, g.sessionOrPlace(a, l.session), &span{first: l.t, last: l.t}, l.ev,
			b, g.sessionNode(b, best), b.sessions[best], b.sessions[best].ev, Weak,
			fmt.Sprintf("%s in %s launches %s on another machine and this session starts %s later; no identifier ties them (order in time only)",
				l.how, a.c.Label, l.cli, bt.Sub(l.t).Round(time.Second)))
	}
}

// window returns the first record of session sid in x inside
// [t-skew, t+window] and the first consequential action from then until
// the window closes (-1 when missing).
func (g *gbuild) window(x *cidx, sid string, t time.Time) (int, int) {
	if t.IsZero() {
		return -1, -1
	}
	lo, hi := t.Add(-g.o.Skew), t.Add(g.o.Window)
	idx := append([]int(nil), x.bySess[sid]...)
	sort.SliceStable(idx, func(i, j int) bool {
		ti, _ := parseTS(x.c.Events[idx[i]].Timestamp)
		tj, _ := parseTS(x.c.Events[idx[j]].Timestamp)
		return ti.Before(tj)
	})
	arrive, act := -1, -1
	for _, i := range idx {
		e := &x.c.Events[i]
		et, ok := parseTS(e.Timestamp)
		if !ok || et.Before(lo) || et.After(hi) {
			continue
		}
		if arrive < 0 {
			arrive = i
		}
		if consequential(e) {
			act = i
			break
		}
	}
	return arrive, act
}

func (g *gbuild) samePlace(a *cidx, sa string, b *cidx, sb string) bool {
	pa, pb := placeKey(a, sa), placeKey(b, sb)
	return pa != "" && pa == pb
}

// placeKey is the machine an agent session ran on, as far as the
// evidence says: its execution environment, else its case's host name.
// Two cases with the same host name and no environment are treated as one
// place: they may be two collections of the same machine.
func placeKey(x *cidx, sid string) string {
	if env := x.sessEnv[sid]; env != "" {
		return "env:" + strings.ToLower(env)
	}
	if x.host != "" {
		return "host:" + x.host
	}
	return ""
}

func (g *gbuild) propFinding(a, b *cidx, sid string, launchS, arrive, act stepRef, how string, e *Edge) CrossFinding {
	steps := []stepRef{launchS, arrive, act}
	names := []string{how, "linked session active in " + b.c.Label, "consequential action in " + b.c.Label}
	f := CrossFinding{Cases: []string{a.c.Label, b.c.Label}}
	f.RuleID, f.Severity = RuleCrossHostPropagation, "HIGH"
	f.Title = "Agent Launched or Delegated on Another Host, Then Acted There"
	f.MitreATLAS, f.MitreATTACK = "AML.T0112.000", "T1021"
	f.Description = fmt.Sprintf("In %s an agent was launched or delegated to another machine; session %s, tied to that launch by an identifier, is recorded in %s (host %s) within %s and went on to take a consequential action there.",
		a.c.Label, detect.MaskSecrets(sid), b.c.Label, orUnknownStr(b.c.Host), g.o.Window)
	f.FalsePositive = "Operators and CI legitimately run agents on remote machines (ssh into a dev box, a container exec). Sequence is not causation: the action followed the launch in the linked session, which does not prove the launch's operator intended it."
	f.SessionID = sid
	f.Endpoint = "UNKNOWN"
	var states []string
	for i, s := range steps {
		ev := &s.x.c.Events[s.ev]
		r := g.ref(s.x, s.ev)
		f.ChainSteps = append(f.ChainSteps, schema.ChainStep{Step: names[i], EventID: ev.EventID, Timestamp: ev.Timestamp, AgentID: ev.AgentID, Evidence: r.String()})
		f.EvidenceRefs = append(f.EvidenceRefs, r.String())
		states = append(states, ev.Corroboration)
	}
	f.Timestamp = a.c.Events[launchS.ev].Timestamp
	f.Status = aggregate(states)
	if e != nil {
		f.Joins = append(f.Joins, joinRef(*e))
	}
	f.Unverified = a.c.Unverified || b.c.Unverified
	f.Confidence, f.Reasons = "HIGH", []string{"the launch and the remote session are tied by an identifier, not by time alone"}
	if f.Unverified {
		f.Confidence = "LOW"
		f.Reasons = append(f.Reasons, "includes a case whose seal did not verify")
	}
	f.Limits = []string{
		"The join is the identifier the evidence records (a session id in the command, or a parent tool call id); it does not say who operated either machine.",
		"Sequence is not causation: the consequential action is the first one recorded in the linked session inside the window.",
		fmt.Sprintf("Clocks are compared as recorded, with %s tolerance; host clock skew beyond that can move records out of the window.", g.o.Skew),
		"Steps not recorded on either machine (missing telemetry, uncollected transcripts) cannot be seen; their absence is not evidence they did not happen.",
	}
	return f
}

// crossHost finds AGENT_CROSS_HOST_ACTIVITY: groups of agent sessions and
// agents tied by strong joins that span two or more places.
func (g *gbuild) crossHost() []CrossFinding {
	parent := map[string]string{}
	var find func(string) string
	find = func(s string) string {
		for parent[s] != s {
			parent[s] = parent[parent[s]]
			s = parent[s]
		}
		return s
	}
	union := func(a, b string) {
		for _, n := range []string{a, b} {
			if _, ok := parent[n]; !ok {
				parent[n] = n
			}
		}
		ra, rb := find(a), find(b)
		if ra != rb {
			if rb < ra {
				ra, rb = rb, ra
			}
			parent[rb] = ra
		}
	}
	var joins []int
	for i, e := range g.edges {
		if e.JoinKey == "" || !agentJoins[e.JoinKey] || e.Confidence != Strong {
			continue
		}
		union(e.From, e.To)
		joins = append(joins, i)
	}
	groups := map[string][]int{}
	for _, i := range joins {
		r := find(g.edges[i].From)
		groups[r] = append(groups[r], i)
	}
	var out []CrossFinding
	for _, r := range sortedKeys(groups) {
		idx := groups[r]
		places := map[string]bool{}
		cases := map[string]bool{}
		members := map[string]bool{}
		for _, i := range idx {
			e := g.edges[i]
			for _, id := range []string{e.From, e.To} {
				members[id] = true
			}
		}
		var first string
		var firstT string
		for _, id := range sortedKeys(members) {
			n := g.nodes[id]
			if n == nil {
				continue
			}
			x := g.byLabel[n.Case]
			cases[n.Case] = true
			sid := g.sessionOf(n, x)
			if p := placeKey(x, sid); p != "" {
				places[p] = true
			} else {
				places["case:"+n.Case] = true
			}
			if n.FirstSeen != "" && (firstT == "" || n.FirstSeen < firstT || n.FirstSeen == firstT && n.Case < first) {
				first, firstT = n.Case, n.FirstSeen
			}
		}
		if len(places) < 2 || len(cases) < 2 {
			continue
		}
		if first == "" {
			first = sortedKeys(cases)[0]
		}
		f := CrossFinding{Cases: sortedKeys(cases)}
		f.RuleID, f.Severity = RuleCrossHostActivity, "MEDIUM"
		f.Title = "The Same Agent Activity Is Recorded on More Than One Host"
		f.MitreATLAS = "AML.T0112.000"
		f.Endpoint = "UNKNOWN"
		far := ""
		for _, id := range sortedKeys(members) {
			n := g.nodes[id]
			if n == nil || n.Case == first {
				continue
			}
			x := g.byLabel[n.Case]
			key := strings.TrimPrefix(id, n.Kind+":"+n.Case+":")
			prefix := "s:"
			if n.Kind == NodeAgent {
				prefix = "a:"
			}
			if rule := x.sev[prefix+key]; rule != "" && far == "" {
				far = n.Case + " " + rule
			}
		}
		var states []string
		seenRef := map[string]bool{}
		for _, i := range idx {
			e := g.edges[i]
			if len(f.Joins) < maxFindingJoins {
				f.Joins = append(f.Joins, joinRef(e))
			}
			for _, r := range e.Evidence {
				s := r.String()
				if !seenRef[s] && len(f.EvidenceRefs) < maxFindingRefs {
					seenRef[s] = true
					f.EvidenceRefs = append(f.EvidenceRefs, s)
				}
				if x := g.byLabel[r.Case]; x != nil {
					if i, ok := x.byID[r.EventID]; ok {
						states = append(states, x.c.Events[i].Corroboration)
						if f.Timestamp == "" || (x.c.Events[i].Timestamp != "" && x.c.Events[i].Timestamp < f.Timestamp) {
							f.Timestamp = x.c.Events[i].Timestamp
						}
					}
				}
				if g.byLabel[r.Case] != nil && g.byLabel[r.Case].c.Unverified {
					f.Unverified = true
				}
			}
		}
		if len(idx) > maxFindingJoins {
			f.Limits = append(f.Limits, fmt.Sprintf("%d further joins not listed (bound)", len(idx)-maxFindingJoins))
		}
		f.Status = aggregate(states)
		f.Description = fmt.Sprintf("Agent activity tied by %d strong join(s) (session, agent, delegation or tool call ids) is recorded in %s, on %d distinct hosts or execution environments.",
			len(idx), strings.Join(f.Cases, ", "), len(places))
		f.Reasons = []string{"tied by identifiers the evidence records, not by time or shared attributes"}
		if far != "" {
			f.Severity = "HIGH"
			f.Reasons = append(f.Reasons, "a HIGH/CRITICAL finding is recorded on the far side: "+far)
		}
		f.Confidence = "HIGH"
		if f.Unverified {
			f.Confidence = "LOW"
			f.Reasons = append(f.Reasons, "includes a case whose seal did not verify")
		}
		f.FalsePositive = "Developers resume their own sessions on a second machine and sync agent state between laptops, dev boxes and containers. Cross-host activity is not compromise; check who held each host."
		f.Limits = append([]string{
			"Hosts are told apart by host name and recorded execution environment; two cases with the same host name and no environment are treated as one place.",
			"A session id recorded on two hosts can be a copied transcript rather than a continuation; overlapping recordings are downgraded and not counted.",
			"The far side is the case whose joined activity starts later; the severity rises only for a HIGH/CRITICAL alert recorded on that side for the joined session or agent.",
		}, f.Limits...)
		out = append(out, f)
	}
	return out
}

func (g *gbuild) sessionOf(n *Node, x *cidx) string {
	key := strings.TrimPrefix(n.ID, n.Kind+":"+n.Case+":")
	switch n.Kind {
	case NodeSession:
		return key
	case NodeAgent:
		for aid, s := range x.agents {
			if detect.MaskSecrets(aid) == key {
				return s.session
			}
		}
	}
	return ""
}

func joinRef(e Edge) JoinRef {
	return JoinRef{JoinKey: e.JoinKey, JoinValue: e.JoinValue, From: e.From, To: e.To, Confidence: e.Confidence, Relation: e.Time.Relation}
}

var stateRank = map[string]int{schema.StateContradicted: 6, schema.StateCorroborated: 5, schema.StatePartial: 4, schema.StateObserved: 3,
	schema.StateReported: 2, schema.StateRequested: 1, schema.StateUnknown: 0}

// aggregate applies the schema's precedence to the cited events' states.
func aggregate(states []string) string {
	best, rank := schema.StateUnknown, -1
	for _, s := range states {
		if r, ok := stateRank[s]; ok && r > rank {
			best, rank = s, r
		}
	}
	return best
}

// ---- output

func (g *gbuild) finish(out *Graph, findings []CrossFinding) {
	nodes := make([]Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, *n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodeRank[nodes[i].Kind] != nodeRank[nodes[j].Kind] {
			return nodeRank[nodes[i].Kind] < nodeRank[nodes[j].Kind]
		}
		return nodes[i].ID < nodes[j].ID
	})
	edges := g.edges
	sort.SliceStable(edges, func(i, j int) bool {
		a, b := edges[i], edges[j]
		if (a.JoinKey == "") != (b.JoinKey == "") {
			return a.JoinKey != "" // joins first
		}
		if confRank[a.Confidence] != confRank[b.Confidence] {
			return confRank[a.Confidence] < confRank[b.Confidence]
		}
		if a.From != b.From {
			return a.From < b.From
		}
		if a.To != b.To {
			return a.To < b.To
		}
		if a.Kind != b.Kind {
			return a.Kind < b.Kind
		}
		if a.JoinKey != b.JoinKey {
			return a.JoinKey < b.JoinKey
		}
		return a.JoinValue < b.JoinValue
	})
	// Bounds: keep nodes in order; drop edges whose ends were dropped.
	if len(nodes) > g.o.MaxNodes {
		g.omit("nodes", len(nodes)-g.o.MaxNodes)
		nodes = nodes[:g.o.MaxNodes]
		out.Truncated = true
	}
	kept := map[string]bool{}
	for _, n := range nodes {
		kept[n.ID] = true
	}
	var es []Edge
	for _, e := range edges {
		if !kept[e.From] || !kept[e.To] {
			g.omit("edges", 1)
			out.Truncated = true
			continue
		}
		if len(es) >= g.o.MaxEdges {
			g.omit("edges", 1)
			out.Truncated = true
			continue
		}
		es = append(es, e)
	}
	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if a.RuleID != b.RuleID {
			return a.RuleID > b.RuleID // the chain first
		}
		if ca, cb := strings.Join(a.Cases, ","), strings.Join(b.Cases, ","); ca != cb {
			return ca < cb
		}
		if a.Timestamp != b.Timestamp {
			return a.Timestamp < b.Timestamp
		}
		return strings.Join(a.EvidenceRefs, "|") < strings.Join(b.EvidenceRefs, "|")
	})
	out.Nodes = append(out.Nodes, nodes...)
	if es != nil {
		out.Edges = es
	}
	out.Findings = append(out.Findings, findings...)
	out.Summary = GraphSummary{Nodes: map[string]int{}, JoinEdges: map[string]int{}, Findings: len(findings)}
	for _, n := range out.Nodes {
		out.Summary.Nodes[n.Kind]++
	}
	for _, e := range out.Edges {
		if e.JoinKey == "" {
			out.Summary.ContextEdges++
		} else {
			out.Summary.JoinEdges[e.Confidence]++
		}
	}
	if len(g.omitted) > 0 {
		out.Omitted = g.omitted
	}
	out.Notes = append(out.Notes, g.notes...)
	if out.Truncated {
		out.Notes = append(out.Notes, "the graph hit a bound; omitted counts what was left out, and no edge points at a dropped node")
	}
	out.Caveats = []string{
		"Entities stay in their own case: two nodes joined by an edge are two records, and the edge names the identifier that ties them.",
		"Weak joins (same destination or address, same file name, similar prompt wording, a launch followed in time by a session) are shown but never make two actions the same agent and never raise a finding.",
		"A strong join whose timestamps contradict its direction is kept, marked with its time relation, and downgraded to moderate; overlapping recordings of one session id are downgraded too.",
		"Session and agent ids shorter than 8 characters, tool call ids shorter than 12 or all digits, and commit ids shorter than 12 hex digits are not strong joins: short ids collide.",
		"Cloud principals, resource ids, execution environments and parent tool call ids are joined only where the parsers recorded them; a case without them cannot be joined by them.",
		"Prompt text is compared by word overlap in memory; no prompt text is written to the graph.",
	}
}

func firstLabel(h string) string {
	h = strings.ToLower(h)
	if i := strings.IndexByte(h, '.'); i > 0 {
		return h[:i]
	}
	return h
}

func orUnknownStr(s string) string {
	if strings.TrimSpace(s) == "" {
		return "unknown"
	}
	return s
}
