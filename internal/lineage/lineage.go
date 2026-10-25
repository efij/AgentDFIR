// Package lineage draws who did what through whom: the human account that
// prompted an agent, the subagents it started, the tool calls each made,
// the processes the operating system saw for them, and the destinations,
// files and cloud resources those reached.
//
// The rule that decides every edge: it must be backed by something the
// evidence records. A parent id written on the record, a tool_use id that
// ties a spawn to the call that made it, a pid or ppid in the telemetry, a
// path or destination named in the recorded command, or a correlation the
// correlate package made and scored. Each edge carries that basis in
// words, the evidence state of the step, and the source references
// (artifact, line, offset; or the telemetry file and line) to check it by
// hand. Two things that merely happened close together are never joined:
// time proximity alone is not a basis, and correlated edges carry the
// correlation's own basis and confidence.
//
// The whole-case graph is written to normalized/lineage.json during
// analysis, bounded; `agentdfir lineage` builds the same graph for one
// session or finding on demand.
package lineage

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/accounts"
	"github.com/efij/AgentDFIR/v3/internal/chain"
	"github.com/efij/AgentDFIR/v3/internal/correlate"
	"github.com/efij/AgentDFIR/v3/internal/detect"
	"github.com/efij/AgentDFIR/v3/internal/endpoint"
	"github.com/efij/AgentDFIR/v3/internal/netdest"
	"github.com/efij/AgentDFIR/v3/internal/notes"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// Schema identifies the document this package writes.
const Schema = "agentdfir.lineage/1"

// Node kinds.
const (
	KindHuman    = "human"
	KindAgent    = "agent"
	KindSubagent = "subagent"
	KindToolCall = "tool_call"
	KindProcess  = "process"
	KindNetwork  = "network"
	KindFile     = "file"
	KindCloud    = "cloud_resource"
	KindMCP      = "mcp_server"
)

// Edge bases, in words. Correlated edges extend basisCorrelated with the
// correlation's own basis and window.
const (
	BasisHumanPrompt  = "human prompt recorded in this agent's transcript"
	BasisSpawnMatch   = "tool_use_id match: the spawn tool call and its launch record name this agent"
	BasisSpawnRecord  = "spawn record names this agent (the spawning tool call is not in the evidence)"
	BasisParentID     = "recorded parent id"
	BasisAgentID      = "recorded agent id on the tool call"
	BasisNamedDest    = "destination named in the recorded command"
	BasisNamedFile    = "file path in the recorded tool input"
	BasisNamedMCP     = "MCP server named in the recorded tool name"
	BasisEndpointPID  = "endpoint pid"
	BasisEndpointPPID = "endpoint ppid"
	basisCorrelated   = "correlated"
)

// AccountFunc resolves the AI login a transcript ran under (see package
// accounts). Nil means accounts are not resolved and the human node names
// the profile only.
type AccountFunc func(logicalPath, product string) *accounts.Account

// Input is what the graph is built from.
type Input struct {
	CaseID      string
	Events      []schema.Event
	Findings    []schema.Finding
	Correlation *correlate.EndpointResult
	Account     AccountFunc
}

// Options select the scope and bound the output.
type Options struct {
	SessionID string // only this session
	Finding   string // a finding: index in findings.json, notes key ("finding:RULE|ref"), or a rule id
	MaxNodes  int    // default 20000
	MaxEdges  int    // default 50000
}

// Graph is normalized/lineage.json and the lineage command's JSON.
type Graph struct {
	Schema    string   `json:"schema"`
	CaseID    string   `json:"case_id"`
	Scope     Scope    `json:"scope"`
	Nodes     []Node   `json:"nodes"`
	Edges     []Edge   `json:"edges"`
	Limits    Limits   `json:"limits"`
	Truncated bool     `json:"truncated"`
	Omitted   Omitted  `json:"omitted"`
	Notes     []string `json:"notes"`
}

// Scope says what the graph covers.
type Scope struct {
	SessionID string   `json:"session_id,omitempty"`
	Finding   string   `json:"finding,omitempty"`
	Findings  []string `json:"finding_keys,omitempty"` // the findings the selector matched
	Events    int      `json:"events_considered"`
}

// Limits are the bounds the graph was built with.
type Limits struct {
	MaxNodes int `json:"max_nodes"`
	MaxEdges int `json:"max_edges"`
}

// Omitted counts what the bounds left out.
type Omitted struct {
	Nodes int `json:"nodes"`
	Edges int `json:"edges"`
}

// Node is one entity in the graph.
type Node struct {
	ID    string            `json:"id"`
	Kind  string            `json:"kind"`
	Label string            `json:"label"`
	State string            `json:"evidence_state,omitempty"`
	Attrs map[string]string `json:"attributes,omitempty"`
	Refs  []Ref             `json:"source_refs,omitempty"`
}

// Edge is one evidence-backed link.
type Edge struct {
	From       string `json:"from"`
	To         string `json:"to"`
	Relation   string `json:"relation"`
	Basis      string `json:"basis"`
	State      string `json:"evidence_state"`
	Confidence string `json:"confidence,omitempty"` // correlated edges only, as correlate.MatchBasis defines it
	Note       string `json:"note,omitempty"`
	Refs       []Ref  `json:"source_refs"`
}

// Ref locates the evidence for a node or edge: a sealed artifact line, or
// a line of imported telemetry.
type Ref struct {
	ArtifactID string `json:"artifact_id,omitempty"`
	Path       string `json:"logical_path,omitempty"`
	Line       int    `json:"line,omitempty"`
	Offset     int64  `json:"offset,omitempty"`
	EventID    string `json:"event_id,omitempty"`
	External   string `json:"telemetry_ref,omitempty"`
}

const maxRefs = 5

func eventRef(ev schema.Event) Ref {
	return Ref{ArtifactID: ev.SourceArtifact, Path: ev.SourcePath, Line: ev.SourceLine, Offset: ev.SourceOffset, EventID: ev.EventID}
}

// Build computes the graph. A selector that matches nothing is an error
// the caller reports; everything else degrades to notes.
func Build(in Input, o Options) (*Graph, error) {
	if o.MaxNodes <= 0 {
		o.MaxNodes = 20000
	}
	if o.MaxEdges <= 0 {
		o.MaxEdges = 50000
	}
	g := &builder{in: in, o: o, nodes: map[string]*Node{}, edges: map[string]*Edge{},
		graph: &Graph{Schema: Schema, CaseID: in.CaseID, Limits: Limits{o.MaxNodes, o.MaxEdges}, Notes: []string{}}}
	g.graph.Scope.SessionID = o.SessionID
	g.graph.Scope.Finding = o.Finding
	if err := g.scope(); err != nil {
		return nil, err
	}
	g.build()
	g.finish()
	return g.graph, nil
}

type builder struct {
	in    Input
	o     Options
	graph *Graph
	nodes map[string]*Node
	edges map[string]*Edge
	// selected event positions, in overlay order
	sel []int
	// finding scope: the nodes the finding cites, the roots of the cut
	seeds map[string]bool
}

// ---- scope

func (g *builder) scope() error {
	ev := g.in.Events
	if g.o.Finding == "" {
		for i := range ev {
			if g.o.SessionID == "" || ev[i].SessionID == g.o.SessionID {
				g.sel = append(g.sel, i)
			}
		}
		if g.o.SessionID != "" && len(g.sel) == 0 {
			return fmt.Errorf("no events for session %q", g.o.SessionID)
		}
		g.graph.Scope.Events = len(g.sel)
		return nil
	}
	fs := selectFindings(g.in.Findings, g.o.Finding)
	if len(fs) == 0 {
		return fmt.Errorf("no finding matches %q (use its index in findings.json, its key finding:RULE|ref, or a rule id)", g.o.Finding)
	}
	byID := make(map[string]int, len(ev))
	for i, e := range ev {
		byID[e.EventID] = i
	}
	refIdx := chain.RefIndex(ev)
	cited := map[int]bool{}
	for _, f := range fs {
		g.graph.Scope.Findings = append(g.graph.Scope.Findings, notes.FindingKey(f.RuleID, f.EvidenceRefs))
		for _, st := range f.ChainSteps {
			if i, ok := byID[st.EventID]; ok {
				cited[i] = true
			}
		}
		for _, r := range f.EvidenceRefs {
			if id := chain.EventForRef(refIdx, r); id != "" {
				cited[byID[id]] = true
			}
		}
	}
	if len(cited) == 0 {
		g.graph.Notes = append(g.graph.Notes, "the finding cites no transcript event (a configuration or artifact finding); the graph is empty")
	}
	// Ancestry: the cited events' agents up to the root, through spawn
	// records and recorded parent ids. Only those agents' spawn records and
	// first human prompt are taken, plus the cited events themselves.
	parent := spawnParents(ev)
	agents := map[string]bool{}
	for i := range cited {
		a := ev[i].AgentID
		for hop := 0; a != "" && !agents[a] && hop < 64; hop++ {
			agents[a] = true
			a = parent[a]
		}
	}
	g.seeds = map[string]bool{}
	firstPrompt := map[string]bool{}
	for i, e := range ev {
		take := cited[i]
		switch {
		case e.EventType == schema.EventAgentSpawn && agents[e.TaskID] && agents[e.AgentID]:
			take = true
		case e.ParentAgentID != "" && agents[e.AgentID] && agents[e.ParentAgentID] && !firstPrompt["p:"+e.AgentID]:
			firstPrompt["p:"+e.AgentID] = true
			take = true
		case e.EventType == schema.EventHumanPrompt && agents[e.AgentID] && !firstPrompt[e.AgentID]:
			firstPrompt[e.AgentID] = true
			take = true
		}
		if take {
			g.sel = append(g.sel, i)
		}
		if cited[i] {
			if e.EventType == schema.EventToolCall {
				g.seeds[toolID(e)] = true
			} else if e.AgentID != "" {
				g.seeds[agentID(e.AgentID)] = true
			}
		}
	}
	g.graph.Scope.Events = len(g.sel)
	return nil
}

// selectFindings resolves the --finding selector.
func selectFindings(fs []schema.Finding, sel string) []schema.Finding {
	var n int
	if _, err := fmt.Sscanf(sel, "%d", &n); err == nil && fmt.Sprint(n) == sel {
		if n >= 0 && n < len(fs) {
			return []schema.Finding{fs[n]}
		}
		return nil
	}
	var out []schema.Finding
	for _, f := range fs {
		if notes.FindingKey(f.RuleID, f.EvidenceRefs) == sel || f.RuleID == sel {
			out = append(out, f)
		}
	}
	return out
}

// spawnParents maps child agent → parent agent from the records that say
// so: spawn records and recorded parent ids.
func spawnParents(ev []schema.Event) map[string]string {
	p := map[string]string{}
	for _, e := range ev {
		if e.EventType == schema.EventAgentSpawn && e.TaskID != "" && e.AgentID != "" && e.TaskID != e.AgentID {
			if _, ok := p[e.TaskID]; !ok {
				p[e.TaskID] = e.AgentID
			}
		}
	}
	for _, e := range ev {
		if e.ParentAgentID != "" && e.ParentAgentID != "UNKNOWN" && e.AgentID != "" && e.ParentAgentID != e.AgentID {
			if _, ok := p[e.AgentID]; !ok {
				p[e.AgentID] = e.ParentAgentID
			}
		}
	}
	return p
}

// ---- nodes and edges

func agentID(id string) string     { return "agent:" + id }
func toolID(e schema.Event) string { return "tool:" + e.EventID }

func (g *builder) node(n Node) *Node {
	if ex := g.nodes[n.ID]; ex != nil {
		return ex
	}
	if len(g.nodes) >= g.o.MaxNodes {
		g.graph.Omitted.Nodes++
		return nil
	}
	cp := n
	g.nodes[n.ID] = &cp
	return &cp
}

func (g *builder) edge(e Edge) {
	if g.nodes[e.From] == nil || g.nodes[e.To] == nil {
		g.graph.Omitted.Edges++
		return
	}
	key := e.From + "\x00" + e.To + "\x00" + e.Relation
	if ex := g.edges[key]; ex != nil {
		for _, r := range e.Refs {
			if len(ex.Refs) < maxRefs {
				ex.Refs = append(ex.Refs, r)
			}
		}
		return
	}
	if len(g.edges) >= g.o.MaxEdges {
		g.graph.Omitted.Edges++
		return
	}
	cp := e
	g.edges[key] = &cp
}

func (g *builder) build() {
	ev := g.in.Events
	byID := make(map[string]int, len(ev))
	callAgent := map[string]string{} // tool_use id → agent that issued it
	for _, i := range g.sel {
		byID[ev[i].EventID] = i
		if ev[i].EventType == schema.EventToolCall && ev[i].ToolCallID != "" {
			callAgent[ev[i].ToolCallID] = ev[i].AgentID
		}
	}
	orphans := map[string]bool{}
	for _, f := range g.in.Findings {
		if f.RuleID == "ORPHAN_AGENT" && f.AgentID != "" {
			orphans[f.AgentID] = true
		}
	}
	parents := spawnParents(ev)
	matches := map[string][]correlate.Match{}
	if c := g.in.Correlation; c != nil {
		for _, m := range c.Matches {
			matches[m.EventID] = append(matches[m.EventID], m)
		}
		if c.MatchesOmitted > 0 {
			g.graph.Notes = append(g.graph.Notes, fmt.Sprintf("%d correlation pairing(s) were not kept by the correlation stage (bound); their process edges are missing", c.MatchesOmitted))
		}
	}

	agentNode := func(e schema.Event, id string) *Node {
		kind := KindAgent
		if !strings.HasPrefix(id, "main:") || parents[id] != "" {
			kind = KindSubagent
		}
		attrs := map[string]string{"session_id": e.SessionID}
		if e.Product != "" {
			attrs["product"] = e.Product
		}
		if orphans[id] {
			attrs["parent"] = "UNKNOWN"
		}
		return g.node(Node{ID: agentID(id), Kind: kind, Label: id, Attrs: attrs})
	}
	prompts := map[string]int{}
	firstPrompt := map[string]schema.Event{}
	for _, i := range g.sel {
		e := ev[i]
		if e.AgentID != "" {
			agentNode(e, e.AgentID)
		}
		switch e.EventType {
		case schema.EventHumanPrompt:
			if _, ok := firstPrompt[e.AgentID]; !ok {
				firstPrompt[e.AgentID] = e
			}
			prompts[e.AgentID]++
		case schema.EventAgentSpawn:
			if e.TaskID == "" || e.TaskID == e.AgentID {
				continue
			}
			agentNode(e, e.TaskID)
			basis := BasisSpawnRecord
			if e.ToolCallID != "" && callAgent[e.ToolCallID] == e.AgentID {
				basis = BasisSpawnMatch
			}
			g.edge(Edge{From: agentID(e.AgentID), To: agentID(e.TaskID), Relation: "spawned", Basis: basis, State: e.Corroboration,
				Note: noteIf("tool_use_id "+e.ToolCallID, e.ToolCallID != ""), Refs: []Ref{eventRef(e)}})
		case schema.EventToolCall:
			g.toolCall(e, matches[e.EventID])
		}
		if p := e.ParentAgentID; p != "" && p != "UNKNOWN" && p != e.AgentID && e.AgentID != "" {
			if g.nodes[agentID(p)] == nil {
				g.node(Node{ID: agentID(p), Kind: KindAgent, Label: p, Attrs: map[string]string{"note": "named as parent; no records of its own in scope"}})
			}
			g.edge(Edge{From: agentID(p), To: agentID(e.AgentID), Relation: "spawned", Basis: BasisParentID, State: e.Corroboration, Refs: []Ref{eventRef(e)}})
		}
	}
	// Human → agent, for agents whose transcript records a human prompt.
	for _, id := range sortedKeys(firstPrompt) {
		e := firstPrompt[id]
		hid, label, attrs, acctBasis := g.human(e)
		g.node(Node{ID: hid, Kind: KindHuman, Label: label, Attrs: attrs})
		g.edge(Edge{From: hid, To: agentID(id), Relation: "prompted", Basis: BasisHumanPrompt + "; " + acctBasis,
			State: e.Corroboration, Note: fmt.Sprintf("%d human prompt(s) in scope", prompts[id]), Refs: []Ref{eventRef(e)}})
	}
	quiet := 0
	for _, id := range sortedKeys(g.nodes) {
		n := g.nodes[id]
		if n.Kind != KindAgent || !strings.HasPrefix(n.Label, "main:") {
			continue
		}
		if _, ok := firstPrompt[n.Label]; ok {
			continue
		}
		if quiet++; quiet <= 25 {
			g.graph.Notes = append(g.graph.Notes, "agent "+n.Label+": no human prompt in scope (headless launch, a prompt delivered another way, or not collected)")
		}
	}
	if quiet > 25 {
		g.graph.Notes = append(g.graph.Notes, fmt.Sprintf("%d more agent(s) with no human prompt in scope", quiet-25))
	}
}

// human resolves the account behind a prompt's transcript.
func (g *builder) human(e schema.Event) (id, label string, attrs map[string]string, basis string) {
	key := accounts.Key(e.SourcePath, e.Product)
	attrs = map[string]string{"profile": key}
	label = accounts.ProductName(e.Product) + " · profile " + key + " (login not recorded)"
	basis = "transcript stored under profile " + key + "; no login file for it in the case"
	if g.in.Account != nil {
		if a := g.in.Account(e.SourcePath, e.Product); a != nil {
			key = a.Key
			attrs["profile"] = a.Key
			label = a.Label
			if a.Email != "" {
				attrs["email"] = a.Email
			}
			if a.Org != "" {
				attrs["org"] = a.Org
			}
			if a.Source != "" {
				attrs["login_source"] = a.Source
			}
			if a.Known && a.Source != "" {
				basis = "transcript stored under profile " + a.Key + ", whose login file " + a.Source + " names this account"
			}
		}
	}
	return "human:" + key, label, attrs, basis
}

func (g *builder) toolCall(e schema.Event, ms []correlate.Match) {
	attrs := map[string]string{"tool": e.Tool}
	put := func(k, v string) {
		if v != "" {
			attrs[k] = v
		}
	}
	put("tool_call_id", e.ToolCallID)
	put("timestamp", e.Timestamp)
	put("session_id", e.SessionID)
	// Commands can carry the credential they leaked; the graph names the
	// key by type and fingerprint instead. The full command is masked
	// first and only then cut, so a cut can never expose part of a key.
	full := e.FullCommand()
	put("command", detect.MaskTruncate(full, 200))
	put("file", detect.MaskSecrets(e.File))
	put("action", e.Action)
	put("witness_note", detect.MaskSecrets(e.WitnessNote))
	label := e.Tool
	switch {
	case full != "":
		label += ": " + detect.MaskTruncate(full, 60)
	case e.File != "":
		label += ": " + detect.MaskTruncate(e.File, 60)
	}
	tid := toolID(e)
	if g.node(Node{ID: tid, Kind: KindToolCall, Label: label, State: e.Corroboration, Attrs: attrs, Refs: []Ref{eventRef(e)}}) == nil {
		return
	}
	ref := []Ref{eventRef(e)}
	if e.AgentID != "" {
		g.edge(Edge{From: agentID(e.AgentID), To: tid, Relation: "invoked", Basis: BasisAgentID, State: e.Corroboration, Refs: ref})
	}
	// What the record itself names.
	dests := netdest.Extract(e.FullCommand())
	if e.NetworkDest != "" && !contains(dests, e.NetworkDest) {
		dests = append([]string{e.NetworkDest}, dests...)
	}
	for k, d := range dests {
		if k >= maxRefs {
			break
		}
		h := strings.ToLower(netdest.Host(d))
		if g.node(Node{ID: "network:" + h, Kind: KindNetwork, Label: h}) != nil {
			g.edge(Edge{From: tid, To: "network:" + h, Relation: "named_destination", Basis: BasisNamedDest, State: e.Corroboration,
				Note: "the command names it; a connection is shown only by a telemetry edge", Refs: ref})
		}
	}
	if e.File != "" {
		rel := map[string]string{"write_file": "wrote", "edit_file": "edited", "read_file": "read"}[e.Action]
		if rel == "" {
			rel = "named_file"
		}
		basis := BasisNamedFile
		if strings.Contains(e.WitnessNote, "host witness:") {
			basis += "; " + detect.MaskSecrets(e.WitnessNote)
		}
		if g.node(Node{ID: "file:" + e.File, Kind: KindFile, Label: detect.MaskSecrets(e.File)}) != nil {
			g.edge(Edge{From: tid, To: "file:" + e.File, Relation: rel, Basis: basis, State: e.Corroboration, Refs: ref})
		}
	}
	if e.MCPServer != "" {
		if g.node(Node{ID: "mcp:" + e.MCPServer, Kind: KindMCP, Label: e.MCPServer}) != nil {
			g.edge(Edge{From: tid, To: "mcp:" + e.MCPServer, Relation: "called", Basis: BasisNamedMCP, State: e.Corroboration, Refs: ref})
		}
	}
	// What an independent witness paired with it.
	for _, m := range ms {
		g.correlated(e, tid, m)
	}
}

// correlated adds the edge for one correlation pairing and, for a process,
// what the telemetry shows that process doing by pid and ppid.
func (g *builder) correlated(e schema.Event, tid string, m correlate.Match) {
	r := m.Record
	basis := fmt.Sprintf("%s within ±%s: %s (%s, score %d)", basisCorrelated, time.Duration(m.WindowMS)*time.Millisecond, m.Basis, m.Witness, m.Score)
	refs := []Ref{eventRef(e), {External: r.Source + " " + r.Ref}}
	note := fmt.Sprintf("record is %s from the transcript time", signedMS(m.DeltaMS))
	switch r.Kind {
	case "process":
		pid := g.processNode(r)
		if pid == "" {
			return
		}
		g.edge(Edge{From: tid, To: pid, Relation: "executed_as", Basis: basis, State: e.Corroboration, Confidence: m.Confidence, Note: note, Refs: refs})
		for _, rel := range m.Related {
			g.related(pid, rel)
		}
	case "script", endpoint.KindProcessImage:
		// A PowerShell script block, or a process creation known only by
		// its image path: the process the call ran as, on a weaker basis.
		pid := g.processNode(r)
		if pid == "" {
			return
		}
		rel := "executed_as"
		if r.Kind == "script" {
			rel = "ran_script"
		}
		g.edge(Edge{From: tid, To: pid, Relation: rel, Basis: basis, State: e.Corroboration, Confidence: m.Confidence, Note: note, Refs: refs})
	case "dns":
		// A lookup shows intent to connect, not a connection.
		if h := strings.ToLower(r.DestHost); h != "" && g.node(Node{ID: "network:" + h, Kind: KindNetwork, Label: h}) != nil {
			g.edge(Edge{From: tid, To: "network:" + h, Relation: "looked_up", Basis: basis, State: e.Corroboration, Confidence: m.Confidence,
				Note: note + noteIf("; client "+r.SourceIP, r.SourceIP != ""), Refs: refs})
		}
	case "auth":
		// sshd names the account and the client address, not the host the
		// log came from; the node is the login itself.
		id := "network:ssh-login:" + r.Source + ":" + r.Ref
		label := "ssh login " + r.User
		if r.SourceIP != "" {
			label += " from " + r.SourceIP
		}
		if g.node(Node{ID: id, Kind: KindNetwork, Label: label, State: schema.StateObserved, Attrs: nonEmpty(map[string]string{"user": r.User, "client": r.SourceIP, "operation": r.Operation})}) != nil {
			g.edge(Edge{From: tid, To: id, Relation: "logged_in", Basis: basis, State: e.Corroboration, Confidence: m.Confidence, Note: note, Refs: refs})
		}
	case "file":
		if g.node(Node{ID: "file:" + r.FilePath, Kind: KindFile, Label: detect.MaskSecrets(r.FilePath)}) != nil {
			g.edge(Edge{From: tid, To: "file:" + r.FilePath, Relation: "touched", Basis: basis, State: e.Corroboration, Confidence: m.Confidence, Note: note, Refs: refs})
		}
	case "network":
		h := destOf(r)
		if h != "" && g.node(Node{ID: "network:" + h, Kind: KindNetwork, Label: h}) != nil {
			g.edge(Edge{From: tid, To: "network:" + h, Relation: "connected_to", Basis: basis, State: e.Corroboration, Confidence: m.Confidence, Note: note, Refs: refs})
		}
	case "cloud":
		res := r.Resource
		if res == "" {
			res = r.Operation
		}
		id := "cloud:" + r.Provider + ":" + res
		attrs := map[string]string{"provider": r.Provider, "operation": r.Operation}
		if r.User != "" {
			attrs["identity"] = r.User
		}
		if r.Failed != "" {
			attrs["refused"] = r.Failed
		}
		if g.node(Node{ID: id, Kind: KindCloud, Label: detect.MaskSecrets(r.Provider + " " + res), Attrs: attrs}) != nil {
			g.edge(Edge{From: tid, To: id, Relation: "acted_on", Basis: basis, State: e.Corroboration, Confidence: m.Confidence, Note: note, Refs: refs})
		}
	}
}

func (g *builder) processNode(r endpoint.Record) string {
	id := "process:" + r.Source + ":" + r.Ref
	attrs := map[string]string{"time": r.Time.UTC().Format(time.RFC3339)}
	if r.Kind != "process" {
		attrs["record_kind"] = r.Kind // script block or image-only process creation
	}
	if r.PID != 0 {
		attrs["pid"] = fmt.Sprint(r.PID)
	}
	if r.PPID != 0 {
		attrs["ppid"] = fmt.Sprint(r.PPID)
	}
	if r.Exe != "" {
		attrs["exe"] = r.Exe
	}
	if r.Cmdline != "" {
		attrs["cmdline"] = detect.MaskTruncate(r.Cmdline, 300)
	}
	if r.User != "" {
		attrs["user"] = r.User
	}
	label := baseName(r.Exe)
	if label == "" {
		label = detect.MaskTruncate(r.Cmdline, 40)
	}
	if r.PID != 0 {
		label += fmt.Sprintf(" (pid %d)", r.PID)
	}
	if g.node(Node{ID: id, Kind: KindProcess, Label: label, State: schema.StateObserved, Attrs: attrs, Refs: []Ref{{External: r.Source + " " + r.Ref}}}) == nil {
		return ""
	}
	return id
}

func (g *builder) related(pid string, rel correlate.RelatedRecord) {
	r := rel.Record
	refs := []Ref{{External: r.Source + " " + r.Ref}}
	switch {
	case r.Kind == "process" && rel.Basis == BasisEndpointPPID:
		if child := g.processNode(r); child != "" {
			g.edge(Edge{From: pid, To: child, Relation: "child_process", Basis: BasisEndpointPPID, State: schema.StateObserved, Refs: refs})
		}
	case r.Kind == "network":
		if h := destOf(r); h != "" && g.node(Node{ID: "network:" + h, Kind: KindNetwork, Label: h}) != nil {
			g.edge(Edge{From: pid, To: "network:" + h, Relation: "connected_to", Basis: rel.Basis, State: schema.StateObserved,
				Note: noteIf(fmt.Sprintf("port %d", r.DestPort), r.DestPort != 0), Refs: refs})
		}
	case r.Kind == "file" && r.FilePath != "":
		if g.node(Node{ID: "file:" + r.FilePath, Kind: KindFile, Label: detect.MaskSecrets(r.FilePath)}) != nil {
			g.edge(Edge{From: pid, To: "file:" + r.FilePath, Relation: "touched", Basis: rel.Basis, State: schema.StateObserved,
				Note: noteIf("file operation "+r.FileOp, r.FileOp != ""), Refs: refs})
		}
	}
}

// ---- finish: cut to the finding, order, bound

var kindRank = map[string]int{KindHuman: 0, KindAgent: 1, KindSubagent: 2, KindToolCall: 3, KindProcess: 4, KindMCP: 5, KindNetwork: 6, KindFile: 7, KindCloud: 8}

func (g *builder) finish() {
	if g.seeds != nil {
		g.cut()
	}
	nodes := make([]Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		nodes = append(nodes, *n)
	}
	sort.Slice(nodes, func(i, j int) bool {
		if kindRank[nodes[i].Kind] != kindRank[nodes[j].Kind] {
			return kindRank[nodes[i].Kind] < kindRank[nodes[j].Kind]
		}
		return nodes[i].ID < nodes[j].ID
	})
	edges := make([]Edge, 0, len(g.edges))
	for _, e := range g.edges {
		edges = append(edges, *e)
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Relation < edges[j].Relation
	})
	g.graph.Nodes, g.graph.Edges = nodes, edges
	g.graph.Truncated = g.graph.Omitted.Nodes > 0 || g.graph.Omitted.Edges > 0
	if g.graph.Truncated {
		g.graph.Notes = append(g.graph.Notes, fmt.Sprintf("bounded at %d nodes / %d edges: %d node(s) and %d edge(s) left out; narrow with --session or --finding",
			g.o.MaxNodes, g.o.MaxEdges, g.graph.Omitted.Nodes, g.graph.Omitted.Edges))
	}
	sort.Strings(g.graph.Notes)
}

// cut keeps what leads to the finding's nodes (ancestors) and what they
// led to (descendants), not their siblings.
func (g *builder) cut() {
	out, in := map[string][]string{}, map[string][]string{}
	for _, e := range g.edges {
		out[e.From] = append(out[e.From], e.To)
		in[e.To] = append(in[e.To], e.From)
	}
	keep := map[string]bool{}
	walk := func(adj map[string][]string, skipTools bool) {
		var stack []string
		for s := range g.seeds {
			if g.nodes[s] != nil {
				stack = append(stack, s)
			}
		}
		seen := map[string]bool{}
		for len(stack) > 0 {
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if seen[n] {
				continue
			}
			seen[n] = true
			keep[n] = true
			for _, m := range adj[n] {
				// Descending from an agent seed must not pull in every tool
				// call that agent made: only the finding's own calls count.
				if skipTools && g.nodes[m] != nil && g.nodes[m].Kind == KindToolCall && !g.seeds[m] {
					continue
				}
				stack = append(stack, m)
			}
		}
	}
	walk(in, false)
	walk(out, true)
	for id := range g.nodes {
		if !keep[id] {
			delete(g.nodes, id)
		}
	}
	for k, e := range g.edges {
		if !keep[e.From] || !keep[e.To] {
			delete(g.edges, k)
		}
	}
}

// ---- helpers

func destOf(r endpoint.Record) string {
	if r.DestHost != "" {
		return strings.ToLower(r.DestHost)
	}
	return strings.ToLower(r.DestIP)
}

func noteIf(s string, ok bool) string {
	if ok {
		return s
	}
	return ""
}

// nonEmpty drops blank attribute values.
func nonEmpty(m map[string]string) map[string]string {
	for k, v := range m {
		if v == "" {
			delete(m, k)
		}
	}
	return m
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func trim(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

func signedMS(ms int64) string {
	d := time.Duration(ms) * time.Millisecond
	if ms < 0 {
		return d.String()
	}
	return "+" + d.String()
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
