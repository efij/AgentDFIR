// Package proof builds the action proof report: for every tool call an
// agent recorded, the claim, the evidence chain from the human who
// prompted the agent down to the effect an independent record shows
// (Human → Agent → Tool → Process → File/Network → Outcome), the state
// of each step, how each link is known, what each link does not show,
// and the telemetry coverage and collection-health facts that justify
// the state.
//
// The report is computed from what analysis already wrote (the events
// overlay, detections/corroboration.json and the action graph lineage
// builds from them); it decides nothing new. Its JSON form is meant to
// be checked without AgentDFIR: every transcript reference names a
// sealed artifact by its content hash, every telemetry reference names
// the telemetry file it came from with that file's SHA-256, and the
// derived files it was read from are listed with theirs
// (docs/action-proof.md).
//
// Output is deterministic: no wall-clock time, no absolute paths, every
// list in a defined order.
package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/correlate"
	"github.com/efij/AgentDFIR/v4/internal/detect"
	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/lineage"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Schema identifies the document.
const Schema = "agentdfir.proof/1"

// DefaultMaxActions bounds the actions listed.
const DefaultMaxActions = 5000

// maxChain bounds the steps of one action's chain.
const maxChain = 64

// Report is the proof report (`agentdfir report <pkg> --format proof --json`).
type Report struct {
	Schema       string        `json:"schema"`
	ToolVersion  string        `json:"tool_version,omitempty"`
	CaseID       string        `json:"case_id"`
	Scope        Scope         `json:"scope"`
	Telemetry    Telemetry     `json:"telemetry"`
	Summary      Summary       `json:"summary"`
	Actions      []Action      `json:"actions"`
	Omitted      int           `json:"actions_omitted,omitempty"`
	Artifacts    []Artifact    `json:"artifacts"`
	Derived      []DerivedFile `json:"derived_from"`
	Notes        []string      `json:"notes"`
	Verification Verification  `json:"verification"`
}

// Scope says what the report covers.
type Scope struct {
	SessionID  string `json:"session_id,omitempty"`
	ToolCalls  int    `json:"tool_calls"`
	MaxActions int    `json:"max_actions"`
	WindowMS   int64  `json:"match_window_ms"`
}

// Telemetry is the "Telemetry coverage & health" section.
type Telemetry struct {
	Imported bool                     `json:"imported"`
	Sources  []endpoint.SourceHealth  `json:"sources"`
	Coverage []correlate.KindCoverage `json:"coverage"`
	Note     string                   `json:"note,omitempty"`
}

// Summary counts actions by state and coverage.
type Summary struct {
	States   map[string]int `json:"states"`
	Coverage map[string]int `json:"coverage"`
}

// Action is one recorded tool call and its proof.
type Action struct {
	EventID     string    `json:"event_id"`
	Timestamp   string    `json:"timestamp,omitempty"`
	SessionID   string    `json:"session_id,omitempty"`
	AgentID     string    `json:"agent_id,omitempty"`
	Host        string    `json:"host,omitempty"`
	Tool        string    `json:"tool"`
	Claim       string    `json:"claim"`
	State       string    `json:"evidence_state"`
	StateLabel  string    `json:"evidence_label"`
	Confidence  string    `json:"confidence"` // verified | corroborated | inferred: the strongest link to an independent record
	Coverage    []Fact    `json:"coverage"`
	Chain       []Step    `json:"chain"`
	Truncated   bool      `json:"chain_truncated,omitempty"`
	Limitations []string  `json:"limitations"`
	Source      SourceRef `json:"source_ref"`
}

// Fact is what coverage says about one kind of telemetry for the action.
type Fact struct {
	Kind     string   `json:"kind"`
	Needed   bool     `json:"needed"` // the kind the claim's state depends on
	Coverage string   `json:"coverage"`
	Reason   string   `json:"reason"`
	Sources  []string `json:"sources,omitempty"`
	// Decided is true when the fact is the correlation's own recorded
	// decision (coverage_decisions), false when recomputed from coverage.
	Decided bool `json:"decided"`
}

// Step is one link of the chain: the edge into a node, and the node.
type Step struct {
	Role        string      `json:"role"` // the node kind
	Node        string      `json:"node"`
	Label       string      `json:"label"`
	From        string      `json:"from,omitempty"`
	Relation    string      `json:"relation,omitempty"`
	Basis       string      `json:"basis,omitempty"`
	State       string      `json:"evidence_state,omitempty"`
	Assurance   string      `json:"assurance,omitempty"`
	Correlation string      `json:"correlation_confidence,omitempty"`
	Limitations []string    `json:"limitations,omitempty"`
	Refs        []SourceRef `json:"source_refs,omitempty"`
}

// SourceRef is one checkable reference: a sealed artifact line or a
// telemetry record.
type SourceRef struct {
	ArtifactID  string `json:"artifact_id,omitempty"`
	LogicalPath string `json:"logical_path,omitempty"`
	Line        int    `json:"line,omitempty"`
	Offset      int64  `json:"offset,omitempty"`
	EventID     string `json:"event_id,omitempty"`
	// Telemetry is "<adapter> <record ref>" as the adapter wrote it
	// (file:line, or an event log record id).
	Telemetry string `json:"telemetry_ref,omitempty"`
	// TelemetryFile names the telemetry_sources entry (telemetry.sources[].file)
	// and TelemetrySHA256 its hash; empty when the reference could not be
	// tied to one imported file.
	TelemetryFile   string `json:"telemetry_file,omitempty"`
	TelemetrySHA256 string `json:"telemetry_sha256,omitempty"`
}

// Artifact is a sealed artifact the report cites.
type Artifact struct {
	ArtifactID  string `json:"artifact_id"`
	LogicalPath string `json:"logical_path"`
	Size        int64  `json:"size"`
	InManifest  bool   `json:"in_manifest"`
}

// DerivedFile is an analysis file the report was read from.
type DerivedFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Note   string `json:"note"`
}

// Verification says, in the document itself, how to check it.
type Verification struct {
	ArtifactRefs  string `json:"artifact_refs"`
	TelemetryRefs string `json:"telemetry_refs"`
	DerivedFiles  string `json:"derived_files"`
	States        string `json:"states"`
}

var verification = Verification{
	ArtifactRefs: "artifact_id is the SHA-256 of the artifact's plaintext. manifest.jsonl lists it with its logical_path; the bytes are raw/<artifact_id> " +
		"(or raw/<artifact_id>.gz, or the chunks the manifest record lists). Hash the plaintext and compare; line and offset locate the transcript record.",
	TelemetryRefs: "telemetry_file names an entry of telemetry.sources; its sha256 is the SHA-256 of that telemetry file as imported. Hash your copy and compare, " +
		"then find telemetry_ref in it (file:line for line-oriented logs, the record id for event logs).",
	DerivedFiles: "sha256 is the SHA-256 of the derived file's JSON content (decompressed when it is stored as .gz). The overlay is regenerable: " +
		"re-running analysis on the same evidence and telemetry reproduces it.",
	States: "evidence_state is the step's corroboration state. A tool call is DISPROVED (CONTRADICTED) only when the kind of telemetry it needs covers its host " +
		"and time with coverage HEALTHY (sequence numbers contiguous) or UNKNOWN (no sequence numbers; completeness unverified); PARTIAL coverage never disproves.",
}

// Input is what the report is built from.
type Input struct {
	CaseID      string
	ToolVersion string
	Events      []schema.Event
	Correlation *correlate.EndpointResult
	Graph       *lineage.Graph
	Manifest    *casepkg.Manifest
	Derived     []DerivedFile
}

// Options select and bound.
type Options struct {
	SessionID  string
	MaxActions int
}

// Build computes the report.
func Build(in Input, o Options) *Report {
	if o.MaxActions <= 0 {
		o.MaxActions = DefaultMaxActions
	}
	r := &Report{Schema: Schema, ToolVersion: in.ToolVersion, CaseID: in.CaseID, Verification: verification,
		Scope:   Scope{SessionID: o.SessionID, MaxActions: o.MaxActions, WindowMS: 3000},
		Summary: Summary{States: map[string]int{}, Coverage: map[string]int{}},
		Actions: []Action{}, Artifacts: []Artifact{}, Derived: append([]DerivedFile{}, in.Derived...), Notes: []string{}}
	c := in.Correlation
	if c != nil && c.WindowMS > 0 {
		r.Scope.WindowMS = c.WindowMS
	}
	r.Telemetry = telemetry(c)
	b := &builder{in: in, r: r, artifacts: map[string]bool{}}
	b.index()
	var calls []schema.Event
	for _, e := range in.Events {
		if e.EventType == schema.EventToolCall && (o.SessionID == "" || e.SessionID == o.SessionID) {
			calls = append(calls, e)
		}
	}
	sort.SliceStable(calls, func(i, j int) bool {
		if calls[i].Timestamp != calls[j].Timestamp {
			return calls[i].Timestamp < calls[j].Timestamp
		}
		return calls[i].EventID < calls[j].EventID
	})
	r.Scope.ToolCalls = len(calls)
	for _, e := range calls {
		if len(r.Actions) >= o.MaxActions {
			r.Omitted++
			continue
		}
		r.Actions = append(r.Actions, b.action(e))
	}
	validate(r)
	for i := range r.Actions {
		a := &r.Actions[i]
		a.StateLabel = Invalid
		if a.State != Invalid {
			a.StateLabel = schema.Label(a.State)
		}
		r.Summary.States[a.StateLabel]++
		for _, f := range a.Coverage {
			if f.Needed {
				r.Summary.Coverage[f.Coverage]++
			}
		}
	}
	if r.Omitted > 0 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d tool call(s) past the bound of %d not listed; narrow with --session", r.Omitted, o.MaxActions))
	}
	if g := in.Graph; g != nil && g.Truncated {
		r.Notes = append(r.Notes, fmt.Sprintf("the action graph was bounded (%d node(s), %d edge(s) left out): some chains are incomplete", g.Omitted.Nodes, g.Omitted.Edges))
	}
	b.finishArtifacts()
	sort.Strings(r.Notes)
	return r
}

func telemetry(c *correlate.EndpointResult) Telemetry {
	t := Telemetry{Sources: []endpoint.SourceHealth{}, Coverage: []correlate.KindCoverage{}}
	if c == nil || (c.Records == 0 && len(c.Health) == 0) {
		t.Note = "no endpoint telemetry was imported: no tool call can be CONFIRMED or DISPROVED by the operating system"
		return t
	}
	t.Imported = true
	t.Sources = append(t.Sources, c.Health...)
	t.Coverage = append(t.Coverage, c.KindCoverage...)
	if len(c.Health) == 0 {
		t.Note = "this analysis predates collection-health reporting: coverage is the single time window of v4 (completeness unverified)"
	}
	return t
}

type builder struct {
	in        Input
	r         *Report
	nodes     map[string]*lineage.Node
	out, in_  map[string][]*lineage.Edge
	decisions map[string]correlate.CoverageDecision
	// telemetry ref → source file, from the correlation's own pairings
	refFile   map[string]string
	fileHash  map[string][]string
	artifacts map[string]bool
}

func (b *builder) index() {
	b.nodes, b.out, b.in_ = map[string]*lineage.Node{}, map[string][]*lineage.Edge{}, map[string][]*lineage.Edge{}
	if g := b.in.Graph; g != nil {
		for i := range g.Nodes {
			b.nodes[g.Nodes[i].ID] = &g.Nodes[i]
		}
		for i := range g.Edges {
			e := &g.Edges[i]
			b.out[e.From] = append(b.out[e.From], e)
			b.in_[e.To] = append(b.in_[e.To], e)
		}
	}
	b.decisions, b.refFile, b.fileHash = map[string]correlate.CoverageDecision{}, map[string]string{}, map[string][]string{}
	c := b.in.Correlation
	if c == nil {
		return
	}
	for _, d := range c.Decisions {
		b.decisions[d.EventID] = d
	}
	for _, m := range c.Matches {
		if m.SourceFile != "" {
			b.refFile[m.Record.Source+" "+m.Record.Ref] = m.SourceFile
		}
		for _, rr := range m.Related {
			if rr.SourceFile != "" {
				b.refFile[rr.Record.Source+" "+rr.Record.Ref] = rr.SourceFile
			}
		}
	}
	for _, h := range c.Health {
		b.fileHash[h.File] = append(b.fileHash[h.File], h.SHA256)
	}
}

// claim is what the tool call says it did, masked like the graph.
func claim(e schema.Event) string {
	var parts []string
	if full := e.FullCommand(); full != "" {
		parts = append(parts, "ran `"+detect.MaskTruncate(full, 300)+"`")
	}
	if e.File != "" {
		verb := map[string]string{"write_file": "wrote", "edit_file": "edited", "read_file": "read"}[e.Action]
		if verb == "" {
			verb = "named file"
		}
		parts = append(parts, verb+" "+detect.MaskSecrets(e.File))
	}
	if e.NetworkDest != "" {
		parts = append(parts, "reached "+detect.MaskSecrets(e.NetworkDest))
	}
	if e.MCPServer != "" {
		parts = append(parts, "called MCP server "+e.MCPServer)
	}
	if len(parts) == 0 {
		return "invoked " + e.Tool + " (no command, file or destination recorded)"
	}
	return strings.Join(parts, "; ")
}

func (b *builder) action(e schema.Event) Action {
	a := Action{EventID: e.EventID, Timestamp: e.Timestamp, SessionID: e.SessionID, AgentID: e.AgentID, Host: e.Host, Tool: e.Tool,
		Claim: claim(e), State: e.Corroboration, StateLabel: schema.Label(e.Corroboration), Source: b.eventRef(e), Coverage: []Fact{}, Chain: []Step{}}
	a.Coverage = b.facts(e)
	tid := "tool:" + e.EventID
	if b.nodes[tid] == nil {
		a.Limitations = []string{"the tool call is not in the action graph (bounded, or the graph was not built); the chain is not shown"}
		a.Confidence = lineage.AssuranceInferred
		return a
	}
	// Upstream: tool ← agent ← (spawning agents) ← human. Listed top
	// down; each step carries the edge that leads into its node.
	var up []*lineage.Edge
	cur := tid
	seen := map[string]bool{tid: true}
	for hop := 0; hop < 16; hop++ {
		e := pickIn(b.in_[cur])
		if e == nil || seen[e.From] {
			break
		}
		seen[e.From] = true
		up = append(up, e)
		cur = e.From
	}
	if top := b.nodes[cur]; top != nil && cur != tid {
		a.Chain = append(a.Chain, Step{Role: top.Kind, Node: top.ID, Label: top.Label, State: top.State, Refs: b.refs(top.Refs)})
	}
	for i := len(up) - 1; i >= 0; i-- {
		a.Chain = append(a.Chain, b.step(up[i]))
	}
	if len(up) == 0 {
		tn := b.nodes[tid]
		a.Chain = append(a.Chain, Step{Role: tn.Kind, Node: tn.ID, Label: tn.Label, State: tn.State, Refs: b.refs(tn.Refs)})
	}
	// Downstream, breadth first: tool → process / file / network / cloud
	// / mcp → (process children and effects) → outcome. Outcome edges are
	// followed only when they cite a record this chain already cites, so a
	// file or host other calls also touched does not lend this call their
	// effects.
	cited := map[string]bool{}
	queue := []string{tid}
	depth := map[string]int{tid: 0}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		if depth[n] >= 3 {
			continue
		}
		for _, ed := range b.out[n] {
			if seen[ed.To] {
				continue
			}
			if to := b.nodes[ed.To]; to != nil && to.Kind == lineage.KindOutcome && !citesAny(ed.Refs, cited) {
				continue
			}
			if len(a.Chain) >= maxChain {
				a.Truncated = true
				break
			}
			seen[ed.To] = true
			for _, r := range ed.Refs {
				cited[refKey(r)] = true
			}
			a.Chain = append(a.Chain, b.step(ed))
			depth[ed.To] = depth[n] + 1
			queue = append(queue, ed.To)
		}
	}
	a.Confidence = confidence(a.Chain)
	lim := map[string]bool{}
	for _, s := range a.Chain {
		for _, l := range s.Limitations {
			lim[l] = true
		}
	}
	for _, f := range a.Coverage {
		if f.Needed && f.Coverage == correlate.CoverUnverified {
			lim["completeness unverified: "+f.Kind+" telemetry carries no sequence numbers"] = true
		}
	}
	a.Limitations = sortedSet(lim)
	return a
}

// pickIn chooses the edge that leads up the chain: invoked, then
// spawned, then prompted; ties by source node id.
func pickIn(es []*lineage.Edge) *lineage.Edge {
	rank := map[string]int{"invoked": 0, "spawned": 1, "prompted": 2}
	var best *lineage.Edge
	for _, e := range es {
		r, ok := rank[e.Relation]
		if !ok {
			continue
		}
		if best == nil || r < rank[best.Relation] || (r == rank[best.Relation] && e.From < best.From) {
			best = e
		}
	}
	return best
}

// step is the node an edge leads to, with that edge.
func (b *builder) step(e *lineage.Edge) Step {
	s := Step{Node: e.To, From: e.From, Relation: e.Relation, Basis: e.Basis, State: e.State, Assurance: e.Assurance, Correlation: e.Confidence,
		Limitations: append([]string(nil), e.Limitations...), Refs: b.refs(e.Refs)}
	if n := b.nodes[e.To]; n != nil {
		s.Role, s.Label = n.Kind, n.Label
	}
	return s
}

func refKey(r lineage.Ref) string {
	if r.External != "" {
		return "t:" + r.External
	}
	return "e:" + r.EventID + "|" + r.ArtifactID
}

func citesAny(refs []lineage.Ref, cited map[string]bool) bool {
	for _, r := range refs {
		if cited[refKey(r)] {
			return true
		}
	}
	return false
}

// confidence: the strongest link from the tool call to an independent
// record. Only the agent's own record behind it is "inferred".
func confidence(chain []Step) string {
	best := lineage.AssuranceInferred
	toolSeen := false
	for _, s := range chain {
		if s.Role == lineage.KindToolCall {
			toolSeen = true
			continue
		}
		if !toolSeen || s.Assurance == "" {
			continue
		}
		independent := false
		for _, r := range s.Refs {
			independent = independent || r.Telemetry != ""
		}
		independent = independent || strings.HasPrefix(s.Basis, lineage.BasisOutcomeWitness) || strings.Contains(s.Basis, "host witness:")
		if !independent {
			continue
		}
		switch s.Assurance {
		case lineage.AssuranceVerified:
			best = lineage.AssuranceVerified
		case lineage.AssuranceCorroborated:
			if best == lineage.AssuranceInferred {
				best = lineage.AssuranceCorroborated
			}
		}
	}
	return best
}

// facts lists coverage for the kinds the claim names, the needed one
// first: the correlation's own decision when it recorded one, otherwise
// recomputed from the per-kind coverage with the same rule.
func (b *builder) facts(e schema.Event) []Fact {
	c := b.in.Correlation
	var kinds []string
	switch {
	case e.Command != "":
		kinds = append(kinds, "process")
	case e.NetworkDest != "":
		kinds = append(kinds, "network")
	case e.File != "":
		kinds = append(kinds, "file")
	}
	if e.Command != "" && e.NetworkDest != "" {
		kinds = append(kinds, "network")
	}
	if e.Command != "" && e.File != "" {
		kinds = append(kinds, "file")
	}
	out := []Fact{}
	if c == nil || len(kinds) == 0 {
		return out
	}
	t, okT := parseTS(e.Timestamp)
	window := time.Duration(b.r.Scope.WindowMS) * time.Millisecond
	for i, k := range kinds {
		f := Fact{Kind: k, Needed: i == 0}
		if d, ok := b.decisions[e.EventID]; ok && d.Needs == k {
			f.Coverage, f.Reason, f.Sources, f.Decided = d.Coverage, d.Reason, d.Sources, true
		} else if !okT {
			f.Coverage, f.Reason = "unknown", "the tool call has no usable timestamp"
		} else if len(c.KindCoverage) == 0 {
			f.Coverage, f.Reason = "unknown", "no per-kind coverage recorded for this analysis"
		} else {
			as := correlate.AssessCoverage(c.KindCoverage, e.Host, k, t, window)
			f.Coverage, f.Reason, f.Sources = as.Coverage, as.Reason, as.Sources
		}
		out = append(out, f)
	}
	return out
}

func (b *builder) eventRef(e schema.Event) SourceRef {
	if e.SourceArtifact != "" {
		b.artifacts[e.SourceArtifact] = true
	}
	return SourceRef{ArtifactID: e.SourceArtifact, LogicalPath: e.SourcePath, Line: e.SourceLine, Offset: e.SourceOffset, EventID: e.EventID}
}

func (b *builder) refs(rs []lineage.Ref) []SourceRef {
	var out []SourceRef
	for _, r := range rs {
		s := SourceRef{ArtifactID: r.ArtifactID, LogicalPath: r.Path, Line: r.Line, Offset: r.Offset, EventID: r.EventID, Telemetry: r.External}
		if r.ArtifactID != "" {
			b.artifacts[r.ArtifactID] = true
		}
		if r.External != "" {
			if f := b.refFile[r.External]; f != "" {
				s.TelemetryFile = f
				if hs := b.fileHash[f]; len(hs) == 1 {
					s.TelemetrySHA256 = hs[0]
				}
			}
		}
		out = append(out, s)
	}
	return out
}

func (b *builder) finishArtifacts() {
	byID := map[string]casepkg.ArtifactRecord{}
	if m := b.in.Manifest; m != nil {
		for _, a := range m.Artifacts {
			if a.ArtifactID != "" {
				byID[a.ArtifactID] = a
			}
		}
	}
	ids := make([]string, 0, len(b.artifacts))
	for id := range b.artifacts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	missing := 0
	for _, id := range ids {
		a, ok := byID[id]
		b.r.Artifacts = append(b.r.Artifacts, Artifact{ArtifactID: id, LogicalPath: a.LogicalPath, Size: a.Size, InManifest: ok})
		if !ok {
			missing++
		}
	}
	if missing > 0 {
		b.r.Notes = append(b.r.Notes, fmt.Sprintf("%d cited artifact id(s) are not in the package manifest", missing))
	}
}

// SHA256 is the hex SHA-256 of b.
func SHA256(data []byte) string {
	s := sha256.Sum256(data)
	return hex.EncodeToString(s[:])
}

func parseTS(s string) (time.Time, bool) {
	for _, l := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(l, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func sortedSet(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
