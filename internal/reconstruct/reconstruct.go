// Package reconstruct merges one or more analyzed cases into a single
// incident reconstruction: one timeline across hosts, agents, sessions and
// users; who delegated to whom; where a session was handed off (resumed in
// another file, continued on another host, the same conversation in a
// cloud export and an endpoint transcript, a git branch pushed here and
// pulled there); what links the hosts; the attack stages in kill-chain
// order; and, for every segment and stage, the telemetry that would
// confirm or refute it.
//
// It is assembly, not a new engine. Delegation comes from the lineage
// graph, shared destinations, credentials, instruction files and MCP
// packages from crosscase, coverage and what to collect next from gaps,
// stage material from the attack-chain findings. What this package adds
// is the join between cases and the ordering.
//
// Two rules decide every link. Identities stay separate: a host, an OS
// user, a session or an agent belongs to its case, and two cases' entities
// are joined only by an identifier the evidence carries (the same session
// id, a named session in a resume command, an account email or uuid, a
// full commit id). And every edge between attack stages is labeled:
// verified when explicit evidence connects the two (the same session, the
// same agent lineage, the same process lineage, one chain finding, a
// session handed off by id), inferred when only order in time and shared
// attributes do. The two are never mixed.
//
// Nothing here writes prose about the incident. The JSON document is the
// input a narrative layer would consume; see Narrative.
package reconstruct

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/chain"
	"github.com/efij/AgentDFIR/v5/internal/correlate"
	"github.com/efij/AgentDFIR/v5/internal/crosscase"
	"github.com/efij/AgentDFIR/v5/internal/detect"
	"github.com/efij/AgentDFIR/v5/internal/gaps"
	"github.com/efij/AgentDFIR/v5/internal/lineage"
	"github.com/efij/AgentDFIR/v5/internal/netdest"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// Schema identifies the document this package writes.
const Schema = "agentdfir.reconstruct/1"

// OverlayFile is the explorer overlay, under each input case's normalized/.
const OverlayFile = "reconstruct.json"

// Link classes.
const (
	Verified   = "verified"
	Inferred   = "inferred"
	Unresolved = "unresolved" // a delegation whose other end is not in the evidence
)

// CaseInput is one analyzed case, as LoadInput reads it.
type CaseInput struct {
	Label       string // C1, C2, … in argument order
	Path        string
	CaseID      string
	Host        string
	OS          string
	OSUsers     []string
	Integrity   string // VERIFIED | FAILED
	Events      []schema.Event
	Findings    []schema.Finding
	Correlation *correlate.EndpointResult
	Coverage    *gaps.Report
	Lineage     *lineage.Graph
}

// Input is everything a reconstruction is built from.
type Input struct {
	Cases []CaseInput
	// Cross is what the cases share (nil for one case).
	Cross *crosscase.Report
	Notes []string
}

// Options bound the output. Zero values take the defaults.
type Options struct {
	AllowUnverified bool // load packages whose seal does not verify; every result is marked
	IncludeCommon   bool // compare allowlisted destinations too (crosscase)
	MaxTimeline     int  // default 5000
	MaxStageItems   int  // default 500
	MaxMissing      int  // default 500
	// Verify checks one package; nil uses the full seal check.
	Verify func(pkg string) crosscase.Integrity
}

func (o *Options) defaults() {
	if o.MaxTimeline <= 0 {
		o.MaxTimeline = 5000
	}
	if o.MaxStageItems <= 0 {
		o.MaxStageItems = 500
	}
	if o.MaxMissing <= 0 {
		o.MaxMissing = 500
	}
}

// Report is the reconstruct document (JSON and normalized/reconstruct.json).
type Report struct {
	Schema      string         `json:"schema"`
	Unverified  bool           `json:"includes_unverified_cases"`
	Summary     Summary        `json:"summary"`
	Cases       []Case         `json:"cases"`
	Identities  Identities     `json:"identities"`
	Segments    []Segment      `json:"segments"`
	Timeline    []Entry        `json:"timeline"`
	Delegations []Delegation   `json:"delegations"`
	Handoffs    []Handoff      `json:"handoffs"`
	Links       []Link         `json:"cross_host_links"`
	Stages      []StageSummary `json:"stages"`
	StageItems  []StageItem    `json:"stage_items"`
	StageEdges  []StageEdge    `json:"stage_edges"`
	Missing     []Missing      `json:"missing_evidence"`
	Narrative   Narrative      `json:"narrative"`
	Omitted     map[string]int `json:"omitted,omitempty"`
	Notes       []string       `json:"notes"`
	Limits      []string       `json:"limits"`
}

// Summary counts the report.
type Summary struct {
	Cases           int `json:"cases"`
	Hosts           int `json:"hosts"`
	Sessions        int `json:"sessions"`
	Agents          int `json:"agents"`
	Segments        int `json:"segments"`
	TimelineEntries int `json:"timeline_entries"`
	Delegations     int `json:"delegations"`
	Handoffs        int `json:"handoffs"`
	Links           int `json:"cross_host_links"`
	StageItems      int `json:"stage_items"`
	VerifiedEdges   int `json:"stage_edges_verified"`
	InferredEdges   int `json:"stage_edges_inferred"`
	Unstaged        int `json:"high_findings_unstaged,omitempty"`
	Missing         int `json:"missing_evidence"`
}

// Case is one input package.
type Case struct {
	Label     string   `json:"label"`
	Path      string   `json:"path"`
	PackageID string   `json:"package_id"` // the case id the package was sealed with
	Host      string   `json:"host"`
	HostID    string   `json:"host_entity"` // label:host, never merged across cases
	OS        string   `json:"os,omitempty"`
	OSUsers   []string `json:"os_users"`
	Integrity string   `json:"integrity"`
	Events    int      `json:"events"`
	Findings  int      `json:"findings"`
	// Telemetry names the second witnesses the case was analyzed with
	// (from coverage.json); empty means none.
	Telemetry      []string `json:"telemetry"`
	TelemetryStart string   `json:"telemetry_start,omitempty"`
	TelemetryEnd   string   `json:"telemetry_end,omitempty"`
}

// Identities lists the entities that stay separate and the exact
// identifiers that tie some of them together.
type Identities struct {
	Hosts []HostEntity             `json:"hosts"`
	Links []crosscase.IdentityLink `json:"identity_links"`
	Notes []string                 `json:"notes"`
}

// HostEntity is one case's host.
type HostEntity struct {
	ID      string   `json:"id"`
	Case    string   `json:"case"`
	Name    string   `json:"name"`
	OSUsers []string `json:"os_users"`
}

// Segment is one agent's recording in one session from one source file
// in one case: the unit the timeline, delegation and hand-offs join.
type Segment struct {
	ID          string `json:"id"`
	Case        string `json:"case"`
	PackageID   string `json:"package_id"`
	Host        string `json:"host"`
	User        string `json:"user,omitempty"`
	Session     string `json:"session_id"`
	Agent       string `json:"agent_id"`
	Product     string `json:"product,omitempty"`
	Source      string `json:"source_logical_path,omitempty"`
	ParentAgent string `json:"parent_agent_id,omitempty"` // from the lineage graph
	Start       string `json:"start,omitempty"`
	End         string `json:"end,omitempty"`
	Events      int    `json:"events"`
	ToolCalls   int    `json:"tool_calls"`
	Untimed     int    `json:"events_without_timestamp,omitempty"`
	Findings    int    `json:"findings"`
	// Telemetry is the endpoint coverage of the segment's tool calls:
	// full | partial | none (from coverage.json activity ranges), or
	// not_applicable when it made none.
	Telemetry string `json:"endpoint_coverage"`
	FirstRef  string `json:"first_ref,omitempty"`
	LastRef   string `json:"last_ref,omitempty"`
	activity  int    // prompts, responses, tool calls, messages: not index or metadata records
}

// Entry is one line of the merged timeline.
type Entry struct {
	Seq        int    `json:"seq"`
	Time       string `json:"time,omitempty"`
	TimeSource string `json:"time_source"` // transcript | provider_export… | finding | none
	Case       string `json:"case"`
	PackageID  string `json:"package_id"`
	Host       string `json:"host"`
	User       string `json:"user,omitempty"`
	Session    string `json:"session_id,omitempty"`
	Agent      string `json:"agent_id,omitempty"`
	Product    string `json:"product,omitempty"`
	Segment    string `json:"segment"`
	Kind       string `json:"kind"` // an event type, or "finding"
	Summary    string `json:"summary"`
	State      string `json:"evidence_state,omitempty"`
	EventID    string `json:"event_id,omitempty"`
	RuleID     string `json:"rule_id,omitempty"`
	Severity   string `json:"severity,omitempty"`
	Ref        string `json:"source_ref"`
}

// Delegation is a parent agent starting another agent.
type Delegation struct {
	Case          string   `json:"case"`
	Kind          string   `json:"kind"` // subagent | agent_cli
	Parent        string   `json:"parent_agent_id"`
	Child         string   `json:"child_agent_id,omitempty"`
	ParentSegment string   `json:"parent_segment,omitempty"`
	ChildSegment  string   `json:"child_segment,omitempty"`
	Session       string   `json:"session_id,omitempty"`
	ToolCallID    string   `json:"tool_call_id,omitempty"`
	Time          string   `json:"time,omitempty"`
	Link          string   `json:"link"` // verified | inferred | unresolved
	Basis         string   `json:"basis"`
	State         string   `json:"evidence_state,omitempty"`
	Refs          []string `json:"source_refs"`
}

// Hand-off kinds.
const (
	HandoffFiles   = "session_resumed_across_files"
	HandoffHosts   = "session_continued_across_hosts"
	HandoffExport  = "session_in_export_and_transcript"
	HandoffCommand = "session_resumed_by_command"
	HandoffBranch  = "git_branch"
	HandoffCommit  = "git_commit"
)

// Handoff is one session or work item passing from one segment to another.
type Handoff struct {
	Kind     string   `json:"kind"`
	Key      string   `json:"key"` // the session id, branch or commit
	From     string   `json:"from_segment"`
	To       string   `json:"to_segment"`
	FromCase string   `json:"from_case"`
	ToCase   string   `json:"to_case"`
	FromTime string   `json:"from_time,omitempty"`
	ToTime   string   `json:"to_time,omitempty"`
	Relation string   `json:"relation,omitempty"` // continued | overlapping
	Link     string   `json:"link"`
	Basis    string   `json:"basis"`
	Refs     []string `json:"source_refs"`
}

// Link is an item two or more cases share, placed on the segments that
// reference it where the reference is to a recorded event.
type Link struct {
	Kind     string   `json:"kind"` // a crosscase kind
	Key      string   `json:"key"`
	Display  string   `json:"display"`
	Class    string   `json:"class"` // shared_attribute | identity
	Cases    []string `json:"cases"`
	Segments []string `json:"segments,omitempty"`
	Basis    string   `json:"basis"`
	Note     string   `json:"note,omitempty"`
}

// StageSummary is one stage and its items, in stage order.
type StageSummary struct {
	Stage string   `json:"stage"`
	Order int      `json:"order"`
	Items []string `json:"items"`
	Cases []string `json:"cases"`
}

// StageItem is one finding (or one step of an attack-chain finding) placed
// in a stage.
type StageItem struct {
	ID        string `json:"id"`
	Stage     string `json:"stage"`
	Case      string `json:"case"`
	Host      string `json:"host"`
	Segment   string `json:"segment,omitempty"`
	Session   string `json:"session_id,omitempty"`
	Agent     string `json:"agent_id,omitempty"`
	RuleID    string `json:"rule_id"`
	Severity  string `json:"severity"`
	Title     string `json:"title"`
	Step      string `json:"chain_step,omitempty"`
	Technique string `json:"mitre_attack,omitempty"`
	Source    string `json:"placed_by"` // chain_step | technique
	Time      string `json:"time,omitempty"`
	EventID   string `json:"event_id,omitempty"`
	State     string `json:"evidence_state,omitempty"`
	Ref       string `json:"source_ref,omitempty"`
	finding   int    // index of the finding within its case
}

// StageEdge orders two stage items. Verified and inferred edges are never
// merged: the label is the point.
type StageEdge struct {
	From      string `json:"from"`
	To        string `json:"to"`
	FromStage string `json:"from_stage"`
	ToStage   string `json:"to_stage"`
	Link      string `json:"link"` // verified | inferred
	Basis     string `json:"basis"`
	Seconds   int64  `json:"seconds_between"`
	CrossHost bool   `json:"cross_host"`
}

// Missing is one thing the reconstruction cannot establish, and what
// would establish it.
type Missing struct {
	Scope    string   `json:"scope"` // case | segment | stage_item | stage_edge | delegation | handoff
	Target   string   `json:"target"`
	Case     string   `json:"case,omitempty"`
	Host     string   `json:"host,omitempty"`
	Status   string   `json:"status"` // unknown | verify_next
	Category string   `json:"category"`
	Text     string   `json:"text"`
	Collect  string   `json:"collect,omitempty"`
	Source   string   `json:"source"` // coverage.json | reconstruct
	Refs     []string `json:"evidence_refs,omitempty"`
}

// Narrative is the documented extension point for a prose layer. None is
// implemented: every field here is fixed.
type Narrative struct {
	Implemented bool   `json:"implemented"`
	Input       string `json:"input"`
	Requirement string `json:"requirement"`
}

var narrative = Narrative{
	Implemented: false,
	Input:       "this document (schema " + Schema + "): segments, timeline, delegations, handoffs, cross_host_links, stage_items, stage_edges, missing_evidence",
	Requirement: "Any narrative produced from this document is not evidence. It must be labeled NON-EVIDENCE wherever it is shown, cite the segment, timeline seq, stage item and edge ids it rests on, keep verified and inferred links distinct, and never state as fact anything this document lists as inferred or missing.",
}

// ---- build

type builder struct {
	in  Input
	o   Options
	rep *Report

	cases []*caseState
	segs  map[string]*Segment // id → segment
	// handoffSessions marks (case|session) pairs joined to another case's
	// same session by a verified hand-off.
	handoff map[string][]string
	// shared network destinations, per case, and the shared items that
	// join two cases.
	sharedNet  map[string]bool
	caseShares map[[2]string][]string
	destSegs   map[string]map[string]bool // shared destination → segments naming it
}

type caseState struct {
	in      *CaseInput
	byID    map[string]int    // event id → index
	refIdx  map[string]string // evidence ref → event id
	segOf   []string          // event index → segment id
	parent  map[string]string // child agent → parent agent (lineage)
	procOf  map[string][]string
	procKid map[string][]string
}

// Build computes the reconstruction from loaded cases. It never fails:
// what cannot be computed becomes a note or a missing-evidence item.
func Build(in Input, o Options) *Report {
	o.defaults()
	b := &builder{in: in, o: o, segs: map[string]*Segment{}, handoff: map[string][]string{},
		sharedNet: map[string]bool{}, caseShares: map[[2]string][]string{}}
	b.rep = &Report{Schema: Schema, Cases: []Case{}, Segments: []Segment{}, Timeline: []Entry{}, Delegations: []Delegation{},
		Handoffs: []Handoff{}, Links: []Link{}, Stages: []StageSummary{}, StageItems: []StageItem{}, StageEdges: []StageEdge{},
		Missing: []Missing{}, Narrative: narrative, Notes: append([]string{}, in.Notes...),
		Identities: Identities{Hosts: []HostEntity{}, Links: []crosscase.IdentityLink{}, Notes: []string{}}}
	for i := range in.Cases {
		b.cases = append(b.cases, b.index(&in.Cases[i]))
	}
	b.caseInfo()
	b.segments()
	b.shared()
	b.timeline()
	b.delegations()
	b.handoffs()
	b.links()
	b.stages()
	b.missing()
	b.finish()
	return b.rep
}

func (b *builder) index(ci *CaseInput) *caseState {
	cs := &caseState{in: ci, byID: make(map[string]int, len(ci.Events)), refIdx: chain.RefIndex(ci.Events),
		segOf: make([]string, len(ci.Events)), parent: map[string]string{}, procOf: map[string][]string{}, procKid: map[string][]string{}}
	for i, e := range ci.Events {
		cs.byID[e.EventID] = i
	}
	if g := ci.Lineage; g != nil {
		for _, e := range g.Edges {
			switch e.Relation {
			case "spawned":
				c, p := strings.TrimPrefix(e.To, "agent:"), strings.TrimPrefix(e.From, "agent:")
				if _, ok := cs.parent[c]; !ok && c != p {
					cs.parent[c] = p
				}
			case "executed_as":
				cs.procOf[strings.TrimPrefix(e.From, "tool:")] = append(cs.procOf[strings.TrimPrefix(e.From, "tool:")], e.To)
			case "child_process":
				cs.procKid[e.From] = append(cs.procKid[e.From], e.To)
			}
		}
	}
	return cs
}

func (b *builder) caseInfo() {
	names := map[string][]string{}
	for _, cs := range b.cases {
		ci := cs.in
		c := Case{Label: ci.Label, Path: ci.Path, PackageID: ci.CaseID, Host: ci.Host, HostID: hostID(ci), OS: ci.OS,
			OSUsers: nonNil(ci.OSUsers), Integrity: ci.Integrity, Events: len(ci.Events), Findings: len(ci.Findings), Telemetry: []string{}}
		if ci.Integrity != "" && ci.Integrity != "VERIFIED" {
			b.rep.Unverified = true
		}
		if cov := ci.Coverage; cov != nil {
			for _, s := range cov.Witness.Sources {
				c.Telemetry = append(c.Telemetry, s.Name)
			}
		}
		if cr := ci.Correlation; cr != nil && cr.Records > 0 {
			if !cr.CoverageStart.IsZero() {
				c.TelemetryStart, c.TelemetryEnd = rfc(cr.CoverageStart), rfc(cr.CoverageEnd)
			}
		}
		b.rep.Cases = append(b.rep.Cases, c)
		b.rep.Identities.Hosts = append(b.rep.Identities.Hosts, HostEntity{ID: c.HostID, Case: ci.Label, Name: ci.Host, OSUsers: c.OSUsers})
		names[strings.ToLower(ci.Host)] = append(names[strings.ToLower(ci.Host)], ci.Label)
	}
	for _, n := range sortedKeys(names) {
		if l := names[n]; len(l) > 1 {
			b.rep.Identities.Notes = append(b.rep.Identities.Notes, fmt.Sprintf("cases %s carry the same host name %q; they stay separate host entities (a host name is not a machine identifier, and two packages can be copies of one machine's evidence)",
				strings.Join(l, ", "), n))
		}
	}
	if b.in.Cross != nil {
		b.rep.Identities.Links = append(b.rep.Identities.Links, b.in.Cross.Links...)
	}
}

func hostID(ci *CaseInput) string {
	h := ci.Host
	if h == "" {
		h = "unknown-host"
	}
	return ci.Label + ":" + h
}

// ---- segments

type segKey struct{ session, agent, source string }

func (b *builder) segments() {
	for _, cs := range b.cases {
		ci := cs.in
		groups := map[segKey][]int{}
		var order []segKey
		for i, e := range ci.Events {
			k := segKey{e.SessionID, e.AgentID, e.SourcePath}
			if _, ok := groups[k]; !ok {
				order = append(order, k)
			}
			groups[k] = append(groups[k], i)
		}
		// Sources of one (session, agent) are numbered in time order so a
		// resumed session reads @1, @2 the way it happened.
		type sa struct{ session, agent string }
		perSA := map[sa][]segKey{}
		for _, k := range order {
			perSA[sa{k.session, k.agent}] = append(perSA[sa{k.session, k.agent}], k)
		}
		first := func(k segKey) (time.Time, string) {
			var best time.Time
			for _, i := range groups[k] {
				if t, ok := parseTS(ci.Events[i].Timestamp); ok && (best.IsZero() || t.Before(best)) {
					best = t
				}
			}
			return best, k.source
		}
		for key, ks := range perSA {
			sort.SliceStable(ks, func(i, j int) bool {
				ti, si := first(ks[i])
				tj, sj := first(ks[j])
				if !ti.Equal(tj) {
					if ti.IsZero() || tj.IsZero() {
						return tj.IsZero()
					}
					return ti.Before(tj)
				}
				return si < sj
			})
			for n, k := range ks {
				id := ci.Label + "/" + orDash(key.session) + "/" + orDash(key.agent)
				if len(ks) > 1 {
					id += fmt.Sprintf("@%d", n+1)
				}
				b.makeSegment(cs, id, k, groups[k])
			}
		}
		for _, f := range ci.Findings {
			if id := b.findingSegment(cs, f); id != "" {
				b.segs[id].Findings++
			}
		}
	}
}

func (b *builder) makeSegment(cs *caseState, id string, k segKey, idx []int) {
	ci := cs.in
	s := &Segment{ID: id, Case: ci.Label, PackageID: ci.CaseID, Host: ci.Host, Session: k.session, Agent: k.agent, Source: k.source,
		ParentAgent: cs.parent[k.agent], Telemetry: "not_applicable"}
	var start, end time.Time
	var firstEv, lastEv *schema.Event
	for _, i := range idx {
		e := &ci.Events[i]
		cs.segOf[i] = id
		s.Events++
		if s.Product == "" {
			s.Product = e.Product
		}
		if s.User == "" {
			s.User = e.User
		}
		if e.EventType == schema.EventToolCall {
			s.ToolCalls++
		}
		if e.EventType != schema.EventSessionMeta && e.EventType != schema.EventTraceGap {
			s.activity++
		}
		t, ok := parseTS(e.Timestamp)
		if !ok {
			s.Untimed++
			continue
		}
		if start.IsZero() || t.Before(start) {
			start, firstEv = t, e
		}
		if t.After(end) || end.IsZero() {
			end, lastEv = t, e
		}
	}
	if !start.IsZero() {
		s.Start, s.End = rfc(start), rfc(end)
	}
	if firstEv != nil {
		s.FirstRef, s.LastRef = gaps.Ref(*firstEv), gaps.Ref(*lastEv)
	} else if len(idx) > 0 {
		s.FirstRef = gaps.Ref(ci.Events[idx[0]])
	}
	if s.ToolCalls > 0 {
		s.Telemetry = segmentCoverage(ci, start, end)
	}
	b.segs[id] = s
}

// segmentCoverage reads the endpoint coverage of a time span from the
// activity ranges coverage.json computed; a case with no telemetry at all
// is "none".
func segmentCoverage(ci *CaseInput, start, end time.Time) string {
	if ci.Coverage == nil {
		if ci.Correlation == nil || ci.Correlation.Records == 0 {
			return "none"
		}
		return "unknown"
	}
	worst := ""
	rank := map[string]int{"full": 0, "partial": 1, "none": 2}
	for _, r := range ci.Coverage.Witness.Activity {
		rs, ok1 := parseTS(r.Start)
		re, ok2 := parseTS(r.End)
		if !ok1 || !ok2 || start.IsZero() || re.Before(start) || rs.After(end) {
			continue
		}
		if worst == "" || rank[r.Coverage] > rank[worst] {
			worst = r.Coverage
		}
	}
	if worst == "" {
		if ci.Correlation == nil || ci.Correlation.Records == 0 {
			return "none"
		}
		return "unknown"
	}
	return worst
}

// findingSegment places a finding on the segment of the first event it
// cites, or of its session and agent.
func (b *builder) findingSegment(cs *caseState, f schema.Finding) string {
	if i, ok := b.findingEvent(cs, f); ok {
		return cs.segOf[i]
	}
	return ""
}

func (b *builder) findingEvent(cs *caseState, f schema.Finding) (int, bool) {
	for _, st := range f.ChainSteps {
		if i, ok := cs.byID[st.EventID]; ok {
			return i, true
		}
	}
	for _, r := range f.EvidenceRefs {
		if id := chain.EventForRef(cs.refIdx, r); id != "" {
			if i, ok := cs.byID[id]; ok {
				return i, true
			}
		}
	}
	return 0, false
}

// ---- shared items between cases

func (b *builder) shared() {
	if b.in.Cross == nil {
		return
	}
	for _, s := range b.in.Cross.Shared {
		if s.Kind == crosscase.KindNetwork {
			b.sharedNet[s.Key] = true
		}
		for i := range s.Cases {
			for j := i + 1; j < len(s.Cases); j++ {
				k := [2]string{s.Cases[i].Case, s.Cases[j].Case}
				if k[0] > k[1] {
					k[0], k[1] = k[1], k[0]
				}
				if s.Kind == crosscase.KindHostName || s.Kind == crosscase.KindSession {
					continue
				}
				b.caseShares[k] = append(b.caseShares[k], s.Kind+" "+s.Display)
			}
		}
	}
}

// ---- timeline

var timelineKinds = map[string]bool{schema.EventHumanPrompt: true, schema.EventAgentMessage: true, schema.EventToolCall: true, schema.EventAgentSpawn: true}

type tEntry struct {
	e   Entry
	t   time.Time
	seq int
}

func (b *builder) timeline() {
	var all []tEntry
	for _, cs := range b.cases {
		ci := cs.in
		for i, e := range ci.Events {
			if !timelineKinds[e.EventType] {
				continue
			}
			en := Entry{Time: e.Timestamp, TimeSource: e.TimestampSrc, Case: ci.Label, PackageID: ci.CaseID, Host: ci.Host, User: e.User,
				Session: e.SessionID, Agent: e.AgentID, Product: e.Product, Segment: cs.segOf[i], Kind: e.EventType,
				Summary: eventSummary(e), State: e.Corroboration, EventID: e.EventID, Ref: gaps.Ref(e)}
			t, ok := parseTS(e.Timestamp)
			switch {
			case !ok:
				en.Time, en.TimeSource = "", "none"
			case en.TimeSource == "":
				en.Time, en.TimeSource = rfcNano(t), "recorded"
			default:
				en.Time = rfcNano(t)
			}
			all = append(all, tEntry{en, t, e.Sequence})
		}
		for _, f := range ci.Findings {
			en := Entry{TimeSource: "finding", Case: ci.Label, PackageID: ci.CaseID, Host: ci.Host, Session: f.SessionID, Agent: f.AgentID,
				Kind: "finding", Summary: detect.MaskTruncate(f.Title, 160), State: f.Status, RuleID: f.RuleID, Severity: f.Severity}
			if len(f.EvidenceRefs) > 0 {
				en.Ref = detect.MaskSecrets(f.EvidenceRefs[0])
			}
			stamp := f.Timestamp
			if i, ok := b.findingEvent(cs, f); ok {
				ev := ci.Events[i]
				en.Segment, en.EventID, en.User, en.Product = cs.segOf[i], ev.EventID, ev.User, ev.Product
				if en.Session == "" {
					en.Session, en.Agent = ev.SessionID, ev.AgentID
				}
				if stamp == "" {
					// The finding carries no time of its own: it is placed at
					// the event it cites, and says so.
					stamp, en.TimeSource = ev.Timestamp, "cited_event"
				}
			}
			t, ok := parseTS(stamp)
			if ok {
				en.Time = rfcNano(t)
			} else {
				en.TimeSource = "none"
			}
			all = append(all, tEntry{en, t, 1 << 30})
		}
	}
	sort.SliceStable(all, func(i, j int) bool {
		a, c := all[i], all[j]
		if a.t.IsZero() != c.t.IsZero() {
			return !a.t.IsZero()
		}
		if !a.t.Equal(c.t) {
			return a.t.Before(c.t)
		}
		if a.e.Case != c.e.Case {
			return a.e.Case < c.e.Case
		}
		if a.e.Session != c.e.Session {
			return a.e.Session < c.e.Session
		}
		if a.e.Agent != c.e.Agent {
			return a.e.Agent < c.e.Agent
		}
		if a.seq != c.seq {
			return a.seq < c.seq
		}
		if a.e.EventID != c.e.EventID {
			return a.e.EventID < c.e.EventID
		}
		return a.e.RuleID+a.e.Ref < c.e.RuleID+c.e.Ref
	})
	if len(all) > b.o.MaxTimeline {
		b.omit("timeline", len(all)-b.o.MaxTimeline)
		all = all[:b.o.MaxTimeline]
	}
	for i, te := range all {
		te.e.Seq = i + 1
		b.rep.Timeline = append(b.rep.Timeline, te.e)
	}
}

func eventSummary(e schema.Event) string {
	switch e.EventType {
	case schema.EventToolCall:
		s := e.Tool
		switch {
		case e.FullCommand() != "":
			s += ": " + detect.MaskTruncate(e.FullCommand(), 160)
		case e.File != "":
			s += ": " + detect.MaskTruncate(e.File, 160)
		case e.NetworkDest != "":
			s += ": " + detect.MaskTruncate(e.NetworkDest, 160)
		case e.MCPServer != "":
			s += " (MCP " + detect.MaskTruncate(e.MCPServer, 60) + ")"
		}
		return s
	case schema.EventAgentSpawn:
		if e.TaskID != "" {
			return "spawned " + e.TaskID
		}
	}
	return detect.MaskTruncate(e.Summary, 160)
}

// ---- delegation

// agentCLIRe finds an agent CLI launched from a shell command; resumeRe
// the session it names, when it names one.
var (
	agentCLIRe = regexp.MustCompile(`(?:^|[\s;&|/(])(claude|codex|gemini|cursor-agent|copilot)(?:\s|$)`)
	resumeRe   = regexp.MustCompile(`(?:--resume|--session-id|-r|\bresume)(?:\s+|=)["']?([0-9A-Za-z][0-9A-Za-z_-]{7,})`)
)

func (b *builder) delegations() {
	for _, cs := range b.cases {
		ci := cs.in
		if g := ci.Lineage; g != nil {
			for _, e := range g.Edges {
				if e.Relation != "spawned" {
					continue
				}
				parent, child := strings.TrimPrefix(e.From, "agent:"), strings.TrimPrefix(e.To, "agent:")
				d := Delegation{Case: ci.Label, Kind: "subagent", Parent: parent, Child: child, Link: Verified, Basis: e.Basis, State: e.State, Refs: []string{}}
				if strings.HasPrefix(e.Note, "tool_use_id ") {
					d.ToolCallID = strings.TrimPrefix(e.Note, "tool_use_id ")
				}
				for _, r := range e.Refs {
					d.Refs = append(d.Refs, r.String())
					if i, ok := cs.byID[r.EventID]; ok && d.ParentSegment == "" {
						ev := ci.Events[i]
						d.Session = ev.SessionID
						if t, ok := parseTS(ev.Timestamp); ok {
							d.Time = rfc(t)
						}
						if ev.AgentID == parent {
							d.ParentSegment = cs.segOf[i]
						}
					}
				}
				if d.ParentSegment == "" {
					d.ParentSegment = b.firstSegment(ci.Label, parent, "")
				}
				d.ChildSegment = b.firstSegment(ci.Label, child, "")
				if d.ChildSegment == "" {
					d.Link = Unresolved
					d.Basis += "; the child agent has no records in this case"
				}
				b.rep.Delegations = append(b.rep.Delegations, d)
			}
		}
		b.cliLaunches(cs)
	}
}

// cliLaunches finds agent CLIs started from a shell tool call: a nested,
// separate agent session.
func (b *builder) cliLaunches(cs *caseState) {
	ci := cs.in
	n := 0
	for i, e := range ci.Events {
		if e.EventType != schema.EventToolCall || e.Action != "shell_execution" {
			continue
		}
		cmd := e.FullCommand()
		m := agentCLIRe.FindStringSubmatch(cmd)
		if m == nil {
			continue
		}
		if n++; n > 200 {
			b.omit("agent_cli_launches", 1)
			continue
		}
		launch, _ := parseTS(e.Timestamp)
		ref := gaps.Ref(e)
		if r := resumeRe.FindStringSubmatch(cmd); r != nil {
			// Resuming a named session is a hand-off, not a new agent.
			to := b.sessionSegments(r[1])
			h := Handoff{Kind: HandoffCommand, Key: r[1], From: cs.segOf[i], FromCase: ci.Label, FromTime: rfcOpt(launch), Refs: []string{ref}}
			if len(to) == 0 {
				h.Link = Unresolved
				h.Basis = "the command names session " + r[1] + "; no transcript of that session is in the evidence"
			} else {
				h.To, h.ToCase, h.ToTime = to[0].ID, to[0].Case, to[0].Start
				h.Link = Verified
				h.Basis = "the recorded command names session " + r[1] + " (" + m[1] + " resume)"
			}
			b.rep.Handoffs = append(b.rep.Handoffs, h)
			continue
		}
		d := Delegation{Case: ci.Label, Kind: "agent_cli", Parent: e.AgentID, ParentSegment: cs.segOf[i], Session: e.SessionID,
			ToolCallID: e.ToolCallID, Time: rfcOpt(launch), State: e.Corroboration, Refs: []string{ref}}
		// The child is the first session of that CLI's product to start on
		// the same host within two minutes of the launch: an inference
		// from order in time, labeled so.
		var best *Segment
		var bestT time.Time
		for _, s := range b.segs {
			if s.Case != ci.Label || s.Session == e.SessionID || !strings.HasPrefix(s.Agent, "main:") || !strings.Contains(strings.ToLower(s.Product), m[1]) {
				continue
			}
			st, ok := parseTS(s.Start)
			if !ok || launch.IsZero() || st.Before(launch) || st.Sub(launch) > 2*time.Minute {
				continue
			}
			if best == nil || st.Before(bestT) || (st.Equal(bestT) && s.ID < best.ID) {
				best, bestT = s, st
			}
		}
		if best != nil {
			d.Child, d.ChildSegment, d.Link = best.Agent, best.ID, Inferred
			d.Basis = fmt.Sprintf("the recorded command launches %s; a %s session started %s later on the same host (order in time only: no session id ties them)",
				m[1], best.Product, bestT.Sub(launch))
		} else {
			d.Link = Unresolved
			d.Basis = "the recorded command launches " + m[1] + "; no session of it starting within two minutes is in this case"
		}
		b.rep.Delegations = append(b.rep.Delegations, d)
	}
}

func (b *builder) firstSegment(label, agent, session string) string {
	var best *Segment
	for _, s := range b.segs {
		if s.Case != label || s.Agent != agent || (session != "" && s.Session != session) {
			continue
		}
		if best == nil || segLess(s, best) {
			best = s
		}
	}
	if best == nil {
		return ""
	}
	return best.ID
}

// sessionSegments lists every main-agent segment of a session id, in
// every case, earliest first.
func (b *builder) sessionSegments(session string) []*Segment {
	var out []*Segment
	for _, s := range b.segs {
		if s.Session == session && strings.HasPrefix(s.Agent, "main:") {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return segLess(out[i], out[j]) })
	return out
}

func segLess(a, c *Segment) bool {
	ta, oka := parseTS(a.Start)
	tc, okc := parseTS(c.Start)
	if oka != okc {
		return oka
	}
	if oka && !ta.Equal(tc) {
		return ta.Before(tc)
	}
	return a.ID < c.ID
}

// ---- hand-offs

// exportProducts are AI-service account exports: the cloud side of a
// conversation.
var exportProducts = map[string]bool{"chatgpt": true, "claude-ai": true, "deepseek": true, "gemini": true, "ai-export": true}

func isExport(s *Segment) bool {
	return exportProducts[strings.ToLower(s.Product)] || strings.HasPrefix(strings.ToLower(s.Product), "ai-export")
}

func (b *builder) handoffs() {
	// The same session and agent recorded in more than one source: a
	// resume into a new file, a continuation on another host, or the same
	// conversation in a provider export and an endpoint transcript.
	type sa struct{ session, agent string }
	groups := map[sa][]*Segment{}
	for _, s := range b.segs {
		// An index or metadata record naming a session (a sessions list, a
		// history file) is not a recording of it.
		if s.Session == "" || s.Agent == "" || s.activity == 0 {
			continue
		}
		groups[sa{s.Session, s.Agent}] = append(groups[sa{s.Session, s.Agent}], s)
	}
	keys := make([]sa, 0, len(groups))
	for k := range groups {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].session != keys[j].session {
			return keys[i].session < keys[j].session
		}
		return keys[i].agent < keys[j].agent
	})
	for _, k := range keys {
		l := groups[k]
		if len(l) < 2 {
			continue
		}
		sort.Slice(l, func(i, j int) bool { return segLess(l[i], l[j]) })
		for i := 1; i < len(l); i++ {
			from, to := l[i-1], l[i]
			h := Handoff{Key: k.session, From: from.ID, To: to.ID, FromCase: from.Case, ToCase: to.Case, FromTime: from.End, ToTime: to.Start,
				Link: Verified, Refs: compact(from.LastRef, to.FirstRef)}
			switch {
			case isExport(from) != isExport(to):
				h.Kind = HandoffExport
				h.Basis = fmt.Sprintf("the same conversation id %s is recorded in a provider export (%s) and in an endpoint transcript (%s)", k.session, exportOf(from, to), endpointOf(from, to))
			case from.Case != to.Case:
				h.Kind = HandoffHosts
				h.Basis = fmt.Sprintf("the same session id %s is recorded on %s (%s) and %s (%s)", k.session, from.Host, from.Case, to.Host, to.Case)
			default:
				h.Kind = HandoffFiles
				h.Basis = fmt.Sprintf("the same session id %s is recorded in %s and %s", k.session, from.Source, to.Source)
			}
			fe, ok1 := parseTS(from.End)
			ts, ok2 := parseTS(to.Start)
			switch {
			case ok1 && ok2 && !ts.Before(fe):
				h.Relation = "continued"
			case ok1 && ok2:
				h.Relation = "overlapping"
				h.Basis += "; the two recordings overlap in time, so they may be copies of the same evidence rather than a continuation"
			}
			b.rep.Handoffs = append(b.rep.Handoffs, h)
			if from.Case != to.Case {
				b.handoff[from.Case+"|"+k.session] = append(b.handoff[from.Case+"|"+k.session], to.Case)
				b.handoff[to.Case+"|"+k.session] = append(b.handoff[to.Case+"|"+k.session], from.Case)
			}
		}
	}
	b.gitHandoffs()
}

func exportOf(a, c *Segment) string {
	if isExport(a) {
		return a.Product
	}
	return c.Product
}

func endpointOf(a, c *Segment) string {
	if isExport(a) {
		return c.Product
	}
	return a.Product
}

var (
	gitRe    = regexp.MustCompile(`(?:^|[\s;&|(])git\s+(?:-C\s+\S+\s+)?(push|pull|fetch|checkout|switch|clone|cherry-pick|reset|merge|rebase|show|revert)\b([^;&|\n]*)`)
	commitRe = regexp.MustCompile(`\b[0-9a-f]{7,40}\b`)
)

type gitRef struct {
	verb, branch string
	commits      []string
	seg          string
	caseLabel    string
	t            time.Time
	ref          string
}

// gitHandoffs pairs a branch pushed in one case with the same branch
// pulled, fetched or checked out later in another, and a commit id named
// in both.
func (b *builder) gitHandoffs() {
	var refs []gitRef
	for _, cs := range b.cases {
		for i, e := range cs.in.Events {
			if e.EventType != schema.EventToolCall || e.Action != "shell_execution" {
				continue
			}
			t, _ := parseTS(e.Timestamp)
			for _, m := range gitRe.FindAllStringSubmatch(e.FullCommand(), 8) {
				g := gitRef{verb: m[1], seg: cs.segOf[i], caseLabel: cs.in.Label, t: t, ref: gaps.Ref(e)}
				args := positional(m[2])
				switch m[1] {
				case "push":
					if len(args) >= 2 {
						rs := strings.TrimPrefix(args[1], "+")
						if j := strings.LastIndexByte(rs, ':'); j >= 0 {
							rs = rs[j+1:]
						}
						g.branch = strings.TrimPrefix(rs, "refs/heads/")
					}
				case "pull", "fetch":
					if len(args) >= 2 {
						g.branch = args[1]
					}
				case "checkout", "switch":
					if len(args) >= 1 {
						g.branch = args[len(args)-1]
					}
				}
				for _, c := range commitRe.FindAllString(m[2], 4) {
					if strings.Trim(c, "0123456789") != "" {
						g.commits = append(g.commits, c)
					}
				}
				if commitRe.MatchString(g.branch) {
					g.branch = ""
				}
				refs = append(refs, g)
			}
		}
	}
	if len(refs) > 2000 {
		b.omit("git_references", len(refs)-2000)
		refs = refs[:2000]
	}
	seen := map[string]bool{}
	for _, p := range refs {
		for _, q := range refs {
			if p.caseLabel == q.caseLabel || p.t.IsZero() || q.t.IsZero() || !q.t.After(p.t) {
				continue
			}
			if p.verb == "push" && p.branch != "" && p.branch == q.branch && (q.verb == "pull" || q.verb == "fetch" || q.verb == "checkout" || q.verb == "switch") {
				k := "b|" + p.seg + "|" + q.seg + "|" + p.branch
				if !seen[k] {
					seen[k] = true
					b.rep.Handoffs = append(b.rep.Handoffs, Handoff{Kind: HandoffBranch, Key: p.branch, From: p.seg, To: q.seg, FromCase: p.caseLabel, ToCase: q.caseLabel,
						FromTime: rfc(p.t), ToTime: rfc(q.t), Relation: "continued", Link: Inferred,
						Basis: fmt.Sprintf("branch %q pushed in %s, then git %s of the same branch name in %s (a branch name is not unique: no commit id ties them)", p.branch, p.caseLabel, q.verb, q.caseLabel),
						Refs:  []string{p.ref, q.ref}})
				}
			}
			for _, c := range p.commits {
				for _, d := range q.commits {
					if c != d && !(len(c) >= 7 && len(d) >= 7 && (strings.HasPrefix(c, d) || strings.HasPrefix(d, c))) {
						continue
					}
					k := "c|" + p.seg + "|" + q.seg + "|" + c
					if seen[k] {
						continue
					}
					seen[k] = true
					h := Handoff{Kind: HandoffCommit, Key: c, From: p.seg, To: q.seg, FromCase: p.caseLabel, ToCase: q.caseLabel,
						FromTime: rfc(p.t), ToTime: rfc(q.t), Relation: "continued", Refs: []string{p.ref, q.ref}}
					if len(c) >= 12 && len(d) >= 12 {
						h.Link = Verified
						h.Basis = fmt.Sprintf("commit %s is named by git %s in %s and git %s in %s", c, p.verb, p.caseLabel, q.verb, q.caseLabel)
					} else {
						h.Link = Inferred
						h.Basis = fmt.Sprintf("abbreviated commit id %s named in %s and %s (short ids can collide)", c, p.caseLabel, q.caseLabel)
					}
					b.rep.Handoffs = append(b.rep.Handoffs, h)
				}
			}
		}
	}
}

// positional returns the non-flag words of a git argument string.
func positional(s string) []string {
	var out []string
	skip := false
	for _, w := range strings.Fields(s) {
		w = strings.Trim(w, `"'`)
		switch {
		case skip:
			skip = false
		case w == "-b" || w == "-B" || w == "-c" || w == "-C" || w == "-t" || w == "--track" || w == "-o" || w == "--push-option" || w == "--depth":
			if w == "-b" || w == "-B" || w == "-c" || w == "-C" {
				continue // the branch follows and is positional for us
			}
			skip = true
		case strings.HasPrefix(w, "-") || w == "":
		case strings.HasPrefix(w, ">") || strings.HasPrefix(w, "2>"):
			return out
		default:
			out = append(out, w)
		}
	}
	return out
}

// ---- cross-host links

func (b *builder) links() {
	if b.in.Cross == nil {
		return
	}
	for _, s := range b.in.Cross.Shared {
		if s.Kind == crosscase.KindSession {
			continue // reported as hand-offs, with the segments they join
		}
		l := Link{Kind: s.Kind, Key: s.Key, Display: s.Display, Class: "shared_attribute", Note: s.Note,
			Basis: "the same " + strings.ReplaceAll(s.Kind, "_", " ") + " appears in each case (crosscase); a shared attribute links the segments, it does not prove one caused the other"}
		for _, o := range s.Cases {
			l.Cases = append(l.Cases, o.Case)
		}
		switch s.Kind {
		case crosscase.KindAccount:
			l.Class = "identity"
			l.Basis = "an exact account identifier read from each case's login files (crosscase identity rule)"
		case crosscase.KindHostName:
			l.Basis = "the same host name; host entities stay separate"
		case crosscase.KindNetwork:
			l.Segments = b.segmentsNaming(s.Key)
		case crosscase.KindAgent:
			for _, seg := range b.segs {
				if seg.Agent == s.Key {
					l.Segments = append(l.Segments, seg.ID)
				}
			}
			sort.Strings(l.Segments)
		default:
			l.Note = joinNote(l.Note, "a case-level artifact (configuration or file); not tied to one segment")
		}
		b.rep.Links = append(b.rep.Links, l)
	}
}

// segmentsNaming lists the segments whose tool calls name a destination
// host, the way crosscase finds it.
func (b *builder) segmentsNaming(host string) []string {
	if b.destSegs == nil {
		// One pass over every tool call, however many destinations are shared.
		b.destSegs = map[string]map[string]bool{}
		for _, cs := range b.cases {
			for i, e := range cs.in.Events {
				if e.EventType != schema.EventToolCall {
					continue
				}
				dests := netdest.Extract(e.FullCommand())
				if e.NetworkDest != "" {
					dests = append(dests, e.NetworkDest)
				}
				for _, d := range dests {
					h := strings.ToLower(netdest.Host(d))
					if !b.sharedNet[h] {
						continue
					}
					if b.destSegs[h] == nil {
						b.destSegs[h] = map[string]bool{}
					}
					b.destSegs[h][cs.segOf[i]] = true
				}
			}
		}
	}
	return sortedKeys(b.destSegs[strings.ToLower(host)])
}

// ---- attack stages

func (b *builder) stages() {
	var items []StageItem
	seen := map[string]bool{}
	unstaged := 0
	add := func(it StageItem, key string) {
		if seen[key] {
			return
		}
		seen[key] = true
		if len(items) >= b.o.MaxStageItems {
			b.omit("stage_items", 1)
			return
		}
		items = append(items, it)
	}
	for _, cs := range b.cases {
		ci := cs.in
		// Chain findings first: their steps carry the event and the step
		// name, which places each step precisely.
		for fi, f := range ci.Findings {
			if len(f.ChainSteps) == 0 {
				continue
			}
			for _, st := range f.ChainSteps {
				stage := StepStage(st.Step)
				src := "chain_step"
				if stage == "" {
					stage, src = TechniqueStage(f.MitreATTACK), "technique"
				}
				if stage == "" {
					continue
				}
				it := b.item(cs, f, fi, stage, src)
				it.Step, it.EventID = st.Step, st.EventID
				if i, ok := cs.byID[st.EventID]; ok {
					b.placeOnEvent(cs, &it, i)
				} else {
					it.Time = normTime(st.Timestamp)
					it.Ref = detect.MaskSecrets(st.Evidence)
				}
				add(it, ci.Label+"|"+stage+"|"+st.EventID)
			}
		}
		for fi, f := range ci.Findings {
			if len(f.ChainSteps) > 0 || (f.Severity != "HIGH" && f.Severity != "CRITICAL") {
				continue
			}
			stage := TechniqueStage(f.MitreATTACK)
			if stage == "" {
				unstaged++
				continue
			}
			it := b.item(cs, f, fi, stage, "technique")
			key := ci.Label + "|" + stage + "|"
			if i, ok := b.findingEvent(cs, f); ok {
				b.placeOnEvent(cs, &it, i)
				key += ci.Events[i].EventID
			} else {
				it.Time = normTime(f.Timestamp)
				if len(f.EvidenceRefs) > 0 {
					it.Ref = detect.MaskSecrets(f.EvidenceRefs[0])
				}
				key += f.RuleID + "|" + it.Ref
			}
			add(it, key)
		}
	}
	b.rep.Summary.Unstaged = unstaged
	if unstaged > 0 {
		b.rep.Notes = append(b.rep.Notes, fmt.Sprintf("%d HIGH/CRITICAL finding(s) carry no ATT&CK technique this report maps to a stage; they are on the timeline but not in a stage", unstaged))
	}
	sort.SliceStable(items, func(i, j int) bool {
		a, c := items[i], items[j]
		if stageRank[a.Stage] != stageRank[c.Stage] {
			return stageRank[a.Stage] < stageRank[c.Stage]
		}
		ta, oka := parseTS(a.Time)
		tc, okc := parseTS(c.Time)
		if oka != okc {
			return oka
		}
		if oka && !ta.Equal(tc) {
			return ta.Before(tc)
		}
		if a.Case != c.Case {
			return a.Case < c.Case
		}
		if a.RuleID != c.RuleID {
			return a.RuleID < c.RuleID
		}
		return a.EventID+a.Ref < c.EventID+c.Ref
	})
	byStage := map[string]*StageSummary{}
	for i := range items {
		items[i].ID = fmt.Sprintf("S%d", i+1)
		st := byStage[items[i].Stage]
		if st == nil {
			st = &StageSummary{Stage: items[i].Stage, Order: stageRank[items[i].Stage] + 1, Items: []string{}, Cases: []string{}}
			byStage[items[i].Stage] = st
		}
		st.Items = append(st.Items, items[i].ID)
		if !contains(st.Cases, items[i].Case) {
			st.Cases = append(st.Cases, items[i].Case)
		}
	}
	for _, s := range StageOrder {
		if st := byStage[s]; st != nil {
			sort.Strings(st.Cases)
			b.rep.Stages = append(b.rep.Stages, *st)
		}
	}
	b.rep.StageItems = items
	b.stageEdges()
}

func (b *builder) item(cs *caseState, f schema.Finding, fi int, stage, src string) StageItem {
	return StageItem{Stage: stage, Case: cs.in.Label, Host: cs.in.Host, Session: f.SessionID, Agent: f.AgentID, RuleID: f.RuleID,
		Severity: f.Severity, Title: detect.MaskTruncate(f.Title, 160), Technique: f.MitreATTACK, Source: src, State: f.Status, finding: fi}
}

func (b *builder) placeOnEvent(cs *caseState, it *StageItem, i int) {
	ev := cs.in.Events[i]
	it.EventID, it.Segment, it.Session, it.Agent = ev.EventID, cs.segOf[i], ev.SessionID, ev.AgentID
	it.Time = normTime(ev.Timestamp)
	it.State = ev.Corroboration
	it.Ref = gaps.Ref(ev)
}

// stageEdges gives every item at most one predecessor: an item of an
// earlier stage that happened no later. An explicitly linked predecessor
// always wins over one linked by order alone, so an inferred edge appears
// only where no verified one exists.
func (b *builder) stageEdges() {
	items := b.rep.StageItems
	byCase := map[string]*caseState{}
	for _, cs := range b.cases {
		byCase[cs.in.Label] = cs
	}
	for j := range items {
		to := &items[j]
		tj, ok := parseTS(to.Time)
		if !ok {
			continue
		}
		var bestV, bestI *StageItem
		var basisV string
		for i := range items {
			from := &items[i]
			ti, ok := parseTS(from.Time)
			if i == j || !ok || ti.After(tj) || stageRank[from.Stage] >= stageRank[to.Stage] {
				continue
			}
			if basis := b.explicit(byCase, from, to); basis != "" {
				if bestV == nil || later(from, bestV) {
					bestV, basisV = from, basis
				}
				continue
			}
			if bestI == nil || later(from, bestI) {
				bestI = from
			}
		}
		switch {
		case bestV != nil:
			b.rep.StageEdges = append(b.rep.StageEdges, b.edge(bestV, to, Verified, basisV))
		case bestI != nil:
			b.rep.StageEdges = append(b.rep.StageEdges, b.edge(bestI, to, Inferred, b.inferredBasis(bestI, to)))
		}
	}
	for _, e := range b.rep.StageEdges {
		if e.Link == Verified {
			b.rep.Summary.VerifiedEdges++
		} else {
			b.rep.Summary.InferredEdges++
		}
	}
}

func later(a, c *StageItem) bool {
	ta, _ := parseTS(a.Time)
	tc, _ := parseTS(c.Time)
	if !ta.Equal(tc) {
		return ta.After(tc)
	}
	if stageRank[a.Stage] != stageRank[c.Stage] {
		return stageRank[a.Stage] > stageRank[c.Stage]
	}
	return a.ID < c.ID
}

func (b *builder) edge(from, to *StageItem, link, basis string) StageEdge {
	tf, _ := parseTS(from.Time)
	tt, _ := parseTS(to.Time)
	return StageEdge{From: from.ID, To: to.ID, FromStage: from.Stage, ToStage: to.Stage, Link: link, Basis: basis,
		Seconds: int64(tt.Sub(tf) / time.Second), CrossHost: from.Case != to.Case}
}

// explicit names the evidence that connects two stage items, or "".
func (b *builder) explicit(byCase map[string]*caseState, from, to *StageItem) string {
	if from.Case == to.Case {
		cs := byCase[from.Case]
		if from.finding == to.finding && from.RuleID == to.RuleID && from.Step != "" && to.Step != "" {
			return "steps of one attack-chain finding (" + from.RuleID + ")"
		}
		if from.Session != "" && from.Session == to.Session {
			return "same session " + from.Session
		}
		if a := agentLink(cs, from.Agent, to.Agent); a != "" {
			return a
		}
		if processLinked(cs, from.EventID, to.EventID) {
			return "process lineage: the later command ran as a descendant of the earlier one's process (endpoint pid/ppid)"
		}
		return ""
	}
	if from.Session != "" && from.Session == to.Session && contains(b.handoff[from.Case+"|"+from.Session], to.Case) {
		return "session " + from.Session + " was handed off from " + from.Case + " to " + to.Case + " (the same session id is recorded on both hosts)"
	}
	return ""
}

// agentLink reports a recorded spawn path between two agents of one case.
func agentLink(cs *caseState, a, c string) string {
	if a == "" || c == "" || a == c {
		return ""
	}
	up := func(x, target string) bool {
		for hop := 0; x != "" && hop < 32; hop++ {
			if x = cs.parent[x]; x == target {
				return true
			}
		}
		return false
	}
	switch {
	case up(c, a):
		return "agent lineage: " + c + " descends from " + a + " by recorded spawn"
	case up(a, c):
		return "agent lineage: " + a + " descends from " + c + " by recorded spawn"
	}
	return ""
}

// processLinked reports whether the process the later event ran as
// descends from the earlier event's process in the endpoint telemetry.
func processLinked(cs *caseState, fromEv, toEv string) bool {
	if fromEv == "" || toEv == "" {
		return false
	}
	target := map[string]bool{}
	for _, p := range cs.procOf[toEv] {
		target[p] = true
	}
	if len(target) == 0 {
		return false
	}
	stack := append([]string{}, cs.procOf[fromEv]...)
	seen := map[string]bool{}
	for steps := 0; len(stack) > 0 && steps < 10000; steps++ {
		p := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[p] {
			continue
		}
		seen[p] = true
		for _, k := range cs.procKid[p] {
			if target[k] {
				return true
			}
			stack = append(stack, k)
		}
	}
	return false
}

func (b *builder) inferredBasis(from, to *StageItem) string {
	tf, _ := parseTS(from.Time)
	tt, _ := parseTS(to.Time)
	parts := []string{fmt.Sprintf("order in time only (%s later)", tt.Sub(tf))}
	if from.Case == to.Case {
		parts = append(parts, "same host, no shared session, agent lineage or process lineage")
	} else {
		k := [2]string{from.Case, to.Case}
		if k[0] > k[1] {
			k[0], k[1] = k[1], k[0]
		}
		sh := b.caseShares[k]
		for i, s := range sh {
			if i == 3 {
				parts = append(parts, fmt.Sprintf("%d more shared item(s)", len(sh)-3))
				break
			}
			parts = append(parts, "both cases share "+s)
		}
		if len(sh) == 0 {
			parts = append(parts, "different hosts with nothing shared between them")
		}
	}
	return strings.Join(parts, "; ")
}

// ---- missing evidence

func (b *builder) missing() {
	out := []Missing{}
	segRefs := map[string]string{}
	for _, cs := range b.cases {
		ci := cs.in
		// Host level: no second witness at all.
		noTelemetry := (ci.Correlation == nil || ci.Correlation.Records == 0) && (ci.Coverage == nil || len(ci.Coverage.Witness.Sources) == 0)
		var calls, segsWithCalls int
		var start, end time.Time
		for _, s := range b.segs {
			if s.Case != ci.Label || s.ToolCalls == 0 {
				continue
			}
			calls += s.ToolCalls
			segsWithCalls++
			if t, ok := parseTS(s.Start); ok && (start.IsZero() || t.Before(start)) {
				start = t
			}
			if t, ok := parseTS(s.End); ok && t.After(end) {
				end = t
			}
		}
		if noTelemetry && calls > 0 {
			out = append(out, Missing{Scope: "case", Target: ci.Label, Case: ci.Label, Host: ci.Host, Status: gaps.VerifyNext, Category: "second_witness",
				Text:    fmt.Sprintf("host %s (%s) has no endpoint telemetry or other second witness: %d tool call(s) in %d segment(s) can be neither confirmed nor refuted", ci.Host, ci.Label, calls, segsWithCalls),
				Collect: fmt.Sprintf("process and network telemetry from %s covering %s (EDR export, Sysmon, auditd, eslogger), then: agentdfir analyze %s --endpoint <log>", ci.Host, span(start, end), ci.Path),
				Source:  "reconstruct"})
		}
		// Coverage items, placed on the segment their evidence names.
		if cov := ci.Coverage; cov != nil {
			n := 0
			for _, it := range cov.Items {
				if it.Status == gaps.Known {
					continue
				}
				if n++; n > 100 {
					b.omit("coverage_items", 1)
					continue
				}
				m := Missing{Scope: "case", Target: ci.Label, Case: ci.Label, Host: ci.Host, Status: it.Status, Category: it.Category,
					Text: detect.MaskSecrets(it.Text), Collect: detect.MaskSecrets(it.Collect), Source: "coverage.json"}
				for _, r := range it.Refs {
					if len(m.Refs) < 3 {
						m.Refs = append(m.Refs, detect.MaskSecrets(r))
					}
					if m.Scope == "case" {
						if id := chain.EventForRef(cs.refIdx, r); id != "" {
							if i, ok := cs.byID[id]; ok && cs.segOf[i] != "" {
								m.Scope, m.Target = "segment", cs.segOf[i]
							}
						}
					}
				}
				out = append(out, m)
			}
		} else {
			out = append(out, Missing{Scope: "case", Target: ci.Label, Case: ci.Label, Host: ci.Host, Status: gaps.Unknown, Category: "coverage",
				Text: "no coverage report (normalized/coverage.json) in this case; evidence gaps were not computed", Collect: "agentdfir analyze " + ci.Path, Source: "reconstruct"})
		}
	}
	// Segment level: the hosts' coverage during each segment that ran
	// tool calls.
	for _, id := range sortedKeys(b.segs) {
		s := b.segs[id]
		segRefs[id] = s.FirstRef
		if s.ToolCalls == 0 || s.Telemetry == "full" {
			continue
		}
		what := "no endpoint telemetry"
		if s.Telemetry == "partial" {
			what = "partial endpoint telemetry"
		} else if s.Telemetry == "unknown" {
			what = "endpoint telemetry of unknown extent"
		}
		out = append(out, Missing{Scope: "segment", Target: id, Case: s.Case, Host: s.Host, Status: gaps.VerifyNext, Category: "second_witness",
			Text:    fmt.Sprintf("host %s has %s during segment %s (%s, %d tool call(s))", s.Host, what, id, span2(s.Start, s.End), s.ToolCalls),
			Collect: fmt.Sprintf("process and network telemetry from %s for %s would confirm or refute this segment's commands", s.Host, span2(s.Start, s.End)),
			Source:  "reconstruct", Refs: compact(s.FirstRef)})
	}
	// Stage items no second witness confirmed.
	for _, it := range b.rep.StageItems {
		if it.State == schema.StateCorroborated || it.State == schema.StatePartial {
			continue
		}
		out = append(out, Missing{Scope: "stage_item", Target: it.ID, Case: it.Case, Host: it.Host, Status: gaps.VerifyNext, Category: it.Stage,
			Text:    fmt.Sprintf("%s %s (%s) in %s has no second-witness confirmation (%s)", it.ID, strings.ReplaceAll(it.Stage, "_", " "), it.RuleID, orDash(it.Segment), schema.Label(orUnknown(it.State))),
			Collect: collectFor[it.Stage] + " on " + it.Host + around(it.Time),
			Source:  "reconstruct", Refs: compact(it.Ref)})
	}
	for _, e := range b.rep.StageEdges {
		if e.Link != Inferred {
			continue
		}
		where := "the same host"
		if e.CrossHost {
			where = "the two hosts"
		}
		out = append(out, Missing{Scope: "stage_edge", Target: e.From + "->" + e.To, Status: gaps.Unknown, Category: "link",
			Text:    fmt.Sprintf("the link %s (%s) → %s (%s) is inferred from order in time and shared attributes only", e.From, e.FromStage, e.To, e.ToStage),
			Collect: "evidence joining " + where + ": a shared session id, a recorded spawn, process lineage (pid/ppid telemetry), or a command or file that names the other side",
			Source:  "reconstruct"})
	}
	for _, d := range b.rep.Delegations {
		if d.Link == Verified {
			continue
		}
		m := Missing{Scope: "delegation", Target: d.Parent + "->" + orDash(d.Child), Case: d.Case, Status: gaps.VerifyNext, Category: "agent_chain",
			Source: "reconstruct", Refs: d.Refs}
		if d.Link == Unresolved {
			m.Text = "delegation from " + d.Parent + " has no child transcript in the case: " + d.Basis
			m.Collect = "the child agent's transcript (subagent file or the launched CLI's session store) from the same host"
		} else {
			m.Text = "delegation from " + d.Parent + " to " + d.Child + " is inferred: " + d.Basis
			m.Collect = "process telemetry linking the launch command to the child session's process (ppid), or a session id in the launch command"
		}
		out = append(out, m)
	}
	for _, h := range b.rep.Handoffs {
		if h.Link == Verified {
			continue
		}
		m := Missing{Scope: "handoff", Target: h.Kind + ":" + h.Key, Case: h.FromCase, Status: gaps.VerifyNext, Category: "handoff", Source: "reconstruct", Refs: h.Refs}
		if h.Link == Unresolved {
			m.Text = "hand-off of " + h.Key + " has no recorded other side: " + h.Basis
			m.Collect = "the named session's transcript from wherever it was resumed"
		} else {
			m.Text = "hand-off " + h.Key + " is inferred: " + h.Basis
			m.Collect = "the repository's reflog or the remote's push/pull audit log showing the same commit on both hosts"
		}
		out = append(out, m)
	}
	if len(out) > b.o.MaxMissing {
		b.omit("missing_evidence", len(out)-b.o.MaxMissing)
		out = out[:b.o.MaxMissing]
	}
	b.rep.Missing = out
}

// ---- finish

func (b *builder) finish() {
	r := b.rep
	ids := sortedKeys(b.segs)
	sessions, agents, hosts := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, id := range ids {
		s := b.segs[id]
		r.Segments = append(r.Segments, *s)
		sessions[s.Case+"|"+s.Session] = true
		agents[s.Case+"|"+s.Agent] = true
	}
	sort.SliceStable(r.Segments, func(i, j int) bool { return segLess(&r.Segments[i], &r.Segments[j]) })
	for _, c := range r.Cases {
		hosts[c.HostID] = true
	}
	sort.SliceStable(r.Delegations, func(i, j int) bool {
		a, c := r.Delegations[i], r.Delegations[j]
		if a.Case != c.Case {
			return a.Case < c.Case
		}
		if a.Time != c.Time {
			return a.Time < c.Time
		}
		return a.Parent+"|"+a.Child+"|"+a.ToolCallID < c.Parent+"|"+c.Child+"|"+c.ToolCallID
	})
	sort.SliceStable(r.Handoffs, func(i, j int) bool {
		a, c := r.Handoffs[i], r.Handoffs[j]
		if a.ToTime != c.ToTime {
			return a.ToTime < c.ToTime
		}
		return a.Kind+"|"+a.Key+"|"+a.From+"|"+a.To < c.Kind+"|"+c.Key+"|"+c.From+"|"+c.To
	})
	r.Summary.Cases, r.Summary.Hosts, r.Summary.Sessions, r.Summary.Agents = len(r.Cases), len(hosts), len(sessions), len(agents)
	r.Summary.Segments, r.Summary.TimelineEntries = len(r.Segments), len(r.Timeline)
	r.Summary.Delegations, r.Summary.Handoffs, r.Summary.Links = len(r.Delegations), len(r.Handoffs), len(r.Links)
	r.Summary.StageItems, r.Summary.Missing = len(r.StageItems), len(r.Missing)
	r.Limits = []string{
		"Deterministic correlation only: every link names its basis. No model wrote any part of this report; the narrative extension point is documented and not implemented.",
		"Identities stay separate: hosts, OS users, sessions and agents belong to their case. Cases are joined only by an identifier the evidence carries (a session id, a session named in a resume command, an account email or uuid, a commit id of 12+ hex digits).",
		"A stage edge is verified only when explicit evidence connects the two items (one chain finding, the same session, a recorded spawn path, endpoint process lineage, or a session handed off by id). Every other edge is inferred from order in time and shared attributes, and says so.",
		"Stages come from attack-chain step names and the ATT&CK technique of HIGH/CRITICAL findings; a technique this report does not map leaves its finding unstaged (counted in the summary).",
		"Absence is not evidence: a segment with no telemetry is listed as missing evidence, never as activity that did not happen.",
	}
	sort.Strings(r.Notes)
}

func (b *builder) omit(k string, n int) {
	if b.rep.Omitted == nil {
		b.rep.Omitted = map[string]int{}
	}
	b.rep.Omitted[k] += n
}

// ---- helpers

func parseTS(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func rfc(t time.Time) string     { return t.UTC().Format(time.RFC3339) }
func rfcNano(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

func rfcOpt(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return rfc(t)
}

func normTime(s string) string {
	if t, ok := parseTS(s); ok {
		return rfcNano(t)
	}
	return ""
}

func span(a, c time.Time) string {
	if a.IsZero() {
		return "the case's activity"
	}
	return a.UTC().Format("2006-01-02 15:04:05") + "–" + c.UTC().Format("2006-01-02 15:04:05") + " UTC"
}

func span2(a, c string) string {
	ta, ok1 := parseTS(a)
	tc, ok2 := parseTS(c)
	if !ok1 || !ok2 {
		return "an untimed span"
	}
	return span(ta, tc)
}

func around(ts string) string {
	if ts == "" {
		return ""
	}
	return " around " + ts
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func orUnknown(s string) string {
	if s == "" {
		return schema.StateUnknown
	}
	return s
}

func joinNote(a, c string) string {
	if a == "" {
		return c
	}
	return a + "; " + c
}

func compact(l ...string) []string {
	out := []string{}
	for _, s := range l {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

func nonNil(l []string) []string {
	if l == nil {
		return []string{}
	}
	return l
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
