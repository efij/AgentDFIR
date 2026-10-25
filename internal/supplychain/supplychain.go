// Package supplychain reconstructs the supply chain of an agent
// environment from a sealed case: every component an agent loads on its
// own (skills, plugins, slash commands, sub-agent definitions, hooks, MCP
// servers, IDE extensions, standing-instruction files), where each one came
// from, when it was first and last seen and by which clock, how its hash
// changed across the case's collection rounds and any baselines, how MCP
// tool definitions and agent settings drifted, and the path from a
// component to the invocations that used it and the commands that
// followed.
//
// It is not a second inventory engine. Components come from the
// inventories extinv and mcpaudit already build; history comes from the
// append-only manifest every round extends; invocations come from the
// normalized events; commands and processes come from the endpoint
// correlation the analysis stored.
//
// The rule that decides every relationship: it is "verified" only when the
// evidence itself ties the two ends together — a hash-identical artifact,
// a logged invocation that names the component, or an explicit reference
// (a tool_use id, an endpoint pid/ppid, an install registry entry). A link
// made from temporal proximity or a bare name match is "inferred", is kept
// in its own list and its own report section, and is never promoted.
//
// Read-only: evidence is read through the case store, bounded per line and
// per run; nothing is executed, resolved or contacted.
package supplychain

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/baseline"
	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/correlate"
	"github.com/efij/AgentDFIR/v4/internal/extinv"
	"github.com/efij/AgentDFIR/v4/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Schema identifies the document this package writes.
const Schema = "agentdfir.supplychain/1"

// File is the overlay file under normalized/.
const File = "supplychain.json"

// Relationship classes.
const (
	Verified = "verified"
	Inferred = "inferred"
)

// Component kinds.
const (
	KindSkill        = "skill"
	KindSubagent     = "subagent"
	KindCommand      = "slash_command"
	KindPlugin       = "plugin"
	KindMarketplace  = "marketplace"
	KindHook         = "hook"
	KindMCP          = "mcp_server"
	KindExtension    = "ide_extension"
	KindInstruction  = "instruction_file"
	KindAgentSetting = "agent_settings"
)

// Timestamp sources. Each first/last-seen time names the clock it came
// from, because they are not equally trustworthy: an mtime is settable by
// any process that can write the file, an install registry is written by
// the host, a log record by the agent at the time, and the collection time
// by this tool.
const (
	TimeInstall    = "install_manifest"
	TimeMTime      = "file_mtime"
	TimeLog        = "log_record"
	TimeCollection = "collection"
)

// Input is what the report is built from. Everything is optional except
// the events; a missing piece degrades to a note.
type Input struct {
	CaseID      string
	Host        string
	Manifest    *casepkg.Manifest // every record of every round
	Store       *casepkg.Store    // nil: raw transcript lines are not read
	Rounds      []casepkg.Round
	Events      []schema.Event
	Findings    []schema.Finding
	Correlation *correlate.EndpointResult
	MCP         *mcpaudit.Inventory
	Ext         *extinv.Inventory
	// MCPBaselines are `agentdfir mcp audit --write-baseline` snapshots;
	// Baselines are `agentdfir baseline` package snapshots.
	MCPBaselines []MCPBaseline
	Baselines    []PackageBaseline
}

// MCPBaseline is one MCP inventory baseline with the label it is reported under.
type MCPBaseline struct {
	Label string
	B     *mcpaudit.Baseline
}

// PackageBaseline is one package snapshot with the label it is reported under.
type PackageBaseline struct {
	Label string
	B     *baseline.Baseline
}

// Options bound the work and set the inference window.
type Options struct {
	// Window is how long after an invocation a later command in the same
	// session is listed as an inferred follow-on, and the rule window for
	// SUPPLY_UNTRUSTED_COMPONENT_BEFORE_HIGH. Default 10 minutes.
	Window       time.Duration
	MaxRawReads  int // transcript lines re-read for tool inputs and hook records; default 20000
	MaxRelations int // per class; default 20000
	MaxTimeline  int // default 5000
	MaxFollow    int // inferred follow-on commands per invocation; default 5
}

func (o *Options) defaults() {
	if o.Window <= 0 {
		o.Window = 10 * time.Minute
	}
	if o.MaxRawReads <= 0 {
		o.MaxRawReads = 20000
	}
	if o.MaxRelations <= 0 {
		o.MaxRelations = 20000
	}
	if o.MaxTimeline <= 0 {
		o.MaxTimeline = 5000
	}
	if o.MaxFollow <= 0 {
		o.MaxFollow = 5
	}
}

// Report is normalized/supplychain.json and the command's JSON.
type Report struct {
	Schema      string           `json:"schema"`
	CaseID      string           `json:"case_id"`
	Host        string           `json:"host,omitempty"`
	Since       string           `json:"since,omitempty"`
	Window      string           `json:"inference_window"`
	Rounds      []RoundInfo      `json:"rounds"`
	Components  []Component      `json:"components"`
	Drift       []Drift          `json:"drift"`
	Relations   Relations        `json:"relations"`
	Reuse       []Reuse          `json:"reuse"`
	Timeline    []TimelineEntry  `json:"timeline"`
	Findings    []schema.Finding `json:"findings"`
	Omitted     map[string]int   `json:"omitted,omitempty"`
	Unsupported []string         `json:"unsupported"`
	Notes       []string         `json:"notes"`
	Limits      []string         `json:"limits"`
}

// RoundInfo is one collection round of the case.
type RoundInfo struct {
	Round     int    `json:"round"`
	Started   string `json:"started_utc,omitempty"`
	Completed string `json:"completed_utc,omitempty"`
}

// Component is one thing an agent loads on its own.
type Component struct {
	ID     string   `json:"id"`
	Kind   string   `json:"kind"`
	Name   string   `json:"name"`
	Host   string   `json:"host,omitempty"`   // the agent product that loads it
	Parent string   `json:"parent,omitempty"` // containing component (a plugin's skills and hooks)
	Origin Origin   `json:"origin"`
	Paths  []string `json:"paths,omitempty"`
	// SHA256 is the component's identity hash now; HashBasis says what it
	// covers (a file's content, a declared command, a server definition).
	SHA256    string    `json:"sha256,omitempty"`
	HashBasis string    `json:"hash_basis,omitempty"`
	FirstSeen *Stamp    `json:"first_seen,omitempty"`
	LastSeen  *Stamp    `json:"last_seen,omitempty"`
	History   []Version `json:"hash_history,omitempty"`
	// Observed is true for a component known only from what the
	// transcripts recorded (a server name in a tool call, a skill name):
	// its definition was not collected.
	Observed    bool     `json:"observed_only,omitempty"`
	Invocations int      `json:"invocations"`
	Sessions    []string `json:"sessions,omitempty"`
	Flags       []string `json:"flagged_by,omitempty"` // rule ids of findings that cite this component
	Tools       []string `json:"tools,omitempty"`      // MCP tool names declared now

	paths map[string]bool // logical paths, for matching finding refs
	cmd   string          // hook: the declared command
	event string          // hook: lifecycle event
}

// Origin is where a component came from, as the evidence records it.
type Origin struct {
	// Type: marketplace | npm | pypi | git | url | gallery | vsix |
	// repository | local | unknown.
	Type string `json:"type"`
	// Trust: default (the host's built-in marketplace or gallery) |
	// third_party | unregistered (present without an install record) |
	// repository (travels with a project) | registry | remote | local |
	// unknown.
	Trust       string `json:"trust"`
	Marketplace string `json:"marketplace,omitempty"`
	Location    string `json:"location,omitempty"` // marketplace repo, URL or path as recorded
	Package     string `json:"package,omitempty"`
	Version     string `json:"version,omitempty"`
	GitRemote   string `json:"git_remote,omitempty"`
	GitCommit   string `json:"git_commit,omitempty"`
	URL         string `json:"url,omitempty"`
	LocalPath   string `json:"local_path,omitempty"`
	Basis       string `json:"basis"` // which record says so
}

// Untrusted reports whether an origin is outside what the host ships
// with: a third-party marketplace or source, a component present without
// an install record, or one that came with a repository.
func (o Origin) Untrusted() bool {
	switch o.Trust {
	case "third_party", "unregistered", "repository":
		return true
	}
	return false
}

// Stamp is one time with the clock it came from.
type Stamp struct {
	Time   string `json:"time"`
	Source string `json:"source"` // install_manifest | file_mtime | log_record | collection
	Detail string `json:"detail,omitempty"`
	Ref    string `json:"ref,omitempty"`
}

// Version is one hash a component had.
type Version struct {
	SHA256 string `json:"sha256"`
	// Source: round (a collection round of this case) | baseline (an MCP
	// inventory baseline) | package_snapshot (an `agentdfir baseline`
	// snapshot of another package).
	Source string `json:"source"`
	Label  string `json:"label"`
	Rounds []int  `json:"rounds,omitempty"`
	Path   string `json:"path,omitempty"`
	MTime  string `json:"mtime,omitempty"`
}

// Drift is one change between two snapshots of the same thing.
type Drift struct {
	// Kind: mcp_tool_definition | mcp_server_definition | agent_settings.
	Kind      string   `json:"kind"`
	Component string   `json:"component"`
	Subject   string   `json:"subject"`
	From      Snapshot `json:"from"`
	To        Snapshot `json:"to"`
	Added     []string `json:"added,omitempty"`
	Removed   []string `json:"removed,omitempty"`
	Changed   []string `json:"changed,omitempty"`
	// Expansion lists what grew: new tools, new env keys or auto-approved
	// tools, new filesystem roots, broader permission rules, new hooks.
	Expansion []string `json:"permission_expansion,omitempty"`
	Class     string   `json:"class"`
	Basis     string   `json:"basis"`
}

// Snapshot is one side of a drift.
type Snapshot struct {
	Label string `json:"label"`
	// Source: round | baseline | package_snapshot | cached_manifest | session_init.
	Source     string `json:"source"`
	Round      int    `json:"round,omitempty"`
	Session    string `json:"session,omitempty"`
	Time       string `json:"time,omitempty"`
	TimeSource string `json:"time_source,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Ref        string `json:"ref,omitempty"`
}

// Relations keeps the two classes apart in the document itself.
type Relations struct {
	Verified []Relation `json:"verified"`
	Inferred []Relation `json:"inferred"`
}

// Relation is one typed link.
type Relation struct {
	From string `json:"from"`
	To   string `json:"to"`
	// Type: installed_from | contains | invoked | hook_executed |
	// hook_for_tool_call | followed_by | produced | related_record |
	// flagged_by.
	Type       string `json:"type"`
	Class      string `json:"class"`
	Basis      string `json:"basis"`
	Time       string `json:"time,omitempty"`
	Session    string `json:"session,omitempty"`
	Confidence string `json:"confidence,omitempty"` // correlated edges: correlate.MatchBasis confidence
	Label      string `json:"label,omitempty"`      // what the target is, in words (a command, a tool)
	Refs       []Ref  `json:"source_refs"`
}

// Ref locates evidence: a sealed artifact line, or a line of imported
// telemetry (same shape as the lineage graph's references).
type Ref struct {
	ArtifactID string `json:"artifact_id,omitempty"`
	Path       string `json:"logical_path,omitempty"`
	Line       int    `json:"line,omitempty"`
	Offset     int64  `json:"offset,omitempty"`
	EventID    string `json:"event_id,omitempty"`
	External   string `json:"telemetry_ref,omitempty"`
}

// Reuse is one component hash seen in several sessions or cases.
type Reuse struct {
	Component string     `json:"component"`
	SHA256    string     `json:"sha256,omitempty"`
	Sessions  []string   `json:"sessions,omitempty"`
	Cases     []CaseSeen `json:"cases,omitempty"`
	Class     string     `json:"class"`
	Basis     string     `json:"basis"`
	Flagged   []string   `json:"flagged_by,omitempty"`
}

// CaseSeen is a component in another case.
type CaseSeen struct {
	Label      string `json:"label"`
	CaseID     string `json:"case_id"`
	Host       string `json:"host"`
	Component  string `json:"component"`
	Unverified bool   `json:"from_unverified_case,omitempty"`
}

// TimelineEntry is one dated step, chronological in the report.
type TimelineEntry struct {
	Time       string `json:"time"`
	TimeSource string `json:"time_source"`
	// Kind: first_seen | installed | version | drift | invocation |
	// hook_execution | command | finding | last_seen.
	Kind      string `json:"kind"`
	Component string `json:"component,omitempty"`
	Class     string `json:"class,omitempty"`
	Session   string `json:"session,omitempty"`
	Text      string `json:"text"`
	Ref       string `json:"ref,omitempty"`
}

// Build computes the report. It does not fail: anything that goes wrong,
// including a panic on input nobody anticipated, becomes a note.
func Build(in Input, o Options) (rep *Report) {
	o.defaults()
	rep = &Report{Schema: Schema, CaseID: in.CaseID, Host: in.Host, Window: o.Window.String(),
		Rounds: []RoundInfo{}, Components: []Component{}, Drift: []Drift{},
		Relations: Relations{Verified: []Relation{}, Inferred: []Relation{}},
		Reuse:     []Reuse{}, Timeline: []TimelineEntry{}, Findings: []schema.Finding{},
		Unsupported: []string{}, Notes: []string{}}
	defer func() {
		if r := recover(); r != nil {
			rep.Notes = append(rep.Notes, fmt.Sprintf("supply-chain build stopped: %v", r))
		}
	}()
	b := &builder{in: in, o: o, rep: rep, byID: map[string]int{}, omitted: map[string]int{}}
	b.rounds()
	b.indexRecords()
	b.components()
	b.history()
	b.drift()
	b.invocations()
	b.flags()
	b.reuse()
	b.rules()
	b.finish()
	return rep
}

type builder struct {
	in      Input
	o       Options
	rep     *Report
	byID    map[string]int // component id → index
	omitted map[string]int
	raw     *rawReader

	// manifest history: logical path → records in manifest (chronological) order
	recs    map[string][]casepkg.ArtifactRecord
	current map[string]casepkg.ArtifactRecord
	maxRnd  int

	// invocations, for the rules
	invs []invocation
	// session-init tool snapshots: server name → snapshots in time order
	initTools map[string][]toolSnap
	// event index
	evByID   map[string]int
	toolUse  map[string]int  // session + tool_use id → event index
	followed map[string]bool // events listed as inferred follow-ons
}

func (b *builder) note(format string, args ...any) {
	b.rep.Notes = append(b.rep.Notes, fmt.Sprintf(format, args...))
}

func (b *builder) unsupported(format string, args ...any) {
	b.rep.Unsupported = append(b.rep.Unsupported, fmt.Sprintf(format, args...))
}

func (b *builder) add(c Component) *Component {
	if i, ok := b.byID[c.ID]; ok {
		return &b.rep.Components[i]
	}
	if c.paths == nil {
		c.paths = map[string]bool{}
	}
	for _, p := range c.Paths {
		c.paths[p] = true
	}
	b.byID[c.ID] = len(b.rep.Components)
	b.rep.Components = append(b.rep.Components, c)
	return &b.rep.Components[len(b.rep.Components)-1]
}

func (b *builder) comp(id string) *Component {
	if i, ok := b.byID[id]; ok {
		return &b.rep.Components[i]
	}
	return nil
}

func (b *builder) relate(r Relation) {
	if r.Refs == nil {
		r.Refs = []Ref{}
	}
	if r.Class == Verified {
		if len(b.rep.Relations.Verified) >= b.o.MaxRelations {
			b.omitted["verified_relations"]++
			return
		}
		b.rep.Relations.Verified = append(b.rep.Relations.Verified, r)
		return
	}
	r.Class = Inferred
	if len(b.rep.Relations.Inferred) >= b.o.MaxRelations {
		b.omitted["inferred_relations"]++
		return
	}
	b.rep.Relations.Inferred = append(b.rep.Relations.Inferred, r)
}

func (b *builder) rounds() {
	for _, r := range b.in.Rounds {
		b.rep.Rounds = append(b.rep.Rounds, RoundInfo{Round: r.Round, Started: r.StartedUTC, Completed: r.CompletedUTC})
	}
}

// roundTime is when a round's collection started, or "" when case.json
// does not say.
func (b *builder) roundTime(n int) string {
	for _, r := range b.in.Rounds {
		if r.Round == n {
			return r.StartedUTC
		}
	}
	return ""
}

func roundOf(a casepkg.ArtifactRecord) int {
	if a.Round <= 0 {
		return 1
	}
	return a.Round
}

func (b *builder) indexRecords() {
	b.recs = map[string][]casepkg.ArtifactRecord{}
	b.current = map[string]casepkg.ArtifactRecord{}
	if b.in.Manifest == nil {
		b.note("no manifest: hash history across rounds is not available")
		return
	}
	for _, a := range b.in.Manifest.Artifacts {
		if a.Status != casepkg.StatusOK || a.ArtifactID == "" {
			continue
		}
		lp := normPath(a.LogicalPath)
		b.recs[lp] = append(b.recs[lp], a)
		if r := roundOf(a); r > b.maxRnd {
			b.maxRnd = r
		}
	}
	for _, a := range b.in.Manifest.Current() {
		if a.Status == casepkg.StatusOK && a.ArtifactID != "" {
			b.current[normPath(a.LogicalPath)] = a
		}
	}
}

func (b *builder) finish() {
	r := b.rep
	sort.SliceStable(r.Components, func(i, j int) bool {
		if r.Components[i].Kind != r.Components[j].Kind {
			return kindRank[r.Components[i].Kind] < kindRank[r.Components[j].Kind]
		}
		return r.Components[i].ID < r.Components[j].ID
	})
	for i := range r.Components {
		sort.Strings(r.Components[i].Sessions)
		sort.Strings(r.Components[i].Flags)
	}
	sortTimeline(r.Timeline)
	if len(r.Timeline) > b.o.MaxTimeline {
		b.omitted["timeline"] += len(r.Timeline) - b.o.MaxTimeline
		r.Timeline = r.Timeline[:b.o.MaxTimeline]
	}
	if b.raw != nil && b.raw.skipped > 0 {
		b.note("%d transcript line(s) were not re-read (the bound is %d); invocations and hook records in them are missing from this report", b.raw.skipped, b.o.MaxRawReads)
	}
	if len(b.omitted) > 0 {
		r.Omitted = b.omitted
	}
	r.Limits = []string{
		"Verified links rest on the evidence alone: a hash-identical artifact, a logged invocation naming the component, a tool_use id, an endpoint pid/ppid, or an install registry entry. Inferred links rest on time proximity or a bare name match and are never promoted.",
		"Endpoint correlation pairs a recorded command with a process by command line within a time window; those edges are listed as inferred with the correlation's confidence. Records tied to the matched process by pid/ppid are verified relative to it.",
		"A file mtime is settable by anything that can write the file; first/last-seen times name their clock so an mtime is never read as an install record.",
		"Hash history covers the rounds this case holds and the baselines given; a change between two collections is visible, its exact time is not.",
		"A component missing from a round was not collected in that round; absence is not proof it was not installed, and no invocation is invented for a component the transcripts do not name.",
	}
}

var kindRank = map[string]int{KindMarketplace: 0, KindPlugin: 1, KindSkill: 2, KindCommand: 3, KindSubagent: 4, KindHook: 5,
	KindMCP: 6, KindExtension: 7, KindInstruction: 8, KindAgentSetting: 9}

func sortTimeline(t []TimelineEntry) {
	sort.SliceStable(t, func(i, j int) bool {
		ti, oki := parseTS(t[i].Time)
		tj, okj := parseTS(t[j].Time)
		if oki && okj && !ti.Equal(tj) {
			return ti.Before(tj)
		}
		if oki != okj {
			return oki
		}
		return false
	})
}

// timeline adds one entry with its time normalized to RFC 3339 UTC. A time
// from evidence that does not parse is not printed as given: the entry is
// kept, flagged, and sorts after the dated ones.
func (b *builder) timeline(e TimelineEntry) {
	if e.Time == "" {
		return
	}
	if t, ok := parseTS(e.Time); ok {
		e.Time = rfc(t)
	} else {
		e.Text = "(unparseable time in evidence) " + e.Text
		e.Time = "unparseable"
		e.TimeSource += ":unparseable"
	}
	b.rep.Timeline = append(b.rep.Timeline, e)
}

// ---- small helpers

func parseTS(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, f := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func normPath(p string) string { return strings.ReplaceAll(p, `\`, "/") }

// refPath strips the artifact suffix and line number from an evidence
// reference ("a/b.json:12 (artifact 0123…)" → "a/b.json").
func refPath(ref string) string {
	if i := strings.Index(ref, " (artifact "); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.Index(ref, " (server "); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, ":"); i > 0 && isDigits(ref[i+1:]) {
		ref = ref[:i]
	}
	return normPath(strings.TrimSpace(ref))
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

func short(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}

func trim(s string, n int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

func appendUniq(l []string, v string) []string {
	for _, x := range l {
		if x == v {
			return l
		}
	}
	return append(l, v)
}

func eventRef(ev schema.Event) Ref {
	return Ref{ArtifactID: ev.SourceArtifact, Path: ev.SourcePath, Line: ev.SourceLine, Offset: ev.SourceOffset, EventID: ev.EventID}
}

func refString(r Ref) string {
	s := r.Path
	if r.Line > 0 {
		s = fmt.Sprintf("%s:%d", s, r.Line)
	}
	if r.ArtifactID != "" {
		s += fmt.Sprintf(" (artifact %s)", short(r.ArtifactID))
	}
	if s == "" {
		s = r.External
	}
	return s
}
