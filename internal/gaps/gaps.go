// Package gaps says what a case does not show.
//
// Every other part of the analysis reports what the evidence holds. An
// investigator also has to know where it is silent: the hours inside a
// session with no transcript record, the products whose newest record is
// days older than the collection, the shell commands no second witness was
// in a position to confirm, the clocks that disagree, the subagents whose
// parent was never collected. Without that list, an absence of findings
// reads as an absence of activity.
//
// The output is one document, normalized/coverage.json, written by every
// analysis, and a list of plain items, each one of
//
//	known        established by the evidence in the case
//	unknown      the case cannot answer it
//	verify_next  what to collect next, and what it would verify
//
// Nothing here speculates. A time gap says nothing was recorded, never
// that something was hidden; an unverified command says no witness covered
// it, never that it did not run. The package reads only what analysis
// already produced and never changes an event, a finding or an evidence
// state.
package gaps

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/correlate"
	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
	"github.com/efij/AgentDFIR/v4/internal/witness"
)

// Schema identifies the document this package writes.
const Schema = "agentdfir.coverage/1"

// Item statuses, in reporting order.
const (
	Known      = "known"
	Unknown    = "unknown"
	VerifyNext = "verify_next"
)

// Item categories.
const (
	CatTranscript  = "transcript"
	CatAcquisition = "acquisition"
	CatWitness     = "second_witness"
	CatClock       = "clock"
	CatChain       = "agent_chain"
)

// Input is everything coverage is computed from. Every field but Events
// may be nil or empty; a missing input becomes a stated limit, not a
// silent zero.
type Input struct {
	CaseID      string
	Host        string
	Manifest    *casepkg.Manifest
	CaseInfo    *casepkg.CaseInfo
	Events      []schema.Event
	Findings    []schema.Finding
	Correlation *correlate.EndpointResult
	Witness     *witness.Record
}

// Options tune the thresholds. Zero values take the defaults.
type Options struct {
	// A silence inside a session is reported when it is at least MinGap
	// and at least CadenceFactor times the session's median spacing.
	MinGap        time.Duration
	CadenceFactor int
	// ClockTolerance absorbs ordinary clock drift and write latency
	// before a timestamp counts as inconsistent.
	ClockTolerance time.Duration
	// ActivityJoin merges tool calls closer than this into one activity
	// range for second-witness coverage.
	ActivityJoin time.Duration
	// Bounds, so a case with a million events yields a readable document.
	MaxGapsPerSession int
	MaxRanges         int
	MaxItemsPerKind   int
	MaxExamples       int
}

func (o *Options) defaults() {
	if o.MinGap <= 0 {
		o.MinGap = 15 * time.Minute
	}
	if o.CadenceFactor <= 0 {
		o.CadenceFactor = 30
	}
	if o.ClockTolerance <= 0 {
		o.ClockTolerance = 5 * time.Minute
	}
	if o.ActivityJoin <= 0 {
		o.ActivityJoin = 30 * time.Minute
	}
	if o.MaxGapsPerSession <= 0 {
		o.MaxGapsPerSession = 20
	}
	if o.MaxRanges <= 0 {
		o.MaxRanges = 200
	}
	if o.MaxItemsPerKind <= 0 {
		o.MaxItemsPerKind = 25
	}
	if o.MaxExamples <= 0 {
		o.MaxExamples = 5
	}
}

// Report is normalized/coverage.json.
type Report struct {
	Schema      string            `json:"schema"`
	CaseID      string            `json:"case_id"`
	Host        string            `json:"host,omitempty"`
	Thresholds  Thresholds        `json:"thresholds"`
	Summary     Summary           `json:"summary"`
	Sessions    []SessionCoverage `json:"sessions"`
	Integrity   []Signal          `json:"transcript_integrity"`
	Acquisition Acquisition       `json:"acquisition"`
	Witness     WitnessCoverage   `json:"second_witness"`
	Clock       Clock             `json:"clock"`
	Chains      Chains            `json:"agent_chains"`
	Items       []Item            `json:"items"`
	Limits      []string          `json:"limits"`
	// Truncated is true when any list hit its bound; the *_omitted
	// counters say by how much.
	Truncated bool `json:"truncated,omitempty"`
}

// Thresholds records the values the report was computed with.
type Thresholds struct {
	MinGapSeconds         int64 `json:"min_gap_seconds"`
	CadenceFactor         int   `json:"cadence_factor"`
	ClockToleranceSeconds int64 `json:"clock_tolerance_seconds"`
	ActivityJoinSeconds   int64 `json:"activity_join_seconds"`
}

// Summary counts the report.
type Summary struct {
	Sessions  int `json:"sessions"`
	ToolCalls int `json:"tool_calls"`
	Verified  int `json:"tool_calls_verified"`
	// Partial is how many of the Verified calls are only PARTLY CONFIRMED
	// (a DNS lookup, a proxy request to another path, an image-only process
	// creation, a cloud operation with no resource to compare).
	Partial    int `json:"tool_calls_partial,omitempty"`
	Disproved  int `json:"tool_calls_disproved"`
	Unverified int `json:"tool_calls_unverified"`
	TimeGaps   int `json:"time_gaps"`
	Known      int `json:"known"`
	Unknown    int `json:"unknown"`
	VerifyNext int `json:"verify_next"`
}

// SessionCoverage is one session's recorded span and its silences.
type SessionCoverage struct {
	SessionID      string    `json:"session_id"`
	Product        string    `json:"product,omitempty"`
	Start          string    `json:"start,omitempty"`
	End            string    `json:"end,omitempty"`
	Events         int       `json:"events"`
	Untimed        int       `json:"events_without_timestamp,omitempty"`
	CadenceSeconds float64   `json:"median_spacing_seconds"`
	Gaps           []TimeGap `json:"time_gaps,omitempty"`
	GapsOmitted    int       `json:"time_gaps_omitted,omitempty"`
}

// TimeGap is a silence inside a session: the last record before it and
// the first after it.
type TimeGap struct {
	Start     string `json:"start"`
	End       string `json:"end"`
	Seconds   int64  `json:"seconds"`
	BeforeRef string `json:"last_record_before"`
	AfterRef  string `json:"first_record_after"`
}

// Signal is one recorded integrity problem in a transcript.
type Signal struct {
	SessionID string `json:"session_id,omitempty"`
	Code      string `json:"code"`
	Detail    string `json:"detail"`
	Ref       string `json:"evidence_ref,omitempty"`
}

// Acquisition is what was collected, when, and from which round.
type Acquisition struct {
	Rounds   []Round         `json:"rounds"`
	Products []ProductWindow `json:"products"`
}

// Round is one collection round as case.json records it.
type Round struct {
	Round     int    `json:"round"`
	Started   string `json:"started_utc,omitempty"`
	Completed string `json:"completed_utc,omitempty"`
	Fresh     int    `json:"artifacts_ok"`
	Carried   int    `json:"artifacts_carried_forward"`
	Failed    int    `json:"artifacts_not_acquired"`
}

// ProductWindow is one product's evidence span against its collection.
type ProductWindow struct {
	Product          string         `json:"product"`
	Events           int            `json:"events"`
	EarliestEvidence string         `json:"earliest_evidence,omitempty"`
	LatestEvidence   string         `json:"latest_evidence,omitempty"`
	FirstCollected   string         `json:"first_collected,omitempty"`
	LastCollected    string         `json:"last_collected,omitempty"`
	LagSeconds       int64          `json:"collection_lag_seconds,omitempty"` // last collection minus latest evidence
	Artifacts        int            `json:"artifacts"`
	Fresh            int            `json:"artifacts_fresh"`
	Carried          int            `json:"artifacts_carried_forward"`
	NotPresent       int            `json:"paths_not_present,omitempty"`
	NotAcquired      map[string]int `json:"not_acquired,omitempty"` // status → count
}

// WitnessCoverage is which agent activity a second source could speak to.
type WitnessCoverage struct {
	Sources         []WitnessSource  `json:"sources"`
	Activity        []ActivityRange  `json:"activity"`
	ActivityOmitted int              `json:"activity_omitted,omitempty"`
	Actions         []ActionCoverage `json:"actions"`
	NarrativeClaims int              `json:"narrative_claims"`
	// KindCoverage is endpoint coverage per host and kind of telemetry,
	// with the intervals collection health marks as incomplete; only
	// kinds that count as coverage can disprove a claim, and only where
	// they are HEALTHY or UNKNOWN (see correlate/coverage.go).
	KindCoverage []correlate.KindCoverage `json:"kind_coverage,omitempty"`
	// CollectionHealth is the health report per telemetry file.
	CollectionHealth []endpoint.SourceHealth `json:"collection_health,omitempty"`
}

// WitnessSource is one independent source the case was checked against.
type WitnessSource struct {
	Name     string `json:"name"`
	Start    string `json:"start,omitempty"`
	End      string `json:"end,omitempty"`
	Records  int    `json:"records,omitempty"`
	Verified int    `json:"tool_calls_verified"`
	Note     string `json:"note,omitempty"`
}

// ActivityRange is a run of agent tool calls on one host and how much of
// it the endpoint telemetry covers.
type ActivityRange struct {
	Host       string   `json:"host,omitempty"`
	Start      string   `json:"start"`
	End        string   `json:"end"`
	ToolCalls  int      `json:"tool_calls"`
	Shell      int      `json:"shell_commands"`
	Network    int      `json:"network_actions"`
	Cloud      int      `json:"cloud_commands"`
	FileWrites int      `json:"file_writes"`
	Coverage   string   `json:"endpoint_coverage"` // full | partial | none
	Unverified int      `json:"unverified"`
	VerifiedBy []string `json:"verified_by,omitempty"`
}

// ActionCoverage counts one kind of tool call by outcome; Reasons says why
// the unverified ones are unverified.
type ActionCoverage struct {
	Action     string         `json:"action"`
	Total      int            `json:"total"`
	Verified   int            `json:"verified"`
	Partial    int            `json:"partial,omitempty"` // of Verified, PARTLY CONFIRMED only
	Disproved  int            `json:"disproved"`
	Unverified int            `json:"unverified"`
	Reasons    map[string]int `json:"unverified_reasons,omitempty"`
}

// Reasons a tool call stays unverified.
const (
	ReasonNoTelemetry    = "no_telemetry_in_window"
	ReasonNoMatch        = "telemetry_present_no_match"
	ReasonNoTimestamp    = "no_timestamp"
	ReasonNotCheckable   = "nothing_a_witness_can_check"
	ReasonWitnessNoMatch = "host_witness_inconclusive"
	ReasonPartial        = "telemetry_partial"
	ReasonNoKind         = "no_telemetry_of_that_kind"
)

// Clock is where timestamps from different sources disagree.
type Clock struct {
	FutureEvents    int            `json:"events_after_collection"`
	FutureExamples  []ClockExample `json:"events_after_collection_examples,omitempty"`
	OutOfOrder      []OutOfOrder   `json:"out_of_order"`
	TranscriptMTime []ClockExample `json:"transcript_mtime_before_last_record"`
	EndpointOffset  *Offset        `json:"endpoint_offset,omitempty"`
	WitnessFiles    []ClockExample `json:"witness_mtime_before_write"`
	Omitted         map[string]int `json:"omitted,omitempty"`
}

// ClockExample is one pair of timestamps that disagree.
type ClockExample struct {
	Ref       string `json:"evidence_ref"`
	Recorded  string `json:"recorded"`
	Reference string `json:"reference"`
	Basis     string `json:"basis"`
	Seconds   int64  `json:"seconds"` // recorded minus reference
}

// OutOfOrder is one source file whose timestamps go backwards.
type OutOfOrder struct {
	Path            string `json:"logical_path"`
	Count           int    `json:"count"`
	MaxStepBackSecs int64  `json:"max_step_back_seconds"`
	ExampleRef      string `json:"example_ref"`
}

// Offset is the measured difference between endpoint and transcript
// clocks over matched pairs (endpoint minus transcript).
type Offset struct {
	Pairs    int   `json:"pairs"`
	MedianMS int64 `json:"median_ms"`
	MinMS    int64 `json:"min_ms"`
	MaxMS    int64 `json:"max_ms"`
}

// Chains are agent records whose links are missing.
type Chains struct {
	Orphans            []AgentRef   `json:"orphan_agents"`
	MissingSubagents   []AgentRef   `json:"spawned_agents_without_records"`
	SpawnWithoutCall   []AgentRef   `json:"spawns_citing_unknown_tool_call"`
	UnknownParents     []AgentRef   `json:"parent_agent_not_in_evidence"`
	ResultsWithoutCall []SessionRef `json:"tool_results_without_call"`
	BrokenDAG          []SessionRef `json:"conversation_chain_breaks"`
	Omitted            int          `json:"omitted,omitempty"`
}

// AgentRef names one agent link problem.
type AgentRef struct {
	AgentID       string `json:"agent_id"`
	ParentAgentID string `json:"parent_agent_id,omitempty"`
	ToolCallID    string `json:"tool_call_id,omitempty"`
	SessionID     string `json:"session_id,omitempty"`
	Ref           string `json:"evidence_ref,omitempty"`
}

// SessionRef counts one kind of problem in one session.
type SessionRef struct {
	SessionID  string `json:"session_id"`
	Count      int    `json:"count"`
	ExampleRef string `json:"example_ref"`
}

// Item is one line of the known / unknown / verify-next list.
type Item struct {
	Status   string   `json:"status"`
	Category string   `json:"category"`
	Text     string   `json:"text"`
	Collect  string   `json:"collect,omitempty"`
	Count    int      `json:"count,omitempty"`
	Refs     []string `json:"evidence_refs,omitempty"`
}

// Build computes the coverage report. It never fails: input it cannot use
// becomes a limit in the report.
func Build(in Input, o Options) *Report {
	o.defaults()
	r := &Report{Schema: Schema, CaseID: in.CaseID, Host: in.Host,
		Thresholds: Thresholds{MinGapSeconds: int64(o.MinGap / time.Second), CadenceFactor: o.CadenceFactor,
			ClockToleranceSeconds: int64(o.ClockTolerance / time.Second), ActivityJoinSeconds: int64(o.ActivityJoin / time.Second)},
		Sessions: []SessionCoverage{}, Integrity: []Signal{}, Items: []Item{}}
	b := &builder{in: in, o: o, r: r}
	b.index()
	b.sessions()
	b.integrity()
	b.acquisition()
	b.witness()
	b.clock()
	b.chains()
	b.limits()
	b.finish()
	return r
}

type builder struct {
	in Input
	o  Options
	r  *Report
	// parsed timestamps, by event position (zero when absent/unparseable)
	ts       []time.Time
	byID     map[string]int
	artByID  map[string]casepkg.ArtifactRecord
	matchBy  map[string]correlate.Match
	verified map[string]string // event id → independent source that confirmed it
	// decisions: event id → the correlation's coverage decision for it
	decisions map[string]string
}

func (b *builder) add(it Item) {
	if len(it.Refs) > b.o.MaxExamples {
		it.Refs = it.Refs[:b.o.MaxExamples]
	}
	b.r.Items = append(b.r.Items, it)
}

func (b *builder) index() {
	b.ts = make([]time.Time, len(b.in.Events))
	b.byID = make(map[string]int, len(b.in.Events))
	for i, ev := range b.in.Events {
		if t, ok := parseTS(ev.Timestamp); ok {
			b.ts[i] = t
		}
		b.byID[ev.EventID] = i
	}
	b.artByID = map[string]casepkg.ArtifactRecord{}
	if b.in.Manifest != nil {
		for _, a := range b.in.Manifest.Current() {
			if a.ArtifactID != "" {
				b.artByID[a.ArtifactID] = a
			}
		}
	}
	b.matchBy = map[string]correlate.Match{}
	b.verified = map[string]string{}
	if c := b.in.Correlation; c != nil {
		for _, m := range c.Matches {
			b.matchBy[m.EventID] = m
		}
	}
	for _, ev := range b.in.Events {
		if ev.EventType != schema.EventToolCall || !isVerified(ev.Corroboration) {
			continue
		}
		b.verified[ev.EventID] = verifiedBy(ev, b.matchBy)
	}
}

// verifiedBy names the independent source behind a confirmed tool call.
func verifiedBy(ev schema.Event, matches map[string]correlate.Match) string {
	if m, ok := matches[ev.EventID]; ok {
		switch m.Witness {
		case correlate.WitnessCloud:
			return "cloud audit log"
		case correlate.WitnessSighting:
			return srcSightings
		case correlate.WitnessScript, correlate.WitnessProcessImage:
			return srcEventLog
		}
		return "endpoint telemetry"
	}
	switch {
	case strings.Contains(ev.WitnessNote, "host witness:"):
		return "host witness"
	case strings.Contains(ev.Summary, "corroborated by shell_history"):
		return "shell history"
	case strings.Contains(ev.Summary, "corroborated by "):
		return "endpoint telemetry"
	}
	return "independent source (not named on the event)"
}

// Independent sources beside endpoint telemetry and cloud audit logs.
const (
	srcSightings = "DNS, proxy, auth and journal logs"
	srcEventLog  = "Windows event log (script block or image-only process creation)"
)

func isVerified(state string) bool {
	return state == schema.StateCorroborated || state == schema.StatePartial
}

// ---- sessions and time gaps

func (b *builder) sessions() {
	type acc struct {
		idx     []int
		untimed int
		product string
	}
	bySess := map[string]*acc{}
	for i, ev := range b.in.Events {
		if ev.SessionID == "" {
			continue
		}
		a := bySess[ev.SessionID]
		if a == nil {
			a = &acc{product: ev.Product}
			bySess[ev.SessionID] = a
		}
		if b.ts[i].IsZero() {
			a.untimed++
			continue
		}
		a.idx = append(a.idx, i)
	}
	ids := sortedKeys(bySess)
	b.r.Summary.Sessions = len(ids)
	var gapItems []Item
	for _, sid := range ids {
		a := bySess[sid]
		sc := SessionCoverage{SessionID: sid, Product: a.product, Events: len(a.idx) + a.untimed, Untimed: a.untimed}
		idx := a.idx
		sort.SliceStable(idx, func(x, y int) bool { return b.ts[idx[x]].Before(b.ts[idx[y]]) })
		if len(idx) > 0 {
			sc.Start, sc.End = rfc(b.ts[idx[0]]), rfc(b.ts[idx[len(idx)-1]])
		}
		var deltas []time.Duration
		for k := 1; k < len(idx); k++ {
			if d := b.ts[idx[k]].Sub(b.ts[idx[k-1]]); d > 0 {
				deltas = append(deltas, d)
			}
		}
		med := medianDur(deltas)
		sc.CadenceSeconds = float64(med.Milliseconds()) / 1000
		threshold := b.o.MinGap
		if f := med * time.Duration(b.o.CadenceFactor); f > threshold {
			threshold = f
		}
		for k := 1; k < len(idx); k++ {
			prev, next := b.in.Events[idx[k-1]], b.in.Events[idx[k]]
			d := b.ts[idx[k]].Sub(b.ts[idx[k-1]])
			if d < threshold {
				continue
			}
			b.r.Summary.TimeGaps++
			if len(sc.Gaps) >= b.o.MaxGapsPerSession {
				sc.GapsOmitted++
				b.r.Truncated = true
				continue
			}
			g := TimeGap{Start: rfc(b.ts[idx[k-1]]), End: rfc(b.ts[idx[k]]), Seconds: int64(d / time.Second), BeforeRef: Ref(prev), AfterRef: Ref(next)}
			sc.Gaps = append(sc.Gaps, g)
			gapItems = append(gapItems, Item{Status: Unknown, Category: CatTranscript,
				Text: fmt.Sprintf("Session %s has no transcript records for %s (%s to %s); its median spacing is %s. The session may have been idle or records may be missing; the transcript alone cannot say which.",
					sid, human(d), clock(b.ts[idx[k-1]]), clock(b.ts[idx[k]]), human(med)),
				Refs: []string{g.BeforeRef, g.AfterRef}})
		}
		if a.untimed > 0 {
			gapItems = append(gapItems, Item{Status: Unknown, Category: CatTranscript, Count: a.untimed,
				Text: fmt.Sprintf("Session %s has %d record(s) without a usable timestamp; they cannot be placed in time.", sid, a.untimed)})
		}
		b.r.Sessions = append(b.r.Sessions, sc)
	}
	b.addBounded(gapItems, "time gap")
}

// addBounded adds items, keeping at most MaxItemsPerKind and summarizing
// the rest in one line.
func (b *builder) addBounded(items []Item, kind string) {
	for i, it := range items {
		if i >= b.o.MaxItemsPerKind {
			rest := len(items) - i
			b.r.Truncated = true
			b.add(Item{Status: it.Status, Category: it.Category, Count: rest,
				Text: fmt.Sprintf("%d more %s item(s) not listed here; the structured sections above list them.", rest, kind)})
			return
		}
		b.add(it)
	}
}

// ---- transcript integrity

var integrityRules = map[string]string{
	"TRANSCRIPT_REWRITTEN": "the transcript differs from what the monitor journal recorded",
	"TRANSCRIPT_TRUNCATED": "the transcript is shorter than the monitor journal recorded",
	"TRANSCRIPT_REPLACED":  "the transcript file was replaced after the monitor journal recorded it",
	"TRANSCRIPT_DELETED":   "a transcript the monitor journal recorded is gone",
	"SESSION_TAMPERING":    "the transcript shows signs of editing",
}

func (b *builder) integrity() {
	var sigs []Signal
	for _, ev := range b.in.Events {
		switch {
		case ev.EventType == schema.EventTraceGap:
			sigs = append(sigs, Signal{SessionID: ev.SessionID, Code: "TRACE_GAP", Detail: "malformed or truncated region in the transcript", Ref: Ref(ev)})
		case ev.EventType == schema.EventSessionMeta && ev.Result == "chain_break":
			sigs = append(sigs, Signal{SessionID: ev.SessionID, Code: "CHAIN_BREAK", Detail: "a record names a parent record that is not in the transcript", Ref: Ref(ev)})
		}
	}
	for _, f := range b.in.Findings {
		d, ok := integrityRules[f.RuleID]
		if !ok {
			continue
		}
		ref := ""
		if len(f.EvidenceRefs) > 0 {
			ref = f.EvidenceRefs[0]
		}
		sigs = append(sigs, Signal{SessionID: f.SessionID, Code: f.RuleID, Detail: d, Ref: ref})
	}
	sort.SliceStable(sigs, func(i, j int) bool {
		if sigs[i].SessionID != sigs[j].SessionID {
			return sigs[i].SessionID < sigs[j].SessionID
		}
		if sigs[i].Code != sigs[j].Code {
			return sigs[i].Code < sigs[j].Code
		}
		return sigs[i].Ref < sigs[j].Ref
	})
	b.r.Integrity = sigs
	// One item per session and code: a corrupt file can carry hundreds of
	// gap records, and the analyst needs to know which sessions, not each line.
	type key struct{ sess, code string }
	grouped := map[key][]Signal{}
	var order []key
	for _, s := range sigs {
		k := key{s.SessionID, s.Code}
		if _, ok := grouped[k]; !ok {
			order = append(order, k)
		}
		grouped[k] = append(grouped[k], s)
	}
	var items []Item
	for _, k := range order {
		g := grouped[k]
		where := "Session " + k.sess
		if k.sess == "" {
			where = "A transcript"
		}
		var refs []string
		for _, s := range g {
			refs = append(refs, s.Ref)
		}
		items = append(items, Item{Status: Unknown, Category: CatTranscript, Count: len(g), Refs: refs,
			Text: fmt.Sprintf("%s: %s (%s, %d record(s)). What was in the affected part is not in the case.", where, g[0].Detail, k.code, len(g))})
	}
	b.addBounded(items, "transcript integrity")
}

// ---- acquisition windows

func (b *builder) acquisition() {
	if ci := b.in.CaseInfo; ci != nil {
		for _, rd := range ci.Rounds {
			b.r.Acquisition.Rounds = append(b.r.Acquisition.Rounds, Round{Round: rd.Round, Started: rd.StartedUTC, Completed: rd.CompletedUTC,
				Fresh: rd.ArtifactsOK, Carried: rd.ArtifactsCarried, Failed: rd.ArtifactsFailed})
		}
	}
	if b.r.Acquisition.Rounds == nil {
		b.r.Acquisition.Rounds = []Round{}
	}
	prods := map[string]*ProductWindow{}
	get := func(p string) *ProductWindow {
		if p == "" {
			p = "unknown"
		}
		w := prods[p]
		if w == nil {
			w = &ProductWindow{Product: p}
			prods[p] = w
		}
		return w
	}
	evMin, evMax := map[string]time.Time{}, map[string]time.Time{}
	for i, ev := range b.in.Events {
		w := get(ev.Product)
		w.Events++
		t := b.ts[i]
		if t.IsZero() {
			continue
		}
		if m, ok := evMin[w.Product]; !ok || t.Before(m) {
			evMin[w.Product] = t
		}
		if m, ok := evMax[w.Product]; !ok || t.After(m) {
			evMax[w.Product] = t
		}
	}
	colMin, colMax := map[string]time.Time{}, map[string]time.Time{}
	if b.in.Manifest != nil {
		for _, a := range b.in.Manifest.Current() {
			w := get(a.Product)
			switch a.Status {
			case casepkg.StatusOK:
				w.Artifacts++
				if a.AcquiredIn != 0 && a.Round != 0 && a.AcquiredIn < a.Round {
					w.Carried++
				} else {
					w.Fresh++
				}
			case casepkg.StatusNotPresent:
				w.NotPresent++
			default:
				if w.NotAcquired == nil {
					w.NotAcquired = map[string]int{}
				}
				w.NotAcquired[a.Status]++
			}
			if t, ok := parseTS(a.CollectedUTC); ok {
				if m, ok := colMin[w.Product]; !ok || t.Before(m) {
					colMin[w.Product] = t
				}
				if m, ok := colMax[w.Product]; !ok || t.After(m) {
					colMax[w.Product] = t
				}
			}
		}
	}
	var known, unknown, next []Item
	for _, p := range sortedKeys(prods) {
		w := prods[p]
		if t, ok := evMin[p]; ok {
			w.EarliestEvidence = rfc(t)
		}
		if t, ok := evMax[p]; ok {
			w.LatestEvidence = rfc(t)
		}
		if t, ok := colMin[p]; ok {
			w.FirstCollected = rfc(t)
		}
		if t, ok := colMax[p]; ok {
			w.LastCollected = rfc(t)
			if e, ok := evMax[p]; ok {
				w.LagSeconds = int64(t.Sub(e) / time.Second)
			}
		}
		b.r.Acquisition.Products = append(b.r.Acquisition.Products, *w)
		if w.Events > 0 && w.EarliestEvidence != "" {
			txt := fmt.Sprintf("%s: transcript evidence spans %s to %s (%d events).", p, clock(evMin[p]), clock(evMax[p]), w.Events)
			if w.LastCollected != "" {
				txt += fmt.Sprintf(" Last collected %s.", clock(colMax[p]))
			}
			known = append(known, Item{Status: Known, Category: CatAcquisition, Text: txt})
		}
		if w.Artifacts > 0 {
			txt := fmt.Sprintf("%s: %d artifact(s) in the case, %d read in the round that recorded them", p, w.Artifacts, w.Fresh)
			if w.Carried > 0 {
				txt += fmt.Sprintf(", %d carried forward unchanged from an earlier round (preserved then, not re-read since)", w.Carried)
			}
			known = append(known, Item{Status: Known, Category: CatAcquisition, Text: txt + "."})
		}
		if n := sumMap(w.NotAcquired); n > 0 {
			unknown = append(unknown, Item{Status: Unknown, Category: CatAcquisition, Count: n,
				Text: fmt.Sprintf("%s: %d artifact(s) were found but not acquired (%s); their content is not in the case.", p, n, mapList(w.NotAcquired))})
			next = append(next, Item{Status: VerifyNext, Category: CatAcquisition, Count: n,
				Text:    fmt.Sprintf("%s: %d artifact(s) were not acquired.", p, n),
				Collect: notAcquiredAdvice(w.NotAcquired)})
		}
	}
	if b.r.Acquisition.Products == nil {
		b.r.Acquisition.Products = []ProductWindow{}
	}
	for _, l := range [][]Item{known, unknown, next} {
		b.addBounded(l, "acquisition")
	}
}

func notAcquiredAdvice(m map[string]int) string {
	var parts []string
	if m[casepkg.StatusAccessDenied] > 0 {
		parts = append(parts, "re-collect as the profile owner or an administrator for the ACCESS_DENIED paths")
	}
	if m[casepkg.StatusSkippedBound] > 0 {
		parts = append(parts, "re-collect with a larger --max-file-mb for the files over the size bound")
	}
	if m[casepkg.StatusSkippedPolicy] > 0 {
		parts = append(parts, "re-collect with --full-plugins if the policy-skipped trees matter")
	}
	if len(parts) == 0 {
		parts = append(parts, "re-collect the listed paths (see the manifest's status and error fields)")
	}
	return strings.Join(parts, "; ") + "."
}

// ---- second-witness coverage

// actionOf is the primary kind of one tool call for coverage purposes.
func actionOf(ev schema.Event) string {
	switch {
	case ev.Command != "" && isCloudCommand(ev.FullCommand()):
		return "cloud_command"
	case ev.NetworkDest != "":
		return "network"
	case ev.Command != "":
		return "shell_command"
	case ev.Action == "write_file" || ev.Action == "edit_file":
		return "file_write"
	case ev.Action == "read_file":
		return "file_read"
	case ev.MCPServer != "":
		return "mcp_call"
	}
	return "other"
}

func isCloudCommand(cmd string) bool {
	for _, seg := range strings.FieldsFunc(cmd, func(r rune) bool { return r == ';' || r == '|' || r == '&' || r == '\n' }) {
		f := strings.Fields(seg)
		for len(f) > 0 && (f[0] == "sudo" || strings.Contains(f[0], "=")) {
			f = f[1:]
		}
		if len(f) == 0 {
			continue
		}
		switch strings.ToLower(f[0]) {
		case "aws", "az", "gcloud", "gsutil", "bq":
			return true
		}
	}
	return false
}

func (b *builder) witness() {
	w := &b.r.Witness
	c := b.in.Correlation
	var epStart, epEnd time.Time
	window := 3 * time.Second
	verifiedBy := map[string]int{}
	for _, src := range b.verified {
		verifiedBy[src]++
	}
	if c != nil && !c.CoverageStart.IsZero() {
		epStart, epEnd = c.CoverageStart.UTC(), c.CoverageEnd.UTC()
		for _, m := range c.Matches {
			if m.Witness == "endpoint" && m.WindowMS > 0 {
				window = time.Duration(m.WindowMS) * time.Millisecond
				break
			}
		}
		w.Sources = append(w.Sources, WitnessSource{Name: "endpoint telemetry", Start: rfc(epStart), End: rfc(epEnd),
			Records: c.Records - c.CloudRecords - c.WitnessRecords - c.ContextRecords, Verified: verifiedBy["endpoint telemetry"],
			Note: "process, file and network records imported with --endpoint; inside this range a command with no matching process is DISPROVED"})
	}
	if c != nil && c.CloudRecords > 0 {
		w.Sources = append(w.Sources, WitnessSource{Name: "cloud audit log", Start: c.CloudCoverageStart, End: c.CloudCoverageEnd,
			Records: c.CloudRecords, Verified: verifiedBy["cloud audit log"],
			Note: "control-plane records; a miss is never a contradiction (the export may cover another account)"})
	}
	if c != nil && (c.WitnessRecords > 0 || verifiedBy[srcSightings] > 0) {
		w.Sources = append(w.Sources, WitnessSource{Name: srcSightings, Records: c.WitnessRecords, Verified: verifiedBy[srcSightings],
			Note: "partial-coverage logs: they corroborate, never contradict and never widen coverage; a DNS lookup or ssh login only PARTLY CONFIRMS"})
	}
	if c != nil && c.ContextRecords > 0 {
		kinds := make([]string, 0, len(c.ContextKinds))
		for _, k := range sortedKeys(c.ContextKinds) {
			kinds = append(kinds, fmt.Sprintf("%s %d", k, c.ContextKinds[k]))
		}
		w.Sources = append(w.Sources, WitnessSource{Name: "Windows event log context", Records: c.ContextRecords,
			Note: "telemetry present: " + strings.Join(kinds, ", ") + "; read by the Windows persistence and credential rules, never used to confirm or disprove a tool call"})
	}
	if n := verifiedBy[srcEventLog]; n > 0 {
		w.Sources = append(w.Sources, WitnessSource{Name: srcEventLog, Verified: n,
			Note: "PowerShell 4104 script blocks and 4688 without a command line; corroborate only, an image name only PARTLY CONFIRMS"})
	}
	if wr := b.in.Witness; wr != nil {
		w.Sources = append(w.Sources, WitnessSource{Name: "host witness", Start: wr.GatheredUTC, End: wr.GatheredUTC, Records: len(wr.Files) + len(wr.Repos),
			Verified: verifiedBy["host witness"], Note: "file state at acquisition: confirms that claimed writes are on disk, not when they happened"})
	}
	if n := verifiedBy["shell history"]; n > 0 {
		w.Sources = append(w.Sources, WitnessSource{Name: "shell history", Verified: n, Note: "history lines carry no reliable time; never contradicts"})
	}
	if n := verifiedBy["independent source (not named on the event)"]; n > 0 {
		w.Sources = append(w.Sources, WitnessSource{Name: "independent source (not named on the event)", Verified: n})
	}
	if w.Sources == nil {
		w.Sources = []WitnessSource{}
	}
	if c != nil {
		w.KindCoverage, w.CollectionHealth = c.KindCoverage, c.Health
		b.decisions = map[string]string{}
		for _, d := range c.Decisions {
			b.decisions[d.EventID] = d.Coverage
		}
		for _, h := range c.Health {
			switch h.Verdict {
			case endpoint.HealthPartial:
				b.add(Item{Status: Unknown, Category: CatWitness, Count: h.Gaps + len(h.Drops) + h.DropsOmitted,
					Text: fmt.Sprintf("Telemetry %s is PARTIAL: %d sequence gap(s) and %d drop signal(s). Inside the affected intervals a missing record proves nothing, so no tool call there is DISPROVED.", h.File, h.Gaps, len(h.Drops)+h.DropsOmitted)})
			case endpoint.HealthUnknown:
				b.add(Item{Status: Unknown, Category: CatWitness,
					Text: fmt.Sprintf("Telemetry %s carries no sequence numbers: its completeness is unverified (absence is still evaluated inside its coverage, as before).", h.File)})
			}
		}
	}
	inEP := func(t time.Time) bool {
		return !epStart.IsZero() && !t.Before(epStart.Add(-window)) && !t.After(epEnd.Add(window))
	}

	actions := map[string]*ActionCoverage{}
	type call struct {
		i   int
		act string
	}
	var timed []call
	for i, ev := range b.in.Events {
		if ev.EventType == schema.EventModelResponse && ev.Corroboration == schema.StateReported {
			w.NarrativeClaims++
		}
		if ev.EventType != schema.EventToolCall {
			continue
		}
		b.r.Summary.ToolCalls++
		act := actionOf(ev)
		ac := actions[act]
		if ac == nil {
			ac = &ActionCoverage{Action: act}
			actions[act] = ac
		}
		ac.Total++
		switch {
		case isVerified(ev.Corroboration):
			ac.Verified++
			b.r.Summary.Verified++
			if ev.Corroboration == schema.StatePartial {
				ac.Partial++
				b.r.Summary.Partial++
			}
		case ev.Corroboration == schema.StateContradicted:
			ac.Disproved++
			b.r.Summary.Disproved++
		default:
			ac.Unverified++
			b.r.Summary.Unverified++
			if ac.Reasons == nil {
				ac.Reasons = map[string]int{}
			}
			ac.Reasons[b.reason(i, act, inEP)]++
		}
		if !b.ts[i].IsZero() {
			timed = append(timed, call{i, act})
		}
	}
	for _, k := range sortedKeys(actions) {
		w.Actions = append(w.Actions, *actions[k])
	}
	if w.Actions == nil {
		w.Actions = []ActionCoverage{}
	}

	// Activity ranges: per host, tool calls joined while the silence between
	// them stays under ActivityJoin.
	sort.SliceStable(timed, func(x, y int) bool {
		hx, hy := b.in.Events[timed[x].i].Host, b.in.Events[timed[y].i].Host
		if hx != hy {
			return hx < hy
		}
		return b.ts[timed[x].i].Before(b.ts[timed[y].i])
	})
	var ranges []ActivityRange
	var cur *ActivityRange
	var curStart, curEnd time.Time
	var curVerified map[string]bool
	flush := func() {
		if cur == nil {
			return
		}
		cur.Start, cur.End = rfc(curStart), rfc(curEnd)
		switch {
		case inEP(curStart) && inEP(curEnd):
			cur.Coverage = "full"
		case !epStart.IsZero() && !curEnd.Before(epStart.Add(-window)) && !curStart.After(epEnd.Add(window)):
			cur.Coverage = "partial"
		default:
			cur.Coverage = "none"
		}
		for s := range curVerified {
			cur.VerifiedBy = append(cur.VerifiedBy, s)
		}
		sort.Strings(cur.VerifiedBy)
		ranges = append(ranges, *cur)
		cur = nil
	}
	for _, c := range timed {
		ev, t := b.in.Events[c.i], b.ts[c.i]
		if cur == nil || ev.Host != cur.Host || t.Sub(curEnd) > b.o.ActivityJoin {
			flush()
			cur = &ActivityRange{Host: ev.Host}
			curStart, curVerified = t, map[string]bool{}
		}
		curEnd = t
		cur.ToolCalls++
		switch c.act {
		case "shell_command":
			cur.Shell++
		case "network":
			cur.Network++
		case "cloud_command":
			cur.Cloud++
		case "file_write":
			cur.FileWrites++
		}
		if src, ok := b.verified[ev.EventID]; ok {
			curVerified[src] = true
		} else if ev.Corroboration != schema.StateContradicted {
			cur.Unverified++
		}
	}
	flush()
	b.nextFromRanges(ranges)
	if len(ranges) > b.o.MaxRanges {
		w.ActivityOmitted = len(ranges) - b.o.MaxRanges
		ranges = ranges[:b.o.MaxRanges]
		b.r.Truncated = true
	}
	w.Activity = ranges
	if w.Activity == nil {
		w.Activity = []ActivityRange{}
	}

	// Items.
	s := b.r.Summary
	if s.ToolCalls > 0 {
		txt := fmt.Sprintf("%d of %d tool call(s) are CONFIRMED by an independent source", s.Verified, s.ToolCalls)
		if s.Partial > 0 {
			txt = fmt.Sprintf("%d of %d tool call(s) are checked by an independent source: %d CONFIRMED, %d PARTLY CONFIRMED", s.Verified, s.ToolCalls, s.Verified-s.Partial, s.Partial)
		}
		if len(verifiedBy) > 0 {
			txt += " (" + mapList(verifiedBy) + ")"
		}
		b.add(Item{Status: Known, Category: CatWitness, Count: s.Verified, Text: txt + "."})
	}
	if s.Disproved > 0 {
		b.add(Item{Status: Known, Category: CatWitness, Count: s.Disproved,
			Text: fmt.Sprintf("%d tool call(s) are DISPROVED: endpoint telemetry covering their time shows no matching process.", s.Disproved)})
	}
	for _, ac := range w.Actions {
		if ac.Unverified == 0 {
			continue
		}
		b.add(Item{Status: Unknown, Category: CatWitness, Count: ac.Unverified,
			Text: fmt.Sprintf("%d %s tool call(s) are unverified: %s.", ac.Unverified, strings.ReplaceAll(ac.Action, "_", " "), reasonList(ac.Reasons))})
	}
	if w.NarrativeClaims > 0 {
		b.add(Item{Status: Unknown, Category: CatWitness, Count: w.NarrativeClaims,
			Text: fmt.Sprintf("%d model response(s) are narrative (CLAIMED). What the model said it did is checked only where a tool call records it.", w.NarrativeClaims)})
	}
	if c == nil || c.CoverageStart.IsZero() {
		if s.ToolCalls > 0 {
			b.add(Item{Status: VerifyNext, Category: CatWitness, Count: s.Unverified,
				Text:    "No endpoint telemetry was imported, so no tool call could be confirmed or disproved by the operating system.",
				Collect: "Process, file and network telemetry from the host for the activity ranges listed (Sysmon, auditd, EDR export, eslogger), then: agentdfir analyze <case> --endpoint <log>."})
		}
	}
	if b.in.Witness == nil && b.r.Summary.ToolCalls > 0 {
		b.add(Item{Status: VerifyNext, Category: CatWitness,
			Text:    "The case has no host witness, so no claimed file write was checked against the disk.",
			Collect: "Collect on the live host with agentdfir run (or collect --live), which records the state of every file the agent claimed to write."})
	}
}

// reason says why one unverified tool call stayed unverified.
func (b *builder) reason(i int, act string, inEP func(time.Time) bool) string {
	ev := b.in.Events[i]
	if b.ts[i].IsZero() {
		return ReasonNoTimestamp
	}
	if ev.Command == "" && ev.File == "" && ev.NetworkDest == "" {
		return ReasonNotCheckable
	}
	if ev.WitnessNote != "" && act == "file_write" {
		return ReasonWitnessNoMatch
	}
	switch b.decisions[ev.EventID] {
	case correlate.CoverPartial:
		return ReasonPartial
	case correlate.CoverNoKind:
		return ReasonNoKind
	}
	if inEP(b.ts[i]) {
		return ReasonNoMatch
	}
	return ReasonNoTelemetry
}

var reasonText = map[string]string{
	ReasonNoTelemetry:    "no telemetry covers their time",
	ReasonNoMatch:        "telemetry covers their time but no record matched",
	ReasonNoTimestamp:    "no timestamp to match on",
	ReasonNotCheckable:   "no command, file or destination for a witness to check",
	ReasonWitnessNoMatch: "the host witness could not confirm the content",
	ReasonPartial:        "the telemetry for their time is incomplete (sequence gap or drop)",
	ReasonNoKind:         "no telemetry of the kind they need on that host",
}

func reasonList(m map[string]int) string {
	var parts []string
	for _, k := range sortedKeys(m) {
		parts = append(parts, fmt.Sprintf("%d %s", m[k], reasonText[k]))
	}
	return strings.Join(parts, ", ")
}

// nextFromRanges turns uncovered activity into concrete collection asks.
func (b *builder) nextFromRanges(ranges []ActivityRange) {
	var items []Item
	for _, rg := range ranges {
		if rg.Coverage == "full" || rg.Unverified == 0 {
			continue
		}
		host := rg.Host
		if host == "" {
			host = "the collected host"
		}
		start, _ := parseTS(rg.Start)
		end, _ := parseTS(rg.End)
		span := fmt.Sprintf("%s–%s UTC on host %s", start.Format("2006-01-02 15:04"), end.Add(time.Minute-time.Nanosecond).Truncate(time.Minute).Format("15:04"), host)
		if end.Format("2006-01-02") != start.Format("2006-01-02") {
			span = fmt.Sprintf("%s – %s UTC on host %s", start.Format("2006-01-02 15:04"), end.Add(time.Minute-time.Nanosecond).Truncate(time.Minute).Format("2006-01-02 15:04"), host)
		}
		if rg.Coverage == "partial" {
			span += " (partly outside the imported telemetry)"
		}
		add := func(n int, what, source string) {
			if n == 0 {
				return
			}
			items = append(items, Item{Status: VerifyNext, Category: CatWitness, Count: n,
				Text:    fmt.Sprintf("%d %s at %s have no second witness.", n, what, span),
				Collect: fmt.Sprintf("%s covering %s would verify %d %s.", source, span, n, what)})
		}
		add(rg.Shell, "shell command(s)", "Process telemetry (Sysmon event 1, auditd EXECVE, EDR process events)")
		add(rg.Network, "network action(s)", "DNS, proxy or firewall logs (or Sysmon event 3/22)")
		add(rg.Cloud, "cloud CLI command(s)", "Cloud audit logs (CloudTrail, Azure Activity Log, GCP Cloud Audit Logs)")
		add(rg.FileWrites, "file write(s)", "File telemetry (Sysmon event 11, auditd PATH records, EDR file events)")
	}
	b.addBounded(items, "collection")
}

// ---- clock consistency

func (b *builder) clock() {
	ck := &b.r.Clock
	tol := b.o.ClockTolerance
	omit := map[string]int{}
	keep := func(kind string, list *[]ClockExample, ex ClockExample) {
		if len(*list) >= b.o.MaxExamples {
			omit[kind]++
			return
		}
		*list = append(*list, ex)
	}

	// Events after their own collection, and steps back in time within
	// one source file (transcripts are append-only).
	type order struct {
		last    time.Time
		count   int
		maxBack time.Duration
		example string
	}
	byArt := map[string]*order{}
	lastByArt := map[string]time.Time{}
	refByArt := map[string]string{}
	for i, ev := range b.in.Events {
		t := b.ts[i]
		if t.IsZero() || ev.SourceArtifact == "" {
			continue
		}
		if a, ok := b.artByID[ev.SourceArtifact]; ok {
			if col, ok := parseTS(a.CollectedUTC); ok && t.After(col.Add(tol)) {
				ck.FutureEvents++
				keep("events_after_collection", &ck.FutureExamples, ClockExample{Ref: Ref(ev), Recorded: rfc(t), Reference: rfc(col),
					Basis: "event timestamp vs collection time of its transcript", Seconds: int64(t.Sub(col) / time.Second)})
			}
		}
		key := ev.SourceArtifact + "\x00" + ev.SourcePath
		o := byArt[key]
		if o == nil {
			o = &order{}
			byArt[key] = o
		}
		if !o.last.IsZero() && t.Before(o.last.Add(-time.Minute)) {
			o.count++
			if back := o.last.Sub(t); back > o.maxBack {
				o.maxBack = back
				o.example = Ref(ev)
			}
		}
		if t.After(o.last) {
			o.last = t
		}
		if t.After(lastByArt[ev.SourceArtifact]) {
			lastByArt[ev.SourceArtifact] = t
			refByArt[ev.SourceArtifact] = Ref(ev)
		}
	}
	for _, k := range sortedKeys(byArt) {
		o := byArt[k]
		if o.count == 0 {
			continue
		}
		path := k[strings.IndexByte(k, 0)+1:]
		ck.OutOfOrder = append(ck.OutOfOrder, OutOfOrder{Path: path, Count: o.count, MaxStepBackSecs: int64(o.maxBack / time.Second), ExampleRef: o.example})
	}
	if len(ck.OutOfOrder) > b.o.MaxItemsPerKind {
		omit["out_of_order"] = len(ck.OutOfOrder) - b.o.MaxItemsPerKind
		ck.OutOfOrder = ck.OutOfOrder[:b.o.MaxItemsPerKind]
	}
	// A transcript's mtime before its own last record.
	for _, id := range sortedKeys(lastByArt) {
		a, ok := b.artByID[id]
		if !ok {
			continue
		}
		mt, ok := parseTS(a.ModTimeUTC)
		last := lastByArt[id]
		if !ok || !mt.Before(last.Add(-tol)) {
			continue
		}
		keep("transcript_mtime", &ck.TranscriptMTime, ClockExample{Ref: refByArt[id], Recorded: rfc(last), Reference: rfc(mt),
			Basis: "last record in the transcript vs the file's modification time", Seconds: int64(last.Sub(mt) / time.Second)})
	}
	// Endpoint vs transcript, over matched pairs.
	if c := b.in.Correlation; c != nil {
		var d []int64
		for _, m := range c.Matches {
			if m.Witness == "endpoint" {
				d = append(d, m.DeltaMS)
			}
		}
		if len(d) > 0 {
			sort.Slice(d, func(i, j int) bool { return d[i] < d[j] })
			ck.EndpointOffset = &Offset{Pairs: len(d), MedianMS: d[len(d)/2], MinMS: d[0], MaxMS: d[len(d)-1]}
		}
	}
	// Host witness mtime before the write the agent claimed.
	if wr := b.in.Witness; wr != nil {
		files := map[string]witness.File{}
		for _, f := range wr.Files {
			files[f.Path] = f
		}
		for i, ev := range b.in.Events {
			if (ev.Action != "write_file" && ev.Action != "edit_file") || b.ts[i].IsZero() || !isVerified(ev.Corroboration) {
				continue
			}
			f, ok := files[cleanAbs(ev.File)]
			if !ok || !f.Exists {
				continue
			}
			mt, ok := parseTS(f.ModTimeUTC)
			if !ok || !mt.Before(b.ts[i].Add(-tol)) {
				continue
			}
			keep("witness_mtime", &ck.WitnessFiles, ClockExample{Ref: Ref(ev), Recorded: rfc(b.ts[i]), Reference: rfc(mt),
				Basis: "write time in the transcript vs the file's modification time on the host (content confirmed)", Seconds: int64(b.ts[i].Sub(mt) / time.Second)})
		}
	}
	if len(omit) > 0 {
		ck.Omitted = omit
		b.r.Truncated = true
	}
	if ck.OutOfOrder == nil {
		ck.OutOfOrder = []OutOfOrder{}
	}
	if ck.TranscriptMTime == nil {
		ck.TranscriptMTime = []ClockExample{}
	}
	if ck.WitnessFiles == nil {
		ck.WitnessFiles = []ClockExample{}
	}

	// Items.
	if ck.FutureEvents > 0 {
		var refs []string
		for _, e := range ck.FutureExamples {
			refs = append(refs, e.Ref)
		}
		b.add(Item{Status: Unknown, Category: CatClock, Count: ck.FutureEvents, Refs: refs,
			Text: fmt.Sprintf("%d event(s) are timestamped more than %s after their transcript was collected. Either the recording clock was ahead or the timestamps were written by something other than the agent.", ck.FutureEvents, human(tol))})
	}
	for _, o := range ck.OutOfOrder {
		b.add(Item{Status: Unknown, Category: CatClock, Count: o.Count, Refs: []string{o.ExampleRef},
			Text: fmt.Sprintf("%s: timestamps go backwards %d time(s), by up to %s, in a file that is only ever appended to. The clock changed while it was written, or lines were inserted.", o.Path, o.Count, human(time.Duration(o.MaxStepBackSecs)*time.Second))})
	}
	for _, e := range ck.TranscriptMTime {
		b.add(Item{Status: Unknown, Category: CatClock, Refs: []string{e.Ref},
			Text: fmt.Sprintf("A transcript was last modified %s before its own last record (%s vs %s): the file clock and the transcript clock disagree, or the modification time was set.", human(time.Duration(e.Seconds)*time.Second), clockS(e.Reference), clockS(e.Recorded))})
	}
	if off := ck.EndpointOffset; off != nil {
		txt := fmt.Sprintf("Across %d matched pair(s), endpoint records are %s from the transcript timestamps (median; range %s to %s).", off.Pairs, signedMS(off.MedianMS), signedMS(off.MinMS), signedMS(off.MaxMS))
		st := Known
		if abs64(off.MedianMS) > tol.Milliseconds() {
			st = Unknown
			txt += " The two clocks disagree by more than the tolerance; times from the two sources should not be compared directly."
		}
		b.add(Item{Status: st, Category: CatClock, Count: off.Pairs, Text: txt})
	}
	for _, e := range ck.WitnessFiles {
		b.add(Item{Status: Unknown, Category: CatClock, Refs: []string{e.Ref},
			Text: fmt.Sprintf("A file the agent wrote (content confirmed on the host) carries a modification time %s before the write was recorded: the host's file clock and the transcript clock disagree.", human(time.Duration(e.Seconds)*time.Second))})
	}
}

// ---- agent chains

func (b *builder) chains() {
	ch := &b.r.Chains
	agentsWithEvents := map[string]bool{}
	toolCalls := map[string]bool{}
	for _, ev := range b.in.Events {
		if ev.AgentID != "" && ev.EventType != schema.EventAgentSpawn {
			agentsWithEvents[ev.AgentID] = true
		}
		if ev.EventType == schema.EventToolCall && ev.ToolCallID != "" {
			toolCalls[ev.ToolCallID] = true
		}
	}
	for _, f := range b.in.Findings {
		if f.RuleID == "ORPHAN_AGENT" && f.AgentID != "" {
			ref := ""
			if len(f.EvidenceRefs) > 0 {
				ref = f.EvidenceRefs[0]
			}
			ch.Orphans = append(ch.Orphans, AgentRef{AgentID: f.AgentID, SessionID: f.SessionID, ParentAgentID: "UNKNOWN", Ref: ref})
		}
	}
	seenChild := map[string]bool{}
	seenParent := map[string]bool{}
	results := map[string]*SessionRef{}
	breaks := map[string]*SessionRef{}
	bump := func(m map[string]*SessionRef, ev schema.Event) {
		s := m[ev.SessionID]
		if s == nil {
			s = &SessionRef{SessionID: ev.SessionID, ExampleRef: Ref(ev)}
			m[ev.SessionID] = s
		}
		s.Count++
	}
	for _, ev := range b.in.Events {
		switch {
		case ev.EventType == schema.EventAgentSpawn && ev.TaskID != "":
			if !agentsWithEvents[ev.TaskID] && !seenChild[ev.TaskID] {
				seenChild[ev.TaskID] = true
				ch.MissingSubagents = append(ch.MissingSubagents, AgentRef{AgentID: ev.TaskID, ParentAgentID: ev.AgentID, ToolCallID: ev.ToolCallID, SessionID: ev.SessionID, Ref: Ref(ev)})
			}
			if ev.ToolCallID != "" && !toolCalls[ev.ToolCallID] {
				ch.SpawnWithoutCall = append(ch.SpawnWithoutCall, AgentRef{AgentID: ev.TaskID, ParentAgentID: ev.AgentID, ToolCallID: ev.ToolCallID, SessionID: ev.SessionID, Ref: Ref(ev)})
			}
		case ev.EventType == schema.EventToolResult && ev.ToolCallID != "" && !toolCalls[ev.ToolCallID]:
			bump(results, ev)
		case ev.EventType == schema.EventSessionMeta && ev.Result == "chain_break":
			bump(breaks, ev)
		}
		if p := ev.ParentAgentID; p != "" && p != "UNKNOWN" && !agentsWithEvents[p] && !seenParent[ev.AgentID] {
			seenParent[ev.AgentID] = true
			ch.UnknownParents = append(ch.UnknownParents, AgentRef{AgentID: ev.AgentID, ParentAgentID: p, SessionID: ev.SessionID, Ref: Ref(ev)})
		}
	}
	for _, k := range sortedKeys(results) {
		ch.ResultsWithoutCall = append(ch.ResultsWithoutCall, *results[k])
	}
	for _, k := range sortedKeys(breaks) {
		ch.BrokenDAG = append(ch.BrokenDAG, *breaks[k])
	}
	byAgent := func(l []AgentRef) {
		sort.SliceStable(l, func(i, j int) bool {
			if l[i].AgentID != l[j].AgentID {
				return l[i].AgentID < l[j].AgentID
			}
			return l[i].Ref < l[j].Ref
		})
	}
	for _, l := range [][]AgentRef{ch.Orphans, ch.MissingSubagents, ch.SpawnWithoutCall, ch.UnknownParents} {
		byAgent(l)
	}
	ch.Orphans, ch.MissingSubagents = b.capAgents(ch.Orphans), b.capAgents(ch.MissingSubagents)
	ch.SpawnWithoutCall, ch.UnknownParents = b.capAgents(ch.SpawnWithoutCall), b.capAgents(ch.UnknownParents)
	if len(ch.ResultsWithoutCall) > b.o.MaxItemsPerKind {
		ch.Omitted += len(ch.ResultsWithoutCall) - b.o.MaxItemsPerKind
		ch.ResultsWithoutCall = ch.ResultsWithoutCall[:b.o.MaxItemsPerKind]
	}
	if ch.Omitted > 0 {
		b.r.Truncated = true
	}

	var items []Item
	for _, a := range ch.Orphans {
		items = append(items, Item{Status: Unknown, Category: CatChain, Refs: []string{a.Ref},
			Text: fmt.Sprintf("Agent %s (session %s) has records but nothing in the case shows which agent started it.", a.AgentID, a.SessionID)})
		items = append(items, Item{Status: VerifyNext, Category: CatChain, Refs: []string{a.Ref},
			Text:    fmt.Sprintf("The parent of agent %s is not in the case.", a.AgentID),
			Collect: fmt.Sprintf("Collect every session of the same profile and project as session %s (agentdfir run collects all of them); the parent transcript holds the spawn record.", a.SessionID)})
	}
	for _, a := range ch.MissingSubagents {
		items = append(items, Item{Status: Unknown, Category: CatChain, Refs: []string{a.Ref},
			Text: fmt.Sprintf("Agent %s started subagent %s, but the case holds no record of what the subagent did.", a.ParentAgentID, a.AgentID)})
		items = append(items, Item{Status: VerifyNext, Category: CatChain, Refs: []string{a.Ref},
			Text:    fmt.Sprintf("Subagent %s's own transcript is missing.", a.AgentID),
			Collect: fmt.Sprintf("Collect the subagent transcript of session %s (for Claude Code, agent-%s.jsonl or subagents/ next to the session file).", a.SessionID, a.AgentID)})
	}
	for _, a := range ch.SpawnWithoutCall {
		items = append(items, Item{Status: Unknown, Category: CatChain, Refs: []string{a.Ref},
			Text: fmt.Sprintf("Subagent %s's launch result cites tool call %s, which is not in the case: the request that started it is missing.", a.AgentID, a.ToolCallID)})
	}
	for _, a := range ch.UnknownParents {
		items = append(items, Item{Status: Unknown, Category: CatChain, Refs: []string{a.Ref},
			Text: fmt.Sprintf("Agent %s names parent agent %s, which has no records in the case.", a.AgentID, a.ParentAgentID)})
	}
	for _, s := range ch.ResultsWithoutCall {
		items = append(items, Item{Status: Unknown, Category: CatChain, Count: s.Count, Refs: []string{s.ExampleRef},
			Text: fmt.Sprintf("Session %s has %d tool result(s) whose tool call is not in the case.", s.SessionID, s.Count)})
	}
	for _, s := range ch.BrokenDAG {
		items = append(items, Item{Status: Unknown, Category: CatChain, Count: s.Count, Refs: []string{s.ExampleRef},
			Text: fmt.Sprintf("Session %s has %d record(s) pointing at a previous record that is not in the transcript.", s.SessionID, s.Count)})
	}
	b.addBounded(items, "agent chain")
	for _, l := range []*[]AgentRef{&ch.Orphans, &ch.MissingSubagents, &ch.SpawnWithoutCall, &ch.UnknownParents} {
		if *l == nil {
			*l = []AgentRef{}
		}
	}
	for _, l := range []*[]SessionRef{&ch.ResultsWithoutCall, &ch.BrokenDAG} {
		if *l == nil {
			*l = []SessionRef{}
		}
	}
}

func (b *builder) capAgents(l []AgentRef) []AgentRef {
	if len(l) > b.o.MaxItemsPerKind {
		b.r.Chains.Omitted += len(l) - b.o.MaxItemsPerKind
		return l[:b.o.MaxItemsPerKind]
	}
	return l
}

// ---- limits and finish

func (b *builder) limits() {
	l := []string{
		"Time gaps are measured from transcript timestamps alone. A gap means nothing was recorded; it does not mean anything was hidden.",
		"Second-witness coverage counts only sources in this case: telemetry imported with --endpoint at analysis time, the host witness recorded at acquisition, and shell history. Telemetry that exists elsewhere is not known to the case.",
		"Cloud audit logs and shell history can confirm an action but never disprove one: their absence of a record is not evidence.",
		"Clock checks compare timestamps the evidence carries; no clock is assumed correct.",
	}
	if b.in.Manifest == nil {
		l = append(l, "The manifest could not be read: acquisition windows and file-time checks are missing.")
	}
	if b.in.Correlation == nil {
		l = append(l, "No endpoint correlation results are in the case.")
	}
	b.r.Limits = l
}

var statusRank = map[string]int{Known: 0, Unknown: 1, VerifyNext: 2}
var catRank = map[string]int{CatAcquisition: 0, CatTranscript: 1, CatWitness: 2, CatClock: 3, CatChain: 4}

func (b *builder) finish() {
	// Stable within a status and category: the order each section added
	// them in, which is itself deterministic.
	sort.SliceStable(b.r.Items, func(i, j int) bool {
		a, c := b.r.Items[i], b.r.Items[j]
		if statusRank[a.Status] != statusRank[c.Status] {
			return statusRank[a.Status] < statusRank[c.Status]
		}
		return catRank[a.Category] < catRank[c.Category]
	})
	for _, it := range b.r.Items {
		switch it.Status {
		case Known:
			b.r.Summary.Known++
		case Unknown:
			b.r.Summary.Unknown++
		case VerifyNext:
			b.r.Summary.VerifyNext++
		}
	}
}

// ---- helpers

// Ref is the evidence reference format every finding uses.
func Ref(ev schema.Event) string {
	id := ev.SourceArtifact
	if len(id) > 12 {
		id = id[:12]
	}
	return fmt.Sprintf("%s:%d (artifact %s, offset %d)", ev.SourcePath, ev.SourceLine, id, ev.SourceOffset)
}

func parseTS(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func rfc(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func clock(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") + " UTC" }

func clockS(s string) string {
	if t, ok := parseTS(s); ok {
		return clock(t)
	}
	return s
}

// human renders a duration the way a report reads it: 2h10m, 45m, 7s.
func human(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%dd%dh", int(d/(24*time.Hour)), int(d%(24*time.Hour)/time.Hour))
	case d >= time.Hour:
		return fmt.Sprintf("%dh%02dm", int(d/time.Hour), int(d%time.Hour/time.Minute))
	case d >= time.Minute:
		return fmt.Sprintf("%dm%02ds", int(d/time.Minute), int(d%time.Minute/time.Second))
	case d >= time.Second:
		return fmt.Sprintf("%ds", int(d/time.Second))
	}
	return fmt.Sprintf("%dms", d.Milliseconds())
}

func signedMS(ms int64) string {
	s := human(time.Duration(ms) * time.Millisecond)
	if ms < 0 {
		return "-" + s
	}
	return "+" + s
}

func abs64(v int64) int64 {
	if v < 0 {
		return -v
	}
	return v
}

func medianDur(d []time.Duration) time.Duration {
	if len(d) == 0 {
		return 0
	}
	c := append([]time.Duration(nil), d...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sumMap(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func mapList(m map[string]int) string {
	var parts []string
	for _, k := range sortedKeys(m) {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	return strings.Join(parts, ", ")
}

// cleanAbs normalizes an absolute path the way the host witness keys it.
func cleanAbs(p string) string {
	if p == "" || !filepath.IsAbs(p) {
		return ""
	}
	return filepath.Clean(p)
}
