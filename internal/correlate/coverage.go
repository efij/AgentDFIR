package correlate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
)

// Per-kind, per-host coverage.
//
// A missing record means something only for the kind of telemetry that
// would have recorded it, on the machine it would have been recorded on,
// at a time that telemetry was recording completely. Coverage is
// therefore computed per (host, kind) from the records that count as
// coverage (the host process / file / network telemetry; sightings,
// context and cloud records never do), as one window per source file
// (two exports with a hole between them leave the hole uncovered), and
// each window carries the intervals in which its source's collection
// health says events may be missing.
//
// A source file covers a kind when it recorded that kind at least once,
// and then for the whole span the file's records show the collector
// running on that host (first to last record of any kind): one file is
// one collector configuration (one eslogger subscription, one audit rule
// set, one Sysmon channel), and a file whose exec events stop while its
// other events go on is still recording exec events. Sequence numbers
// are what say whether it recorded all of them.
//
// A command (kind process) is DISPROVED only when process coverage on the
// claim's host contains its time and no gap or drop signal touches the
// match window: HEALTHY (the source's sequence numbers are contiguous) or
// UNKNOWN (the source has no sequence numbers; v4 behaviour, labelled
// "completeness unverified"). PARTIAL never yields a contradiction.
//
// Hosts: a record names its host when the source does (EVTX Computer,
// Tetragon node_name, Falco hostname, journald _HOSTNAME). A tool call's
// host is the host the case was acquired on, which is not always the
// machine the agent ran on (a collected profile, an imported directory).
// So: a record without a host covers every host, as in v4; when the
// telemetry names exactly one host it is taken to be the agent's machine
// even under another name, and the decision says so; when it names
// several, only the one matching the tool call's host covers it, and a
// tool call matching none of them is not covered. Host names compare
// case-insensitively on their first label.

// Coverage states of one claim (CoverageDecision.Coverage).
const (
	CoverHealthy    = "healthy"        // covered, sequence numbers contiguous
	CoverUnverified = "unverified"     // covered, source has no sequence numbers
	CoverPartial    = "partial"        // covered, but a gap or drop touches the window
	CoverNoKind     = "no_telemetry"   // no telemetry of the needed kind for that host
	CoverOutside    = "outside_window" // telemetry of that kind exists, not at that time
)

// Bounds on the coverage model (hostile input can name many hosts).
const (
	maxCoverHosts    = 256
	maxCoverWindows  = 256
	maxCoverPartials = 100
	maxDecisions     = MaxMatches
)

// KindCoverage is coverage of one kind of telemetry on one host.
type KindCoverage struct {
	Host string `json:"host"` // empty: the records name no host (they cover any host)
	Kind string `json:"kind"`
	// CountsAsCoverage is false for corroborate-only telemetry (DNS,
	// proxy, auth logs, journal): listed for completeness, never used to
	// disprove anything.
	CountsAsCoverage bool          `json:"counts_as_coverage"`
	Records          int           `json:"records"`
	Start            time.Time     `json:"start"`
	End              time.Time     `json:"end"`
	Windows          []CoverWindow `json:"windows"`
	Health           string        `json:"health"` // HEALTHY | PARTIAL | UNKNOWN
	Partial          []Interval    `json:"partial,omitempty"`
	PartialOmitted   int           `json:"partial_omitted,omitempty"`
	Note             string        `json:"note,omitempty"`
}

// CoverWindow is the span one source file covers for a kind.
type CoverWindow struct {
	Source    string    `json:"source"` // telemetry file name
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	Records   int       `json:"records"`
	Sequenced bool      `json:"sequenced"` // the source's sequence numbers apply to this kind
}

// Interval is a span in which collection may have missed events. A zero
// Start or End is open towards that side (to the edge of the window).
type Interval struct {
	Start  time.Time `json:"start,omitempty"`
	End    time.Time `json:"end,omitempty"`
	Source string    `json:"source"`
	Reason string    `json:"reason"`
}

// CoverageDecision records, for one checked tool call, the kind of
// telemetry the claim needs, what coverage said, and why.
type CoverageDecision struct {
	EventID  string   `json:"event_id"`
	Needs    string   `json:"needs"` // process | file | network
	Host     string   `json:"host,omitempty"`
	Coverage string   `json:"coverage"`
	Reason   string   `json:"reason"`
	Sources  []string `json:"sources,omitempty"`
}

// Assessment is what coverage says about one kind on one host at a time.
type Assessment struct {
	Coverage string
	Reason   string
	Sources  []string
}

// Family maps a record kind to the coverage kind it counts towards.
func Family(kind string) string {
	switch kind {
	case "process", "file", "network":
		return kind
	}
	return kind
}

// hostKey normalizes a host name for comparison.
func hostKey(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	if i := strings.IndexByte(h, '.'); i > 0 && !isIPLike(h) {
		h = h[:i]
	}
	return h
}

func isIPLike(h string) bool {
	return strings.Trim(h, "0123456789.") == "" || strings.Contains(h, ":")
}

// coverModel is built once per correlation pass.
type coverModel struct {
	entries []KindCoverage
}

// buildCoverage computes per-(host, kind) coverage from the coverage
// records (host) and the corroborate-only records (sight), with the
// collection health of every source.
func buildCoverage(all, host, sight []endpoint.Record, health map[string]*endpoint.SourceHealth) *coverModel {
	type key struct {
		host, kind, origin string
		cover              bool
	}
	type span struct {
		start, end time.Time
		n          int
	}
	spans := map[key]*span{}
	hosts := map[string]bool{}
	// The span each source file shows its collector running, per host.
	type oh struct{ origin, host string }
	alive := map[oh]*span{}
	for _, r := range all {
		if r.Time.IsZero() {
			continue
		}
		k := oh{r.Origin, hostKey(r.Host)}
		a := alive[k]
		if a == nil {
			if len(alive) >= maxCoverHosts*maxCoverWindows {
				continue
			}
			a = &span{start: r.Time, end: r.Time}
			alive[k] = a
		}
		if r.Time.Before(a.start) {
			a.start = r.Time
		}
		if r.Time.After(a.end) {
			a.end = r.Time
		}
	}
	add := func(r endpoint.Record, cover bool) {
		if r.Time.IsZero() {
			return
		}
		h := hostKey(r.Host)
		if !hosts[h] && len(hosts) >= maxCoverHosts {
			h = "" // past the bound: treated as naming no host
		}
		hosts[h] = true
		k := key{h, Family(r.Kind), r.Origin, cover}
		s := spans[k]
		if s == nil {
			if len(spans) >= maxCoverHosts*maxCoverWindows {
				return
			}
			s = &span{start: r.Time, end: r.Time}
			spans[k] = s
		}
		if r.Time.Before(s.start) {
			s.start = r.Time
		}
		if r.Time.After(s.end) {
			s.end = r.Time
		}
		s.n++
	}
	for _, r := range host {
		add(r, true)
	}
	for _, r := range sight {
		add(r, false)
	}
	// A cleared Windows event log takes records of other channels with it
	// (104 is written to System when any channel is cleared), so a clear
	// counts against every EVTX source of the same host, not only the file
	// that recorded it.
	type clear struct {
		hosts []string
		iv    Interval
	}
	var clears []clear
	for _, h := range health {
		for _, d := range h.Drops {
			if d.Signal == "log-clear" {
				clears = append(clears, clear{hosts: h.Hosts, iv: Interval{Start: d.Start, End: d.End, Source: sourceName(h.Origin, h), Reason: "log-clear: " + d.Detail}})
			}
		}
	}
	isEVTX := func(h *endpoint.SourceHealth) bool {
		for _, d := range h.Domains {
			if strings.HasPrefix(d.Domain, "evtx/") {
				return true
			}
		}
		return h.Format == string(endpoint.FormatEVTX)
	}
	type hk struct {
		host, kind string
		cover      bool
	}
	byHK := map[hk]*KindCoverage{}
	for k, s := range spans {
		hk := hk{k.host, k.kind, k.cover}
		kc := byHK[hk]
		if kc == nil {
			kc = &KindCoverage{Host: k.host, Kind: k.kind, CountsAsCoverage: k.cover, Start: s.start, End: s.end}
			byHK[hk] = kc
		}
		if s.start.Before(kc.Start) {
			kc.Start = s.start
		}
		if s.end.After(kc.End) {
			kc.End = s.end
		}
		kc.Records += s.n
		if a := alive[oh{k.origin, k.host}]; a != nil {
			s.start, s.end = a.start, a.end
			if s.start.Before(kc.Start) {
				kc.Start = s.start
			}
			if s.end.After(kc.End) {
				kc.End = s.end
			}
		}
		h := health[k.origin]
		w := CoverWindow{Source: sourceName(k.origin, h), Start: s.start, End: s.end, Records: s.n}
		if h != nil {
			w.Sequenced = h.Sequenced(k.kind)
			kc.Partial = append(kc.Partial, partialIntervals(h, k.kind, w.Source)...)
			if isEVTX(h) {
				for _, c := range clears {
					if c.iv.Source == w.Source {
						continue // already counted from the source's own drops
					}
					same := len(c.hosts) == 0 || k.host == ""
					for _, x := range c.hosts {
						same = same || hostKey(x) == k.host
					}
					if same {
						kc.Partial = append(kc.Partial, c.iv)
					}
				}
			}
		}
		if len(kc.Windows) < maxCoverWindows {
			kc.Windows = append(kc.Windows, w)
		}
	}
	m := &coverModel{}
	for _, kc := range byHK {
		sort.Slice(kc.Windows, func(i, j int) bool {
			if !kc.Windows[i].Start.Equal(kc.Windows[j].Start) {
				return kc.Windows[i].Start.Before(kc.Windows[j].Start)
			}
			return kc.Windows[i].Source < kc.Windows[j].Source
		})
		sort.SliceStable(kc.Partial, func(i, j int) bool {
			if !kc.Partial[i].Start.Equal(kc.Partial[j].Start) {
				return kc.Partial[i].Start.Before(kc.Partial[j].Start)
			}
			return kc.Partial[i].Reason < kc.Partial[j].Reason
		})
		if len(kc.Partial) > maxCoverPartials {
			kc.PartialOmitted = len(kc.Partial) - maxCoverPartials
			kc.Partial = kc.Partial[:maxCoverPartials]
		}
		allSeq := true
		for _, w := range kc.Windows {
			allSeq = allSeq && w.Sequenced
		}
		switch {
		case len(kc.Partial) > 0 || kc.PartialOmitted > 0:
			kc.Health = endpoint.HealthPartial
		case allSeq:
			kc.Health = endpoint.HealthHealthy
		default:
			kc.Health = endpoint.HealthUnknown
			kc.Note = "completeness unverified: the source carries no sequence numbers for this kind"
		}
		m.entries = append(m.entries, *kc)
	}
	sort.Slice(m.entries, func(i, j int) bool {
		if m.entries[i].Host != m.entries[j].Host {
			return m.entries[i].Host < m.entries[j].Host
		}
		return m.entries[i].Kind < m.entries[j].Kind
	})
	return m
}

func sourceName(origin string, h *endpoint.SourceHealth) string {
	if h != nil && h.File != "" {
		return h.File
	}
	if origin == "" {
		return "(records given directly)"
	}
	if i := strings.LastIndexAny(origin, `/\`); i >= 0 {
		return origin[i+1:]
	}
	return origin
}

// partialIntervals lists the intervals a source's health marks as
// possibly incomplete for kind.
func partialIntervals(h *endpoint.SourceHealth, kind, src string) []Interval {
	var out []Interval
	for _, d := range h.Domains {
		if len(d.Kinds) > 0 && !containsS(d.Kinds, kind) {
			continue
		}
		if d.Overflow {
			out = append(out, Interval{Source: src, Reason: fmt.Sprintf("sequence %s too fragmented to check", d.Domain)})
		}
		for _, g := range d.GapRanges {
			why := fmt.Sprintf("sequence gap in %s: %d missing after %d", d.Domain, g.Missing, g.After)
			if g.Restart {
				why = fmt.Sprintf("sequence %s restarted after %d (collector restarted)", d.Domain, g.After)
			}
			out = append(out, Interval{Start: g.Start, End: g.End, Source: src, Reason: why})
		}
		if extra := d.Gaps - len(d.GapRanges); extra > 0 {
			out = append(out, Interval{Source: src, Reason: fmt.Sprintf("%d more sequence gap(s) in %s not placed", extra, d.Domain)})
		}
	}
	for _, dr := range h.Drops {
		if len(dr.Kinds) > 0 && !containsS(dr.Kinds, kind) {
			continue
		}
		out = append(out, Interval{Start: dr.Start, End: dr.End, Source: src, Reason: dr.Signal + ": " + dr.Detail})
	}
	if h.DropsOmitted > 0 {
		out = append(out, Interval{Source: src, Reason: fmt.Sprintf("%d more drop signal(s) not kept", h.DropsOmitted)})
	}
	return out
}

func containsS(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// Entries returns the per-(host, kind) coverage, sorted.
func (m *coverModel) Entries() []KindCoverage { return m.entries }

// AssessCoverage says what the coverage in kc tells about kind on host at
// t, within ±window. It is the one rule both the correlation pass and the
// proof report apply.
func AssessCoverage(kc []KindCoverage, host, kind string, t time.Time, window time.Duration) Assessment {
	hk := hostKey(host)
	lo, hi := t.Add(-window), t.Add(window)
	named := map[string]bool{}
	for _, c := range kc {
		if c.CountsAsCoverage && c.Host != "" {
			named[c.Host] = true
		}
	}
	attribution := ""
	if hk != "" && len(named) == 1 && !named[hk] {
		for h := range named {
			attribution = "; host attribution unverified: the telemetry names host " + h + ", the case was acquired on " + host
		}
	}
	anyKind := false
	var srcs []string
	var partial []string
	in, allSeq := false, true
	for _, c := range kc {
		if c.Kind != kind || !c.CountsAsCoverage {
			continue
		}
		if c.Host != "" && hk != "" && c.Host != hk && attribution == "" {
			continue
		}
		anyKind = true
		hit := false
		for _, w := range c.Windows {
			if !hi.Before(w.Start) && !lo.After(w.End) {
				hit, in = true, true
				allSeq = allSeq && w.Sequenced
				srcs = append(srcs, w.Source)
			}
		}
		if !hit {
			continue
		}
		for _, p := range c.Partial {
			if (p.End.IsZero() || !lo.After(p.End)) && (p.Start.IsZero() || !hi.Before(p.Start)) {
				partial = append(partial, p.Reason+" ("+p.Source+spanText(p)+")")
			}
		}
		if c.PartialOmitted > 0 {
			partial = append(partial, fmt.Sprintf("%d more incomplete interval(s) not listed", c.PartialOmitted))
		}
	}
	sort.Strings(srcs)
	srcs = dedupe(srcs)
	hostTxt := "this host"
	if host != "" {
		hostTxt = "host " + host
	}
	var a Assessment
	switch {
	case !anyKind:
		a = Assessment{Coverage: CoverNoKind, Reason: "no " + kind + " telemetry for " + hostTxt}
	case !in:
		a = Assessment{Coverage: CoverOutside, Reason: kind + " telemetry for " + hostTxt + " does not cover " + t.UTC().Format(time.RFC3339)}
	case len(partial) > 0:
		sort.Strings(partial)
		partial = dedupe(partial)
		if len(partial) > 3 {
			partial = append(partial[:3], fmt.Sprintf("and %d more", len(partial)-3))
		}
		a = Assessment{Coverage: CoverPartial, Sources: srcs, Reason: kind + " telemetry partial: " + strings.Join(partial, "; ")}
	case allSeq:
		a = Assessment{Coverage: CoverHealthy, Sources: srcs, Reason: kind + " telemetry covers the time; sequence numbers contiguous"}
	default:
		a = Assessment{Coverage: CoverUnverified, Sources: srcs, Reason: kind + " telemetry covers the time; completeness unverified (no sequence numbers)"}
	}
	if attribution != "" && a.Coverage != CoverNoKind {
		a.Reason += attribution
	}
	return a
}

func spanText(p Interval) string {
	switch {
	case p.Start.IsZero() && p.End.IsZero():
		return ", whole window"
	case p.Start.IsZero():
		return ", until " + p.End.UTC().Format("15:04:05")
	case p.End.IsZero():
		return ", from " + p.Start.UTC().Format("15:04:05")
	}
	return ", " + p.Start.UTC().Format("15:04:05") + "–" + p.End.UTC().Format("15:04:05")
}

func dedupe(l []string) []string {
	out := l[:0]
	for i, s := range l {
		if i == 0 || s != l[i-1] {
			out = append(out, s)
		}
	}
	return out
}

// sourceHealth resolves the health report of every source file the
// records came from: the one Load computed (opts.Health), or one derived
// from the records themselves.
func sourceHealth(records []endpoint.Record, given []*endpoint.SourceHealth) (map[string]*endpoint.SourceHealth, []endpoint.SourceHealth) {
	byOrigin := map[string]*endpoint.SourceHealth{}
	for _, h := range given {
		if h != nil {
			byOrigin[h.Origin] = h
		}
	}
	groups := map[string][]endpoint.Record{}
	var order []string
	for _, r := range records {
		if _, ok := groups[r.Origin]; !ok {
			order = append(order, r.Origin)
		}
		groups[r.Origin] = append(groups[r.Origin], r)
	}
	for _, o := range order {
		if byOrigin[o] == nil {
			byOrigin[o] = endpoint.RecordsHealth(o, groups[o])
			if o == "" {
				byOrigin[o].File = "(records given directly)"
			}
		}
	}
	var list []endpoint.SourceHealth
	for _, h := range byOrigin {
		list = append(list, *h)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].File != list[j].File {
			return list[i].File < list[j].File
		}
		return list[i].SHA256 < list[j].SHA256
	})
	return byOrigin, list
}
