package endpoint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"
)

// Collection health: whether a telemetry source shows signs of having
// missed events. Absence of a record only means something when the
// source was recording completely at that time, so every source is
// checked for the signals it carries:
//
//   - sequence gaps: a source-assigned counter that skips numbers. EVTX
//     EventRecordID per channel, the audit serial, eslogger seq_num per
//     event type and global_seq_num, journald __SEQNUM. Numbers are
//     tracked for every event the adapter parsed, mapped or not, so an
//     event type the adapter does not use never looks like a gap.
//   - drop signals the source writes about itself: Tetragon
//     rate_limit_info / process_throttle, bpftrace lost_events, auditd
//     daemon errors and lost counters, a cleared Windows event log
//     (1102/104), and Windows context records past the per-file bound
//     (LoadResult.ContextDropped).
//
// The verdict per source is HEALTHY (sequence numbers present, contiguous,
// no drop signal), PARTIAL (a gap or a drop) or UNKNOWN (no sequence
// numbers: completeness cannot be established either way).

// Health verdicts.
const (
	HealthHealthy = "HEALTHY"
	HealthPartial = "PARTIAL"
	HealthUnknown = "UNKNOWN"
)

// Bounds on what health tracking keeps.
const (
	maxSeqRuns      = 1 << 16 // contiguous runs per domain before tracking gives up
	maxSeqDomains   = 1024
	maxGapRanges    = 50 // gap ranges reported per domain
	maxDropSignals  = 200
	seqDomainGlobal = "/global"
)

// SeqGap is one break in a sequence. Start and End are the times of the
// events on either side; zero when the break cannot be placed in time.
type SeqGap struct {
	After   uint64    `json:"after_seq"`
	Before  uint64    `json:"before_seq"`
	Missing uint64    `json:"missing"`
	Start   time.Time `json:"start,omitempty"`
	End     time.Time `json:"end,omitempty"`
	// Restart is set when the counter went backwards in a stream: the
	// collector was restarted and what happened in between is not covered.
	Restart bool `json:"restart,omitempty"`
}

// SeqDomainHealth is one sequence domain of a source.
type SeqDomainHealth struct {
	Domain    string    `json:"domain"`
	Events    int       `json:"events"`
	FirstSeq  uint64    `json:"first_seq"`
	LastSeq   uint64    `json:"last_seq"`
	Gaps      int       `json:"gaps"`
	Missing   uint64    `json:"missing"`
	GapRanges []SeqGap  `json:"gap_ranges,omitempty"`
	Kinds     []string  `json:"kinds,omitempty"` // record kinds the domain's events produced; empty = all of the source
	Overflow  bool      `json:"overflow,omitempty"`
	First     time.Time `json:"first,omitempty"`
	Last      time.Time `json:"last,omitempty"`
}

// DropSignal is the source saying it lost events. Start/End bound the
// affected interval; a zero Start means "from the beginning of the
// window", a zero End "to its end". Kinds names the record kinds
// affected; empty means every kind the source produces.
type DropSignal struct {
	Signal string    `json:"signal"` // rate-limit | throttle | lost-events | log-clear | context-bound | daemon
	Start  time.Time `json:"start,omitempty"`
	End    time.Time `json:"end,omitempty"`
	Count  int       `json:"count,omitempty"`
	Kinds  []string  `json:"kinds,omitempty"`
	Detail string    `json:"detail"`
	Ref    string    `json:"ref,omitempty"`
}

// SourceHealth is the collection-health report for one telemetry file.
type SourceHealth struct {
	// Origin is the path the source was loaded from (in memory only; the
	// persisted report names the file and its hash).
	Origin  string            `json:"-"`
	File    string            `json:"file"`
	SHA256  string            `json:"sha256,omitempty"`
	Format  string            `json:"format,omitempty"`
	Records int               `json:"records"`
	First   time.Time         `json:"first,omitempty"`
	Last    time.Time         `json:"last,omitempty"`
	Kinds   map[string]int    `json:"kinds,omitempty"`
	Hosts   []string          `json:"hosts,omitempty"`
	Domains []SeqDomainHealth `json:"sequence_domains,omitempty"`
	Drops   []DropSignal      `json:"drops,omitempty"`
	// DropsOmitted counts drop signals past the bound.
	DropsOmitted int    `json:"drops_omitted,omitempty"`
	Gaps         int    `json:"gaps"`
	Verdict      string `json:"verdict"`
	Note         string `json:"note,omitempty"`
}

// Sequenced reports whether any of the source's events carried sequence
// numbers that apply to kind.
func (h *SourceHealth) Sequenced(kind string) bool {
	for _, d := range h.Domains {
		if d.Events > 0 && !d.Overflow && (len(d.Kinds) == 0 || containsStr(d.Kinds, kind)) {
			return true
		}
	}
	return false
}

// seqRun is a contiguous run of sequence numbers.
type seqRun struct {
	lo, hi   uint64
	loT, hiT time.Time
}

type seqDomain struct {
	sortable bool // numbers are unique per file (EVTX record ids): sort runs before looking for gaps
	runs     []seqRun
	events   int
	overflow bool
	kinds    map[string]bool
}

// seqTracker collects sequence numbers while an adapter parses.
type seqTracker struct {
	domains map[string]*seqDomain
	order   []string
}

// seqObserve records sequence number n of domain at time t. sortable
// says the numbers are unique within the file, so runs may be sorted
// (an EVTX file's chunks wrap); otherwise the stream order is kept and a
// number that goes backwards is a collector restart.
func (r *LoadResult) seqObserve(domain string, n uint64, t time.Time, sortable bool) {
	if domain == "" {
		return
	}
	if r.seqs == nil {
		r.seqs = &seqTracker{domains: map[string]*seqDomain{}}
	}
	d := r.seqs.domains[domain]
	if d == nil {
		if len(r.seqs.domains) >= maxSeqDomains {
			return
		}
		d = &seqDomain{sortable: sortable}
		r.seqs.domains[domain] = d
		r.seqs.order = append(r.seqs.order, domain)
	}
	d.events++
	if d.overflow {
		return
	}
	if k := len(d.runs); k > 0 {
		last := &d.runs[k-1]
		if n == last.hi+1 {
			last.hi, last.hiT = n, t
			return
		}
		if n == last.hi { // the same number again (auditd: several records of one event)
			return
		}
	}
	if len(d.runs) >= maxSeqRuns {
		d.overflow = true
		return
	}
	d.runs = append(d.runs, seqRun{lo: n, hi: n, loT: t, hiT: t})
}

// seqKind notes that domain produced a record of kind.
func (r *LoadResult) seqKind(domain, kind string) {
	if r.seqs == nil || domain == "" {
		return
	}
	if d := r.seqs.domains[domain]; d != nil {
		if d.kinds == nil {
			d.kinds = map[string]bool{}
		}
		d.kinds[kind] = true
	}
}

// dropSignal records that the source said it lost events.
func (r *LoadResult) dropSignal(d DropSignal) {
	if len(r.drops) >= maxDropSignals {
		r.dropsOmitted++
		return
	}
	r.drops = append(r.drops, d)
}

// analyze turns the runs into a domain report.
func (d *seqDomain) analyze(name string) SeqDomainHealth {
	h := SeqDomainHealth{Domain: name, Events: d.events, Overflow: d.overflow}
	for k := range d.kinds {
		h.Kinds = append(h.Kinds, k)
	}
	sort.Strings(h.Kinds)
	runs := append([]seqRun(nil), d.runs...)
	if len(runs) == 0 {
		return h
	}
	if d.sortable {
		sort.SliceStable(runs, func(i, j int) bool { return runs[i].lo < runs[j].lo })
	}
	h.FirstSeq, h.LastSeq = runs[0].lo, runs[0].hi
	h.First, h.Last = runs[0].loT, runs[0].hiT
	prev := runs[0]
	for _, cur := range runs[1:] {
		if cur.hi > h.LastSeq {
			h.LastSeq = cur.hi
		}
		if cur.lo < h.FirstSeq {
			h.FirstSeq = cur.lo
		}
		if !cur.loT.IsZero() && (h.First.IsZero() || cur.loT.Before(h.First)) {
			h.First = cur.loT
		}
		if cur.hiT.After(h.Last) {
			h.Last = cur.hiT
		}
		var g SeqGap
		switch {
		case cur.lo > prev.hi+1:
			g = SeqGap{After: prev.hi, Before: cur.lo, Missing: cur.lo - prev.hi - 1, Start: prev.hiT, End: cur.loT}
		case d.sortable:
			// Overlapping numbers in a file whose numbers should be unique
			// (a duplicated chunk, or two files concatenated): not a gap.
			if cur.hi > prev.hi {
				prev = cur
			}
			continue
		default:
			g = SeqGap{After: prev.hi, Before: cur.lo, Start: prev.hiT, End: cur.loT, Restart: true}
		}
		if g.End.Before(g.Start) {
			g.Start, g.End = time.Time{}, time.Time{} // cannot be placed in time
		}
		h.Gaps++
		h.Missing += g.Missing
		if len(h.GapRanges) < maxGapRanges {
			h.GapRanges = append(h.GapRanges, g)
		}
		prev = cur
	}
	return h
}

// health builds the report for a loaded file. Record-level signals
// (log-clear records, context bounds) are added here; sequence numbers
// come from the tracker the adapter filled, or, when the adapter did not
// track any, from the records' own Seq fields.
func (r *LoadResult) health(path string) *SourceHealth {
	h := &SourceHealth{Origin: path, File: baseName(path), Format: string(r.Format)}
	if r.seqs == nil {
		fillSeqFromRecords(r)
	}
	if r.seqs != nil {
		for _, name := range r.seqs.order {
			h.Domains = append(h.Domains, r.seqs.domains[name].analyze(name))
		}
	}
	h.Drops = append(h.Drops, r.drops...)
	h.DropsOmitted = r.dropsOmitted
	for _, k := range sortedKeysInt(r.ContextDropped) {
		h.Drops = append(h.Drops, DropSignal{Signal: "context-bound", Count: r.ContextDropped[k], Kinds: []string{k},
			Detail: fmt.Sprintf("%d %s record(s) past the per-file bound were not kept: coverage of that kind is incomplete", r.ContextDropped[k], k)})
	}
	finishHealth(h, r.Records)
	return h
}

// RecordsHealth derives a health report from records alone (their Seq,
// SeqDomain and GlobalSeq fields and log-clear records), for records that
// did not come through Load. Numbers are only those of the records given:
// events the producer filtered out look like gaps, which is the safe side
// (a gap never yields a contradiction).
func RecordsHealth(origin string, recs []Record) *SourceHealth {
	tmp := &LoadResult{Records: recs}
	fillSeqFromRecords(tmp)
	h := &SourceHealth{Origin: origin, File: baseName(origin)}
	if tmp.seqs != nil {
		for _, name := range tmp.seqs.order {
			h.Domains = append(h.Domains, tmp.seqs.domains[name].analyze(name))
		}
	}
	finishHealth(h, recs)
	return h
}

func fillSeqFromRecords(r *LoadResult) {
	for _, rec := range r.Records {
		if rec.Seq != 0 && rec.SeqDomain != "" {
			r.seqObserve(rec.SeqDomain, rec.Seq, rec.Time, strings.HasPrefix(rec.SeqDomain, "evtx/"))
			r.seqKind(rec.SeqDomain, rec.Kind)
		}
		if rec.GlobalSeq != 0 {
			g := rec.Source + seqDomainGlobal
			r.seqObserve(g, rec.GlobalSeq, rec.Time, false)
		}
	}
}

// finishHealth fills counts, kinds, hosts, log-clear drops and the verdict.
func finishHealth(h *SourceHealth, recs []Record) {
	h.Records = len(recs)
	hosts := map[string]bool{}
	for _, rec := range recs {
		if rec.Time.IsZero() {
			continue
		}
		if h.First.IsZero() || rec.Time.Before(h.First) {
			h.First = rec.Time
		}
		if rec.Time.After(h.Last) {
			h.Last = rec.Time
		}
		if h.Kinds == nil {
			h.Kinds = map[string]int{}
		}
		h.Kinds[rec.Kind]++
		if rec.Host != "" && len(hosts) < 64 {
			hosts[rec.Host] = true
		}
		if rec.Kind == "log-clear" {
			// Everything the cleared log held before this moment is gone.
			if len(h.Drops) < maxDropSignals {
				h.Drops = append(h.Drops, DropSignal{Signal: "log-clear", End: rec.Time, Ref: rec.Ref,
					Detail: "event log cleared: records before this time were deleted"})
			} else {
				h.DropsOmitted++
			}
		}
	}
	for k := range hosts {
		h.Hosts = append(h.Hosts, k)
	}
	sort.Strings(h.Hosts)
	sequenced := false
	for _, d := range h.Domains {
		h.Gaps += d.Gaps
		if d.Overflow {
			h.Gaps++ // too fragmented to check: treated as a gap of unknown place
		}
		if d.Events > 0 {
			sequenced = true
		}
	}
	switch {
	case h.Gaps > 0 || len(h.Drops) > 0 || h.DropsOmitted > 0:
		h.Verdict = HealthPartial
	case sequenced:
		h.Verdict = HealthHealthy
	default:
		h.Verdict = HealthUnknown
		h.Note = "completeness not established: the source carries no sequence numbers"
	}
}

// FileSHA256 hashes a telemetry file (bounded by MaxLogBytes), so a
// report can name exactly which bytes it was computed from.
func FileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	hs := sha256.New()
	if _, err := io.Copy(hs, io.LimitReader(f, MaxLogBytes+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(hs.Sum(nil)), nil
}

func sortedKeysInt(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func containsStr(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}
