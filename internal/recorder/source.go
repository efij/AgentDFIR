package recorder

import (
	"bytes"
	"fmt"
	"sync"
	"time"
)

// Sequence-number kinds a source can carry. A jump in them means the
// source (or the pipe to us) lost records.
const (
	SeqNone        = ""
	SeqAuditSerial = "audit-serial"  // msg=audit(<sec>.<ms>:<serial>)
	SeqESGlobal    = "es-global-seq" // eslogger global_seq_num
)

const (
	maxProblems   = 10
	maxGapSamples = 10
	maxCarry      = 64 << 10 // longest partial line kept for sequence parsing
	pendingWindow = 1024     // sequence numbers this far behind the max are final
	maxPending    = 4096     // missing numbers tracked individually for late arrival
)

// Source is the live health of one recording source. All methods are safe
// for concurrent use.
type Source struct {
	mu        sync.Mutex
	name      string
	kind      string
	input     string
	format    string
	state     string
	capture   string
	lastEvent time.Time
	records   int64
	bytes     int64
	rotations int64
	drops     int64
	problems  []string
	notes     []string

	seqKind  string
	haveSeq  bool
	maxSeq   uint64
	pending  map[uint64]bool
	ranges   []gapRange
	finalGap int64
	finalMis uint64
	resets   int64
	samples  []string
	carry    []byte

	now func() time.Time
}

type gapRange struct {
	from, to uint64
	left     uint64
}

// SourceStatus is a snapshot of a Source, as written to status.json.
type SourceStatus struct {
	Name         string   `json:"name"`
	Kind         string   `json:"kind"`            // transcripts | mcp-config | eslogger | auditd | tail
	Input        string   `json:"input,omitempty"` // what is read (file, directory, command)
	Format       string   `json:"format,omitempty"`
	State        string   `json:"state"` // running | waiting | error | stopped | not-started
	Capture      string   `json:"capture,omitempty"`
	LastEventUTC string   `json:"last_event_utc,omitempty"`
	Records      int64    `json:"records"`
	Bytes        int64    `json:"bytes"`
	SeqKind      string   `json:"seq_kind,omitempty"`
	Gaps         int64    `json:"gaps"`
	MissingSeq   uint64   `json:"missing_seq"`
	SeqResets    int64    `json:"seq_resets,omitempty"`
	GapSamples   []string `json:"gap_samples,omitempty"`
	Drops        int64    `json:"drops"`
	Rotations    int64    `json:"rotations,omitempty"`
	Problems     []string `json:"problems,omitempty"`
	Notes        []string `json:"notes,omitempty"`
}

// NewSource makes a source in state not-started.
func NewSource(name, kind, input string) *Source {
	return &Source{name: name, kind: kind, input: input, state: "not-started", pending: map[uint64]bool{}, now: time.Now}
}

// Name is the source's name (also the capture file prefix).
func (s *Source) Name() string { return s.name }

// SetState sets running | waiting | error | stopped | not-started.
func (s *Source) SetState(st string) { s.mu.Lock(); s.state = st; s.mu.Unlock() }

// SetFormat records the format the source was sniffed as.
func (s *Source) SetFormat(f string) { s.mu.Lock(); s.format = f; s.mu.Unlock() }

// Format returns the sniffed format.
func (s *Source) Format() string { s.mu.Lock(); defer s.mu.Unlock(); return s.format }

// SetSeq selects the sequence-number parser (Seq* constants).
func (s *Source) SetSeq(kind string) { s.mu.Lock(); s.seqKind = kind; s.mu.Unlock() }

// SetCapture records the capture file currently written.
func (s *Source) SetCapture(p string) { s.mu.Lock(); s.capture = p; s.mu.Unlock() }

// Rotated counts a rotation of the input file.
func (s *Source) Rotated() { s.mu.Lock(); s.rotations++; s.mu.Unlock() }

// Drop adds records the source itself reported as dropped.
func (s *Source) Drop(n int64) { s.mu.Lock(); s.drops += n; s.mu.Unlock() }

// Problem records an operator-facing problem (permission denied, input
// missing). Repeats are kept once; the list is bounded.
func (s *Source) Problem(msg string) {
	s.mu.Lock()
	s.problems = addOnce(s.problems, msg)
	s.mu.Unlock()
}

// Note records context that is not a problem.
func (s *Source) Note(msg string) { s.mu.Lock(); s.notes = addOnce(s.notes, msg); s.mu.Unlock() }

func addOnce(list []string, msg string) []string {
	for _, m := range list {
		if m == msg {
			return list
		}
	}
	if len(list) >= maxProblems {
		return list
	}
	return append(list, msg)
}

// AddRange counts one journaled range of n bytes as one record (agent
// transcripts: the range is what is journaled, lines are not re-read).
func (s *Source) AddRange(n int64) {
	s.mu.Lock()
	s.records++
	s.bytes += n
	s.lastEvent = s.now()
	s.mu.Unlock()
}

// Observe accounts bytes written to the capture: one record per line,
// and sequence numbers where the source has them.
func (s *Source) Observe(p []byte) {
	if len(p) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bytes += int64(len(p))
	s.lastEvent = s.now()
	for len(p) > 0 {
		i := bytes.IndexByte(p, '\n')
		if i < 0 {
			if len(s.carry)+len(p) <= maxCarry {
				s.carry = append(s.carry, p...)
			} else {
				s.carry = s.carry[:0] // an over-long line: counted, not parsed
			}
			return
		}
		line := p[:i]
		if len(s.carry) > 0 {
			line = append(s.carry, line...)
		}
		s.records++
		if s.seqKind != SeqNone {
			if v, ok := parseSeq(s.seqKind, line); ok {
				s.seq(v)
			}
		}
		s.carry = s.carry[:0]
		p = p[i+1:]
	}
}

// seq tracks one sequence number. Late arrivals (audit records of
// neighbouring events interleave) fill earlier holes; a number further
// back than the window means the source restarted (reboot, new eslogger).
func (s *Source) seq(v uint64) {
	if !s.haveSeq {
		s.haveSeq, s.maxSeq = true, v
		return
	}
	switch {
	case v == s.maxSeq:
	case v == s.maxSeq+1:
		s.maxSeq = v
	case v > s.maxSeq+1:
		r := gapRange{from: s.maxSeq + 1, to: v - 1, left: v - s.maxSeq - 1}
		if r.left <= maxPending && len(s.pending)+int(r.left) <= maxPending {
			for n := r.from; n <= r.to; n++ {
				s.pending[n] = true
			}
		} else {
			// Too large to wait for: final now.
			s.finalGap++
			s.finalMis += r.left
			r.left = 0
		}
		if len(s.samples) < maxGapSamples {
			s.samples = append(s.samples, fmt.Sprintf("%s: %d → %d (%d missing) at %s", s.seqKind, s.maxSeq, v, v-s.maxSeq-1, s.now().UTC().Format(time.RFC3339)))
		}
		if r.left > 0 {
			s.ranges = append(s.ranges, r)
		}
		s.maxSeq = v
	case s.maxSeq-v <= pendingWindow:
		if s.pending[v] {
			delete(s.pending, v)
			for i := range s.ranges {
				if v >= s.ranges[i].from && v <= s.ranges[i].to {
					s.ranges[i].left--
					break
				}
			}
		}
	default:
		s.resets++
		s.finalize(true)
		s.maxSeq = v
	}
	s.finalize(false)
}

// finalize moves gap ranges that are out of the late-arrival window (or
// all of them) to the final counters.
func (s *Source) finalize(all bool) {
	keep := s.ranges[:0]
	for _, r := range s.ranges {
		if all || s.maxSeq-r.to > pendingWindow {
			if r.left > 0 {
				s.finalGap++
				s.finalMis += r.left
			}
			for n := r.from; n <= r.to && r.to-r.from < maxPending; n++ {
				delete(s.pending, n)
			}
			continue
		}
		keep = append(keep, r)
	}
	s.ranges = keep
}

// parseSeq pulls the sequence number out of one raw line.
func parseSeq(kind string, line []byte) (uint64, bool) {
	switch kind {
	case SeqAuditSerial:
		i := bytes.Index(line, []byte("msg=audit("))
		if i < 0 {
			return 0, false
		}
		rest := line[i+len("msg=audit("):]
		c := bytes.IndexByte(rest, ':')
		e := bytes.IndexByte(rest, ')')
		if c < 0 || e < c {
			return 0, false
		}
		return digits(rest[c+1 : e])
	case SeqESGlobal:
		i := bytes.Index(line, []byte(`"global_seq_num"`))
		if i < 0 {
			return 0, false
		}
		rest := bytes.TrimLeft(line[i+len(`"global_seq_num"`):], " \t:")
		end := 0
		for end < len(rest) && rest[end] >= '0' && rest[end] <= '9' {
			end++
		}
		return digits(rest[:end])
	}
	return 0, false
}

func digits(b []byte) (uint64, bool) {
	if len(b) == 0 || len(b) > 19 {
		return 0, false
	}
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			return 0, false
		}
		v = v*10 + uint64(c-'0')
	}
	return v, true
}

// Snapshot returns the current status.
func (s *Source) Snapshot() SourceStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := SourceStatus{Name: s.name, Kind: s.kind, Input: s.input, Format: s.format, State: s.state, Capture: s.capture,
		Records: s.records, Bytes: s.bytes, SeqKind: s.seqKind, Drops: s.drops, Rotations: s.rotations, SeqResets: s.resets,
		Gaps: s.finalGap, MissingSeq: s.finalMis}
	for _, r := range s.ranges {
		if r.left > 0 {
			st.Gaps++
			st.MissingSeq += r.left
		}
	}
	if !s.lastEvent.IsZero() {
		st.LastEventUTC = s.lastEvent.UTC().Format(time.RFC3339)
	}
	st.GapSamples = append([]string(nil), s.samples...)
	st.Problems = append([]string(nil), s.problems...)
	st.Notes = append([]string(nil), s.notes...)
	return st
}
