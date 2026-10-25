package correlate

import (
	"sort"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Match records which independent record explained which tool call, and
// on what basis. The event's own state and summary note already say that
// it was corroborated; the match keeps the pairing itself, so a lineage
// graph can draw the tool call → process edge with the record's pid, the
// time difference and the reason the two were paired, instead of
// re-deriving any of it from the note text.
type Match struct {
	EventID    string `json:"event_id"`
	Witness    string `json:"witness"` // endpoint | cloud | sighting | script | process-image
	Score      int    `json:"score"`
	Basis      string `json:"basis"`
	Confidence string `json:"confidence"` // HIGH | MEDIUM | LOW
	WindowMS   int64  `json:"window_ms"`
	// DeltaMS is the record's time minus the tool call's transcript time.
	// Across many matches it is the measured offset between the two
	// clocks, which is what clock-consistency reporting reads.
	DeltaMS int64           `json:"delta_ms"`
	Record  endpoint.Record `json:"record"`
	// Related are records the matched process itself produced: network and
	// file activity with the same pid, and processes whose ppid is its pid,
	// starting no earlier than it and within relatedHorizon. They are linked
	// by process identity in the telemetry, never by time alone.
	Related []RelatedRecord `json:"related,omitempty"`
}

// RelatedRecord is one record tied to a matched process by pid or ppid.
type RelatedRecord struct {
	Basis  string          `json:"basis"` // "endpoint pid" | "endpoint ppid"
	Record endpoint.Record `json:"record"`
}

// Bounds on what a match keeps. Matches are persisted with the summary in
// detections/corroboration.json, so they must stay small on a case with a
// million tool calls and a telemetry export to match.
const (
	MaxMatches     = 20000
	maxRelated     = 20
	maxCmdline     = 300
	relatedHorizon = 10 * time.Minute
)

// MatchBasis states, in words, what a correlation score means and how much
// weight the pairing carries. It is the one definition of correlation
// confidence: the score ladder in score and cloudScore decides which
// record is the best explanation, and this names the rung.
//
//	process 100  exact command line                         HIGH
//	process  90  command inside a shell wrapper (sh -c …)    HIGH
//	process  70  telemetry holds a truncated copy            MEDIUM
//	process  60  same program, most arguments shared         LOW
//	file     80  same path                                   MEDIUM
//	network  80  same destination host or address            MEDIUM
//	cloud    95  same operation on the named resource        HIGH
//	cloud    75  same operation, command named no resource   MEDIUM
//	cloud    70  same operation, record names no resource    LOW
func MatchBasis(kind string, score int) (basis, confidence string) {
	switch kind {
	case "process":
		switch {
		case score >= 100:
			return "same command line", "HIGH"
		case score >= 90:
			return "same command inside a shell wrapper", "HIGH"
		case score >= 70:
			return "command matches a truncated telemetry copy", "MEDIUM"
		case score > 0:
			return "same program with most arguments shared", "LOW"
		}
	case "file":
		if score > 0 {
			return "same file path", "MEDIUM"
		}
	case "network":
		if score > 0 {
			return "same destination", "MEDIUM"
		}
	case "cloud":
		switch {
		case score >= 95:
			return "same cloud operation on the named resource", "HIGH"
		case score >= 75:
			return "same cloud operation; the command named no resource", "MEDIUM"
		case score > 0:
			return "same cloud operation; the record names no resource", "LOW"
		}
	}
	return "", ""
}

// Match witnesses: which pass made the pairing. The host process, file and
// network telemetry is "endpoint"; CloudTrail, Azure, GCP and the
// cloud-like audit sources (Kubernetes, Git hosting, object storage) are
// "cloud"; DNS, proxy, auth.log and journal records are "sighting"; native
// PowerShell script-block records are "script"; Security 4688 records
// without a command line are "process-image".
const (
	WitnessEndpoint     = "endpoint"
	WitnessCloud        = "cloud"
	WitnessSighting     = "sighting"
	WitnessScript       = "script"
	WitnessProcessImage = "process-image"
)

// The partial-coverage and corroborate-only passes are not on the
// MatchBasis ladder: their scores are not process-telemetry scores, so
// each match states exactly what was compared.
//
//	sighting  proxy request to the same host and path        MEDIUM
//	sighting  proxy request to the same host                 MEDIUM
//	sighting  proxy request to the host, another path        LOW
//	sighting  DNS lookup of the host                         LOW
//	sighting  sshd login for the user (host not logged)      LOW
//	sighting  sudo / journal command line                    as MatchBasis("process")
//	script    script block equals the command                HIGH
//	script    whole command inside the script block          MEDIUM
//	image     process image basename only                    LOW
//	cloud     k8s verb+resource, Git hosting action,          as MatchBasis("cloud")
//	          storage operation (+ bucket/key)

// addMatch appends one match to the result, within MaxMatches, with the
// basis and confidence MatchBasis gives the record's kind and score.
func addMatch(res *EndpointResult, witness string, ev *schema.Event, r endpoint.Record, score int, window time.Duration, related []RelatedRecord) {
	basis, conf := MatchBasis(r.Kind, score)
	addMatchBasis(res, witness, ev, r, score, basis, conf, window, related)
}

// addMatchBasis appends one match with an explicit basis and confidence.
func addMatchBasis(res *EndpointResult, witness string, ev *schema.Event, r endpoint.Record, score int, basis, conf string, window time.Duration, related []RelatedRecord) {
	if len(res.Matches) >= MaxMatches {
		res.MatchesOmitted++
		return
	}
	m := Match{EventID: ev.EventID, Witness: witness, Score: score, Basis: basis, Confidence: conf,
		WindowMS: window.Milliseconds(), Record: boundRecord(r), Related: related}
	if t, ok := parseEventTime(ev.Timestamp); ok {
		m.DeltaMS = r.Time.Sub(t).Milliseconds()
	}
	res.Matches = append(res.Matches, m)
}

func boundRecord(r endpoint.Record) endpoint.Record {
	r.Cmdline = trim(r.Cmdline, maxCmdline)
	return r
}

// pidIndex maps pids and ppids to record positions for relatedOf.
type pidIndex struct {
	byPID  map[int][]int
	byPPID map[int][]int
}

func newPIDIndex(records []endpoint.Record) *pidIndex {
	ix := &pidIndex{byPID: map[int][]int{}, byPPID: map[int][]int{}}
	for i, r := range records {
		if r.PID != 0 {
			ix.byPID[r.PID] = append(ix.byPID[r.PID], i)
		}
		if r.Kind == "process" && r.PPID != 0 {
			ix.byPPID[r.PPID] = append(ix.byPPID[r.PPID], i)
		}
	}
	return ix
}

// relatedOf lists what a matched process record did, by pid identity.
// pids recycle, so only records from the process's own start up to
// relatedHorizon later are taken; anything older or later is another
// process that happened to get the same number.
func (ix *pidIndex) relatedOf(records []endpoint.Record, j int) []RelatedRecord {
	p := records[j]
	if p.Kind != "process" || p.PID == 0 {
		return nil
	}
	in := func(r endpoint.Record) bool {
		return !r.Time.Before(p.Time) && r.Time.Sub(p.Time) <= relatedHorizon
	}
	var out []RelatedRecord
	for _, k := range ix.byPID[p.PID] {
		if k == j || records[k].Kind == "process" || !in(records[k]) {
			continue
		}
		out = append(out, RelatedRecord{Basis: "endpoint pid", Record: boundRecord(records[k])})
	}
	for _, k := range ix.byPPID[p.PID] {
		if k == j || !in(records[k]) {
			continue
		}
		out = append(out, RelatedRecord{Basis: "endpoint ppid", Record: boundRecord(records[k])})
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Record.Time.Before(out[b].Record.Time) })
	if len(out) > maxRelated {
		out = out[:maxRelated]
	}
	return out
}
