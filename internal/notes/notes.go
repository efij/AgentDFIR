// Package notes is the analyst's case file: verdicts on findings, free-text
// notes, pinned events and session tags. Records are appended to
// <pkg>/notes/notes.jsonl as a hash chain (same construction as the custody
// log), outside the sealed evidence zone, so the evidence stays untouched
// while every analyst action is itself tamper-evident and attributable.
package notes

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/efij/AgentDFIR/internal/hashchain"
)

// Record kinds.
const (
	// KindVerdict targets finding:<key>. Values:
	//   true_positive  the rule was right and the activity was not authorised
	//   benign         the rule was right and the activity was authorised
	//   false_positive the rule was wrong
	//   needs_review   undecided
	//   ""             clears the verdict
	//
	// benign exists because without it an analyst has to mark a correct
	// detection "false positive" just to clear it, which is both untrue and
	// the wrong signal for tuning.
	KindVerdict = "verdict"
	KindNote    = "note" // any target, free text
	KindPin     = "pin"  // target event:<id> | chain node, value "on"|"off"
	KindTag     = "tag"  // target session:<id>, value "add"|"remove", text = tag
)

// Record is one appended analyst action (plus the chain fields seq/ts_utc/prev).
type Record struct {
	Seq      int    `json:"seq"`
	TS       string `json:"ts_utc"`
	Prev     string `json:"prev"`
	Operator string `json:"operator"`
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	Value    string `json:"value,omitempty"`
	Text     string `json:"text,omitempty"`
}

// Verdict is the folded state of one finding.
type Verdict struct {
	Verdict  string `json:"verdict"`
	Note     string `json:"note,omitempty"`
	Operator string `json:"operator"`
	TS       string `json:"ts_utc"`
}

// Pin is one pinned event or chain node.
type Pin struct {
	Target   string `json:"target"`
	Note     string `json:"note,omitempty"`
	Operator string `json:"operator"`
	TS       string `json:"ts_utc"`
}

// State is the current case file, folded from the record history.
type State struct {
	Verdicts map[string]Verdict  `json:"verdicts"` // finding key → verdict
	Notes    map[string][]Record `json:"notes"`    // target → notes in order
	Pins     []Pin               `json:"pins"`
	Tags     map[string][]string `json:"tags"` // session id → tags
	Records  int                 `json:"records"`
	ChainOK  bool                `json:"chain_ok"`
	ChainErr string              `json:"chain_error,omitempty"`
}

// Store is the notes file of one package.
type Store struct {
	path string
	mu   sync.Mutex
}

// Open returns the store for a package; the file is created on first Append.
func Open(pkg string) *Store {
	return &Store{path: filepath.Join(pkg, "notes", "notes.jsonl")}
}

// Path is the notes file location.
func (s *Store) Path() string { return s.path }

// Append adds one record to the chain, continuing from the last record's hash.
func (s *Store) Append(kind, target, value, text string) (Record, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if kind == "" || target == "" {
		return Record{}, fmt.Errorf("notes: kind and target are required")
	}
	if len(text) > 8000 {
		return Record{}, fmt.Errorf("notes: text too long")
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return Record{}, err
	}
	prev, seq := hashchain.Genesis, 0
	if last, n, err := lastLine(s.path); err == nil && n > 0 {
		sum := sha256.Sum256(last)
		prev, seq = hex.EncodeToString(sum[:]), n
	}
	op := ""
	if u, err := user.Current(); err == nil {
		op = u.Username
	}
	rec := Record{Seq: seq, TS: time.Now().UTC().Format(time.RFC3339Nano), Prev: prev, Operator: op, Kind: kind, Target: target, Value: value, Text: text}
	line, err := json.Marshal(rec)
	if err != nil {
		return Record{}, err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return Record{}, err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return Record{}, err
	}
	return rec, f.Sync()
}

// Load reads and folds the record history; a broken chain is reported, not hidden.
func (s *Store) Load() (*State, []Record) {
	st := &State{Verdicts: map[string]Verdict{}, Notes: map[string][]Record{}, Tags: map[string][]string{}, ChainOK: true}
	f, err := os.Open(s.path)
	if err != nil {
		return st, nil
	}
	defer f.Close()
	var recs []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var r Record
		if json.Unmarshal(sc.Bytes(), &r) == nil {
			recs = append(recs, r)
		}
	}
	if _, err := hashchain.VerifyFile(s.path); err != nil {
		st.ChainOK, st.ChainErr = false, err.Error()
	}
	pins := map[string]Pin{}
	for _, r := range recs {
		st.Records++
		switch r.Kind {
		case KindVerdict:
			if r.Value == "" {
				delete(st.Verdicts, r.Target)
			} else {
				st.Verdicts[r.Target] = Verdict{Verdict: r.Value, Note: r.Text, Operator: r.Operator, TS: r.TS}
			}
		case KindNote:
			st.Notes[r.Target] = append(st.Notes[r.Target], r)
		case KindPin:
			if r.Value == "off" {
				delete(pins, r.Target)
			} else {
				pins[r.Target] = Pin{Target: r.Target, Note: r.Text, Operator: r.Operator, TS: r.TS}
			}
		case KindTag:
			sid := strings.TrimPrefix(r.Target, "session:")
			tags := st.Tags[sid]
			if r.Value == "remove" {
				var keep []string
				for _, t := range tags {
					if t != r.Text {
						keep = append(keep, t)
					}
				}
				st.Tags[sid] = keep
			} else if r.Text != "" && !contains(tags, r.Text) {
				st.Tags[sid] = append(tags, r.Text)
			}
		}
	}
	for _, p := range pins {
		st.Pins = append(st.Pins, p)
	}
	sort.Slice(st.Pins, func(i, j int) bool { return st.Pins[i].TS < st.Pins[j].TS })
	return st, recs
}

// FindingKey identifies a finding across re-analyses: rule plus first evidence
// reference (indexes shift when findings are re-sorted or re-generated).
func FindingKey(ruleID string, evidence []string) string {
	first := ""
	if len(evidence) > 0 {
		first = evidence[0]
	}
	return "finding:" + ruleID + "|" + first
}

func lastLine(path string) ([]byte, int, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, 0, err
	}
	defer f.Close()
	var last []byte
	n := 0
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		last = append(last[:0], sc.Bytes()...)
		n++
	}
	return last, n, sc.Err()
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}
