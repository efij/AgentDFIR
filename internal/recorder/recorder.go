// Package recorder is the black-box side of `agentdfir monitor --record`:
// it captures OS telemetry next to the agent transcripts the monitor
// already journals, keeps it tamper-evident, bounds it with a retention
// policy, and keeps a status file that `agentdfir monitor status` reads
// offline.
//
// It is not a second monitoring engine. The transcript watch, live
// detection and the hash-chained journal stay where they are (internal/
// watch, internal/realtime, internal/journal); this package adds the
// sources the monitor did not have (auditd and any endpoint export file,
// MCP config changes), a rolling capture writer that journals every flushed
// byte range, retention that journals each deletion, and collection health.
//
// Layout of the state directory (~/.agentdfir/monitor):
//
//	journal.jsonl                     hash-chained journal (internal/journal)
//	status.json                       collection health, rewritten while running
//	<source>-<UTC>[-n].<ext>          raw captures: eslogger, auditd, tail-<name>, mcp-config
//
// Everything is local to the host. Nothing is sent anywhere.
package recorder

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
)

// Journal is what the recorder needs from internal/journal.
type Journal interface {
	Grow(path string, from, to int64)
	Prune(path string, size int64, sha256hex, reason string)
	PruneFailed(path, reason string)
}

// StatusFile is the status file name in the state directory.
const StatusFile = "status.json"

// StatusSchema versions status.json.
const StatusSchema = "agentdfir.monitor.status/1"

// Dir is the monitor state directory under a user's home.
func Dir(home string) string { return filepath.Join(home, ".agentdfir", "monitor") }

var captureRe = regexp.MustCompile(`^([a-z0-9][a-z0-9._-]*)-(\d{8}T\d{6}Z)(?:-\d{1,3})?\.(jsonl|log|xml)$`)

// IsCaptureName reports whether a base name is a recorder capture file.
func IsCaptureName(base string) bool {
	m := captureRe.FindStringSubmatch(base)
	return m != nil && !strings.HasPrefix(m[1], "journal")
}

// CaptureSource returns the source part of a capture file name.
func CaptureSource(base string) string {
	if m := captureRe.FindStringSubmatch(base); m != nil {
		return m[1]
	}
	return ""
}

// CaptureFiles lists the capture files in dir, sorted by name.
func CaptureFiles(dir string) []string {
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if e.Type().IsRegular() && IsCaptureName(e.Name()) {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(out)
	return out
}

// IsStateDir reports whether dir looks like a monitor state directory
// (journal or status file present, and not a case package).
func IsStateDir(dir string) bool {
	fi, err := os.Stat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	for _, m := range []string{"manifest.jsonl", "manifest.json"} {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			return false
		}
	}
	for _, m := range []string{"journal.jsonl", StatusFile} {
		if _, err := os.Stat(filepath.Join(dir, m)); err == nil {
			return true
		}
	}
	return len(CaptureFiles(dir)) > 0
}

// EndpointFiles returns the capture files in a state directory that the
// endpoint importer can read, sniffed by content, and a notice for every
// capture it leaves out (MCP config records are not OS telemetry; an empty
// or unrecognized capture is reported UNSUPPORTED, never dropped quietly).
func EndpointFiles(dir string) ([]string, []string) {
	var files, notices []string
	for _, p := range CaptureFiles(dir) {
		base := filepath.Base(p)
		if CaptureSource(base) == "mcp-config" {
			notices = append(notices, base+": MCP config change records (not OS telemetry); verified by journal verify, not imported")
			continue
		}
		fi, err := os.Stat(p)
		if err != nil {
			notices = append(notices, base+": "+err.Error())
			continue
		}
		if fi.Size() == 0 {
			notices = append(notices, base+": empty capture, nothing to import")
			continue
		}
		if _, err := endpoint.Sniff(p); err != nil {
			notices = append(notices, base+": UNSUPPORTED: "+err.Error())
			continue
		}
		files = append(files, p)
	}
	return files, notices
}

// Status is status.json.
type Status struct {
	Schema      string          `json:"schema"`
	Host        string          `json:"host"`
	PID         int             `json:"pid"`
	StartedUTC  string          `json:"started_utc"`
	UpdatedUTC  string          `json:"updated_utc"`
	StoppedUTC  string          `json:"stopped_utc,omitempty"`
	IntervalSec float64         `json:"interval_sec"`
	Sources     []SourceStatus  `json:"sources"`
	Retention   *RetentionState `json:"retention,omitempty"`
	Journal     string          `json:"journal,omitempty"`
	AnchorFile  string          `json:"anchor_file,omitempty"`
}

// Live reports whether the monitor that wrote s is still updating it.
func (s *Status) Live(now time.Time) bool {
	if s.StoppedUTC != "" {
		return false
	}
	t, err := time.Parse(time.RFC3339, s.UpdatedUTC)
	if err != nil {
		return false
	}
	stale := 3 * time.Duration(s.IntervalSec*float64(time.Second))
	if stale < StatusEvery*3 {
		stale = StatusEvery * 3
	}
	return now.Sub(t) <= stale
}

// LoadStatus reads status.json from a state directory.
func LoadStatus(dir string) (*Status, error) {
	b, err := os.ReadFile(filepath.Join(dir, StatusFile))
	if err != nil {
		return nil, err
	}
	if len(b) > 16<<20 {
		return nil, os.ErrInvalid
	}
	var s Status
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// How often the recorder rewrites status.json and applies retention.
var (
	StatusEvery = 10 * time.Second
	PruneEvery  = time.Minute
)

// Recorder drives the recording sources on a ticker.
type Recorder struct {
	Dir        string
	Journal    Journal // nil: captures are written but not journaled
	Interval   time.Duration
	Retention  *Retention
	JournalLog string // journal path, for status
	AnchorFile string

	mu        sync.Mutex
	sources   []*Source
	tails     []*tailEntry
	mcp       *MCPConfigWatcher
	captures  []*Capture
	retState  *RetentionState
	started   time.Time
	lastSave  time.Time
	lastPrune time.Time
	stop      chan struct{}
	done      chan struct{}
	stopped   bool
	now       func() time.Time
}

type tailEntry struct {
	t    *Tailer
	cap  *Capture
	kind string
}

// New makes a recorder for a state directory.
func New(dir string, jn Journal) *Recorder {
	return &Recorder{Dir: dir, Journal: jn, Interval: 2 * time.Second, now: time.Now, started: time.Now()}
}

// AddSource registers a source whose counters the caller updates (the
// transcript watch, eslogger).
func (r *Recorder) AddSource(name, kind, input string) *Source {
	r.mu.Lock()
	defer r.mu.Unlock()
	s := NewSource(r.uniqueLocked(name), kind, input)
	s.now = r.now
	r.sources = append(r.sources, s)
	return s
}

func (r *Recorder) uniqueLocked(name string) string {
	n, i := name, 2
	for {
		clash := false
		for _, s := range r.sources {
			if s.name == n {
				clash = true
			}
		}
		if !clash {
			return n
		}
		n = name + "-" + strconv.Itoa(i)
		i++
	}
}

// NewCapture makes a capture series the recorder flushes, protects from
// retention while it is open, and closes on Stop.
func (r *Recorder) NewCapture(src *Source, ext string) *Capture {
	c := NewCapture(r.Dir, src.Name(), ext, r.Journal, src)
	c.now = r.now
	r.mu.Lock()
	r.captures = append(r.captures, c)
	r.mu.Unlock()
	return c
}

var nameRe = regexp.MustCompile(`[^a-z0-9._-]+`)

// AddTail records a growing endpoint log. kind is "auditd" (source name
// auditd) or "tail" (source tail-<file name>). The format is sniffed with
// the endpoint importer once the file has data.
func (r *Recorder) AddTail(path, kind string, fromStart bool) *Source {
	name := "auditd"
	if kind != "auditd" {
		base := strings.ToLower(filepath.Base(path))
		base = strings.TrimSuffix(base, filepath.Ext(base))
		base = strings.Trim(nameRe.ReplaceAllString(base, "-"), "-.")
		if base == "" {
			base = "file"
		}
		if len(base) > 40 {
			base = base[:40]
		}
		name = "tail-" + base
	}
	src := r.AddSource(name, kind, path)
	ext := ".jsonl"
	if kind == "auditd" {
		ext = ".log"
		src.SetSeq(SeqAuditSerial)
	}
	c := r.NewCapture(src, ext)
	t := &Tailer{Path: path, Src: src, Out: c, FromStart: fromStart}
	t.OnOpen = func(p string) { sniffTail(p, kind, src, c) }
	r.mu.Lock()
	r.tails = append(r.tails, &tailEntry{t: t, cap: c, kind: kind})
	r.mu.Unlock()
	return src
}

// sniffTail names the format of a tailed file and picks the capture
// extension and sequence parser to match.
func sniffTail(p, kind string, src *Source, c *Capture) {
	if fi, err := os.Stat(p); err != nil || fi.Size() == 0 {
		if src.Format() == "" {
			src.SetFormat("unknown (empty so far)")
		}
		return
	}
	f, err := endpoint.Sniff(p)
	if err != nil {
		src.SetFormat("UNSUPPORTED")
		src.Problem("format not recognized by the endpoint importer (" + err.Error() + "); raw bytes are still recorded and journaled")
		return
	}
	src.SetFormat(string(f))
	switch f {
	case endpoint.FormatAuditd:
		src.SetSeq(SeqAuditSerial)
		c.SetExt(".log")
	case endpoint.FormatSysmon:
		c.SetExt(".xml")
	case endpoint.FormatESLogger:
		src.SetSeq(SeqESGlobal)
	case endpoint.FormatEVTX:
		src.Problem("binary .evtx files are not tailed (records are not appended as lines); export them or pass the file to --endpoint")
	}
	if kind == "auditd" && f != endpoint.FormatAuditd {
		src.Problem("--auditd input sniffed as " + string(f) + ", not an auditd log")
	}
}

// AddMCPConfig records changes to the MCP config files matching patterns.
func (r *Recorder) AddMCPConfig(patterns []string) *Source {
	src := r.AddSource("mcp-config", "mcp-config", strings.Join(patterns, ", "))
	c := r.NewCapture(src, ".jsonl")
	r.mu.Lock()
	r.mcp = &MCPConfigWatcher{Patterns: patterns, Out: c, Src: src, now: r.now}
	r.mu.Unlock()
	return src
}

// Tick polls every recorder-owned source once, flushes captures to the
// journal, applies retention when due and rewrites status.json when due.
func (r *Recorder) Tick() {
	r.mu.Lock()
	tails := append([]*tailEntry(nil), r.tails...)
	mcp := r.mcp
	r.mu.Unlock()
	for _, te := range tails {
		if strings.HasPrefix(te.t.Src.Format(), "unknown") {
			// Opened while empty: name the format before the first bytes
			// are captured, so the capture gets the right extension.
			sniffTail(te.t.Path, te.kind, te.t.Src, te.cap)
		}
		te.t.Poll()
	}
	if mcp != nil {
		mcp.Poll()
	}
	r.flush()
	now := r.now()
	if r.Retention != nil && now.Sub(r.lastPrune) >= PruneEvery {
		r.Prune()
	}
	if now.Sub(r.lastSave) >= StatusEvery {
		_ = r.Save()
	}
}

func (r *Recorder) flush() {
	r.mu.Lock()
	caps := append([]*Capture(nil), r.captures...)
	r.mu.Unlock()
	for _, c := range caps {
		c.Flush()
	}
}

// Prune applies the retention policy now.
func (r *Recorder) Prune() []Pruned {
	r.mu.Lock()
	if r.Retention == nil {
		r.mu.Unlock()
		return nil
	}
	if r.retState == nil {
		r.retState = &RetentionState{Policy: r.Retention.Spec, MaxAgeSec: int64(r.Retention.MaxAge / time.Second), MaxBytes: r.Retention.MaxBytes}
	}
	active := map[string]bool{}
	for _, c := range r.captures {
		if a := c.Active(); a != "" {
			active[a] = true
		}
	}
	ret := *r.Retention
	r.mu.Unlock()
	r.flush() // journal everything up to now before deleting anything
	now := r.now()
	pruned, problems := ret.Prune(r.Dir, active, r.Journal, now)
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastPrune = now
	st := r.retState
	for _, p := range pruned {
		st.PrunedFiles++
		st.PrunedBytes += p.Size
		st.LastPruneUTC = now.UTC().Format(time.RFC3339)
		st.LastReason = p.Reason
	}
	for _, p := range problems {
		st.Problems = addOnce(st.Problems, p)
	}
	st.Files, st.Bytes = 0, 0
	for _, p := range CaptureFiles(r.Dir) {
		if fi, err := os.Stat(p); err == nil {
			st.Files++
			st.Bytes += fi.Size()
		}
	}
	return pruned
}

// Status assembles the current status.
func (r *Recorder) Status() Status {
	r.mu.Lock()
	defer r.mu.Unlock()
	host, _ := os.Hostname()
	st := Status{Schema: StatusSchema, Host: host, PID: os.Getpid(), StartedUTC: r.started.UTC().Format(time.RFC3339),
		UpdatedUTC: r.now().UTC().Format(time.RFC3339), IntervalSec: r.Interval.Seconds(), Journal: r.JournalLog, AnchorFile: r.AnchorFile}
	for _, s := range r.sources {
		st.Sources = append(st.Sources, s.Snapshot())
	}
	if r.retState != nil {
		c := *r.retState
		c.Problems = append([]string(nil), c.Problems...)
		st.Retention = &c
	} else if r.Retention != nil {
		st.Retention = &RetentionState{Policy: r.Retention.Spec, MaxAgeSec: int64(r.Retention.MaxAge / time.Second), MaxBytes: r.Retention.MaxBytes}
	}
	if r.stopped {
		st.StoppedUTC = st.UpdatedUTC
	}
	return st
}

// Save writes status.json atomically (temp file + rename).
func (r *Recorder) Save() error {
	st := r.Status()
	r.mu.Lock()
	r.lastSave = r.now()
	r.mu.Unlock()
	if err := os.MkdirAll(r.Dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp := filepath.Join(r.Dir, StatusFile+".tmp")
	if err := os.WriteFile(tmp, append(b, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(r.Dir, StatusFile))
}

// Start runs Tick every Interval until Stop.
func (r *Recorder) Start() {
	r.mu.Lock()
	if r.stop != nil {
		r.mu.Unlock()
		return
	}
	r.stop, r.done = make(chan struct{}), make(chan struct{})
	iv := r.Interval
	if iv <= 0 {
		iv = 2 * time.Second
	}
	stop, done := r.stop, r.done
	r.mu.Unlock()
	r.Tick()
	go func() {
		defer close(done)
		t := time.NewTicker(iv)
		defer t.Stop()
		for {
			select {
			case <-t.C:
				r.Tick()
			case <-stop:
				return
			}
		}
	}()
}

// Stop ends the loop, reads each source one last time, closes the
// captures (journaling their last ranges) and writes the final status.
// Safe on a nil recorder and more than once.
func (r *Recorder) Stop() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if r.stopped {
		r.mu.Unlock()
		return
	}
	stop, done := r.stop, r.done
	r.stop = nil
	r.mu.Unlock()
	if stop != nil {
		close(stop)
		<-done
	}
	r.mu.Lock()
	tails := append([]*tailEntry(nil), r.tails...)
	mcp := r.mcp
	r.mu.Unlock()
	for _, te := range tails {
		te.t.Poll()
		te.t.Close()
	}
	if mcp != nil {
		mcp.Poll()
	}
	r.mu.Lock()
	caps := append([]*Capture(nil), r.captures...)
	r.mu.Unlock()
	for _, c := range caps {
		_ = c.Close()
	}
	r.mu.Lock()
	r.stopped = true
	for _, s := range r.sources {
		s.mu.Lock()
		if s.state == "running" || s.state == "waiting" {
			s.state = "stopped"
		}
		s.mu.Unlock()
	}
	r.mu.Unlock()
	_ = r.Save()
}
