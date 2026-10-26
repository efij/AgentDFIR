package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/hashchain"
	"github.com/efij/AgentDFIR/v5/internal/journal"
	"github.com/efij/AgentDFIR/v5/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v5/internal/recorder"
	"github.com/efij/AgentDFIR/v5/internal/sanitize"
	"github.com/efij/AgentDFIR/v5/internal/watch"
)

// recordFlags are the black-box recorder flags of `monitor`.
type recordFlags struct {
	record    *bool
	auditd    *string
	tails     multiFlag
	retain    *string
	fromStart *bool
	noMCP     *bool
}

func addRecordFlags(fs *flag.FlagSet) *recordFlags {
	f := &recordFlags{}
	f.record = fs.Bool("record", false, "black-box recorder: journal transcripts (as --journal), record MCP config changes, keep ~/.agentdfir/monitor/status.json for `monitor status`")
	f.auditd = fs.String("auditd", "", "with --record: tail this auditd log read-only (Linux: /var/log/audit/audit.log, root), rotation-aware")
	fs.Var(&f.tails, "tail", "with --record: tail any endpoint log the importer reads (Tetragon/Falco JSON export, Sysmon XML export, MCP gateway JSONL...); repeatable")
	f.retain = fs.String("retain", "", "with --record: keep captures within an age and/or size (7d, 2GB, 7d,2GB); every deletion is journaled")
	f.fromStart = fs.Bool("tail-from-start", false, "with --auditd/--tail: also record what the file already holds (default: from now on)")
	f.noMCP = fs.Bool("no-mcp-config", false, "with --record: do not record MCP config changes")
	return f
}

// enabled: any recorder flag turns the recorder (and the journal) on.
func (f *recordFlags) enabled() bool {
	return *f.record || *f.auditd != "" || len(f.tails) > 0 || *f.retain != ""
}

// validate checks the recorder flags before anything is opened.
func (f *recordFlags) validate() error {
	if *f.retain != "" {
		if _, err := recorder.ParseRetention(*f.retain); err != nil {
			return err
		}
	}
	return nil
}

// start builds and starts the recorder. It does not start eslogger; the
// caller hands the recorder to startES through the esHandle.
func (f *recordFlags) start(jn *journal.Journal, home, anchorFile string, interval time.Duration) (*recorder.Recorder, error) {
	var ret *recorder.Retention
	if *f.retain != "" {
		r, err := recorder.ParseRetention(*f.retain)
		if err != nil {
			return nil, err
		}
		ret = &r
	}
	var j recorder.Journal
	if jn != nil {
		j = jn
	}
	r := recorder.New(recorder.Dir(home), j)
	r.Interval, r.Retention, r.AnchorFile = interval, ret, anchorFile
	r.JournalLog = journal.DefaultPath(home)
	if !*f.noMCP {
		r.AddMCPConfig(mcpaudit.ConfigPatterns(home))
	}
	if *f.auditd != "" {
		src := r.AddTail(*f.auditd, "auditd", *f.fromStart)
		if runtime.GOOS != "linux" {
			src.Note("auditd is a Linux source; reading " + *f.auditd + " as a file on " + runtime.GOOS)
		}
		fmt.Printf("monitor --auditd: %s → %s/auditd-*.log\n", sanitize.Terminal(*f.auditd), sanitize.Terminal(r.Dir))
	}
	for _, t := range f.tails {
		src := r.AddTail(t, "tail", *f.fromStart)
		fmt.Printf("monitor --tail: %s → %s/%s-*\n", sanitize.Terminal(t), sanitize.Terminal(r.Dir), src.Name())
	}
	if ret != nil {
		fmt.Printf("monitor --retain: %s (oldest captures pruned first; each prune is journaled; journal records are never pruned)\n", ret.Spec)
	}
	return r, nil
}

// monitorHome is where the monitor keeps its state: the effective user's
// home (resolved from the uid when root, never from an inherited $HOME),
// with the state dir checked before anything is written into it.
func monitorHome() (string, error) {
	home, err := recorder.Home()
	if err != nil {
		return "", err
	}
	if err := recorder.CheckDir(recorder.Dir(home)); err != nil {
		return "", err
	}
	return home, nil
}

// wireTranscripts counts journaled transcript appends as a source.
func wireTranscripts(w *watch.Watcher, r *recorder.Recorder, paths []string) {
	src := r.AddSource("transcripts", "transcripts", strings.Join(paths, ", "))
	src.SetState("running")
	grow := w.OnGrow
	w.OnGrow = func(p string, from, to int64) {
		if grow != nil {
			grow(p, from, to)
		}
		if to > from {
			src.AddRange(to - from)
		}
	}
}

// ---- monitor status ----

type journalInfo struct {
	Path        string `json:"path"`
	Present     bool   `json:"present"`
	Records     int    `json:"records"`
	Intact      bool   `json:"intact"`
	Error       string `json:"error,omitempty"`
	Head        string `json:"head,omitempty"`
	LastSealUTC string `json:"last_seal_utc,omitempty"`
	AnchorFile  string `json:"anchor_file,omitempty"` // the one checked (--journal-anchor)
	Anchor      string `json:"anchor"`                // anchored | NOT FOUND | not configured | unreadable | not checked
	// StatusAnchorFile is what status.json names. status.json is written
	// in a directory the monitored user can write, so it is shown as
	// information only and never used to pick the file that is checked.
	StatusAnchorFile string `json:"status_anchor_file,omitempty"`
	Warning          string `json:"warning,omitempty"`
}

type monitorStatusOut struct {
	Dir     string           `json:"dir"`
	Running bool             `json:"running"`
	Status  *recorder.Status `json:"status,omitempty"`
	Journal journalInfo      `json:"journal"`
	Note    string           `json:"note,omitempty"`
}

func cmdMonitorStatus(args []string) int {
	fs := flag.NewFlagSet("monitor status", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	dir := fs.String("dir", "", "monitor state directory (default ~/.agentdfir/monitor; a copied one works offline)")
	anchorFlag := fs.String("journal-anchor", "", "anchor file the monitor appends chain heads to (the --journal-anchor it was started with); checked against the journal")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir monitor status [--dir <state-dir>] [--journal-anchor <file>] [--json]")
		return 2
	}
	if *dir == "" {
		home, _ := recorder.Home()
		*dir = recorder.Dir(home)
	}
	out := monitorStatusOut{Dir: *dir}
	st, err := recorder.LoadStatus(*dir)
	if err == nil {
		out.Status = st
		out.Running = st.Live(time.Now())
	} else {
		out.Note = "no recorder status in " + *dir + " (start one with `agentdfir monitor --record`)"
	}
	out.Journal = inspectJournal(filepath.Join(*dir, "journal.jsonl"), *anchorFlag)
	if st != nil && st.AnchorFile != "" {
		out.Journal.StatusAnchorFile = st.AnchorFile
		switch {
		case *anchorFlag == "":
			out.Journal.Anchor = "not checked: status.json names " + st.AnchorFile + " (status.json is not trusted; pass --journal-anchor <file> to check)"
		case filepath.Clean(*anchorFlag) != filepath.Clean(st.AnchorFile):
			out.Journal.Warning = "status.json names anchor file " + st.AnchorFile + ", not " + *anchorFlag + ": the monitor was started with another anchor, or status.json was edited"
		}
	}
	rc := 0
	if out.Status == nil || (out.Journal.Present && !out.Journal.Intact) {
		rc = 1
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return rc
	}
	printMonitorStatus(out)
	return rc
}

func inspectJournal(p, anchorFile string) journalInfo {
	ji := journalInfo{Path: p, AnchorFile: anchorFile, Anchor: "not configured"}
	if _, err := os.Stat(p); err != nil {
		ji.Anchor = "no journal"
		return ji
	}
	ji.Present = true
	n, err := hashchain.VerifyFile(p)
	ji.Records, ji.Intact = n, err == nil
	if err != nil {
		ji.Error = err.Error()
	}
	ji.Head, _ = journal.Head(p)
	ji.LastSealUTC = lastSeal(p)
	if anchorFile != "" {
		head := lastAnchorHead(anchorFile, p)
		switch {
		case head == "":
			ji.Anchor = "unreadable (no head for this journal in " + anchorFile + ")"
		default:
			if ok, _, _ := journal.VerifyAnchor(p, head); ok {
				ji.Anchor = "anchored (last head in the anchor file is in the chain)"
			} else {
				ji.Anchor = "NOT FOUND: the last anchored head is not in the chain; the journal was rebuilt"
			}
		}
	}
	return ji
}

// lastSeal returns the time of the journal's last seal record.
func lastSeal(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	last := ""
	for sc.Scan() {
		b := sc.Bytes()
		if !strings.Contains(string(b), `"kind":"seal"`) {
			continue
		}
		var r struct {
			At string `json:"monitor_utc"`
		}
		if json.Unmarshal(b, &r) == nil {
			last = r.At
		}
	}
	return last
}

// lastAnchorHead reads the newest "<ts> <journal path> <head>" line for
// exactly this journal path from a --journal-anchor file (heads of other
// journals in the same file never count).
func lastAnchorHead(anchorFile, jp string) string {
	f, err := os.Open(anchorFile)
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	want := filepath.Clean(jp)
	head := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		first := strings.IndexByte(line, ' ')
		last := strings.LastIndexByte(line, ' ')
		if first < 0 || last <= first {
			continue
		}
		if filepath.Clean(strings.TrimSpace(line[first+1:last])) == want {
			head = line[last+1:]
		}
	}
	return head
}

func printMonitorStatus(o monitorStatusOut) {
	st := o.Status
	switch {
	case st == nil:
		fmt.Println("monitor: " + sanitize.Terminal(o.Note))
	case o.Running:
		fmt.Printf("monitor: RUNNING  pid %d on %s, since %s, status updated %s\n", st.PID, sanitize.Terminal(st.Host), st.StartedUTC, st.UpdatedUTC)
	case st.StoppedUTC != "":
		fmt.Printf("monitor: STOPPED  cleanly at %s (pid %d on %s, started %s)\n", st.StoppedUTC, st.PID, sanitize.Terminal(st.Host), st.StartedUTC)
	default:
		fmt.Printf("monitor: NOT RUNNING  last status %s from pid %d on %s, no clean stop: killed, crashed or the host went down\n", st.UpdatedUTC, st.PID, sanitize.Terminal(st.Host))
	}
	if st != nil {
		fmt.Printf("\n%-22s %-11s %-20s %10s %10s %6s %8s %6s %5s\n", "SOURCE", "STATE", "LAST EVENT (UTC)", "RECORDS", "BYTES", "GAPS", "MISSING", "DROPS", "ROT")
		for _, s := range st.Sources {
			gaps, missing := "-", "-"
			if s.SeqKind != "" {
				gaps, missing = fmt.Sprint(s.Gaps), fmt.Sprint(s.MissingSeq)
			}
			last := s.LastEventUTC
			if last == "" {
				last = "-"
			}
			fmt.Printf("%-22s %-11s %-20s %10d %10s %6s %8s %6d %5d\n", sanitize.Terminal(s.Name), s.State, last, s.Records, humanBytes(s.Bytes), gaps, missing, s.Drops, s.Rotations)
			detail := []string{}
			if s.Format != "" {
				detail = append(detail, "format "+s.Format)
			}
			if s.SeqKind != "" {
				detail = append(detail, "sequence "+s.SeqKind)
			} else if s.Kind != "transcripts" && s.Kind != "mcp-config" {
				detail = append(detail, "no sequence numbers: drops cannot be detected")
			}
			if s.Capture != "" {
				detail = append(detail, "capture "+filepath.Base(s.Capture))
			}
			if len(detail) > 0 {
				fmt.Println("    " + sanitize.Terminal(strings.Join(detail, "; ")))
			}
			for _, g := range s.GapSamples {
				fmt.Println("    gap: " + sanitize.Terminal(g))
			}
			for _, p := range s.Problems {
				fmt.Println("    ! " + sanitize.Terminal(p))
			}
			for _, n := range s.Notes {
				fmt.Println("    · " + sanitize.Terminal(n))
			}
		}
		if r := st.Retention; r != nil {
			fmt.Printf("\nretention: %s — %d capture file(s), %s on disk; pruned %d file(s), %s", r.Policy, r.Files, humanBytes(r.Bytes), r.PrunedFiles, humanBytes(r.PrunedBytes))
			if r.LastPruneUTC != "" {
				fmt.Printf("; last %s (%s)", r.LastPruneUTC, sanitize.Terminal(r.LastReason))
			}
			fmt.Println()
			for _, p := range r.Problems {
				fmt.Println("    ! " + sanitize.Terminal(p))
			}
		} else {
			fmt.Println("\nretention: none (captures are kept until removed by hand; use --retain)")
		}
	}
	j := o.Journal
	switch {
	case !j.Present:
		fmt.Printf("journal: none at %s\n", sanitize.Terminal(j.Path))
	case j.Intact:
		fmt.Printf("journal: %s — %d records, chain intact, head %.16s…, last seal %s\n", sanitize.Terminal(j.Path), j.Records, j.Head, orDash(j.LastSealUTC))
	default:
		fmt.Printf("journal: %s — BROKEN after record %d (%s)\n", sanitize.Terminal(j.Path), j.Records, sanitize.Terminal(j.Error))
	}
	fmt.Println("anchor:  " + sanitize.Terminal(j.Anchor))
	if j.Warning != "" {
		fmt.Println("  ! " + sanitize.Terminal(j.Warning))
	}
	if j.Present {
		fmt.Println("check recorded files against the journal: agentdfir journal verify " + sanitize.Terminal(j.Path))
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---- journal verify: recorded captures ----

// captureResolver maps a journaled capture path to the copy next to the
// journal being verified (the live state dir, or one copied off the host).
func captureResolver(journalPath string) func(string) (string, bool) {
	jdir := filepath.Dir(journalPath)
	return func(recorded string) (string, bool) {
		norm := strings.ReplaceAll(recorded, `\`, "/")
		base := norm[strings.LastIndex(norm, "/")+1:]
		if !recorder.IsCaptureName(base) {
			return "", false
		}
		dir := strings.TrimSuffix(norm, "/"+base)
		if filepath.Clean(filepath.FromSlash(dir)) != filepath.Clean(jdir) && !strings.HasSuffix(dir, "/.agentdfir/monitor") {
			return "", false
		}
		return filepath.Join(jdir, base), true
	}
}

// verifyRecordedCaptures checks the recorder's capture files against the
// journal: intact, pruned-and-journaled, or a problem. Returns 1 on any
// problem.
func verifyRecordedCaptures(jp string) int {
	rep, err := journal.VerifyFiles(jp, captureResolver(jp))
	if err != nil {
		fmt.Printf("FILES   cannot read %s: %v\n", sanitize.Terminal(jp), err)
		return 1
	}
	if len(rep.Files) == 0 {
		return 0
	}
	for _, f := range rep.Files {
		if f.Problem || f.State == journal.FilePruned {
			fmt.Printf("  %-14s %s: %s\n", f.State, sanitize.Terminal(filepath.Base(f.Path)), sanitize.Terminal(f.Detail))
		}
	}
	fmt.Printf("FILES   %d recorded capture(s): %d intact, %d pruned by retention (journaled), %d problem(s)\n", len(rep.Files), rep.OK, rep.Pruned, rep.Problems)
	if rep.Problems > 0 {
		fmt.Println("        DELETED = gone with no prune record (not retention); REWRITTEN/TRUNCATED = edited after it was journaled.")
		return 1
	}
	return 0
}

// ---- recorded → investigate ----

// expandEndpointDirs replaces a monitor state directory given to
// --endpoint with the OS-telemetry captures in it, so
// `agentdfir run --endpoint ~/.agentdfir/monitor` correlates the agent's
// transcripts with everything the black box recorded.
func expandEndpointDirs(in []string) ([]string, error) {
	var out []string
	for _, p := range in {
		fi, err := os.Stat(p)
		if err != nil || !fi.IsDir() {
			out = append(out, p)
			continue
		}
		files, notices := recorder.EndpointFiles(p)
		for _, n := range notices {
			fmt.Fprintln(os.Stderr, "endpoint: "+sanitize.Terminal(n))
		}
		if len(files) == 0 {
			return nil, fmt.Errorf("%s: no recorded OS telemetry to import (a directory given to --endpoint must be a monitor state dir with captures)", p)
		}
		fmt.Fprintf(os.Stderr, "endpoint: %s: %d recorded capture(s)\n", sanitize.Terminal(p), len(files))
		out = append(out, files...)
	}
	return out, nil
}

// cmdReplayMonitor replays a black-box recording offline: it verifies the
// journal and the captures against it, then steps through every recorded
// OS record in time order.
func cmdReplayMonitor(dir, filter string, all bool) int {
	jp := filepath.Join(dir, "journal.jsonl")
	if _, err := os.Stat(jp); err == nil {
		if n, err := hashchain.VerifyFile(jp); err != nil {
			fmt.Printf("BROKEN  journal %s: %v (%d records verify before the break)\n", sanitize.Terminal(jp), err, n)
		} else {
			fmt.Printf("OK      journal %s: %d records, chain intact\n", sanitize.Terminal(jp), n)
		}
		verifyRecordedCaptures(jp)
	} else {
		fmt.Println("NOTE    no journal in " + sanitize.Terminal(dir) + ": the captures cannot be shown to be unedited")
	}
	files, notices := recorder.EndpointFiles(dir)
	for _, n := range notices {
		fmt.Println("        " + sanitize.Terminal(n))
	}
	var recs []endpoint.Record
	for _, p := range files {
		lr, err := endpoint.Load(p, endpoint.FormatAuto)
		if err != nil {
			fmt.Printf("        %s: %v\n", sanitize.Terminal(filepath.Base(p)), err)
			continue
		}
		fmt.Printf("        %s: %s, %d record(s), %d skipped\n", sanitize.Terminal(filepath.Base(p)), lr.Format, len(lr.Records), lr.Skipped)
		for typ, n := range lr.Unsupported {
			fmt.Printf("          UNSUPPORTED %s: %d record(s) recognized but not mapped\n", sanitize.Terminal(typ), n)
		}
		recs = append(recs, lr.Records...)
	}
	sort.SliceStable(recs, func(i, j int) bool { return recs[i].Time.Before(recs[j].Time) })
	sc := bufio.NewScanner(os.Stdin)
	n := 0
	for _, r := range recs {
		what := firstNonEmptyStr(r.Cmdline, r.FilePath, r.URL, r.DestHost, r.DestIP, r.Operation, r.Resource, r.Message, r.Details)
		line := fmt.Sprintf("%s %-13s pid=%-6d %s %s", r.Time.UTC().Format(time.RFC3339), r.Kind, r.PID, baseNameOf(r.Exe), trimTo(what, 200))
		if filter != "" && !strings.Contains(line, filter) && !strings.Contains(r.Exe, filter) {
			continue
		}
		n++
		fmt.Printf("%s  [%s]\n", sanitize.Terminal(line), sanitize.Terminal(r.Ref))
		if !all {
			fmt.Print("  [Enter=next, q=quit] ")
			if !sc.Scan() || strings.TrimSpace(sc.Text()) == "q" {
				break
			}
		}
	}
	fmt.Printf("replayed %d recorded OS record(s) from %d capture(s). Check the agent transcripts against them: agentdfir run --endpoint %s\n", n, len(files), sanitize.Terminal(dir))
	return 0
}
