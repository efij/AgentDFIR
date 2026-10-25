// Package endpoint loads independent operating-system telemetry — the
// second witness for what an agent did on a machine. Adapters turn
// auditd logs, Sysmon XML exports and generic process/network/file event
// exports (Velociraptor, osquery, evtx_dump JSON, macOS eslogger) and
// native Windows .evtx files into one Record model that the correlation
// engine consumes.
//
// Inputs are hostile evidence: bounded reads, no execution, tolerant
// parsing that records problems instead of aborting.
package endpoint

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/endpoint/evtx"
)

// Record is one endpoint observation.
type Record struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"` // process | network | file | cloud | dns | auth | process-image | script | service | log-clear (evtx) | process-fork | process-exit | persistence | tcc | av | ipc | signal | log (macOS)
	PID       int       `json:"pid,omitempty"`
	PPID      int       `json:"ppid,omitempty"`
	Exe       string    `json:"exe,omitempty"`
	Cmdline   string    `json:"cmdline,omitempty"`
	ParentExe string    `json:"parent_exe,omitempty"`
	User      string    `json:"user,omitempty"`
	DestIP    string    `json:"dest_ip,omitempty"`
	DestPort  int       `json:"dest_port,omitempty"`
	DestHost  string    `json:"dest_host,omitempty"`
	FilePath  string    `json:"file_path,omitempty"`
	FileOp    string    `json:"file_op,omitempty"` // create | delete | modify | open
	URL       string    `json:"url,omitempty"`     // proxy/HTTP records: the requested URL (kind network)
	Answers   string    `json:"answers,omitempty"` // DNS records: space-separated answers, when the log has them
	// Cloud control-plane records (kind cloud): who did what to which
	// resource, from where, and whether the cloud allowed it.
	Provider  string `json:"provider,omitempty"`  // aws | azure | gcp
	Operation string `json:"operation,omitempty"` // s3:DeleteBucket, microsoft.storage/storageaccounts/delete, storage.buckets.delete
	Resource  string `json:"resource,omitempty"`  // resource ids and names the record names
	SourceIP  string `json:"source_ip,omitempty"`
	Failed    string `json:"failed,omitempty"` // error code when the cloud refused the call
	Source    string `json:"source"`           // adapter name
	Ref       string `json:"ref"`              // file:line or event id

	// Process identity beyond pid/ppid, for sources that record it (macOS
	// Endpoint Security via eslogger fills all of them; other adapters may
	// fill some). UID/EUID are strings so that root (0) is not dropped.
	OrigPPID       int    `json:"orig_ppid,omitempty"` // parent at process start, before any reparenting
	RespPID        int    `json:"resp_pid,omitempty"`  // macOS responsible process
	AuditToken     string `json:"audit_token,omitempty"`
	SigningID      string `json:"signing_id,omitempty"`
	TeamID         string `json:"team_id,omitempty"`
	CDHash         string `json:"cdhash,omitempty"`
	PlatformBinary bool   `json:"platform_binary,omitempty"`
	UID            string `json:"uid,omitempty"`
	EUID           string `json:"euid,omitempty"`
	ProcSession    int    `json:"proc_session,omitempty"` // POSIX session id of the process
	TTY            string `json:"tty,omitempty"`
	Cwd            string `json:"cwd,omitempty"`
	// Collection health: a source-assigned sequence number. Seq is
	// contiguous within SeqDomain (eslogger seq_num per event type, an EVTX
	// channel's EventRecordID, an audit serial); GlobalSeq is a stream-wide
	// counter (eslogger global_seq_num). A jump means the source dropped
	// events. Zero means the source has no sequence numbers.
	Seq       uint64 `json:"seq,omitempty"`
	SeqDomain string `json:"seq_domain,omitempty"`
	GlobalSeq uint64 `json:"global_seq,omitempty"`
	// Message is the raw text of a log record kept for the timeline
	// (kind log, macOS unified log), bounded.
	Message string `json:"message,omitempty"`
}

// Format names an adapter.
type Format string

const (
	FormatAuto   Format = "auto"
	FormatAuditd Format = "auditd"
	FormatSysmon Format = "sysmon-xml"
	FormatJSONL  Format = "jsonl"
	FormatCSV    Format = "csv"
	FormatCloud  Format = "cloud-audit" // AWS CloudTrail, Azure Activity Log, GCP Cloud Audit Logs
	FormatEVTX   Format = "evtx"        // native Windows event log files
	MaxLogBytes         = 2 << 30       // 2 GiB streaming bound
	maxLineBytes        = 4 << 20
)

// LoadResult is what one file produced.
type LoadResult struct {
	Format   Format
	Records  []Record
	Skipped  int      // lines/events that did not parse
	Problems []string // first few parse problems, for the operator
	// Notices are forensically notable events the adapter recognized
	// but that are not process/network/file telemetry (an event log
	// cleared, a service installed). Shown to the operator; no rule.
	Notices []string
	// Unsupported counts input records of a type the adapter recognized
	// as well-formed but does not map (an eslogger event type it has no
	// mapping for), keyed by that type. Counted and reported, never
	// silently dropped.
	Unsupported map[string]int
}

// Load reads one endpoint log with the given (or sniffed) format.
func Load(path string, f Format) (*LoadResult, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if fi.Size() > MaxLogBytes {
		return nil, fmt.Errorf("%s exceeds %d-byte bound", path, MaxLogBytes)
	}
	if f == "" || f == FormatAuto {
		f, err = Sniff(path)
		if err != nil {
			return nil, err
		}
	}
	var res *LoadResult
	switch f {
	case FormatAuditd:
		res, err = loadAuditd(path)
	case FormatSysmon:
		res, err = loadSysmonXML(path)
	case FormatJSONL:
		res, err = loadJSONL(path)
	case FormatCSV:
		res, err = loadCSV(path)
	case FormatCloud:
		res, err = loadCloud(path)
	case FormatEVTX:
		res, err = loadEVTX(path)
	default:
		var ok bool
		if res, ok, err = loadTelemetry(path, f); !ok {
			if res, ok, err = loadMacOS(path, f); !ok {
				return nil, fmt.Errorf("unknown endpoint format %q", f)
			}
		}
	}
	if err != nil {
		return nil, err
	}
	res.Format = f
	sort.SliceStable(res.Records, func(i, j int) bool { return res.Records[i].Time.Before(res.Records[j].Time) })
	return res, nil
}

// Sniff guesses the format from the first non-empty bytes.
func Sniff(path string) (Format, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	head := make([]byte, 64<<10)
	n, _ := io.ReadFull(f, head)
	if bytes.HasPrefix(head[:n], []byte(evtx.FileMagic)) {
		return FormatEVTX, nil
	}
	head = bytes.TrimLeft(head[:n], "\xef\xbb\xbf \t\r\n")
	if tf := sniffTelemetry(head); tf != "" {
		return tf, nil
	}
	if mf := sniffMacOS(head); mf != "" {
		return mf, nil
	}
	switch {
	case bytes.HasPrefix(head, []byte("type=")) || bytes.Contains(head[:min(len(head), 4096)], []byte("\ntype=")):
		return FormatAuditd, nil
	case bytes.HasPrefix(head, []byte("<")) && (bytes.Contains(head, []byte("<Event")) || bytes.Contains(head, []byte("<Events"))):
		return FormatSysmon, nil
	case (bytes.HasPrefix(head, []byte("{")) || bytes.HasPrefix(head, []byte("["))) && looksLikeCloudAudit(head):
		return FormatCloud, nil
	case bytes.HasPrefix(head, []byte("{")) || bytes.HasPrefix(head, []byte("[")):
		return FormatJSONL, nil
	}
	first := head
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		first = head[:i]
	}
	if bytes.Count(first, []byte(",")) >= 2 {
		return FormatCSV, nil
	}
	return "", errors.New("cannot determine endpoint log format; pass --format auditd|sysmon-xml|evtx|jsonl|csv|cloud-audit|" + telemetryFormatList + "|" + macOSFormatList)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// scanLines is a bounded line iterator shared by the text adapters.
func scanLines(path string, fn func(line string, n int)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	n := 0
	for sc.Scan() {
		n++
		fn(sc.Text(), n)
	}
	return sc.Err()
}

func (r *LoadResult) problem(msg string) {
	r.Skipped++
	if len(r.Problems) < 5 {
		r.Problems = append(r.Problems, msg)
	}
}

// note records an operator-facing problem without counting a skipped
// event (the caller accounts for skips itself).
func (r *LoadResult) note(msg string) {
	if len(r.Problems) < 10 {
		r.Problems = append(r.Problems, msg)
	}
}

// notice records a notable recognized event; see LoadResult.Notices.
func (r *LoadResult) notice(msg string) {
	if len(r.Notices) < 50 {
		r.Notices = append(r.Notices, msg)
	}
}

// baseName is a path-separator-agnostic basename (endpoint logs come
// from other operating systems).
func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// parseTime accepts the timestamp shapes endpoint tools emit.
func parseTime(s string) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{
		time.RFC3339Nano, time.RFC3339,
		"2006-01-02 15:04:05.000", "2006-01-02 15:04:05.000000", "2006-01-02 15:04:05",
		"2006-01-02T15:04:05.000000Z07:00", "2006-01-02T15:04:05",
		"2006-01-02 15:04:05.000000-0700", // macOS log show
		"01/02/2006 15:04:05", "2006/01/02 15:04:05",
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	// epoch seconds(.fraction) or milliseconds / nanoseconds
	var sec, frac float64
	if _, err := fmt.Sscanf(s, "%f", &sec); err == nil && sec > 1e9 {
		switch {
		case sec > 1e17: // ns
			return time.Unix(0, int64(sec)).UTC(), true
		case sec > 1e14: // µs
			return time.UnixMicro(int64(sec)).UTC(), true
		case sec > 1e11: // ms
			return time.UnixMilli(int64(sec)).UTC(), true
		}
		frac = sec - float64(int64(sec))
		return time.Unix(int64(sec), int64(frac*1e9)).UTC(), true
	}
	return time.Time{}, false
}
