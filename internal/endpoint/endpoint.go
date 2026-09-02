// Package endpoint loads independent operating-system telemetry — the
// second witness for what an agent did on a machine. Adapters turn
// auditd logs, Sysmon XML exports and generic process/network/file event
// exports (Velociraptor, osquery, evtx_dump JSON, macOS eslogger) into one
// Record model that the correlation engine consumes.
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
)

// Record is one endpoint observation.
type Record struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"` // process | network | file
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
	Source    string    `json:"source"`            // adapter name
	Ref       string    `json:"ref"`               // file:line or event id
}

// Format names an adapter.
type Format string

const (
	FormatAuto   Format = "auto"
	FormatAuditd Format = "auditd"
	FormatSysmon Format = "sysmon-xml"
	FormatJSONL  Format = "jsonl"
	FormatCSV    Format = "csv"
	MaxLogBytes         = 2 << 30 // 2 GiB streaming bound
	maxLineBytes        = 4 << 20
)

// LoadResult is what one file produced.
type LoadResult struct {
	Format   Format
	Records  []Record
	Skipped  int      // lines/events that did not parse
	Problems []string // first few parse problems, for the operator
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
	default:
		return nil, fmt.Errorf("unknown endpoint format %q", f)
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
	head = bytes.TrimLeft(head[:n], "\xef\xbb\xbf \t\r\n")
	switch {
	case bytes.HasPrefix(head, []byte("type=")) || bytes.Contains(head[:min(len(head), 4096)], []byte("\ntype=")):
		return FormatAuditd, nil
	case bytes.HasPrefix(head, []byte("<")) && (bytes.Contains(head, []byte("<Event")) || bytes.Contains(head, []byte("<Events"))):
		return FormatSysmon, nil
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
	return "", errors.New("cannot determine endpoint log format; pass --format auditd|sysmon-xml|jsonl|csv")
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
