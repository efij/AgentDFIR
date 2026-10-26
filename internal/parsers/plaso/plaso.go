// Package plaso reads Plaso (log2timeline) timelines produced by psort:
//
//	psort.py -o json_line   one JSON object per line ("timestamp" in µs since the epoch)
//	psort.py -o l2tcsv      the 17-column log2timeline CSV
//
// It is a reader only: it turns each line into an Entry carrying the
// fields Plaso documents for every event (timestamp, timestamp_desc,
// source/sourcetype, parser, display_name/filename, message, host, user)
// plus the few event-data attributes AgentDFIR maps (url, title, command,
// executable). Everything else on the line is left in the original file,
// which the callers keep sealed.
//
// Lines are bounded (MaxLine); an over-long line is counted and skipped,
// and reading resumes at the next line. A line that does not parse is
// counted, never guessed at.
package plaso

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/parsers/linereader"
)

// Formats.
const (
	FormatJSONLine = "json_line"
	FormatL2TCSV   = "l2tcsv"
)

// Bounds.
const (
	MaxLine     = 1 << 20 // one timeline line
	maxProblems = 8
	maxField    = 8 << 10 // one normalized string field
)

// L2TCSVHeader is the header psort writes for -o l2tcsv.
const L2TCSVHeader = "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc,version,filename,inode,notes,format,extra"

// Entry is one timeline event.
type Entry struct {
	Time        time.Time // zero when the line carries no usable time
	TimeRaw     string    // the time as written ("1600000000000000", "09/13/2020 12:26:40 UTC")
	TimeDesc    string    // timestamp_desc / l2tcsv type ("Last Visited Time")
	Source      string    // l2tcsv source (WEBHIST, FILE, LOG …); json_line: the data_type prefix
	SourceType  string    // l2tcsv sourcetype; json_line: data_type
	DataType    string    // json_line data_type ("chrome:history:page_visited")
	Parser      string    // json_line parser / l2tcsv format ("sqlite/chrome_27_history")
	DisplayName string    // json_line display_name
	Filename    string    // filename (path of the source file inside the image)
	Message     string    // json_line message / l2tcsv desc
	Host        string
	User        string
	URL         string // event-data url (json_line) or the first URL in an l2tcsv WEBHIST desc
	Title       string // event-data title
	Command     string // shell-history command
	Executable  string // prefetch / process executable
	Format      string
	Line        int
	Offset      int64
}

// Stats is what a read saw.
type Stats struct {
	Lines     int // non-empty lines
	Entries   int // lines that produced an Entry
	Malformed int // lines that did not parse
	Overlong  int // lines over MaxLine
	Undated   int // entries without a usable time
	Problems  []string
}

func (s *Stats) problem(msg string) {
	if len(s.Problems) < maxProblems {
		s.Problems = append(s.Problems, msg)
	}
}

// Sniff names the Plaso output format of a file head, or "".
func Sniff(head []byte) string {
	head = bytes.TrimLeft(head, "\xef\xbb\xbf \t\r\n")
	first := head
	if i := bytes.IndexByte(head, '\n'); i >= 0 {
		first = head[:i]
	}
	first = bytes.TrimRight(first, "\r")
	if strings.EqualFold(string(first), L2TCSVHeader) {
		return FormatL2TCSV
	}
	if len(first) == 0 || first[0] != '{' {
		return ""
	}
	has := func(k string) bool { return bytes.Contains(first, []byte(`"`+k+`"`)) }
	if has("data_type") && has("timestamp") && (has("timestamp_desc") || has("__container_type__") || has("parser")) {
		return FormatJSONLine
	}
	return ""
}

// Read streams a timeline of the given format and calls fn per entry. An
// error from fn stops the read and is returned.
func Read(r io.Reader, format string, fn func(Entry) error) (Stats, error) {
	var st Stats
	lr := linereader.New(r, MaxLine)
	header := false
	for {
		ln, err := lr.Next()
		if err == io.EOF {
			return st, nil
		}
		if err != nil {
			return st, err
		}
		if ln.Overflow {
			st.Lines++
			st.Overlong++
			st.problem(fmt.Sprintf("line %d: %d bytes exceeds the %d-byte line bound; skipped", ln.Number, ln.OverBytes, MaxLine))
			continue
		}
		b := bytes.TrimRight(ln.Bytes, "\r\n")
		if ln.Number == 1 {
			b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
		}
		if len(bytes.TrimSpace(b)) == 0 {
			continue
		}
		if format == FormatL2TCSV && !header {
			header = true
			if strings.EqualFold(strings.TrimSpace(string(b)), L2TCSVHeader) {
				continue
			}
		}
		st.Lines++
		var e Entry
		var ok bool
		var why string
		switch format {
		case FormatJSONLine:
			e, ok, why = jsonLine(b)
		case FormatL2TCSV:
			e, ok, why = csvLine(b)
		default:
			return st, fmt.Errorf("plaso: unknown format %q", format)
		}
		if !ok {
			st.Malformed++
			st.problem(fmt.Sprintf("line %d: %s", ln.Number, why))
			continue
		}
		e.Format, e.Line, e.Offset = format, ln.Number, ln.Offset
		st.Entries++
		if e.Time.IsZero() {
			st.Undated++
		}
		if err := fn(e); err != nil {
			return st, err
		}
	}
}

func jsonLine(b []byte) (Entry, bool, string) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var doc map[string]any
	if err := dec.Decode(&doc); err != nil {
		return Entry{}, false, "not a JSON object: " + clip(err.Error(), 120)
	}
	str := func(k string) string {
		switch v := doc[k].(type) {
		case string:
			return clip(v, maxField)
		case json.Number:
			return v.String()
		}
		return ""
	}
	e := Entry{
		TimeDesc: str("timestamp_desc"), DataType: str("data_type"), Parser: str("parser"),
		DisplayName: str("display_name"), Filename: str("filename"), Message: str("message"),
		Host: str("hostname"), User: str("username"), URL: str("url"), Title: str("title"),
		Command: str("command"), Executable: str("executable"),
	}
	if e.DataType == "" {
		return Entry{}, false, "no data_type"
	}
	e.SourceType = e.DataType
	e.Source = e.DataType
	if i := strings.IndexByte(e.Source, ':'); i > 0 {
		e.Source = e.Source[:i]
	}
	if n, ok := doc["timestamp"].(json.Number); ok {
		e.TimeRaw = n.String()
		if us, err := strconv.ParseInt(n.String(), 10, 64); err == nil {
			e.Time = microTime(us)
		} else if f, err := n.Float64(); err == nil && f < 9e15 {
			e.Time = microTime(int64(f))
		}
	} else if s := str("datetime"); s != "" {
		e.TimeRaw = s
		if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
			e.Time = t.UTC()
		}
	}
	return e, true, ""
}

// microTime converts Plaso's µs timestamp. Zero means "not a time" in
// Plaso; anything outside 1970–2200 is treated as not a time too.
func microTime(us int64) time.Time {
	if us <= 0 || us > 7258118400000000 {
		return time.Time{}
	}
	return time.UnixMicro(us).UTC()
}

var urlRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

func csvLine(b []byte) (Entry, bool, string) {
	r := csv.NewReader(bytes.NewReader(b))
	r.FieldsPerRecord = -1
	r.LazyQuotes = true
	rec, err := r.Read()
	if err != nil {
		return Entry{}, false, "csv: " + clip(err.Error(), 120)
	}
	if len(rec) < 17 {
		return Entry{}, false, fmt.Sprintf("%d columns, l2tcsv has 17", len(rec))
	}
	for i := range rec {
		rec[i] = clip(rec[i], maxField)
	}
	e := Entry{
		TimeDesc: rec[6], Source: rec[4], SourceType: rec[5], User: rec[7], Host: rec[8],
		Message: rec[10], Filename: rec[12], Parser: rec[15],
	}
	if e.Message == "" {
		e.Message = rec[9]
	}
	e.TimeRaw = strings.TrimSpace(rec[0] + " " + rec[1] + " " + rec[2])
	e.Time = l2tTime(rec[0], rec[1], rec[2])
	if strings.EqualFold(e.Source, "WEBHIST") {
		if m := urlRe.FindString(rec[10]); m != "" {
			e.URL = m
		} else if m := urlRe.FindString(rec[9]); m != "" {
			e.URL = m
		}
	}
	return e, true, ""
}

// l2tTime reads the MM/DD/YYYY + HH:MM:SS columns. Only a UTC/GMT zone
// is normalized: psort writes the zone it was told to (-z), and resolving
// a named zone would depend on the analysis host's tz database.
func l2tTime(date, clock, zone string) time.Time {
	z := strings.ToUpper(strings.TrimSpace(zone))
	if z != "UTC" && z != "GMT" && z != "ZULU" && z != "Z" && z != "ETC/UTC" {
		return time.Time{}
	}
	t, err := time.Parse("01/02/2006 15:04:05", strings.TrimSpace(date)+" "+strings.TrimSpace(clock))
	if err != nil || t.Year() < 1971 {
		return time.Time{}
	}
	return t.UTC()
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut]
}
