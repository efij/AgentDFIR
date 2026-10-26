package endpoint

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/parsers/plaso"
)

// FormatPlaso is a Plaso timeline written by psort (-o json_line or
// -o l2tcsv).
//
// A super-timeline is a partial witness: it holds what the parsers found
// in the image (browser history, shell history, file-system times), not
// a record of every process or connection. Its records corroborate a
// matching action and never contradict one, and they never count as
// telemetry coverage (source "plaso" is a sighting source).
//
// Mapped: lines with a URL (browser history, bookmarks, downloads) →
// network records with the URL and its host; shell-history lines with a
// command → process records with that command line; file-system lines
// (fs:stat and other entries with a filename) → file records whose
// operation follows the timestamp description. Undated lines and every
// other entry are counted as skipped and stay in the original file.
const FormatPlaso Format = "plaso"

func loadPlaso(path string) (*LoadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	head := make([]byte, 64<<10)
	n, _ := f.Read(head)
	format := plaso.Sniff(head[:n])
	if format == "" {
		return nil, fmt.Errorf("%s: not a psort json_line or l2tcsv timeline", baseName(path))
	}
	if _, err := f.Seek(0, 0); err != nil {
		return nil, err
	}
	res := &LoadResult{}
	base := baseName(path)
	st, err := plaso.Read(f, format, func(e plaso.Entry) error {
		if e.Time.IsZero() {
			res.ignore()
			return nil
		}
		r := Record{Time: e.Time, User: e.User, Source: "plaso", Ref: fmt.Sprintf("%s:%d", base, e.Line)}
		switch {
		case e.URL != "":
			r.Kind, r.URL = "network", e.URL
			if u, err := url.Parse(e.URL); err == nil {
				r.DestHost = strings.ToLower(u.Hostname())
			}
			if r.DestHost == "" {
				res.ignore()
				return nil
			}
		case e.Command != "":
			r.Kind, r.Cmdline = "process", e.Command
			if fields := strings.Fields(e.Command); len(fields) > 0 {
				r.Exe = fields[0]
			}
		case e.Filename != "" && strings.HasPrefix(e.DataType, "fs:"):
			r.Kind, r.FilePath, r.FileOp = "file", e.Filename, fileOp(e.TimeDesc)
		default:
			res.ignore()
			return nil
		}
		res.Records = append(res.Records, r)
		return nil
	})
	res.Skipped += st.Malformed + st.Overlong
	for _, p := range st.Problems {
		res.note(p)
	}
	if st.Undated > 0 {
		res.note(fmt.Sprintf("%d undated Plaso line(s) not used", st.Undated))
	}
	return res, err
}

// fileOp maps a Plaso timestamp description to a file operation.
func fileOp(desc string) string {
	l := strings.ToLower(desc)
	switch {
	case strings.Contains(l, "creat"):
		return "create"
	case strings.Contains(l, "delet"):
		return "delete"
	case strings.Contains(l, "modif") || strings.Contains(l, "change"):
		return "modify"
	}
	return "open"
}
