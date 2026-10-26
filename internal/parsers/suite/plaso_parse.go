package suite

import (
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/parsers/plaso"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// maxTimelineEvents bounds the events one timeline (Plaso, Autopsy) yields.
const maxTimelineEvents = 200000

// Plaso timelines in a package. A line becomes an event when it concerns
// an AI service or agent: its URL is an AI-service URL (browser history,
// bookmarks, cookies …), its file lies in an AI agent / assistant data
// directory, or its executable is an AI application. Every other line is
// counted per parser and stays in the sealed timeline. For checking an
// agent transcript against the same timeline, pass it to
// `analyze --endpoint` instead: it is then a partial-coverage witness.
func (p *parser) parsePlaso(r io.Reader) error {
	head, rr := readHead(r, 64<<10)
	format := plaso.Sniff(head)
	if format == "" {
		p.unsupported("not a psort json_line or l2tcsv timeline")
		return nil
	}
	byParser := map[string]int{}
	events, dropped := 0, 0
	st, err := plaso.Read(rr, format, func(e plaso.Entry) error {
		key := e.Parser
		if key == "" {
			key = e.SourceType
		}
		byParser[clip(key, 64)]++
		var (
			result, who, vendor string
			um                  *URLMatch
		)
		file := e.Filename
		if file == "" {
			file = e.DisplayName
		}
		exe := strings.TrimSuffix(path.Base(strings.ReplaceAll(e.Executable, `\`, "/")), path.Ext(e.Executable))
		switch {
		case e.URL != "":
			if um = FindAIURL(e.URL); um != nil {
				result, who, vendor = "ai-url:"+um.Kind, um.Name+" URL", um.Key
			}
		}
		if result == "" && e.Executable != "" {
			if a := MatchApp(exe); a != nil {
				result, who, vendor = "ai-app:process", a.Name, a.Key
			}
		}
		if result == "" && (agentPath(e.Filename) || agentPath(e.DisplayName)) {
			result, who, vendor = "agent-path", "AI agent data", ""
		}
		if result == "" {
			return nil
		}
		if events >= maxTimelineEvents {
			dropped++
			return nil
		}
		events++
		ev := schema.Event{SourceOffset: e.Offset, SourceLine: e.Line, Result: result, Vendor: vendor}
		field := "timestamp"
		if e.Format == plaso.FormatL2TCSV {
			field = "date,time,timezone"
		}
		p.setTime(&ev, field, e.TimeRaw, e.Time)
		src := e.DataType
		if src == "" {
			src = strings.TrimSpace(e.Source + " " + e.SourceType)
		}
		parts := []string{fmt.Sprintf("Plaso %s (%s)", src, who)}
		if e.TimeDesc != "" {
			parts = append(parts, e.TimeDesc)
		}
		if um != nil {
			parts = append(parts, "url="+clip(um.URL, 200))
			if um.ID != "" {
				parts = append(parts, um.Kind+" id="+um.ID)
			}
		}
		if e.Title != "" {
			parts = append(parts, "title="+clip(e.Title, 160))
		}
		if e.Executable != "" {
			parts = append(parts, "executable="+clip(e.Executable, 160))
		}
		if file != "" {
			parts = append(parts, "file="+clip(file, 200))
		}
		if e.Parser != "" {
			parts = append(parts, "parser="+e.Parser)
		}
		if um == nil && e.Message != "" {
			parts = append(parts, "message="+clip(e.Message, 200))
		}
		ev.Summary = strings.Join(parts, " · ")
		if vendor != "" {
			ev.SessionID = "plaso:" + vendor
		}
		p.record(ev)
		return nil
	})
	if err != nil {
		p.gap(0, 0, fmt.Sprintf("Plaso timeline read stopped: %v", err))
	}
	if st.Malformed+st.Overlong > 0 {
		p.gap(0, 0, fmt.Sprintf("Plaso %s timeline: %d malformed line(s) and %d line(s) over the %d-byte bound were skipped and are preserved in the sealed file (first: %s)",
			format, st.Malformed, st.Overlong, plaso.MaxLine, strings.Join(st.Problems, "; ")))
	}
	inv := fmt.Sprintf("Plaso %s timeline: %d line(s), %d entr(ies) (%d undated); %d normalized (AI-service URL, AI application, AI agent data path)",
		format, st.Lines, st.Entries, st.Undated, events)
	if dropped > 0 {
		inv += fmt.Sprintf(", %d more over the per-timeline bound", dropped)
	}
	inv += "; by parser: " + counts(byParser, 20) + ". Every other entry is preserved in the sealed timeline."
	p.meta(actionInventory, "plaso:inventory", inv)
	p.describe(p.session, "Plaso "+format+" "+path.Base(p.art.LogicalPath), map[string]string{"format": format,
		"entries": fmt.Sprint(st.Entries), "normalized": fmt.Sprint(events)})
	return nil
}

// Autopsy "Generate Report → Files - Text": one row per file, columns
// named after FileReportDataTypes (Name, Full Path, Last Modified …),
// tab- or comma-delimited. Rows under an AI agent / assistant data
// directory become events; the rest are counted.
func (p *parser) parseAutopsy(r io.Reader) error {
	var h []string
	var name, full, mod, acc, cre, size, hash, del int
	events, dropped := 0, 0
	sh, rows, err := readTable(r, func(sh tableShape) {
		h = sh.Header
		name, full = column(h, "Name"), column(h, "Full Path")
		mod, acc, cre = column(h, "Last Modified"), column(h, "Last Accessed"), column(h, "File Created")
		size, hash, del = column(h, "Size"), column(h, "Hash Value"), column(h, "Is Deleted")
	}, func(row []string, line int) error {
		cell := func(i int) string {
			if i >= 0 && i < len(row) {
				return strings.TrimSpace(row[i])
			}
			return ""
		}
		fp := cell(full)
		if !agentPath(fp) {
			return nil
		}
		if events >= maxTimelineEvents {
			dropped++
			return nil
		}
		events++
		ev := schema.Event{SourceLine: line, Result: "agent-path"}
		raw := cell(mod)
		p.setTime(&ev, "Last Modified", raw, autopsyTime(raw))
		parts := []string{"Autopsy file listing: " + clip(fp, 240)}
		for _, c := range []struct {
			n string
			i int
		}{{"name", name}, {"created", cre}, {"accessed", acc}, {"size", size}, {"deleted", del}, {"hash", hash}} {
			if v := cell(c.i); v != "" {
				parts = append(parts, c.n+"="+clip(v, 80))
			}
		}
		ev.Summary = strings.Join(parts, " · ")
		p.record(ev)
		return nil
	})
	if err != nil {
		p.gap(0, 0, fmt.Sprintf("Autopsy Files - Text report stopped at %v; %d row(s) were read before it", err, rows))
	}
	s := fmt.Sprintf("Autopsy Files - Text report: %d row(s), %d column(s) (%s, delimiter %q); %d row(s) under AI agent data directories normalized",
		rows, len(h), sh.Encoding, string(sh.Delim), events)
	if dropped > 0 {
		s += fmt.Sprintf(", %d more over the bound", dropped)
	}
	p.meta(actionInventory, "autopsy:inventory", s+"; every row is preserved in the sealed report.")
	return nil
}

// autopsyTime reads "yyyy-MM-dd HH:mm:ss zzz". Only a UTC/GMT zone is
// normalized; Autopsy writes the zone the case was set to display.
func autopsyTime(v string) time.Time {
	v = strings.TrimSpace(v)
	i := strings.LastIndexByte(v, ' ')
	if i < 0 {
		return time.Time{}
	}
	z := strings.ToUpper(v[i+1:])
	if z != "UTC" && z != "GMT" {
		return time.Time{}
	}
	t, err := time.Parse("2006-01-02 15:04:05", v[:i])
	if err != nil || t.Year() <= 1970 {
		return time.Time{}
	}
	return t.UTC()
}
