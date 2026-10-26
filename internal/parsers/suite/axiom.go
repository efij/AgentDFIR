package suite

import (
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/parsers/sqlitero"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Magnet AXIOM.
//
// Supported routes are the ones AXIOM documents for getting data out:
// the CSV export (one file per artifact type, columns vary by artifact,
// AXIOM appends per-hit columns such as Source, Location, Evidence number
// and Item ID) and the Portable Case / exported file tree (imported like
// any tree; the CSVs inside it are read here). A row becomes an event
// when its artifact names an AI application or one of its cells is an
// AI-service URL; every other row is counted and stays in the sealed CSV.
// Every column is kept raw in the sealed file; only the well-known
// columns below are lifted into events.
//
// Case.mfdb is AXIOM's working database. Its schema is not published, so
// it is sealed losslessly, its SQLite table names and row counts are
// listed (read-only, sqlitero), and the case gets AXIOM_CASE_DB_UNSUPPORTED.

// MaxCaseDBBytes bounds the Case.mfdb image read for the table inventory.
const MaxCaseDBBytes = 256 << 20

const maxCaseDBTables = 512

// axiomCols are the well-known AXIOM column names lifted into events.
type axiomCols struct {
	url, title, when, source, location, item, artifact, evidence int
	body                                                         []int
	whenName                                                     string
}

func axiomColumns(h []string) axiomCols {
	c := axiomCols{
		url:      column(h, "URL", "Url", "Page URL", "Website URL"),
		title:    column(h, "Title", "Page Title", "Name"),
		source:   column(h, "Source"),
		location: column(h, "Location"),
		item:     column(h, "Item ID"),
		artifact: column(h, "Artifact type", "Artifact"),
		evidence: column(h, "Evidence number"),
		when:     -1,
	}
	// Date/Time columns carry their zone and format in the name:
	// "Visit Date/Time - UTC (yyyy-mm-dd)".
	for _, pref := range []string{"visit date/time", "last visited date/time", "date/time", "created date/time", "sent date/time", "start date/time", "timestamp"} {
		for i, name := range h {
			if strings.Contains(strings.ToLower(name), pref) {
				c.when, c.whenName = i, name
				break
			}
		}
		if c.when >= 0 {
			break
		}
	}
	for _, n := range []string{"Message", "Body", "Text", "Content", "Prompt", "Response", "Query", "Search Term"} {
		if i := column(h, n); i >= 0 {
			c.body = append(c.body, i)
		}
	}
	return c
}

var (
	utcOffsetRe = regexp.MustCompile(`(?i)\bUTC\s*([+-])\s*(\d{1,2})(?::?(\d{2}))?`)
	utcRe       = regexp.MustCompile(`(?i)\bUTC\b`)
)

// columnTime parses a value of a Date/Time column whose name states the
// zone ("- UTC", "- UTC+02:00") and, optionally, the date order
// ("(yyyy-mm-dd)", "(M/d/yyyy)", "(dd/MM/yyyy)"). Without a stated zone,
// or with a slashed date and no stated order, nothing is normalized.
func columnTime(colName, v string) (time.Time, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return time.Time{}, false
	}
	var loc *time.Location
	if m := utcOffsetRe.FindStringSubmatch(colName); m != nil {
		h, mm := atoi(m[2]), atoi(m[3])
		off := h*3600 + mm*60
		if m[1] == "-" {
			off = -off
		}
		loc = time.FixedZone("UTC"+m[1]+m[2], off)
	} else if utcRe.MatchString(colName) {
		loc = time.UTC
	} else {
		return time.Time{}, false
	}
	l := strings.ToLower(colName)
	var layouts []string
	switch {
	case strings.Contains(l, "dd/mm/yyyy") || strings.Contains(l, "d/m/yyyy"):
		layouts = []string{"2/1/2006 15:04:05", "02/01/2006 15:04:05", "2/1/2006 3:04:05 PM", "02/01/2006 03:04:05 PM", "2/1/2006 15:04", "02/01/2006 15:04"}
	case strings.Contains(l, "m/d/yyyy") || strings.Contains(l, "mm/dd/yyyy"):
		layouts = []string{"1/2/2006 3:04:05 PM", "01/02/2006 03:04:05 PM", "1/2/2006 15:04:05", "01/02/2006 15:04:05", "1/2/2006 3:04 PM", "1/2/2006 15:04"}
	}
	layouts = append(layouts, "2006-01-02 15:04:05.999999999", "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05", "2006-01-02T15:04:05", "2006-01-02 15:04")
	for _, lay := range layouts {
		if t, err := time.ParseInLocation(lay, v, loc); err == nil && t.Year() > 1970 {
			return t.UTC(), true
		}
	}
	if t, err := time.Parse(time.RFC3339Nano, v); err == nil {
		return t.UTC(), true
	}
	return time.Time{}, false
}

func atoi(s string) int {
	n := 0
	for _, c := range s {
		if c >= '0' && c <= '9' {
			n = n*10 + int(c-'0')
		}
	}
	return n
}

func (p *parser) parseAxiom(r io.Reader) error {
	head, rr := readHead(r, SniffBytes)
	det, _ := Sniff(head, p.art.LogicalPath)
	artifact := det.Artifact
	if artifact == "" {
		artifact = strings.TrimSuffix(path.Base(p.art.LogicalPath), path.Ext(p.art.LogicalPath))
	}
	fileApp := MatchApp(artifact)
	var cols axiomCols
	var header []string
	events := 0
	sh, rows, err := readTable(rr, func(sh tableShape) {
		header = sh.Header
		cols = axiomColumns(sh.Header)
	}, func(row []string, line int) error {
		cell := func(i int) string {
			if i >= 0 && i < len(row) {
				return strings.TrimSpace(row[i])
			}
			return ""
		}
		app := fileApp
		if a := MatchApp(cell(cols.artifact)); a != nil {
			app = a
		}
		var um *URLMatch
		if v := cell(cols.url); v != "" {
			if um = FindAIURL(v); um != nil {
				um.Field = header[cols.url]
			}
		}
		for i := 0; um == nil && i < len(row) && i < len(header); i++ {
			if strings.HasPrefix(strings.TrimSpace(row[i]), "http") {
				if um = FindAIURL(row[i]); um != nil {
					um.Field = header[i]
				}
			}
		}
		if app == nil && um == nil {
			return nil
		}
		events++
		ev := schema.Event{SourceLine: line}
		var who string
		if app != nil {
			ev.Vendor, who, ev.Result = app.Key, app.Name, "ai-app:"+clip(artifact, 80)
		} else {
			ev.Vendor, who, ev.Result = um.Key, um.Name+" URL", "ai-url:"+um.Kind
		}
		raw := cell(cols.when)
		t, _ := columnTime(cols.whenName, raw)
		p.setTime(&ev, cols.whenName, raw, t)
		parts := []string{"AXIOM " + artifact + " (" + who + ")"}
		if v := cell(cols.title); v != "" {
			parts = append(parts, "title="+clip(v, 160))
		}
		if um != nil {
			parts = append(parts, um.Field+"="+clip(um.URL, 200))
			if um.ID != "" {
				parts = append(parts, um.Kind+" id="+um.ID)
			}
		}
		for _, i := range cols.body {
			if v := cell(i); v != "" {
				parts = append(parts, header[i]+"="+clip(v, 200))
			}
		}
		if v := cell(cols.item); v != "" {
			parts = append(parts, "Item ID="+v)
		}
		if v := cell(cols.evidence); v != "" {
			parts = append(parts, "Evidence number="+clip(v, 80))
		}
		if v := cell(cols.location); v != "" {
			parts = append(parts, "Location="+clip(v, 120))
		}
		ev.Summary = strings.Join(parts, " · ")
		ev.SessionID = "axiom:" + ev.Vendor + ":" + clip(artifact, 80)
		p.record(ev)
		p.describe(ev.SessionID, who+" — AXIOM "+artifact, map[string]string{"service": ev.Vendor, "artifact": artifact})
		return nil
	})
	if err != nil {
		p.gap(0, 0, fmt.Sprintf("AXIOM CSV %q stopped at %v; %d row(s) were read before it, the rest is preserved unparsed in the sealed file", artifact, err, rows))
	}
	mapped := []string{}
	for _, c := range []struct {
		n string
		i int
	}{{"url", cols.url}, {"title", cols.title}, {"time", cols.when}, {"source", cols.source}, {"location", cols.location}, {"item_id", cols.item}, {"artifact", cols.artifact}, {"evidence_number", cols.evidence}} {
		if c.i >= 0 && c.i < len(header) {
			mapped = append(mapped, c.n+"←"+header[c.i])
		}
	}
	colList := header
	if len(colList) > 40 {
		colList = append(append([]string(nil), colList[:40]...), fmt.Sprintf("… %d more", len(header)-40))
	}
	timeNote := ""
	if cols.when >= 0 && !utcRe.MatchString(cols.whenName) {
		timeNote = fmt.Sprintf(" Times in %q state no zone and were not normalized.", cols.whenName)
	}
	p.meta(actionInventory, "axiom:inventory", fmt.Sprintf("AXIOM CSV export %q: %d row(s), %d column(s) (%s, delimiter %q); %d row(s) normalized (AI application or AI-service URL), %d preserved unparsed in the sealed file. Mapped: %s. Columns: %s.%s",
		artifact, rows, len(header), sh.Encoding, string(sh.Delim), events, rows-events, strings.Join(mapped, ", "), strings.Join(colList, " | "), timeNote))
	p.describe(p.session, "AXIOM "+artifact, map[string]string{"artifact": artifact, "rows": fmt.Sprint(rows), "columns": fmt.Sprint(len(header)), "normalized_rows": fmt.Sprint(events)})
	return nil
}

func (p *parser) parseCaseDB(store *casepkg.Store) error {
	if p.art.Status != casepkg.StatusOK {
		p.unsupported(CaseDBUnsupported + fmt.Sprintf(". This Case.mfdb was not sealed (%s: %s); no table inventory", p.art.Status, p.art.Error))
		return nil
	}
	inv, note := caseDBInventory(store, p.art)
	p.meta(actionInventory, "axiom:casedb", fmt.Sprintf("AXIOM Case.mfdb sealed losslessly (sha256 %s, %d bytes). %s", p.art.ArtifactID, p.art.Size, note))
	attrs := map[string]string{"sha256": p.art.ArtifactID, "size": fmt.Sprint(p.art.Size)}
	for i, t := range inv {
		if i >= 140 {
			break
		}
		attrs["table:"+t.name] = fmt.Sprint(t.rows)
	}
	p.describe(p.session, "AXIOM Case.mfdb", attrs)
	p.unsupported(CaseDBUnsupported)
	return nil
}

type tableCount struct {
	name string
	rows int64
}

// caseDBInventory lists the tables of a Case.mfdb and their row counts.
// Nothing in a row is read beyond counting it.
func caseDBInventory(store *casepkg.Store, art casepkg.ArtifactRecord) ([]tableCount, string) {
	if art.Size > MaxCaseDBBytes {
		return nil, fmt.Sprintf("Table inventory skipped: the database is larger than the %d-byte inventory bound.", MaxCaseDBBytes)
	}
	data, err := store.ReadAll(art.ArtifactID, MaxCaseDBBytes)
	if err != nil {
		return nil, "Table inventory skipped: " + err.Error() + "."
	}
	var out []tableCount
	var note string
	func() {
		defer func() {
			if r := recover(); r != nil {
				note = fmt.Sprintf("Table inventory stopped: %v.", r)
			}
		}()
		db, err := sqlitero.Open(data, nil)
		if err != nil {
			note = "Table inventory not possible: " + err.Error() + "."
			return
		}
		tables, err := db.Tables()
		if err != nil {
			note = "Table inventory not possible: " + err.Error() + "."
			return
		}
		var parts []string
		var total int64
		for i := range tables {
			if i >= maxCaseDBTables {
				parts = append(parts, fmt.Sprintf("… %d more tables", len(tables)-maxCaseDBTables))
				break
			}
			t := &tables[i]
			var n int64
			cerr := db.Each(t, func(int64, []any) error { n++; return nil })
			out = append(out, tableCount{t.Name, n})
			total += n
			s := fmt.Sprintf("%s(%d)", t.Name, n)
			if cerr != nil {
				s = fmt.Sprintf("%s(%d, count stopped: %v)", t.Name, n, cerr)
			}
			parts = append(parts, s)
		}
		note = fmt.Sprintf("SQLite table inventory: %d table(s), %d row(s): %s. Rows were counted, not read.", len(tables), total, strings.Join(parts, ", "))
	}()
	return out, note
}
