package report

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/version"
)

// PDF report. A deliberately small PDF 1.4 writer (standard library only,
// core Helvetica/Courier fonts, no embedding) so the report is one
// self-contained file with no renderer dependency. Text is sanitized then
// PDF-escaped; runes outside WinAnsi are replaced with '?' and counted so
// nothing disappears silently.

const (
	pdfPageW    = 595.28 // A4 portrait, points
	pdfPageH    = 841.89
	pdfMargin   = 48.0
	pdfLineGap  = 1.35
	pdfBodySize = 9.5
	pdfMonoSize = 8.0
	pdfH1Size   = 18.0
	pdfH2Size   = 12.5
)

// PDFOptions tunes the excerpt sizes.
type PDFOptions struct {
	MaxTimelineRows int // default 300
	MaxArtifactRows int // default 300
}

// CustodyRecord is one decoded chain-of-custody line.
type CustodyRecord struct {
	Seq   int
	TS    string
	Event string
	Extra string
}

// ReadCustody decodes chain-of-custody.jsonl for reporting.
func ReadCustody(pkgDir string) ([]CustodyRecord, error) {
	f, err := os.Open(filepath.Join(pkgDir, "chain-of-custody.jsonl"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []CustodyRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var m map[string]any
		if err := json.Unmarshal(sc.Bytes(), &m); err != nil {
			continue
		}
		rec := CustodyRecord{}
		if v, ok := m["seq"].(float64); ok {
			rec.Seq = int(v)
		}
		rec.TS, _ = m["ts_utc"].(string)
		rec.Event, _ = m["event"].(string)
		var extras []string
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch k {
			case "seq", "ts_utc", "event", "prev", "case_id":
				continue
			}
			extras = append(extras, fmt.Sprintf("%s=%v", k, m[k]))
		}
		rec.Extra = strings.Join(extras, "  ")
		out = append(out, rec)
	}
	return out, nil
}

// pdfDoc accumulates pages and objects.
type pdfDoc struct {
	pages    []*bytes.Buffer
	cur      *bytes.Buffer
	y        float64
	replaced int
}

func (d *pdfDoc) newPage() {
	d.cur = &bytes.Buffer{}
	d.pages = append(d.pages, d.cur)
	d.y = pdfPageH - pdfMargin
}

func (d *pdfDoc) ensure(h float64) {
	if d.cur == nil || d.y-h < pdfMargin {
		d.newPage()
	}
}

// encode maps a string to WinAnsi bytes with PDF string escaping.
func (d *pdfDoc) encode(s string) string {
	var b strings.Builder
	for _, r := range sanitize.Terminal(s) {
		var c byte
		switch {
		case r == '\\' || r == '(' || r == ')':
			b.WriteByte('\\')
			c = byte(r)
		case r >= 0x20 && r < 0x7f:
			c = byte(r)
		case r >= 0xa0 && r <= 0xff:
			c = byte(r)
		case r == '\t':
			c = ' '
		case r == '…':
			c = 0x85 // WinAnsi ellipsis
		case r == '—':
			c = 0x97
		case r == '–':
			c = 0x96
		case r == '‘' || r == '’':
			c = '\''
		case r == '“' || r == '”':
			c = '"'
		default:
			d.replaced++
			c = '?'
		}
		if c < 0x20 || c >= 0x7f {
			fmt.Fprintf(&b, "\\%03o", c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

// approximate glyph widths (fraction of font size) — enough for wrapping.
func charWidth(font string, r rune) float64 {
	if font == "F3" {
		return 0.6
	}
	switch {
	case r == ' ':
		return 0.28
	case strings.ContainsRune("iljtfI.,:;'|!", r):
		return 0.28
	case strings.ContainsRune("mwMW@", r):
		return 0.85
	case r >= 'A' && r <= 'Z':
		return 0.68
	default:
		return 0.53
	}
}

func textWidth(font string, size float64, s string) float64 {
	w := 0.0
	for _, r := range s {
		w += charWidth(font, r) * size
	}
	return w
}

// wrap splits s into lines that fit width (word-aware, hard-splits long tokens).
func wrap(font string, size float64, s string, width float64) []string {
	var lines []string
	for _, para := range strings.Split(s, "\n") {
		words := strings.Fields(para)
		if len(words) == 0 {
			lines = append(lines, "")
			continue
		}
		line := ""
		for _, w := range words {
			for textWidth(font, size, w) > width {
				// hard split an over-long token
				cut := len([]rune(w))
				for cut > 1 && textWidth(font, size, string([]rune(w)[:cut])) > width {
					cut--
				}
				if line != "" {
					lines = append(lines, line)
					line = ""
				}
				lines = append(lines, string([]rune(w)[:cut]))
				w = string([]rune(w)[cut:])
			}
			cand := w
			if line != "" {
				cand = line + " " + w
			}
			if textWidth(font, size, cand) > width && line != "" {
				lines = append(lines, line)
				line = w
			} else {
				line = cand
			}
		}
		lines = append(lines, line)
	}
	return lines
}

// text writes wrapped text at the current cursor in font F1 (Helvetica),
// F2 (Helvetica-Bold) or F3 (Courier), indented by x.
func (d *pdfDoc) text(font string, size float64, x float64, s string) {
	width := pdfPageW - 2*pdfMargin - x
	for _, line := range wrap(font, size, s, width) {
		d.ensure(size * pdfLineGap)
		d.y -= size * pdfLineGap
		fmt.Fprintf(d.cur, "BT /%s %.1f Tf %.2f %.2f Td (%s) Tj ET\n", font, size, pdfMargin+x, d.y, d.encode(line))
	}
}

func (d *pdfDoc) gap(h float64) {
	d.ensure(h)
	d.y -= h
}

func (d *pdfDoc) h1(s string) { d.gap(6); d.text("F2", pdfH1Size, 0, s); d.gap(4) }
func (d *pdfDoc) h2(s string) {
	d.gap(10)
	d.ensure(pdfH2Size*pdfLineGap + 30) // keep heading with some body
	d.text("F2", pdfH2Size, 0, s)
	d.rule()
	d.gap(3)
}
func (d *pdfDoc) rule() {
	d.ensure(4)
	fmt.Fprintf(d.cur, "0.6 w %.2f %.2f m %.2f %.2f l S\n", pdfMargin, d.y-2, pdfPageW-pdfMargin, d.y-2)
	d.y -= 4
}
func (d *pdfDoc) kv(k, v string) {
	if v == "" {
		v = "—"
	}
	d.text("F1", pdfBodySize, 0, k+": "+v)
}
func (d *pdfDoc) mono(s string) { d.text("F3", pdfMonoSize, 8, s) }

// render assembles the final PDF bytes with a correct xref table. Object
// numbers are assigned up front (1 catalog, 2 pages, 3-5 fonts, 6 info,
// then content/page pairs) so every reference is known before writing.
func (d *pdfDoc) render(title string) []byte {
	if len(d.pages) == 0 {
		d.newPage()
	}
	total := len(d.pages)
	objs := make([]string, 0, 6+2*total)
	var kids []string
	for i := range d.pages {
		kids = append(kids, fmt.Sprintf("%d 0 R", 8+2*i))
	}
	objs = append(objs,
		"<< /Type /Catalog /Pages 2 0 R >>",
		fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), total),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Courier /Encoding /WinAnsiEncoding >>",
		fmt.Sprintf("<< /Title (%s) /Producer (AgentDFIR %s) /Creator (AgentDFIR) /CreationDate (D:%sZ) >>",
			d.encode(title), version.Version, time.Now().UTC().Format("20060102150405")),
	)
	for i, pg := range d.pages {
		footer := fmt.Sprintf("BT /F1 7.5 Tf %.2f %.2f Td (%s) Tj ET\n", pdfMargin, pdfMargin-18,
			d.encode(fmt.Sprintf("%s — page %d of %d — generated by AgentDFIR %s", title, i+1, total, version.Version)))
		content := pg.String() + footer
		objs = append(objs,
			fmt.Sprintf("<< /Length %d >>\nstream\n%sendstream", len(content), content),
			fmt.Sprintf("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /Font << /F1 3 0 R /F2 4 0 R /F3 5 0 R >> >> /Contents %d 0 R >>",
				pdfPageW, pdfPageH, 7+2*i),
		)
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	offsets := make([]int, len(objs))
	for i, body := range objs {
		offsets[i] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(objs)+1)
	for _, off := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R /Info 6 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objs)+1, xref)
	return out.Bytes()
}

// WritePDF renders the case as a PDF report. Returns the number of
// non-WinAnsi runes replaced (reported to the operator, never hidden).
func WritePDF(c *Case, custody []CustodyRecord, signature string, path string, opts PDFOptions) (int, error) {
	if opts.MaxTimelineRows <= 0 {
		opts.MaxTimelineRows = 300
	}
	if opts.MaxArtifactRows <= 0 {
		opts.MaxArtifactRows = 300
	}
	d := &pdfDoc{}
	d.newPage()
	caseID := ""
	if c.Manifest != nil {
		caseID = c.Manifest.CaseID
	}
	title := "AgentDFIR Report — " + caseID

	d.h1("AgentDFIR Report")
	d.text("F1", pdfBodySize, 0, "Case "+caseID+"  ·  generated "+time.Now().UTC().Format(time.RFC3339)+"  ·  agentdfir "+version.Version)
	d.text("F1", 8.5, 0, "Findings state what the evidence shows. Corroboration states: REQUESTED / REPORTED / OBSERVED / PARTIALLY_CORROBORATED / CORROBORATED / CONTRADICTED / UNKNOWN. Model text is never treated as proof of execution.")

	// --- Case summary
	d.h2("1. Case summary")
	if c.Manifest != nil {
		d.kv("Host", c.Manifest.Host+" ("+c.Manifest.OS+"/"+c.Manifest.Arch+")")
		d.kv("Created (UTC)", c.Manifest.CreatedUTC)
		d.kv("Collector", c.Manifest.CollectorName+" "+c.Manifest.CollectorVersion)
		d.kv("Collector binary SHA-256", c.Manifest.CollectorBinary)
		d.kv("Package format", ".adfir "+c.Manifest.ADFIRVersion)
		d.kv("Artifacts in manifest", fmt.Sprint(len(c.Manifest.Artifacts)))
	}
	if ci := c.CaseInfo; ci != nil {
		d.kv("Operator (OS user)", ci.OperatorOSUser)
		d.kv("Operator (asserted)", ci.OperatorAsserted)
		d.kv("Authorization reference", ci.Authorization)
		d.kv("Local time / timezone", ci.LocalTime+" "+ci.Timezone)
		keys := make([]string, 0, len(ci.Notes))
		for k := range ci.Notes {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			d.kv("Note "+k, ci.Notes[k])
		}
		if len(ci.CollectionArgs) > 0 {
			d.kv("Collection arguments", strings.Join(ci.CollectionArgs, " "))
		}
	}

	// --- Integrity
	d.h2("2. Package integrity")
	if v := c.Verify; v != nil {
		d.kv("Files checked", fmt.Sprint(v.FilesChecked))
		d.kv("Artifacts OK / not acquired", fmt.Sprintf("%d / %d", v.ArtifactsOK, v.ArtifactsFailed))
		d.kv("Collection log records (hash chain)", fmt.Sprint(v.CollectionRecs))
		d.kv("Custody log records (hash chain)", fmt.Sprint(v.CustodyRecs))
		if len(v.Problems) == 0 {
			d.kv("Verification", "VERIFIED — no modifications detected")
		} else {
			d.kv("Verification", fmt.Sprintf("FAILED — %d problem(s)", len(v.Problems)))
			for _, p := range v.Problems {
				d.mono("- " + p)
			}
		}
	} else {
		d.kv("Verification", "not run")
	}
	d.kv("Seal signature", signature)

	// --- Findings
	d.h2("3. Findings")
	counts := map[string]int{}
	for _, f := range c.Findings {
		counts[f.Severity]++
	}
	d.kv("Total", fmt.Sprintf("%d  (CRITICAL %d · HIGH %d · MEDIUM %d · LOW %d · INFO %d)", len(c.Findings),
		counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"], counts["LOW"], counts["INFO"]))
	sorted := append([]schema.Finding(nil), c.Findings...)
	sort.SliceStable(sorted, func(i, j int) bool { return sevRank(sorted[i].Severity) > sevRank(sorted[j].Severity) })
	for i, f := range sorted {
		d.gap(5)
		d.ensure(60)
		d.text("F2", pdfBodySize, 0, fmt.Sprintf("%d. [%s] %s — %s", i+1, f.Severity, f.RuleID, f.Title))
		d.text("F1", pdfBodySize, 8, f.Description)
		meta := "Status: " + f.Status + "  ·  Endpoint corroboration: " + f.Endpoint
		if f.SessionID != "" {
			meta += "  ·  Session: " + f.SessionID
		}
		if f.AgentID != "" {
			meta += "  ·  Agent: " + f.AgentID
		}
		if f.ParentAgentID != "" {
			meta += "  ·  Parent: " + f.ParentAgentID
		}
		d.text("F1", 8.5, 8, meta)
		mitre := ""
		if f.MitreATTACK != "" {
			mitre += "ATT&CK " + f.MitreATTACK + "  "
		}
		if f.MitreATLAS != "" {
			mitre += "ATLAS " + f.MitreATLAS
		}
		if mitre != "" {
			d.text("F1", 8.5, 8, "MITRE: "+mitre)
		}
		for _, r := range f.Related {
			d.text("F1", 8.5, 8, "Related: "+r)
		}
		for _, e := range f.EvidenceRefs {
			d.mono("Evidence: " + e)
		}
		if f.FalsePositive != "" {
			d.text("F1", 8.5, 8, "False-positive notes: "+f.FalsePositive)
		}
	}
	if len(sorted) == 0 {
		d.text("F1", pdfBodySize, 8, "No findings.")
	}

	// --- Timeline excerpt
	d.h2("4. Timeline (excerpt)")
	events := append([]schema.Event(nil), c.Events...)
	sort.SliceStable(events, func(i, j int) bool { return events[i].Timestamp < events[j].Timestamp })
	shown := events
	if len(shown) > opts.MaxTimelineRows {
		shown = shown[:opts.MaxTimelineRows]
	}
	d.text("F1", 8.5, 0, fmt.Sprintf("%d of %d events shown, oldest first. Full timeline: normalized/events.jsonl, reports/timeline.csv.", len(shown), len(events)))
	for _, e := range shown {
		what := e.EventType
		switch {
		case e.Command != "":
			what += " " + e.Tool + ": " + e.Command
		case e.File != "":
			what += " " + e.Tool + ": " + e.File
		case e.Tool != "":
			what += " " + e.Tool
		}
		if e.Summary != "" {
			what += " — " + e.Summary
		}
		line := fmt.Sprintf("%-24s %-7s %-11s %s", e.Timestamp, shortState(e.Corroboration), shortID(e.AgentID), what)
		if r := []rune(line); len(r) > 220 {
			line = string(r[:220]) + "…"
		}
		d.mono(line)
	}

	// --- Artifacts
	d.h2("5. Artifact inventory")
	if c.Manifest != nil {
		arts := c.Manifest.Artifacts
		d.text("F1", 8.5, 0, fmt.Sprintf("%d artifacts; showing up to %d. Full inventory: manifest.json, SHA256SUMS.", len(arts), opts.MaxArtifactRows))
		for i, a := range arts {
			if i >= opts.MaxArtifactRows {
				break
			}
			status := a.Status
			if a.Error != "" {
				status += " (" + a.Error + ")"
			}
			d.mono(fmt.Sprintf("%-12s %9d  %s  %s  [%s]", shortID(a.ArtifactID), a.Size, a.ArtifactType, a.LogicalPath, status))
		}
	}

	// --- Custody
	d.h2("6. Chain of custody")
	if len(custody) == 0 {
		d.text("F1", pdfBodySize, 8, "chain-of-custody.jsonl not available.")
	}
	for _, r := range custody {
		d.mono(fmt.Sprintf("#%-3d %-30s %-22s %s", r.Seq, r.TS, r.Event, r.Extra))
	}
	d.gap(6)
	d.text("F1", 8.5, 0, "Both logs are hash-chained (each record carries the SHA-256 of the previous one) and covered by SHA256SUMS; `agentdfir verify` re-checks them independently of this report.")

	if d.replaced > 0 {
		d.gap(8)
		d.text("F1", 8, 0, fmt.Sprintf("Rendering note: %d character(s) outside the PDF core-font character set were shown as '?'. The sealed evidence is unaffected.", d.replaced))
	}

	data := d.render(title)
	return d.replaced, os.WriteFile(path, data, 0o600)
}

func sevRank(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	}
	return 0
}

func shortState(s string) string {
	switch s {
	case schema.StateCorroborated:
		return "CORROB"
	case schema.StatePartial:
		return "PARTIAL"
	case schema.StateContradicted:
		return "CONTRA"
	case schema.StateObserved:
		return "OBSERV"
	case schema.StateReported:
		return "REPORT"
	case schema.StateRequested:
		return "REQUES"
	default:
		return "UNKNOWN"
	}
}

func shortID(s string) string {
	if r := []rune(s); len(r) > 11 {
		return string(r[:11])
	}
	return s
}
