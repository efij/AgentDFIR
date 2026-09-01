// Package report renders a case into analyst-facing outputs. HTML
// reports are network-silent by construction (plan §24): no external
// resource loads, a restrictive CSP meta tag, and every evidence-derived
// string HTML-escaped and control/invisible-char sanitized before it
// reaches the document.
package report

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"html"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/schema"
)

// Case bundles everything a report renders.
type Case struct {
	Manifest *casepkg.Manifest
	CaseInfo *casepkg.CaseInfo
	Verify   *casepkg.VerifyResult
	Events   []schema.Event
	Entities []schema.Entity
	Findings []schema.Finding
}

// safe escapes a string for HTML after neutralizing terminal/invisible
// payloads (defense in depth: sanitize then escape).
func safe(s string) string { return html.EscapeString(sanitize.Terminal(s)) }

// WriteJSON writes the full case as one JSON document.
func WriteJSON(c *Case, path string) error {
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// WriteFindingsCSV writes findings as CSV.
func WriteFindingsCSV(c *Case, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"rule_id", "severity", "title", "session", "agent", "parent", "status", "endpoint", "evidence", "mitre_atlas", "mitre_attack"})
	for _, fd := range c.Findings {
		ev := ""
		if len(fd.EvidenceRefs) > 0 {
			ev = fd.EvidenceRefs[0]
		}
		_ = w.Write([]string{fd.RuleID, fd.Severity, fd.Title, fd.SessionID, fd.AgentID,
			fd.ParentAgentID, fd.Status, fd.Endpoint, ev, fd.MitreATLAS, fd.MitreATTACK})
	}
	return nil
}

// WriteTimelineCSV writes the timeline as CSV.
func WriteTimelineCSV(c *Case, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := csv.NewWriter(f)
	defer w.Flush()
	_ = w.Write([]string{"timestamp", "corroboration", "actor", "event_type", "tool", "command", "summary", "evidence_path", "evidence_line", "artifact"})
	for _, e := range sortedEvents(c.Events) {
		_ = w.Write([]string{e.Timestamp, e.Corroboration, e.ActorType, e.EventType, e.Tool,
			e.Command, e.Summary, e.SourcePath, fmt.Sprint(e.SourceLine), e.SourceArtifact})
	}
	return nil
}

func sortedEvents(in []schema.Event) []schema.Event {
	out := make([]schema.Event, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Timestamp != out[j].Timestamp {
			return out[i].Timestamp < out[j].Timestamp
		}
		return out[i].Sequence < out[j].Sequence
	})
	return out
}

var sevClass = map[string]string{
	"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "info",
}

// MaxHTMLRows caps timeline/inventory rows in HTML (full data lives in
// normalized/events.jsonl and reports/timeline.csv).
var MaxHTMLRows = 2000

// WriteHTML renders a self-contained, network-silent HTML report.
func WriteHTML(c *Case, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	w := func(s string) { _, _ = f.WriteString(s) }

	integrity := "VERIFIED — no modifications detected"
	intClass := "ok"
	if c.Verify != nil && len(c.Verify.Problems) > 0 {
		integrity = fmt.Sprintf("FAILED — %d problem(s)", len(c.Verify.Problems))
		intClass = "bad"
	}

	w(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`)
	w(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">`)
	w(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	w(`<title>AgentDFIR Report — ` + safe(c.Manifest.CaseID) + `</title>`)
	w(`<style>` + reportCSS + `</style></head><body>`)

	w(`<header><h1>AgentDFIR Incident Report</h1><p class="sub">Case ` + safe(c.Manifest.CaseID) + `</p></header><main>`)

	// Executive summary
	sev := map[string]int{}
	for _, fd := range c.Findings {
		sev[fd.Severity]++
	}
	w(`<section><h2>Executive Summary</h2><div class="cards">`)
	w(card("Findings", fmt.Sprint(len(c.Findings))))
	w(card("HIGH+", fmt.Sprint(sev["CRITICAL"]+sev["HIGH"])))
	w(card("Timeline events", fmt.Sprint(len(c.Events))))
	w(card("Integrity", integrity, intClass))
	w(`</div></section>`)

	// Case / collection / environment
	w(`<section><h2>Case &amp; Collection</h2><table class="kv">`)
	w(kv("Case ID", c.Manifest.CaseID))
	if c.CaseInfo != nil {
		w(kv("Operator (OS user)", c.CaseInfo.OperatorOSUser))
		w(kv("Operator (asserted)", c.CaseInfo.OperatorAsserted))
		w(kv("Authorization", c.CaseInfo.Authorization))
		w(kv("Timezone", fmt.Sprintf("%s (UTC%+d s)", c.CaseInfo.Timezone, c.CaseInfo.UTCOffsetSeconds)))
	}
	w(kv("Host", c.Manifest.Host))
	w(kv("OS / Arch", c.Manifest.OS+" / "+c.Manifest.Arch))
	w(kv("Collector", c.Manifest.CollectorName+" "+c.Manifest.CollectorVersion))
	w(kv("Collector binary SHA-256", c.Manifest.CollectorBinary))
	w(kv("Created (UTC)", c.Manifest.CreatedUTC))
	w(`</table></section>`)

	// Findings
	w(`<section><h2>Suspicious Behaviour &amp; Findings</h2>`)
	if len(c.Findings) == 0 {
		w(`<p class="muted">No findings.</p>`)
	}
	for _, fd := range c.Findings {
		cls := sevClass[fd.Severity]
		w(`<div class="finding ` + cls + `"><div class="fhead"><span class="badge ` + cls + `">` + safe(fd.Severity) + `</span> <strong>` + safe(fd.Title) + `</strong> <span class="rule">` + safe(fd.RuleID) + `</span></div>`)
		w(`<p>` + safe(fd.Description) + `</p><table class="kv">`)
		if fd.SessionID != "" {
			w(kv("Session", fd.SessionID))
		}
		if fd.AgentID != "" {
			w(kv("Agent", fd.AgentID))
			w(kv("Parent", fd.ParentAgentID))
		}
		w(kv("Status", fd.Status))
		w(kv("Endpoint corroboration", fd.Endpoint))
		atlas := fd.MitreATLAS
		if atlas == "" {
			atlas = "not mapped"
		}
		w(kv("MITRE ATLAS", atlas))
		if fd.MitreATTACK != "" {
			w(kv("MITRE ATT&CK", fd.MitreATTACK))
		}
		for _, r := range fd.Related {
			w(kv("Related", r))
		}
		for _, e := range fd.EvidenceRefs {
			w(kv("Evidence", e))
		}
		w(`</table></div>`)
	}
	w(`</section>`)

	// Timeline
	w(`<section><h2>Incident Timeline</h2><table class="tl"><thead><tr><th>Time</th><th>State</th><th>Actor</th><th>Event</th><th>Detail</th><th>Evidence</th></tr></thead><tbody>`)
	tlEvents := sortedEvents(c.Events)
	tlShown := tlEvents
	if len(tlShown) > MaxHTMLRows {
		tlShown = tlShown[:MaxHTMLRows]
	}
	for _, e := range tlShown {
		detail := e.Summary
		if e.Command != "" {
			detail = "$ " + e.Command
		}
		label := e.EventType
		if e.Tool != "" {
			label += ":" + e.Tool
		}
		w(`<tr><td class="mono">` + safe(e.Timestamp) + `</td><td><span class="st st-` + e.Corroboration + `">` + safe(e.Corroboration) + `</span></td><td>` + safe(e.ActorType) + `</td><td class="mono">` + safe(label) + `</td><td>` + safe(detail) + `</td><td class="mono ev">` + safe(fmt.Sprintf("%s:%d", e.SourcePath, e.SourceLine)) + `</td></tr>`)
	}
	w(`</tbody></table>`)
	if len(tlEvents) > MaxHTMLRows {
		w(fmt.Sprintf(`<p class="muted">Showing first %d of %d events. Full timeline: normalized/events.jsonl and reports/timeline.csv.</p>`, MaxHTMLRows, len(tlEvents)))
	}
	w(`</section>`)

	// Evidence inventory
	w(`<section><h2>Evidence Inventory</h2><table class="tl"><thead><tr><th>Logical path</th><th>Type</th><th>Status</th><th>Size</th><th>SHA-256</th></tr></thead><tbody>`)
	for _, a := range c.Manifest.Artifacts {
		w(`<tr><td class="mono">` + safe(a.LogicalPath) + `</td><td>` + safe(a.ArtifactType) + `</td><td>` + safe(a.Status) + `</td><td>` + fmt.Sprint(a.Size) + `</td><td class="mono ev">` + safe(a.ArtifactID) + `</td></tr>`)
	}
	w(`</tbody></table></section>`)

	if c.Verify != nil && len(c.Verify.Problems) > 0 {
		w(`<section><h2 class="bad">Integrity Problems</h2><ul>`)
		for _, p := range c.Verify.Problems {
			w(`<li class="mono">` + safe(p) + `</li>`)
		}
		w(`</ul></section>`)
	}

	w(`<footer>Generated by AgentDFIR at ` + safe(time.Now().UTC().Format(time.RFC3339)) +
		` · This report is self-contained and loads no external resources. AI-generated narrative (REPORTED) is not evidence of execution.</footer>`)
	w(`</main></body></html>`)
	return nil
}

func card(label, value string, class ...string) string {
	c := ""
	if len(class) > 0 {
		c = " " + class[0]
	}
	return `<div class="metric` + c + `"><div class="mv">` + safe(value) + `</div><div class="ml">` + safe(label) + `</div></div>`
}

func kv(k, v string) string {
	if v == "" {
		v = "—"
	}
	return `<tr><th>` + safe(k) + `</th><td>` + safe(v) + `</td></tr>`
}

// ReadCaseInfo loads case.json from a package.
func ReadCaseInfo(pkgDir string) (*casepkg.CaseInfo, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "case.json"))
	if err != nil {
		return nil, err
	}
	var ci casepkg.CaseInfo
	if err := json.Unmarshal(data, &ci); err != nil {
		return nil, err
	}
	return &ci, nil
}

// ReadManifest loads manifest.json from a package.
func ReadManifest(pkgDir string) (*casepkg.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var man casepkg.Manifest
	if err := json.Unmarshal(data, &man); err != nil {
		return nil, err
	}
	return &man, nil
}

const reportCSS = `
:root{--bg:#0b1120;--surface:#151f35;--border:#2b3a55;--text:#f1f5f9;--muted:#94a3b8;--accent:#22c55e;--red:#ef4444;--amber:#f59e0b}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:system-ui,-apple-system,Segoe UI,sans-serif;line-height:1.55}
header{padding:32px 24px;border-bottom:1px solid var(--border);background:var(--surface)}
h1{margin:0;font-size:24px}.sub{color:var(--muted);margin:6px 0 0;font-family:ui-monospace,monospace}
main{max-width:1100px;margin:0 auto;padding:24px}
section{margin:32px 0}h2{font-size:19px;border-bottom:1px solid var(--border);padding-bottom:8px}
.cards{display:grid;grid-template-columns:repeat(4,1fr);gap:14px}
.metric{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:16px}
.metric .mv{font-size:22px;font-weight:700}.metric .ml{color:var(--muted);font-size:13px;margin-top:4px}
.metric.ok .mv{color:var(--accent)}.metric.bad .mv{color:var(--red)}
table{width:100%;border-collapse:collapse;font-size:14px}
.kv th{text-align:left;color:var(--muted);font-weight:500;width:230px;vertical-align:top;padding:5px 10px 5px 0}
.kv td{padding:5px 0}
.tl th{text-align:left;background:var(--surface);padding:8px 10px;font-size:12px;text-transform:uppercase;color:var(--muted);letter-spacing:.04em}
.tl td{padding:8px 10px;border-bottom:1px solid var(--border);vertical-align:top}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px}
.ev{color:var(--muted)}.muted{color:var(--muted)}
.finding{background:var(--surface);border:1px solid var(--border);border-left-width:4px;border-radius:8px;padding:16px;margin:14px 0}
.finding.crit,.finding.high{border-left-color:var(--red)}.finding.med{border-left-color:var(--amber)}.finding.low,.finding.info{border-left-color:var(--muted)}
.fhead{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.rule{color:var(--muted);font-family:ui-monospace,monospace;font-size:12px}
.badge{padding:2px 9px;border-radius:999px;font-size:12px;font-weight:700}
.badge.crit,.badge.high{background:rgba(239,68,68,.2);color:#fca5a5}.badge.med{background:rgba(245,158,11,.2);color:#fcd34d}.badge.low,.badge.info{background:rgba(148,163,184,.2);color:var(--muted)}
.st{font-family:ui-monospace,monospace;font-size:11.5px;font-weight:600}
.st-OBSERVED{color:#a3e635}.st-REPORTED{color:var(--amber)}.st-CORROBORATED{color:var(--accent)}.st-CONTRADICTED{color:var(--red)}.st-UNKNOWN,.st-REQUESTED{color:var(--muted)}
.bad{color:var(--red)}
footer{margin-top:40px;padding-top:16px;border-top:1px solid var(--border);color:var(--muted);font-size:13px}
@media(max-width:700px){.cards{grid-template-columns:repeat(2,1fr)}.kv th{width:auto}}
`
