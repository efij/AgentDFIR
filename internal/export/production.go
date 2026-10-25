package export

// Production sets: the derivative exports a legal or eDiscovery reviewer
// receives (RSMF per session, the HTML and PDF report, the CSV timeline and
// findings), plus a production manifest that lists every produced file
// with its SHA-256, the source artifacts and lines each item derives from,
// who produced it with which binary, the case's processing history, the
// seal it was produced from, what was redacted (category, location, count
// — never values), and an explicit list of missing records and
// limitations.
//
// A production is reproducible: the same package and options give the same
// bytes, except for produced_at, which is fixed with --produced-at or
// SOURCE_DATE_EPOCH. Files whose bytes follow produced_at are named in the
// manifest.
//
// Nothing here writes to the package. Redaction is applied to an in-memory
// copy of the derived case; the sealed evidence is only read.

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/custody"
	"github.com/efij/AgentDFIR/v4/internal/overlay"
	"github.com/efij/AgentDFIR/v4/internal/redact"
	"github.com/efij/AgentDFIR/v4/internal/report"
	"github.com/efij/AgentDFIR/v4/internal/schema"
	"github.com/efij/AgentDFIR/v4/internal/seal"
	"github.com/efij/AgentDFIR/v4/internal/version"
)

// ProductionSchema versions the manifest layout.
const ProductionSchema = "agentdfir.production/1"

// Production file names, relative to the output directory.
const (
	ProductionManifestJSON = "production-manifest.json"
	ProductionManifestCSV  = "production-manifest.csv"
	traceabilityCSV        = "traceability.csv"
)

// maxLimitationRefs caps how many individual records one limitation lists;
// the count is always complete.
const maxLimitationRefs = 1000

// ProductionOptions configures one production run.
type ProductionOptions struct {
	Out              string
	Sessions         []string
	Redactor         *redact.Redactor
	Examiner         string
	ProducedAt       time.Time
	ProducedAtSource string // "--produced-at", "SOURCE_DATE_EPOCH" or "clock"
	// BinarySHA256 is the running binary's hash (computed by the caller so
	// tests can pin it).
	BinarySHA256 string
}

// ProductionManifest is production-manifest.json.
type ProductionManifest struct {
	Schema          string           `json:"schema"`
	ProducedAt      string           `json:"produced_at"`
	Reproducibility Reproducibility  `json:"reproducibility"`
	Case            ProductionCase   `json:"case"`
	Examiner        Examiner         `json:"examiner"`
	Tool            ToolIdentity     `json:"tool"`
	Options         ProductionOpts   `json:"options"`
	Files           []ProducedFile   `json:"files"`
	Traceability    TraceSummary     `json:"traceability"`
	History         []HistoryEntry   `json:"processing_history"`
	Redaction       RedactionSummary `json:"redaction"`
	Limitations     []Limitation     `json:"missing_records_and_limitations"`
	Statement       string           `json:"statement"`
}

// Reproducibility states what may differ between two runs.
type Reproducibility struct {
	VariesWith       []string `json:"varies_with"`
	ProducedAtSource string   `json:"produced_at_source"`
	FilesFollowing   []string `json:"files_whose_bytes_follow_produced_at"`
	Note             string   `json:"note"`
}

// ProductionCase identifies the sealed case the production came from.
type ProductionCase struct {
	CaseID         string   `json:"case_id"`
	PackageName    string   `json:"package_name"`
	ADFIRVersion   string   `json:"adfir_version,omitempty"`
	CreatedUTC     string   `json:"created_utc,omitempty"`
	SealDigest     string   `json:"seal_digest"`
	SealDigestNote string   `json:"seal_digest_note"`
	Integrity      string   `json:"integrity"`
	Problems       []string `json:"integrity_problems,omitempty"`
	Signature      string   `json:"signature"`
	Operator       string   `json:"collection_operator,omitempty"`
	Authorization  string   `json:"authorization_reference,omitempty"`
}

// Examiner is who made the production.
type Examiner struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

// ToolIdentity is the producing binary.
type ToolIdentity struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	BinarySHA256 string `json:"binary_sha256"`
}

// ProductionOpts echoes the options that shape the output.
type ProductionOpts struct {
	Sessions []string    `json:"sessions,omitempty"`
	Redact   redact.Spec `json:"redact"`
}

// ProducedFile is one file of the production.
type ProducedFile struct {
	Path        string       `json:"path"`
	SHA256      string       `json:"sha256"`
	Size        int64        `json:"size"`
	Kind        string       `json:"kind"`
	MediaType   string       `json:"media_type"`
	Items       int          `json:"items"`
	DerivedFrom []SourceSpan `json:"derived_from"`
	Note        string       `json:"note,omitempty"`
}

// SourceSpan summarizes the lines of one source artifact a file derives
// from; traceability.csv has the item-level rows.
type SourceSpan struct {
	ArtifactID  string `json:"artifact_id"`
	LogicalPath string `json:"logical_path,omitempty"`
	LineFirst   int    `json:"line_first"`
	LineLast    int    `json:"line_last"`
	Items       int    `json:"items"`
}

// TraceSummary describes traceability.csv.
type TraceSummary struct {
	File           string `json:"file"`
	Rows           int    `json:"rows"`
	EventsInScope  int    `json:"events_in_scope"`
	EventsProduced int    `json:"events_in_rsmf"`
	EventsOmitted  int    `json:"events_not_in_rsmf"`
	WithoutSource  int    `json:"rows_without_source_ref"`
}

// HistoryEntry is one processing step.
type HistoryEntry struct {
	Source string `json:"source"`
	Seq    int    `json:"seq,omitempty"`
	TS     string `json:"ts_utc,omitempty"`
	Event  string `json:"event"`
	Actor  string `json:"actor,omitempty"`
	Detail string `json:"detail,omitempty"`
}

// RedactionSummary is the redaction log of the production.
type RedactionSummary struct {
	Applied      bool           `json:"applied"`
	Scope        string         `json:"scope"`
	Spec         redact.Spec    `json:"spec"`
	Totals       map[string]int `json:"totals"`
	Log          []redact.Entry `json:"log"`
	MarkerForm   string         `json:"marker_form,omitempty"`
	ExaminerNote string         `json:"examiner_note"`
}

// Limitation is a missing record or a known limit of the production.
type Limitation struct {
	Code   string   `json:"code"`
	Detail string   `json:"detail"`
	Count  int      `json:"count"`
	Refs   []string `json:"refs,omitempty"`
}

// ProductionResult is what Produce returns.
type ProductionResult struct {
	Dir            string
	Manifest       *ProductionManifest
	ManifestSHA256 string
}

// Produce writes a production set for the case into opts.Out. c must be
// the analyzed case as `report` renders it; pkg is read for custody,
// collection and seal state only.
func Produce(pkg string, c *report.Case, opts ProductionOptions) (*ProductionResult, error) {
	if c == nil || c.Manifest == nil {
		return nil, errors.New("production: no case loaded")
	}
	if err := checkOut(pkg, opts.Out); err != nil {
		return nil, err
	}
	if opts.ProducedAt.IsZero() {
		opts.ProducedAt = time.Now().UTC().Truncate(time.Second)
		opts.ProducedAtSource = "clock"
	}
	producedAt := opts.ProducedAt.UTC().Format(time.RFC3339)

	scoped := scopeCase(c, opts.Sessions)
	scoped.GeneratedAt = opts.ProducedAt.UTC()
	r := opts.Redactor
	rc, err := report.RedactCase(scoped, r)
	if err != nil {
		return nil, err
	}
	custodyRecs, _ := report.ReadCustody(pkg)
	custodyRecs = report.RedactCustody(custodyRecs, r)

	out := opts.Out
	if err := os.MkdirAll(out, 0o700); err != nil {
		return nil, err
	}
	man := &ProductionManifest{
		Schema:     ProductionSchema,
		ProducedAt: producedAt,
		Tool:       ToolIdentity{Name: "agentdfir", Version: version.Version, BinarySHA256: opts.BinarySHA256},
		Options:    ProductionOpts{Sessions: sortedCopy(opts.Sessions), Redact: r.Spec()},
		Statement: "Derivative production generated from a sealed AgentDFIR case. The sealed evidence was read, not modified; " +
			"redaction (if any) applies to these derivative files only. RSMF output is validated against the RSMF 2.0 " +
			"manifest structure only, not against a review platform. This manifest makes no claim of admissibility.",
	}
	man.Case = caseIdentity(pkg, c)
	man.Examiner = examiner(opts.Examiner, c)
	if man.Options.Redact.Categories == nil {
		man.Options.Redact.Categories = []string{}
	}

	var trace [][]string
	addTrace := func(file, id, typ, art, path string, line int, off int64, state string) {
		trace = append(trace, []string{file, id, typ, art, path, strconv.Itoa(line), strconv.FormatInt(off, 10), state})
	}
	var files []ProducedFile
	record := func(rel, kind, media string, items int, spans []SourceSpan, note string) error {
		sum, size, err := hashFile(filepath.Join(out, filepath.FromSlash(rel)))
		if err != nil {
			return err
		}
		if spans == nil {
			spans = []SourceSpan{}
		}
		files = append(files, ProducedFile{Path: rel, SHA256: sum, Size: size, Kind: kind, MediaType: media,
			Items: items, DerivedFrom: spans, Note: note})
		return nil
	}

	// 1. RSMF, one file per session.
	rsmfFiles, omitted, err := report.WriteRSMF(rc, filepath.Join(out, "rsmf"), report.RSMFOptions{})
	if err != nil {
		return nil, err
	}
	stateOf := map[string]string{}
	for _, e := range rc.Events {
		stateOf[e.EventID] = schema.Label(e.Corroboration)
	}
	produced := 0
	for _, f := range rsmfFiles {
		rel := "rsmf/" + f.Name
		sp := spanBuilder{}
		for _, t := range f.Trace {
			sp.add(t.ArtifactID, t.LogicalPath, t.Line)
			addTrace(rel, t.EventID, "rsmf_event", t.ArtifactID, t.LogicalPath, t.Line, t.Offset, stateOf[t.EventID])
		}
		produced += len(f.Trace)
		if err := record(rel, "rsmf", "message/rfc822", len(f.Trace), sp.spans(), "RSMF "+report.RSMFVersion+" conversation "+f.Conversation); err != nil {
			return nil, err
		}
	}

	// 2. Reports and timeline, all from the same (redacted) case.
	all := spanBuilder{}
	for _, e := range rc.Events {
		all.add(e.SourceArtifact, e.SourcePath, e.SourceLine)
	}
	if err := os.MkdirAll(filepath.Join(out, "report"), 0o700); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(out, "timeline"), 0o700); err != nil {
		return nil, err
	}
	if err := report.WriteHTML(rc, filepath.Join(out, "report", "report.html")); err != nil {
		return nil, err
	}
	if err := record("report/report.html", "report_html", "text/html", len(rc.Events), all.spans(),
		fmt.Sprintf("renders at most %d timeline rows; the full timeline is timeline/timeline.csv", report.MaxHTMLRows)); err != nil {
		return nil, err
	}
	if _, err := report.WritePDF(rc, custodyRecs, signatureState(pkg), filepath.Join(out, "report", "report.pdf"), report.PDFOptions{}); err != nil {
		return nil, err
	}
	if err := record("report/report.pdf", "report_pdf", "application/pdf", len(rc.Events), all.spans(),
		"an excerpt (row caps apply; characters outside the PDF core fonts print as '?'); the full timeline is timeline/timeline.csv"); err != nil {
		return nil, err
	}
	if err := report.WriteTimelineCSV(rc, filepath.Join(out, "timeline", "timeline.csv")); err != nil {
		return nil, err
	}
	for _, e := range rc.Events {
		addTrace("timeline/timeline.csv", e.EventID, "timeline_row", e.SourceArtifact, e.SourcePath, e.SourceLine, e.SourceOffset, schema.Label(e.Corroboration))
	}
	if err := record("timeline/timeline.csv", "timeline_csv", "text/csv", len(rc.Events), all.spans(), ""); err != nil {
		return nil, err
	}
	if err := report.WriteFindingsCSV(rc, filepath.Join(out, "timeline", "findings.csv")); err != nil {
		return nil, err
	}
	fsp := spanBuilder{}
	without := 0
	byLine := eventsByLine(rc.Events)
	for i, f := range rc.Findings {
		id := fmt.Sprintf("%s#%d", f.RuleID, i)
		if len(f.EvidenceRefs) == 0 {
			addTrace("timeline/findings.csv", id, "finding", "", "", 0, 0, schema.Label(f.Status))
			without++
		}
		for _, ref := range f.EvidenceRefs {
			pr := parseRef(ref)
			art, off := "", pr.offset
			if e, ok := byLine[pr.path+":"+strconv.Itoa(pr.line)]; ok && pr.line > 0 {
				art, off = e.SourceArtifact, e.SourceOffset
			} else if pr.artPrefix != "" {
				art = artByPrefix(rc, pr.path, pr.artPrefix)
			}
			fsp.add(art, pr.path, pr.line)
			addTrace("timeline/findings.csv", id, "finding", art, pr.path, pr.line, off, schema.Label(f.Status))
			if art == "" || (pr.line == 0 && !pr.byteRef) {
				without++
			}
		}
	}
	if err := record("timeline/findings.csv", "findings_csv", "text/csv", len(rc.Findings), fsp.spans(), ""); err != nil {
		return nil, err
	}

	// 3. traceability.csv — one row per produced item. Event rows always
	// carry artifact and line; a finding citing an artifact by byte offset
	// has line 0 and the offset in source_offset.
	for _, row := range trace {
		if row[2] != "finding" && (row[3] == "" || row[5] == "0") {
			without++
		}
	}
	if err := writeCSV(filepath.Join(out, traceabilityCSV),
		[]string{"produced_file", "item_id", "item_type", "source_artifact_id", "source_logical_path", "source_line", "source_offset", "evidence_state"}, trace); err != nil {
		return nil, err
	}
	if err := record(traceabilityCSV, "traceability_csv", "text/csv", len(trace), nil, "item-level source-to-export mapping for every file above"); err != nil {
		return nil, err
	}
	man.Traceability = TraceSummary{File: traceabilityCSV, Rows: len(trace), EventsInScope: len(rc.Events),
		EventsProduced: produced, EventsOmitted: len(omitted), WithoutSource: without}

	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	man.Files = files

	// 4. History, limitations, redaction log.
	man.History = history(pkg, c, man.Examiner.Name, producedAt, r)
	r.Walk(&man.Case, "production-manifest case")
	man.Limitations = limitations(c, rc, omitted, opts.Sessions, without)
	// Limitations quote evidence-derived text (verify problems, session
	// ids, artifact paths and errors); mask it like every other derivative.
	for i := range man.Limitations {
		r.Walk(&man.Limitations[i], fmt.Sprintf("production-manifest missing_records_and_limitations[%d]", i))
	}
	man.Redaction = RedactionSummary{Applied: r != nil, Spec: r.Spec(), Totals: r.Totals(), Log: r.Log(),
		Scope:        "derivative files in this production only; the sealed evidence and the package are not modified",
		ExaminerNote: "examiner identity is never redacted: the examiner is the producing party, and masking them would break accountability"}
	if man.Redaction.Spec.Categories == nil {
		man.Redaction.Spec.Categories = []string{}
	}
	if man.Redaction.Log == nil {
		man.Redaction.Log = []redact.Entry{}
	}
	if r != nil {
		man.Redaction.MarkerForm = "[REDACTED:<category>:<first 8 hex of sha256(value)>]"
	}
	man.Reproducibility = Reproducibility{
		VariesWith:       []string{"produced_at"},
		ProducedAtSource: opts.ProducedAtSource,
		FilesFollowing:   []string{"report/report.html", "report/report.pdf", ProductionManifestJSON, ProductionManifestCSV},
		Note: "Re-running on the same package with the same options and the same produced_at (--produced-at or SOURCE_DATE_EPOCH) " +
			"yields byte-identical files. Earlier production runs are not listed in processing_history so that a re-run reproduces; " +
			"each is in custody/activity.jsonl.",
	}

	// 5. Manifest JSON and CSV.
	data, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	if err := os.WriteFile(filepath.Join(out, ProductionManifestJSON), data, 0o600); err != nil {
		return nil, err
	}
	var rows [][]string
	for _, f := range files {
		var arts []string
		for _, s := range f.DerivedFrom {
			arts = append(arts, s.ArtifactID)
		}
		rows = append(rows, []string{f.Path, f.SHA256, strconv.FormatInt(f.Size, 10), f.Kind, strconv.Itoa(f.Items), strings.Join(arts, ";")})
	}
	if err := writeCSV(filepath.Join(out, ProductionManifestCSV), []string{"path", "sha256", "size", "kind", "items", "source_artifact_ids"}, rows); err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	return &ProductionResult{Dir: out, Manifest: man, ManifestSHA256: hex.EncodeToString(sum[:])}, nil
}

// checkOut refuses an output inside the package (derivatives never go
// into the evidence directory) or an existing non-empty directory (a
// production is never mixed with older files).
func checkOut(pkg, out string) error {
	if out == "" {
		return errors.New("production: no output directory")
	}
	ap, err := filepath.Abs(pkg)
	if err != nil {
		return err
	}
	ao, err := filepath.Abs(out)
	if err != nil {
		return err
	}
	if rp, err := filepath.EvalSymlinks(ap); err == nil {
		ap = rp
	}
	if ro, err := filepath.EvalSymlinks(filepath.Dir(ao)); err == nil {
		ao = filepath.Join(ro, filepath.Base(ao))
	}
	if rel, err := filepath.Rel(ap, ao); err == nil && (rel == "." || !strings.HasPrefix(rel, "..")) {
		return fmt.Errorf("production: output %s is inside the case package; write it beside the case instead", out)
	}
	if ents, err := os.ReadDir(out); err == nil && len(ents) > 0 {
		return fmt.Errorf("production: output directory %s already exists and is not empty", out)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// scopeCase returns a shallow copy limited to the given sessions.
func scopeCase(c *report.Case, sessions []string) *report.Case {
	cp := *c
	if len(sessions) == 0 {
		return &cp
	}
	want := map[string]bool{}
	for _, s := range sessions {
		want[s] = true
	}
	cp.Events = nil
	for _, e := range c.Events {
		if want[e.SessionID] {
			cp.Events = append(cp.Events, e)
		}
	}
	cp.Findings = nil
	for _, f := range c.Findings {
		if want[f.SessionID] {
			cp.Findings = append(cp.Findings, f)
		}
	}
	return &cp
}

func caseIdentity(pkg string, c *report.Case) ProductionCase {
	pc := ProductionCase{CaseID: c.Manifest.CaseID, PackageName: filepath.Base(filepath.Clean(pkg)),
		ADFIRVersion: c.Manifest.ADFIRVersion, CreatedUTC: c.Manifest.CreatedUTC,
		SealDigest:     custody.SealDigest(pkg),
		SealDigestNote: "sha256 of the package's SHA256SUMS at production time",
		Signature:      signatureState(pkg)}
	switch {
	case c.Verify == nil:
		pc.Integrity = "NOT CHECKED"
	case len(c.Verify.Problems) == 0:
		pc.Integrity = "VERIFIED"
	default:
		pc.Integrity = fmt.Sprintf("FAILED (%d problem(s))", len(c.Verify.Problems))
		pc.Problems = c.Verify.Problems
	}
	if c.CaseInfo != nil {
		pc.Operator = firstOf(c.CaseInfo.OperatorAsserted, c.CaseInfo.OperatorOSUser)
		pc.Authorization = c.CaseInfo.Authorization
	}
	return pc
}

func examiner(flag string, c *report.Case) Examiner {
	if flag != "" {
		return Examiner{Name: flag, Source: "--examiner"}
	}
	if c.CaseInfo != nil {
		if c.CaseInfo.OperatorAsserted != "" {
			return Examiner{Name: c.CaseInfo.OperatorAsserted, Source: "case operator"}
		}
		if c.CaseInfo.OperatorOSUser != "" {
			return Examiner{Name: c.CaseInfo.OperatorOSUser, Source: "os user"}
		}
	}
	return Examiner{Name: "", Source: "not recorded"}
}

func signatureState(pkg string) string {
	sr, err := seal.Verify(pkg, "")
	switch {
	case err != nil:
		return "error: " + err.Error()
	case sr.Present && sr.Valid:
		return "VALID (ed25519, key " + sr.PublicKey + ")"
	case sr.Present:
		return "INVALID — " + sr.Reason
	}
	return "none (package is unsigned)"
}

// history assembles the processing history from the sealed custody log,
// the collection rounds and log, the stored analysis, the post-seal
// activity log (minus earlier productions) and this run's stages.
func history(pkg string, c *report.Case, examiner, producedAt string, r *redact.Redactor) []HistoryEntry {
	var h []HistoryEntry
	all, err := custody.Load(pkg)
	if err != nil {
		h = append(h, HistoryEntry{Source: "sealed_custody_log", Event: "unreadable", Detail: err.Error()})
	} else {
		for _, rec := range all.Sealed {
			h = append(h, HistoryEntry{Source: "sealed_custody_log", Seq: rec.Seq, TS: rec.TS, Event: rec.Event,
				Actor: rec.OSUser, Detail: custody.Describe(rec)})
		}
		if all.SealedChainErr != "" {
			h = append(h, HistoryEntry{Source: "sealed_custody_log", Event: "chain_broken", Detail: all.SealedChainErr})
		}
	}
	if c.CaseInfo != nil {
		for _, rd := range c.CaseInfo.Rounds {
			h = append(h, HistoryEntry{Source: "collection_round", Seq: rd.Round, TS: rd.StartedUTC, Event: "collection_round",
				Detail: fmt.Sprintf("collector %s; completed %s; ok %d, carried %d, not acquired %d; args %s",
					rd.CollectorVersion, rd.CompletedUTC, rd.ArtifactsOK, rd.ArtifactsCarried, rd.ArtifactsFailed, strings.Join(rd.CollectionArgs, " "))})
		}
	}
	h = append(h, collectionLog(pkg)...)
	if data, err := overlay.ReadFile(filepath.Join(pkg, "detections", "analysis.json")); err == nil {
		var a struct {
			Version  string `json:"agentdfir_version"`
			At       string `json:"analyzed_utc"`
			Analysis string `json:"analysis_fingerprint"`
			Events   int    `json:"events"`
			Findings int    `json:"findings"`
		}
		if json.Unmarshal(data, &a) == nil {
			h = append(h, HistoryEntry{Source: "analysis", TS: a.At, Event: "analysis",
				Detail: fmt.Sprintf("agentdfir %s; analysis fingerprint %s; %d event(s), %d finding(s)", a.Version, a.Analysis, a.Events, a.Findings)})
		}
	}
	if all != nil {
		for _, rec := range all.Activity {
			if rec.Event == custody.EventProductionGenerated {
				continue
			}
			h = append(h, HistoryEntry{Source: "activity_log", Seq: rec.Seq, TS: rec.TS, Event: rec.Event,
				Actor: rec.OSUser + "@" + rec.Host, Detail: custody.Describe(rec)})
		}
		if all.ActivityChainErr != "" {
			h = append(h, HistoryEntry{Source: "activity_log", Event: "chain_broken", Detail: all.ActivityChainErr})
		}
	}
	stages := []struct{ ev, detail string }{
		{"verify", "full package verification (casepkg.Verify) before production"},
		{"redact", "derivative redaction: " + strings.Join(r.Spec().Categories, ",")},
		{"rsmf", "RSMF " + report.RSMFVersion + " per session, validated against the manifest structure"},
		{"report", "report.html, report.pdf"},
		{"timeline", "timeline.csv, findings.csv"},
		{"manifest", "traceability.csv, production manifest"},
	}
	// Evidence-derived history is masked; this run's own stages are
	// tool-written text whose actor is the examiner, never redacted.
	for i := range h {
		r.Walk(&h[i], fmt.Sprintf("production-manifest processing_history[%d]", i))
	}
	for _, s := range stages {
		if s.ev == "redact" && r == nil {
			continue
		}
		h = append(h, HistoryEntry{Source: "this_production", TS: producedAt, Event: s.ev, Actor: examiner, Detail: s.detail})
	}
	return h
}

// collectionLog lists the run-level records of collection.jsonl (per
// artifact lines are summarized in the files and rounds, not repeated).
func collectionLog(pkg string) []HistoryEntry {
	f, err := os.Open(filepath.Join(pkg, "collection.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []HistoryEntry
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	for sc.Scan() {
		var rec map[string]any
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		ev, _ := rec["event"].(string)
		if ev == "artifact" || ev == "" {
			continue
		}
		ts, _ := rec["ts_utc"].(string)
		seq, _ := rec["seq"].(float64)
		var parts []string
		for _, k := range []string{"product", "round", "ok", "failed", "not_present"} {
			if v, ok := rec[k]; ok {
				parts = append(parts, fmt.Sprintf("%s=%v", k, v))
			}
		}
		out = append(out, HistoryEntry{Source: "collection_log", Seq: int(seq), TS: ts, Event: ev, Detail: strings.Join(parts, " ")})
		if len(out) >= maxLimitationRefs {
			break
		}
	}
	return out
}

// limitations lists what is missing or limited, record by record where
// the records exist.
func limitations(orig, rc *report.Case, omitted []report.RSMFOmission, sessions []string, without int) []Limitation {
	var out []Limitation
	addL := func(code, detail string, refs []string) {
		l := Limitation{Code: code, Detail: detail, Count: len(refs)}
		if len(refs) > maxLimitationRefs {
			refs = refs[:maxLimitationRefs]
		}
		l.Refs = refs
		out = append(out, l)
	}
	ref := func(art, path string, line int) string {
		return fmt.Sprintf("artifact %s line %d (%s)", art, line, path)
	}

	var gaps []string
	for _, e := range rc.Events {
		if e.EventType == schema.EventTraceGap {
			gaps = append(gaps, ref(e.SourceArtifact, e.SourcePath, e.SourceLine)+": "+e.Summary)
		}
	}
	if len(gaps) > 0 {
		addL("TRACE_GAP", "transcript regions that could not be parsed (malformed or truncated lines); their content is not in any derivative", gaps)
	}
	if len(omitted) > 0 {
		var refs []string
		for _, o := range omitted {
			refs = append(refs, ref(o.ArtifactID, o.LogicalPath, o.Line)+" event "+o.EventID+": "+o.Reason)
		}
		addL("NOT_IN_RSMF_UNDATED", "events without a usable timestamp cannot be placed in an RSMF conversation; they are in timeline/timeline.csv", refs)
	}

	// Sessions without transcript content.
	msgs := map[string]int{}
	for _, e := range rc.Events {
		switch e.EventType {
		case schema.EventHumanPrompt, schema.EventModelResponse, schema.EventAgentMessage, schema.EventToolCall, schema.EventToolResult:
			msgs[e.SessionID]++
		}
	}
	want := map[string]bool{}
	for _, s := range sessions {
		want[s] = true
	}
	var empty []string
	for _, en := range orig.Entities {
		if en.Kind != "session" {
			continue
		}
		sid := strings.TrimPrefix(en.EntityID, "session:")
		if len(want) > 0 && !want[sid] {
			continue
		}
		if msgs[sid] == 0 {
			empty = append(empty, "session "+sid)
		}
	}
	sort.Strings(empty)
	if len(empty) > 0 {
		addL("SESSION_WITHOUT_TRANSCRIPT", "sessions known from metadata with no transcript messages in the case", empty)
	}

	// Acquired session artifacts no parser produced events from, and
	// artifacts that were not acquired.
	parsed := map[string]bool{}
	for _, e := range orig.Events {
		parsed[e.SourceArtifact] = true
	}
	var unparsed, notAcq []string
	seen := map[string]bool{}
	for _, a := range rc.Manifest.Artifacts {
		key := a.LogicalPath + "|" + a.ArtifactID + "|" + a.Status
		if seen[key] {
			continue
		}
		seen[key] = true
		switch {
		case a.Status == "OK" && a.ArtifactType == "agent_session" && a.Size > 0 && !parsed[a.ArtifactID]:
			unparsed = append(unparsed, fmt.Sprintf("artifact %s (%s, product %s)", a.ArtifactID, a.LogicalPath, a.Product))
		case a.Status != "OK" && a.Status != "NOT_PRESENT" && a.Status != "":
			d := fmt.Sprintf("%s: %s", a.Status, a.LogicalPath)
			if a.Error != "" {
				d += " — " + a.Error
			}
			notAcq = append(notAcq, d)
		}
	}
	if len(unparsed) > 0 {
		addL("UNSUPPORTED_OR_UNPARSED_SESSION", "session artifacts were acquired and sealed but produced no events (unsupported format version, or empty); their content is not in any derivative", unparsed)
	}
	if len(notAcq) > 0 {
		addL("ARTIFACT_NOT_ACQUIRED", "artifacts the collector found but did not acquire (status per the collection log)", notAcq)
	}
	if orig.Verify != nil && len(orig.Verify.Problems) > 0 {
		addL("INTEGRITY_FAILED", "package verification found problems; derivatives were produced from a case that does not verify", orig.Verify.Problems)
	}
	if len(rc.Events) == 0 {
		addL("NO_EVENTS", "no normalized events in scope; the production holds no conversations", nil)
	}
	if without > 0 {
		addL("ITEMS_WITHOUT_SOURCE_REF", fmt.Sprintf("%d traceability row(s) carry no source artifact or line (e.g. a finding with no evidence reference)", without), nil)
	}
	if len(sessions) > 0 {
		addL("SCOPE_LIMITED_TO_SESSIONS", "the production was limited to the listed sessions; other sessions in the case are not included", sortedCopy(sessions))
	}
	addL("RSMF_BODY_IS_NORMALIZED_EXTRACT", "RSMF event bodies carry the normalized event text (summary, command); the authoritative content is the sealed source line named in each event's custom fields", nil)
	addL("RSMF_VALIDATION_SCOPE", "RSMF files are validated against the RSMF 2.0 manifest structure by AgentDFIR's own validator, not against a review platform", nil)
	return out
}

type spanBuilder map[string]*SourceSpan

func (s spanBuilder) add(art, path string, line int) {
	if art == "" && path == "" {
		return
	}
	k := art + "\x00" + path
	sp := s[k]
	if sp == nil {
		sp = &SourceSpan{ArtifactID: art, LogicalPath: path, LineFirst: line, LineLast: line}
		s[k] = sp
	}
	if line < sp.LineFirst {
		sp.LineFirst = line
	}
	if line > sp.LineLast {
		sp.LineLast = line
	}
	sp.Items++
}

func (s spanBuilder) spans() []SourceSpan {
	out := make([]SourceSpan, 0, len(s))
	for _, sp := range s {
		out = append(out, *sp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ArtifactID != out[j].ArtifactID {
			return out[i].ArtifactID < out[j].ArtifactID
		}
		return out[i].LogicalPath < out[j].LogicalPath
	})
	return out
}

func eventsByLine(evs []schema.Event) map[string]schema.Event {
	out := map[string]schema.Event{}
	for _, e := range evs {
		k := e.SourcePath + ":" + strconv.Itoa(e.SourceLine)
		if _, ok := out[k]; !ok {
			out[k] = e
		}
	}
	return out
}

type evidenceRef struct {
	path      string
	line      int
	artPrefix string
	offset    int64
	byteRef   bool
}

// parseRef reads the two evidence reference forms findings use:
// "logical_path:line (artifact <id12>, offset N)" for events and
// "logical_path (artifact <id12>, byte offset N)" for whole artifacts.
func parseRef(ref string) evidenceRef {
	var r evidenceRef
	head, tail := ref, ""
	if i := strings.Index(ref, " ("); i >= 0 {
		head, tail = ref[:i], strings.TrimSuffix(ref[i+2:], ")")
	}
	r.path = head
	for _, part := range strings.Split(tail, ", ") {
		switch {
		case strings.HasPrefix(part, "artifact "):
			r.artPrefix = strings.TrimPrefix(part, "artifact ")
		case strings.HasPrefix(part, "byte offset "):
			r.offset, _ = strconv.ParseInt(strings.TrimPrefix(part, "byte offset "), 10, 64)
			r.byteRef = true
		case strings.HasPrefix(part, "offset "):
			r.offset, _ = strconv.ParseInt(strings.TrimPrefix(part, "offset "), 10, 64)
		}
	}
	if !r.byteRef {
		if j := strings.LastIndex(head, ":"); j >= 0 {
			if n, err := strconv.Atoi(head[j+1:]); err == nil {
				r.path, r.line = head[:j], n
			}
		}
	}
	return r
}

// artByPrefix resolves a shortened artifact id against the manifest.
func artByPrefix(c *report.Case, path, prefix string) string {
	if c.Manifest == nil || prefix == "" {
		return ""
	}
	for _, a := range c.Manifest.Artifacts {
		if a.ArtifactID != "" && strings.HasPrefix(a.ArtifactID, prefix) && (path == "" || a.LogicalPath == path) {
			return a.ArtifactID
		}
	}
	return ""
}

func hashFile(p string) (string, int64, error) {
	data, err := os.ReadFile(p)
	if err != nil {
		return "", 0, err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), int64(len(data)), nil
}

func writeCSV(p string, header []string, rows [][]string) error {
	var b bytes.Buffer
	w := csv.NewWriter(&b)
	_ = w.Write(header)
	_ = w.WriteAll(rows)
	if err := w.Error(); err != nil {
		return err
	}
	return os.WriteFile(p, b.Bytes(), 0o600)
}

func sortedCopy(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}

func firstOf(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
