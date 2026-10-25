package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/analysis"
	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/custody"
	"github.com/efij/AgentDFIR/v3/internal/export"
	"github.com/efij/AgentDFIR/v3/internal/notes"
	"github.com/efij/AgentDFIR/v3/internal/redact"
	"github.com/efij/AgentDFIR/v3/internal/report"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
)

const reportRSMFUsage = `usage: agentdfir report <package-dir> --format rsmf [--out dir] [--session ID ...] [--redact secrets,emails,paths,ips[,custom:<file>]]

Writes one RSMF 2.0 file (.rsmf, an RFC 5322 message with rsmf.zip) per
session into <out> (default: <package>/reports/rsmf). Every file is checked
by AgentDFIR's RSMF validator before it is written. Structural validation
only; not tested against a review platform; no admissibility claim.
`

const exportProductionUsage = `usage: agentdfir export <package-dir> --production [--out dir] [--examiner name]
                        [--session ID ...] [--redact secrets,emails,paths,ips[,custom:<file>]]
                        [--produced-at RFC3339]

Produces an eDiscovery production set beside the case (default
<package>.production): RSMF per session, report.html, report.pdf,
timeline.csv, findings.csv, traceability.csv and production-manifest.json /
.csv (every file's SHA-256, source artifact ids and lines, examiner, tool
version and binary SHA-256, processing history, seal digest, redaction log,
missing records and limitations). --redact applies to these derivative
files only, never to the sealed case. --produced-at (or SOURCE_DATE_EPOCH)
fixes the one time-dependent field so a re-run is byte-identical.
`

// isRSMFReport reports whether report args ask for --format rsmf.
func isRSMFReport(args []string) bool {
	for i, a := range args {
		switch {
		case a == "--format=rsmf" || a == "-format=rsmf":
			return true
		case (a == "--format" || a == "-format") && i+1 < len(args) && args[i+1] == "rsmf":
			return true
		}
	}
	return false
}

// hasFlag reports whether a boolean flag is present in args.
func hasFlag(args []string, name string) bool {
	for _, a := range args {
		if a == "--"+name || a == "-"+name || a == "--"+name+"=true" || a == "-"+name+"=true" {
			return true
		}
	}
	return false
}

// loadReportCase loads a package the way `report` does: the same analysis
// run the analyst saw, states included, with the case file attached.
func loadReportCase(pkg string) (*report.Case, error) {
	man, err := report.ReadManifest(pkg)
	if err != nil {
		return nil, err
	}
	ci, _ := report.ReadCaseInfo(pkg)
	vres, err := casepkg.Verify(pkg)
	if err != nil {
		return nil, err
	}
	if _, err := analysis.Ensure(pkg, os.Stdout); err != nil {
		return nil, err
	}
	c := &report.Case{Manifest: man, CaseInfo: ci, Verify: vres,
		Events: analysis.LoadEvents(pkg), Entities: analysis.LoadEntities(pkg), Findings: analysis.LoadFindings(pkg)}
	if st, _ := notes.Open(pkg).Load(); st.Records > 0 {
		c.Notes = st
	}
	return c, nil
}

// sessionList flattens repeated and comma-separated --session values.
func sessionList(m multiFlag) []string {
	var out []string
	for _, v := range m {
		for _, s := range strings.Split(v, ",") {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
	}
	return out
}

func cmdReportRSMF(args []string) int {
	fs := flag.NewFlagSet("report rsmf", flag.ContinueOnError)
	fs.String("format", "rsmf", "rsmf")
	outDir := fs.String("out", "", "output directory (default: <package>/reports/rsmf)")
	redactSpec := fs.String("redact", "", "secrets,emails,paths,ips[,custom:<file>] — derivative output only")
	var sessions multiFlag
	fs.Var(&sessions, "session", "limit to this session id (repeatable, or comma-separated)")
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || (pkg == "" && fs.NArg() != 1) || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprint(os.Stderr, reportRSMFUsage)
		return 2
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}
	r, err := redact.Parse(*redactSpec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	c, err := loadReportCase(pkg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if c, err = report.RedactCase(c, r); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	dir := *outDir
	if dir == "" {
		dir = filepath.Join(pkg, "reports", "rsmf")
	}
	ids := sessionList(sessions)
	files, omitted, err := report.WriteRSMF(c, dir, report.RSMFOptions{Sessions: ids})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("RSMF %s written for case %s (%d conversation(s), validated against the RSMF manifest structure):\n",
		report.RSMFVersion, sanitize.Terminal(c.Manifest.CaseID), len(files))
	events := 0
	for _, f := range files {
		events += len(f.Manifest.Events)
		fmt.Printf("  %s  (%d event(s))\n", sanitize.Terminal(filepath.Join(dir, f.Name)), len(f.Manifest.Events))
	}
	if len(files) == 0 {
		if len(ids) > 0 {
			fmt.Println("  no dated events in the selected session(s)")
		} else {
			fmt.Println("  no dated events in this case")
		}
	}
	if len(omitted) > 0 {
		fmt.Printf("Note: %d event(s) without a usable timestamp are not in RSMF (they are in timeline.csv).\n", len(omitted))
	}
	if r != nil {
		tot := r.Totals()
		fmt.Printf("Redacted (derivative output only): secret=%d email=%d path=%d ip=%d custom=%d. The sealed case is unchanged.\n",
			tot[redact.Secret], tot[redact.Email], tot[redact.Path], tot[redact.IP], tot[redact.Custom])
	}
	return 0
}

// producedAt resolves the production time: --produced-at, then
// SOURCE_DATE_EPOCH, then the clock.
func producedAt(flagVal string) (time.Time, string, error) {
	if flagVal != "" {
		t, err := time.Parse(time.RFC3339, flagVal)
		if err != nil {
			return time.Time{}, "", fmt.Errorf("--produced-at: want RFC 3339 (e.g. 2026-10-25T12:00:00Z): %w", err)
		}
		return t.UTC(), "--produced-at", nil
	}
	if v := os.Getenv("SOURCE_DATE_EPOCH"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return time.Time{}, "", fmt.Errorf("SOURCE_DATE_EPOCH must be a non-negative integer, got %q", v)
		}
		return time.Unix(n, 0).UTC(), "SOURCE_DATE_EPOCH", nil
	}
	return time.Now().UTC().Truncate(time.Second), "clock", nil
}

func cmdExportProduction(args []string) int {
	fs := flag.NewFlagSet("export production", flag.ContinueOnError)
	fs.Bool("production", true, "produce an eDiscovery production set")
	out := fs.String("out", "", "output directory (default: <package>.production)")
	examinerName := fs.String("examiner", "", "examiner producing the set (default: the case operator)")
	redactSpec := fs.String("redact", "", "secrets,emails,paths,ips[,custom:<file>] — derivative output only")
	at := fs.String("produced-at", "", "fixed production time (RFC 3339); default SOURCE_DATE_EPOCH, then the clock")
	var sessions multiFlag
	fs.Var(&sessions, "session", "limit to this session id (repeatable, or comma-separated)")
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || fs.NArg() > 1 || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprint(os.Stderr, exportProductionUsage)
		return 2
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}
	if pkg == "" {
		pkg = defaultCase()
	}
	if pkg == "" {
		fmt.Fprint(os.Stderr, exportProductionUsage)
		return 2
	}
	r, err := redact.Parse(*redactSpec)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	when, whenSrc, err := producedAt(*at)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	dst := *out
	if dst == "" {
		dst = strings.TrimRight(pkg, `/\`) + ".production"
	}
	c, err := loadReportCase(pkg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	binSHA := ""
	if exe, err := os.Executable(); err == nil {
		binSHA, _ = custody.FileSHA256(exe)
	}
	res, err := export.Produce(pkg, c, export.ProductionOptions{
		Out: dst, Sessions: sessionList(sessions), Redactor: r, Examiner: *examinerName,
		ProducedAt: when, ProducedAtSource: whenSrc, BinarySHA256: binSHA,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	m := res.Manifest
	if _, err := custody.Append(pkg, custody.EventProductionGenerated, map[string]any{
		"out": dst, "files": len(m.Files), "manifest_sha256": res.ManifestSHA256,
		"produced_at": m.ProducedAt, "examiner": m.Examiner.Name,
		"redaction": strings.Join(m.Redaction.Spec.Categories, ","), "sessions": strings.Join(m.Options.Sessions, ","),
	}); err != nil {
		fmt.Fprintln(os.Stderr, "warning: custody activity not recorded:", err)
	}
	fmt.Printf("Production set for case %s written to %s (%d file(s)).\n", sanitize.Terminal(m.Case.CaseID), sanitize.Terminal(dst), len(m.Files)+2)
	fmt.Printf("  %s  sha256 %s\n", export.ProductionManifestJSON, res.ManifestSHA256)
	fmt.Printf("  traceability: %d row(s); %d event(s) in RSMF, %d not representable (listed under limitations)\n",
		m.Traceability.Rows, m.Traceability.EventsProduced, m.Traceability.EventsOmitted)
	fmt.Printf("  seal digest %s · integrity %s · produced_at %s (%s)\n", m.Case.SealDigest, m.Case.Integrity, m.ProducedAt, whenSrc)
	if m.Redaction.Applied {
		total := 0
		for _, n := range m.Redaction.Totals {
			total += n
		}
		fmt.Printf("  redacted %d value(s) in derivative files (categories/locations/counts in the manifest; no values). The sealed case is unchanged.\n", total)
	}
	if len(m.Limitations) > 0 {
		fmt.Printf("  %d limitation record(s) listed under missing_records_and_limitations.\n", len(m.Limitations))
	}
	fmt.Println("Structural RSMF validation only; not tested against a review platform. No admissibility claim.")
	return 0
}
