package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/accountability"
	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/custody"
	"github.com/efij/AgentDFIR/v4/internal/sanitize"
)

const accountabilityUsage = `usage: agentdfir report accountability [<case.adfir>] [--session <id>] [--since <rfc3339>] [--until <rfc3339>]
                                       [--finding <rule-id>] [--format md|json|html|all] [--out <dir>]

For every consequential action in the case — HIGH/CRITICAL findings and any
destructive, cloud, exfiltration, credential, configuration or execution
rule — one row with four parts: who asked (the nearest human prompt or the
tool result that triggered it), what was allowed (permission state as
captured), what the agent did (event, evidence state, witness), and whether
it went beyond the instruction (rule-based gap codes, or NONE_DETECTED).
Default: this machine's case. Output: <case>/reports/accountability.{md,json,html}
and a report_generated record in the case's custody activity log. Not legal advice.
`

// cmdReportAccountability is `report accountability`.
func cmdReportAccountability(args []string) int {
	fs := flag.NewFlagSet("report accountability", flag.ContinueOnError)
	session := fs.String("session", "", "one session id")
	since := fs.String("since", "", "actions at or after this time (RFC 3339)")
	until := fs.String("until", "", "actions at or before this time (RFC 3339)")
	finding := fs.String("finding", "", "one rule id (or prefix)")
	format := fs.String("format", "md", "md|json|html|all")
	outDir := fs.String("out", "", "output directory (default: <case>/reports)")
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || fs.NArg() > 1 || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprint(os.Stderr, accountabilityUsage)
		return 2
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}
	if pkg == "" {
		pkg = defaultCase()
		if pkg == "" {
			fmt.Fprint(os.Stderr, accountabilityUsage)
			return 2
		}
	}
	switch *format {
	case "md", "json", "html", "all":
	default:
		fmt.Fprintf(os.Stderr, "unknown format %q (md|json|html|all)\n", sanitize.Terminal(*format))
		return 2
	}
	// The report renders the analysis the analyst saw; it never re-runs it
	// when the stored results are current.
	if _, err := analysis.Ensure(pkg, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	rep, err := accountability.Build(pkg, accountability.Options{SessionID: *session, Since: *since, Until: *until, Finding: *finding})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	dir := *outDir
	if dir == "" {
		dir = filepath.Join(pkg, "reports")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	want := func(f string) bool { return *format == "all" || *format == f }
	type out struct {
		name string
		fn   func(string) error
	}
	var outs []out
	if want("md") {
		outs = append(outs, out{"accountability.md", func(p string) error { return accountability.WriteMarkdown(rep, p) }})
	}
	if want("json") {
		outs = append(outs, out{"accountability.json", func(p string) error { return accountability.WriteJSON(rep, p) }})
	}
	if want("html") {
		outs = append(outs, out{"accountability.html", func(p string) error { return accountability.WriteHTML(rep, p) }})
	}
	files := map[string]any{}
	var written []string
	for _, o := range outs {
		p := filepath.Join(dir, o.name)
		if err := o.fn(p); err != nil {
			fmt.Fprintln(os.Stderr, "error writing "+o.name+":", err)
			return 1
		}
		sum, _ := custody.FileSHA256(p)
		files[o.name] = sum
		written = append(written, p)
	}
	// The report is derived data outside the seal; the custody activity
	// log records that it was made, from which seal, and what it hashes to.
	if _, err := custody.Append(pkg, custody.EventReportGenerated, map[string]any{
		"report": "accountability", "files": files, "out_dir": dir, "actions": rep.Summary.Actions, "with_gaps": rep.Summary.WithGaps,
		"filter_session": *session, "filter_finding": *finding,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "warning: custody activity not recorded:", err)
	}
	fmt.Printf("Accountability report for case %s: %d consequential action(s), %d with a gap\n", sanitize.Terminal(rep.Case.CaseID), rep.Summary.Actions, rep.Summary.WithGaps)
	for _, code := range sortedGapCodes(rep.Summary.ByGap) {
		fmt.Printf("  %-36s %d\n", code, rep.Summary.ByGap[code])
	}
	for _, p := range written {
		fmt.Printf("  %s\n", sanitize.Terminal(p))
	}
	fmt.Println("Recorded in " + sanitize.Terminal(custody.Path(pkg)) + " (hash chain outside the seal). Not legal advice.")
	return 0
}

func sortedGapCodes(m map[string]int) []string {
	var keys []string
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

const caseUsage = `usage: agentdfir case authorize [<case.adfir>] --by <name> --basis <text> [--reference <ticket>]
       agentdfir case log [<case.adfir>]

authorize  record who authorized this acquisition and on what basis. Written to
           the case's custody activity log (a hash chain outside the seal, every
           record names the seal digest it was made against); shown in the
           accountability report and the custody package. The reference given
           at collection time (--authorization) stays as it was.
log        print the sealed custody log and the activity log, with chain state.
`

// cmdCase is `case authorize` and `case log`.
func cmdCase(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, caseUsage)
		return 2
	}
	switch args[0] {
	case "authorize":
		return cmdCaseAuthorize(args[1:])
	case "log":
		return cmdCaseLog(args[1:])
	}
	fmt.Fprint(os.Stderr, caseUsage)
	return 2
}

func cmdCaseAuthorize(args []string) int {
	fs := flag.NewFlagSet("case authorize", flag.ContinueOnError)
	by := fs.String("by", "", "who authorized the acquisition")
	basis := fs.String("basis", "", "on what basis (policy, ticket, consent, legal process)")
	ref := fs.String("reference", "", "ticket or document reference")
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || fs.NArg() > 1 || (pkg != "" && fs.NArg() != 0) || *by == "" || *basis == "" {
		fmt.Fprint(os.Stderr, caseUsage)
		return 2
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}
	if pkg == "" {
		pkg = defaultCase()
		if pkg == "" {
			fmt.Fprint(os.Stderr, caseUsage)
			return 2
		}
	}
	rec, err := custody.Append(pkg, custody.EventAuthorized, map[string]any{"by": *by, "basis": *basis, "reference": *ref})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Recorded: acquisition of case %s authorized by %s — %s\n", sanitize.Terminal(rec.CaseID), sanitize.Terminal(*by), sanitize.Terminal(*basis))
	fmt.Printf("  record %d at %s, by %s@%s, against seal %.16s…\n", rec.Seq, rec.TS, sanitize.Terminal(rec.OSUser), sanitize.Terminal(rec.Host), rec.SealDigest)
	fmt.Printf("  %s\n", sanitize.Terminal(custody.Path(pkg)))
	return 0
}

func cmdCaseLog(args []string) int {
	pkg, _ := splitPositional(args)
	if pkg == "" {
		pkg = defaultCase()
		if pkg == "" {
			fmt.Fprint(os.Stderr, caseUsage)
			return 2
		}
	}
	all, err := custody.Load(pkg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Sealed custody log (chain-of-custody.jsonl): %d record(s), chain %s\n", len(all.Sealed), okOr(all.SealedChainErr))
	for _, r := range all.Sealed {
		fmt.Printf("  %3d  %s  %-24s round %d  %s\n", r.Seq, r.TS, r.Event, r.Round, sanitize.Terminal(custody.Describe(r)))
	}
	fmt.Printf("Activity log (custody/activity.jsonl, outside the seal): %d record(s), chain %s\n", len(all.Activity), okOr(all.ActivityChainErr))
	for _, r := range all.Activity {
		fmt.Printf("  %3d  %s  %-24s by %s@%s  seal %.12s  %s\n", r.Seq, r.TS, r.Event, sanitize.Terminal(r.OSUser), sanitize.Terminal(r.Host), r.SealDigest, sanitize.Terminal(custody.Describe(r)))
	}
	if all.SealedChainErr != "" || all.ActivityChainErr != "" {
		return 1
	}
	return 0
}

func okOr(err string) string {
	if err == "" {
		return "intact"
	}
	return "BROKEN: " + strings.TrimSpace(err)
}
