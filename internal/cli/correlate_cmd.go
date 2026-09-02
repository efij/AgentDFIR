package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/correlate"
	"github.com/efij/AgentDFIR/internal/endpoint"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/schema"
)

const correlateUsage = `usage: agentdfir correlate <package-dir> <endpoint-log>... [--window 3s] [--format auto|auditd|sysmon-xml|jsonl|csv]
                                                    [--known-destinations a.example,b.example]

Second witness: match the agent transcript against OS telemetry.
  auditd      /var/log/audit/audit.log (SYSCALL/EXECVE/PATH/SOCKADDR)
  sysmon-xml  wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml   (events 1, 3, 11, 23)
  jsonl/csv   Velociraptor, osquery, evtx_dump JSON, macOS eslogger — field names auto-mapped
Format is sniffed per file. Results are written back to normalized/events.jsonl
(OBSERVED → CORROBORATED / CONTRADICTED) and detections/corroboration.json.
`

// cmdCorrelate runs endpoint correlation on an already-normalized package
// (it normalizes first if needed).
func cmdCorrelate(args []string) int {
	fs := flag.NewFlagSet("correlate", flag.ContinueOnError)
	window := fs.Duration("window", 3*time.Second, "match window around each tool call")
	format := fs.String("format", "auto", "endpoint log format")
	knownDest := fs.String("known-destinations", "", "extra allowlisted destinations")
	var positional []string
	rest := args
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		fmt.Fprint(os.Stderr, correlateUsage)
		return 2
	}
	positional = append(positional, fs.Args()...)
	if len(positional) < 2 {
		fmt.Fprint(os.Stderr, correlateUsage)
		return 2
	}
	pkg, logs := positional[0], positional[1:]
	dir := filepath.Join(pkg, "normalized")
	if _, err := os.Stat(filepath.Join(dir, "events.jsonl")); err != nil {
		fmt.Println("Package not normalized yet — normalizing first.")
		if rc := cmdNormalize([]string{pkg}); rc != 0 {
			return rc
		}
	}
	var extra []string
	if *knownDest != "" {
		extra = strings.Split(*knownDest, ",")
	}
	findings, res, rc := runEndpointCorrelation(pkg, logs, endpoint.Format(*format), correlate.EndpointOptions{Window: *window, KnownDests: extra}, nil)
	if rc != 0 {
		return rc
	}
	printFindings(findings)
	if res != nil && res.Contradicted+res.Unlogged > 0 {
		return 3
	}
	return 0
}

// runEndpointCorrelation loads endpoint logs, correlates against the
// events overlay, persists the updated states and returns findings.
// Shared by `correlate` and `triage --endpoint`. extraFindings are merged
// into detections/corroboration.json (e.g. shell-history notes).
func runEndpointCorrelation(pkg string, logs []string, f endpoint.Format, opts correlate.EndpointOptions, events []schema.Event) ([]schema.Finding, *correlate.EndpointResult, int) {
	dir := filepath.Join(pkg, "normalized")
	if events == nil {
		events = loadEvents(dir)
	}
	var records []endpoint.Record
	for _, path := range logs {
		lr, err := endpoint.Load(path, f)
		if err != nil {
			fmt.Fprintln(os.Stderr, "endpoint:", err)
			return nil, nil, 1
		}
		fmt.Printf("Endpoint log %s: %s, %d records", sanitize.Terminal(filepath.Base(path)), lr.Format, len(lr.Records))
		if lr.Skipped > 0 {
			fmt.Printf(" (%d skipped)", lr.Skipped)
		}
		fmt.Println()
		for _, p := range lr.Problems {
			fmt.Printf("  note: %s\n", sanitize.Terminal(p))
		}
		records = append(records, lr.Records...)
	}
	res, findings := correlate.Endpoint(events, records, opts)
	if err := writeJSONL(filepath.Join(dir, "events.jsonl"), len(events), func(i int) any { return events[i] }); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return nil, nil, 1
	}
	detDir := filepath.Join(pkg, "detections")
	_ = os.MkdirAll(detDir, 0o700)
	out := struct {
		Summary  *correlate.EndpointResult `json:"summary"`
		Findings []schema.Finding          `json:"findings"`
	}{res, findings}
	data, _ := json.MarshalIndent(out, "", "  ")
	_ = os.WriteFile(filepath.Join(detDir, "corroboration.json"), append(data, '\n'), 0o600)

	fmt.Printf("Endpoint correlation: %d tool calls checked — %d CORROBORATED, %d CONTRADICTED, %d outside telemetry coverage; %d agent-lineage records, %d unlogged.\n",
		res.ToolCalls, res.Corroborated, res.Contradicted, res.OutsideCover, res.AgentProcesses, res.Unlogged)
	if !res.CoverageStart.IsZero() {
		fmt.Printf("Telemetry coverage: %s → %s\n", res.CoverageStart.Format(time.RFC3339), res.CoverageEnd.Format(time.RFC3339))
	}
	return findings, res, 0
}

func printFindings(findings []schema.Finding) {
	sortFindings(findings)
	fmt.Printf("\n%d finding(s):\n", len(findings))
	for _, f := range findings {
		fmt.Printf("%s — %s [%s]\n", f.Severity, f.Title, f.RuleID)
		fmt.Printf("  Finding: %s\n", sanitize.Terminal(f.Description))
		for _, r := range f.Related {
			fmt.Printf("  Related: %s\n", sanitize.Terminal(r))
		}
		for _, e := range f.EvidenceRefs {
			fmt.Printf("  Evidence: %s\n", sanitize.Terminal(e))
		}
		fmt.Printf("  Status: %s    Endpoint corroboration: %s\n", f.Status, f.Endpoint)
	}
}
