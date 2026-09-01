package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/correlate"
	"github.com/efij/AgentDFIR/internal/detect"
	"github.com/efij/AgentDFIR/internal/normalize"
	"github.com/efij/AgentDFIR/internal/rulepack"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/simulate"
)

// cmdNormalize parses a sealed package into the analysis overlay:
// normalized/{events,entities,relationships}.jsonl. The sealed zone is
// never touched; the overlay is regenerable.
func cmdNormalize(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir normalize <package-dir>")
		return 2
	}
	res, err := normalize.ParsePackage(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	dir := filepath.Join(args[0], "normalized")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := writeJSONL(filepath.Join(dir, "events.jsonl"), len(res.Events), func(i int) any { return res.Events[i] }); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := writeJSONL(filepath.Join(dir, "entities.jsonl"), len(res.Entities), func(i int) any { return res.Entities[i] }); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := writeJSONL(filepath.Join(dir, "relationships.jsonl"), len(res.Relationships), func(i int) any { return res.Relationships[i] }); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Normalized: %d events, %d entities, %d relationships -> %s\n",
		len(res.Events), len(res.Entities), len(res.Relationships), dir)
	return 0
}

// cmdTimeline prints the unified timeline. Every entry is traceable:
// evidence path, line and artifact are printed alongside.
func cmdTimeline(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir timeline <package-dir>")
		return 2
	}
	res, err := normalize.ParsePackage(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	events := make([]schema.Event, len(res.Events))
	copy(events, res.Events)
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].Timestamp != events[j].Timestamp {
			return events[i].Timestamp < events[j].Timestamp
		}
		return events[i].Sequence < events[j].Sequence
	})
	for _, ev := range events {
		detail := ev.Summary
		if ev.Command != "" {
			detail = "$ " + ev.Command
		}
		if ev.Tool != "" && detail == "" {
			detail = ev.Tool
		}
		label := ev.EventType
		if ev.Tool != "" {
			label = ev.EventType + ":" + ev.Tool
		}
		fmt.Printf("%-20s %-13s %-9s %-22s %s\n    evidence: %s:%d (artifact %.12s)\n",
			ev.Timestamp,
			"["+ev.Corroboration+"]",
			ev.ActorType,
			sanitize.Terminal(label),
			sanitize.Terminal(detail),
			sanitize.Terminal(ev.SourcePath), ev.SourceLine, ev.SourceArtifact)
	}
	fmt.Printf("\n%d timeline entries. States: OBSERVED = present in transcript records; REPORTED = model narrative only (NOT proof of execution).\n", len(events))
	return 0
}

// cmdTriage runs normalize + detections and prints IR-ready findings.
func cmdTriage(args []string) int {
	fs := flag.NewFlagSet("triage", flag.ContinueOnError)
	triageShellHistory := fs.String("shell-history", "", "correlate against a shell history file (endpoint evidence)")
	rulesDir := fs.String("rules", "", "directory of declarative JSON rule packs")
	honeyFile := fs.String("honeytokens", "", "file of planted canary markers (one per line)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir triage <package-dir> [--shell-history <path>]")
		return 2
	}
	args = []string{fs.Arg(0)}
	if rc := cmdNormalize(args); rc != 0 {
		return rc
	}
	res, err := normalize.ParsePackage(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *triageShellHistory != "" {
		cres, cerr := correlate.Apply(res.Events, &correlate.ShellHistoryAdapter{Path: *triageShellHistory})
		if cerr == nil && cres.Corroborated > 0 {
			fmt.Printf("Endpoint correlation: %d tool call(s) corroborated by shell history.\n", cres.Corroborated)
		}
	}
	var honey []string
	if *honeyFile != "" {
		if data, herr := os.ReadFile(*honeyFile); herr == nil {
			honey = strings.Split(string(data), "\n")
		} else {
			fmt.Fprintln(os.Stderr, "honeytokens:", herr)
		}
	}
	findings := detect.RunPackageWithOptions(res, args[0], honey)
	if *rulesDir != "" {
		packs, perr := rulepack.LoadDir(*rulesDir)
		if perr != nil {
			fmt.Fprintln(os.Stderr, "rule packs:", perr)
			return 1
		}
		extra, perr := rulepack.Apply(packs, res, args[0])
		if perr != nil {
			fmt.Fprintln(os.Stderr, "rule packs:", perr)
			return 1
		}
		if len(extra) > 0 {
			fmt.Printf("Rule packs: %d pack(s) contributed %d finding(s).\n", len(packs), len(extra))
			findings = append(findings, extra...)
		}
	}

	dir := filepath.Join(args[0], "detections")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	data, _ := json.MarshalIndent(findings, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "findings.json"), append(data, '\n'), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	fmt.Printf("\n%d finding(s):\n", len(findings))
	for _, f := range findings {
		fmt.Printf("\n%s — %s [%s]\n", f.Severity, sanitize.Terminal(f.Title), f.RuleID)
		if f.SessionID != "" {
			fmt.Printf("  Session: %s\n", sanitize.Terminal(f.SessionID))
		}
		if f.AgentID != "" {
			parent := f.ParentAgentID
			if parent == "" {
				parent = "-"
			}
			fmt.Printf("  Agent:   %s    Parent: %s\n", sanitize.Terminal(f.AgentID), sanitize.Terminal(parent))
		}
		fmt.Printf("  Finding: %s\n", sanitize.Terminal(f.Description))
		for _, r := range f.Related {
			fmt.Printf("  Related: %s\n", sanitize.Terminal(r))
		}
		for _, e := range f.EvidenceRefs {
			fmt.Printf("  Evidence: %s\n", sanitize.Terminal(e))
		}
		fmt.Printf("  Status: %s    Endpoint corroboration: %s\n", f.Status, f.Endpoint)
		atlas := f.MitreATLAS
		if atlas == "" {
			atlas = "not mapped (no valid technique)"
		}
		fmt.Printf("  MITRE ATLAS: %s\n", atlas)
	}
	fmt.Printf("\nfindings written to %s\n", filepath.Join(dir, "findings.json"))
	return 0
}

// cmdSimulate generates a synthetic incident profile.
func cmdSimulate(args []string) int {
	fs := flag.NewFlagSet("simulate", flag.ContinueOnError)
	scenario := fs.String("scenario", "orphan-agent", "scenario id")
	out := fs.String("out", "simulated-profile", "output profile root")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	switch *scenario {
	case "orphan-agent":
		if err := simulate.OrphanAgent(*out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown scenario %q; available: %v\n", *scenario, simulate.Scenarios)
		return 2
	}
	fmt.Printf("Synthetic scenario %q written to %s\n", *scenario, *out)
	fmt.Printf("Next: agentdfir collect --product claude --path %s\n", *out)
	return 0
}

func writeJSONL(path string, n int, get func(int) any) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for i := 0; i < n; i++ {
		if err := enc.Encode(get(i)); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}
