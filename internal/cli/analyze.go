package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/correlate"
	"github.com/efij/AgentDFIR/internal/detect"
	"github.com/efij/AgentDFIR/internal/endpoint"
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
	var endpointLogs multiFlag
	fs.Var(&endpointLogs, "endpoint", "OS telemetry log to corroborate against (auditd, Sysmon XML, JSONL/CSV export); repeatable")
	rulesDir := fs.String("rules", "", "directory of declarative JSON rule packs")
	honeyFile := fs.String("honeytokens", "", "file of planted canary markers (one per line)")
	spawnTh := fs.Int("spawn-threshold", 10, "AGENT_SPAWN_EXPLOSION per-session threshold")
	knownDest := fs.String("known-destinations", "", "comma-separated extra allowlisted network destinations")
	// Package may come first or last (`triage pkg --endpoint x` is how people type it).
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || (pkg == "" && fs.NArg() != 1) || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprintln(os.Stderr, "usage: agentdfir triage <package-dir> [--endpoint <log>]... [--shell-history <path>] [--rules <dir>]")
		return 2
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}
	// Streaming pipeline (v0.5.1): events are written to the overlay as
	// they are parsed and never all held in memory; detection re-reads
	// the overlay in bounded passes. Memory scales with sessions/agents,
	// not event count.
	dir := filepath.Join(pkg, "normalized")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	evFile, err := os.OpenFile(filepath.Join(dir, "events.jsonl"), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	enc := json.NewEncoder(evFile)
	sr, err := normalize.ParseStream(pkg, func(ev schema.Event) error { return enc.Encode(ev) })
	if err != nil {
		evFile.Close()
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	evFile.Close()
	if err := writeJSONL(filepath.Join(dir, "entities.jsonl"), len(sr.Entities), func(i int) any { return sr.Entities[i] }); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if err := writeJSONL(filepath.Join(dir, "relationships.jsonl"), len(sr.Relationships), func(i int) any { return sr.Relationships[i] }); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Normalized: %d events, %d entities, %d relationships -> %s\n",
		sr.EventCount, len(sr.Entities), len(sr.Relationships), dir)
	var extraDest []string
	if *knownDest != "" {
		extraDest = strings.Split(*knownDest, ",")
	}
	// Second-witness correlation runs BEFORE detection so findings carry
	// the upgraded/downgraded corroboration states; results are persisted
	// to the overlay (shell-history states used to be lost here).
	var corrFindings []schema.Finding
	if *triageShellHistory != "" || len(endpointLogs) > 0 {
		evs := loadEvents(dir)
		if *triageShellHistory != "" {
			cres, cerr := correlate.Apply(evs, &correlate.ShellHistoryAdapter{Path: *triageShellHistory})
			if cerr == nil && cres.Corroborated > 0 {
				fmt.Printf("Endpoint correlation: %d tool call(s) corroborated by shell history.\n", cres.Corroborated)
			}
			if len(endpointLogs) == 0 {
				if err := writeJSONL(filepath.Join(dir, "events.jsonl"), len(evs), func(i int) any { return evs[i] }); err != nil {
					fmt.Fprintln(os.Stderr, "error:", err)
					return 1
				}
			}
		}
		if len(endpointLogs) > 0 {
			f, _, rc := runEndpointCorrelation(pkg, endpointLogs, endpoint.FormatAuto, correlate.EndpointOptions{KnownDests: extraDest}, evs)
			if rc != 0 {
				return rc
			}
			corrFindings = f
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
	findings, err := detect.RunStream(pkg, sr.Entities, detect.Options{
		Honeytokens: honey, SpawnThreshold: *spawnTh, KnownDestinations: extraDest,
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *rulesDir != "" {
		packs, perr := rulepack.LoadDir(*rulesDir)
		if perr != nil {
			fmt.Fprintln(os.Stderr, "rule packs:", perr)
			return 1
		}
		extra, perr := rulepack.Apply(packs, &schema.Normalized{Events: loadEvents(dir)}, pkg)
		if perr != nil {
			fmt.Fprintln(os.Stderr, "rule packs:", perr)
			return 1
		}
		if len(extra) > 0 {
			fmt.Printf("Rule packs: %d pack(s) contributed %d finding(s).\n", len(packs), len(extra))
			findings = append(findings, extra...)
		}
	}

	if len(corrFindings) > 0 {
		findings = append(findings, corrFindings...)
	}
	detDir := filepath.Join(pkg, "detections")
	if err := os.MkdirAll(detDir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	data, _ := json.MarshalIndent(findings, "", "  ")
	if err := os.WriteFile(filepath.Join(detDir, "findings.json"), append(data, '\n'), 0o600); err != nil {
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
	fmt.Printf("\nfindings written to %s\n", filepath.Join(detDir, "findings.json"))
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

// loadEvents reads back the streamed events overlay (used only by the
// optional --shell-history and --rules features, which need full events).
func loadEvents(normalizedDir string) []schema.Event {
	f, err := os.Open(filepath.Join(normalizedDir, "events.jsonl"))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []schema.Event
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var ev schema.Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil {
			out = append(out, ev)
		}
	}
	return out
}

// writeOverlay writes the normalized/ overlay from an already-parsed
// result, avoiding a second parse.
func writeOverlay(pkg string, res *schema.Normalized) int {
	dir := filepath.Join(pkg, "normalized")
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
