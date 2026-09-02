package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/efij/AgentDFIR/internal/analysis"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/normalize"
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

// cmdAnalyze runs EVERY analysis stage in the right order and prints the
// findings. `triage` is the same command (kept for scripts and habit).
func cmdAnalyze(args []string) int {
	fs := flag.NewFlagSet("analyze", flag.ContinueOnError)
	var endpointLogs, gwServers multiFlag
	fs.Var(&endpointLogs, "endpoint", "OS telemetry log (auditd, Sysmon XML, JSONL/CSV export) to check the transcript against; repeatable")
	fs.Var(&gwServers, "gateway-server", "transcript MCP server name routed through the gateway; repeatable")
	shellHistory := fs.String("shell-history", "", "shell history file to check commands against")
	gwLog := fs.String("gateway-log", "", "MCP gateway log (JSONL) to check MCP calls against")
	gwMap := fs.String("gateway-map", "", "field-name map for the gateway log")
	rulesDir := fs.String("rules", "", "directory of extra JSON rule packs")
	honeyFile := fs.String("honeytokens", "", "file of planted canary markers (one per line)")
	spawnTh := fs.Int("spawn-threshold", 10, "AGENT_SPAWN_EXPLOSION per-session threshold")
	knownDest := fs.String("known-destinations", "", "comma-separated extra allowlisted network destinations")
	renorm := fs.Bool("renormalize", false, "re-parse the evidence even if the overlay is current (discards earlier corroboration states)")
	asJSON := fs.Bool("json", false, "print findings as JSON")
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || (pkg == "" && fs.NArg() != 1) || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprintln(os.Stderr, "usage: agentdfir analyze <package-dir> [--endpoint <os-log>]... [--gateway-log <f>] [--rules <dir>] [--honeytokens <f>]")
		return 2
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}
	opts := analysis.Options{EndpointLogs: endpointLogs, ShellHistory: *shellHistory, GatewayLog: *gwLog, GatewayMap: *gwMap,
		GatewayServers: gwServers, RulesDir: *rulesDir, SpawnThreshold: *spawnTh, Renormalize: *renorm, Log: os.Stdout}
	if *honeyFile != "" {
		data, err := os.ReadFile(*honeyFile)
		if err != nil {
			fmt.Fprintln(os.Stderr, "honeytokens:", err)
			return 1
		}
		opts.Honeytokens = strings.Split(string(data), "\n")
	}
	if *knownDest != "" {
		opts.KnownDests = strings.Split(*knownDest, ",")
	}
	if *asJSON {
		opts.Log = nil
	}
	res, err := analysis.Run(pkg, opts)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	for _, n := range res.StageNotes {
		fmt.Fprintln(os.Stderr, "note:", n)
	}
	if *asJSON {
		data, _ := json.MarshalIndent(res.Findings, "", "  ")
		fmt.Println(string(data))
		return exitFor(res.Findings)
	}
	printTriageFindings(res.Findings)
	fmt.Printf("\nResults: %s   (open them: agentdfir serve %s)\n", filepath.Join(pkg, "detections"), pkg)
	return exitFor(res.Findings)
}

// printTriageFindings renders findings the way analysts read them.
func printTriageFindings(findings []schema.Finding) {
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
		if f.MitreATTACK != "" || f.MitreATLAS != "" {
			fmt.Printf("  MITRE: %s %s\n", f.MitreATTACK, f.MitreATLAS)
		}
	}
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
