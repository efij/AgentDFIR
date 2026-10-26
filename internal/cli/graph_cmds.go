package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/analysis"
	"github.com/efij/AgentDFIR/v5/internal/crosscase"
	"github.com/efij/AgentDFIR/v5/internal/gaps"
	"github.com/efij/AgentDFIR/v5/internal/lineage"
	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/sanitize"
)

// The investigation layer: what the case does not show (gaps), who did
// what through whom (lineage), and what several cases share
// (correlate-cases). docs/investigation-graph.md documents the JSON.

const gapsUsage = `usage: agentdfir gaps [<case.adfir>] [--json]

What the evidence does not show, and what to collect next: silences inside
sessions, truncated or rewritten transcripts, each product's evidence window
against its collection, which agent activity a second witness (endpoint
telemetry, cloud audit log, host witness, shell history) covers and why the
rest is unverified, clock disagreements, and agents whose parent or subagent
records are missing. Every item is KNOWN, UNKNOWN or VERIFY NEXT; nothing is
inferred. Default: this machine's case. The same report is stored by every
analysis as normalized/coverage.json.
`

// cmdGaps is `agentdfir gaps`.
func cmdGaps(args []string) int {
	fs := flag.NewFlagSet("gaps", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the structured report (normalized/coverage.json)")
	pkg, ok := graphPackage(fs, args, gapsUsage)
	if !ok {
		return 2
	}
	log := io.Writer(os.Stdout)
	if *asJSON {
		log = os.Stderr
	}
	if _, err := analysis.Ensure(pkg, log); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	rep := analysis.LoadCoverage(pkg)
	if rep == nil {
		// Written by every analysis; built here when that stage could not
		// write it (a read-only overlay, a note in analysis.json says why).
		rep = gaps.Build(analysis.GapsInput(pkg, nil, nil, analysis.LoadCorrelation(pkg)), gaps.Options{})
	}
	if *asJSON {
		return writeJSONOut(rep)
	}
	gaps.WriteText(os.Stdout, rep)
	return 0
}

const lineageUsage = `usage: agentdfir lineage [<case.adfir>] [--finding <id> | --session <id>] [--format text|json|mermaid|dot] [--max-nodes N] [--max-edges N]

Human (account) → agent → subagent → tool call → process → destination / file /
cloud resource. Every edge names its basis (recorded parent id, tool_use_id
match, endpoint pid/ppid, a path or destination named in the recorded
command, or a scored correlation), the evidence state of that step and the
source references; nothing is joined by time proximity alone.
  --finding  index in findings.json (as the explorer numbers them), the finding
             key "finding:RULE|evidence-ref", or a rule id (every finding of it)
  --session  one session id
Default: this machine's case, whole case, text. The whole-case graph is also
stored by every analysis as normalized/lineage.json (bounded).
`

// cmdLineage is `agentdfir lineage`.
func cmdLineage(args []string) int {
	fs := flag.NewFlagSet("lineage", flag.ContinueOnError)
	finding := fs.String("finding", "", "one finding (index, key, or rule id)")
	session := fs.String("session", "", "one session id")
	format := fs.String("format", "text", "text|json|mermaid|dot")
	maxNodes := fs.Int("max-nodes", 0, "node bound (default 20000)")
	maxEdges := fs.Int("max-edges", 0, "edge bound (default 50000)")
	pkg, ok := graphPackage(fs, args, lineageUsage)
	if !ok {
		return 2
	}
	switch *format {
	case "text", "json", "mermaid", "dot":
	default:
		fmt.Fprintf(os.Stderr, "unknown format %q (text|json|mermaid|dot)\n", sanitize.Terminal(*format))
		return 2
	}
	if *finding != "" && *session != "" {
		fmt.Fprintln(os.Stderr, "--finding and --session are exclusive")
		return 2
	}
	log := io.Writer(os.Stdout)
	if *format != "text" {
		log = os.Stderr
	}
	if _, err := analysis.Ensure(pkg, log); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	var g *lineage.Graph
	if *finding == "" && *session == "" && *maxNodes == 0 && *maxEdges == 0 {
		g = loadLineage(pkg)
	}
	if g == nil {
		var err error
		g, err = lineage.Build(analysis.LineageInput(pkg, nil, nil, analysis.LoadCorrelation(pkg)),
			lineage.Options{SessionID: *session, Finding: *finding, MaxNodes: *maxNodes, MaxEdges: *maxEdges})
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", sanitize.Terminal(err.Error()))
			return 1
		}
	}
	switch *format {
	case "json":
		return writeJSONOut(g)
	case "mermaid":
		lineage.WriteMermaid(os.Stdout, g)
	case "dot":
		lineage.WriteDOT(os.Stdout, g)
	default:
		lineage.WriteText(os.Stdout, g)
	}
	return 0
}

func loadLineage(pkg string) *lineage.Graph {
	data, err := overlay.ReadFile(filepath.Join(pkg, "normalized", analysis.LineageFile))
	if err != nil {
		return nil
	}
	var g lineage.Graph
	if json.Unmarshal(data, &g) != nil || g.Schema != lineage.Schema {
		return nil
	}
	return &g
}

const correlateCasesUsage = `usage: agentdfir correlate-cases <case-a> <case-b> [<case-c> ...] [--graph] [--json] [--allow-unverified] [--include-common]

What two or more analyzed cases have in common: outbound destinations, incident
indicator hits, credentials (by SHA-256 fingerprint, never the value),
instruction files (CLAUDE.md, AGENTS.md … by content hash), MCP server packages,
URLs and tool definitions, reused session and agent ids, AI accounts, and a
timeline of the shared items. Hosts and OS users stay separate; identities are
linked only by an exact shared account email or account uuid, and the link
names it. Every package's seal is verified first (full re-hash); one that fails
is refused unless --allow-unverified, which marks every result from it.
Packages must be analyzed by this version (agentdfir analyze <case>).
--graph adds a typed activity graph (hosts, sessions, agents, MCP tools, cloud
principals and resources, commits, files, destinations) whose cross-case edges
are graded strong / moderate / weak with evidence on both sides and a time
relation, plus the cross-case findings AGENT_CROSS_HOST_ACTIVITY and
CHAIN_CROSS_HOST_AGENT_PROPAGATION. Weak joins never raise a finding.
(agentdfir correlate is endpoint-telemetry correlation for one case.)
`

// cmdCorrelateCases is `agentdfir correlate-cases`.
func cmdCorrelateCases(args []string) int {
	fs := flag.NewFlagSet("correlate-cases", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the structured report")
	allow := fs.Bool("allow-unverified", false, "compare packages whose seal does not verify (results are marked)")
	common := fs.Bool("include-common", false, "also compare allowlisted destinations (model providers, package registries)")
	graph := fs.Bool("graph", false, "also build the cross-case activity graph and its findings")
	var pkgs []string
	rest := args
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		pkgs = append(pkgs, rest[0])
		rest = rest[1:]
	}
	fs.SetOutput(io.Discard)
	if err := fs.Parse(rest); err != nil {
		fmt.Fprint(os.Stderr, correlateCasesUsage)
		return 2
	}
	pkgs = append(pkgs, fs.Args()...)
	if len(pkgs) < 2 {
		fmt.Fprint(os.Stderr, correlateCasesUsage)
		return 2
	}
	rep, err := crosscase.Run(pkgs, crosscase.Options{AllowUnverified: *allow, IncludeCommon: *common, Graph: *graph})
	if err != nil {
		var re *crosscase.RefusedError
		if errors.As(err, &re) {
			fmt.Fprintln(os.Stderr, "Cannot compare these cases:")
			for _, p := range re.Problems {
				fmt.Fprintln(os.Stderr, "  - "+sanitize.Terminal(p))
			}
			return 1
		}
		fmt.Fprintln(os.Stderr, "error:", sanitize.Terminal(err.Error()))
		return 2
	}
	if *asJSON {
		return writeJSONOut(rep)
	}
	crosscase.WriteText(os.Stdout, rep)
	crosscase.WriteGraphText(os.Stdout, rep.Graph)
	return 0
}

// graphPackage parses `[<pkg>] [flags]` / `[flags] [<pkg>]` and falls back
// to this machine's case.
func graphPackage(fs *flag.FlagSet, args []string, usage string) (string, bool) {
	fs.SetOutput(io.Discard)
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || fs.NArg() > 1 || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprint(os.Stderr, usage)
		return "", false
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}
	if pkg == "" {
		pkg = defaultCase()
	}
	if pkg == "" {
		fmt.Fprint(os.Stderr, usage)
		return "", false
	}
	return pkg, true
}

func writeJSONOut(v any) int {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(v); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	return 0
}
