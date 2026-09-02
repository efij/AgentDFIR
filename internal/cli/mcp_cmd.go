package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/mcpaudit"
	"github.com/efij/AgentDFIR/internal/normalize"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/schema"
)

const mcpUsage = `usage:
  agentdfir mcp audit [<package-dir>] [flags]     audit MCP servers in a sealed package
  agentdfir mcp audit --profile <root> [flags]    audit a live host or offline profile root
                                                   (default: current user's home)
flags:
  --json                      machine-readable output (inventory + findings + gateway summary)
  --out <file>                write the JSON report here (package mode default: <pkg>/detections/mcp-audit.json)
  --write-baseline <file>     snapshot the inventory as a known-good baseline
  --baseline <file>           compare against a baseline: MCP_SERVER_ADDED/REMOVED/CHANGED
  --gateway-log <jsonl>       MCP gateway log to correlate with transcript calls (package mode)
  --gateway-map <json>        field-name map for the gateway log (defaults: ts, call_id, tool, backend,
                              status, latency_ms, actor, decision, error)
  --gateway-server <name>     transcript server name(s) routed through the gateway (repeatable; default all)
  --error-threshold <n>       backend error count that raises MCP_GATEWAY_BACKEND_ERRORS (default 3)

Read-only: never launches, resolves or contacts an MCP server.
`

type mcpReport struct {
	Inventory *mcpaudit.Inventory      `json:"inventory"`
	Findings  []schema.Finding         `json:"findings"`
	Gateway   *mcpaudit.GatewaySummary `json:"gateway,omitempty"`
}

func cmdMCP(args []string) int {
	if len(args) < 1 || args[0] != "audit" {
		fmt.Fprint(os.Stderr, mcpUsage)
		return 2
	}
	fs := flag.NewFlagSet("mcp audit", flag.ContinueOnError)
	profile := fs.String("profile", "", "live/offline profile root")
	asJSON := fs.Bool("json", false, "JSON output")
	out := fs.String("out", "", "JSON report path")
	writeBase := fs.String("write-baseline", "", "write baseline")
	baseline := fs.String("baseline", "", "compare with baseline")
	gwLog := fs.String("gateway-log", "", "gateway JSONL log")
	gwMap := fs.String("gateway-map", "", "gateway field map JSON")
	errThresh := fs.Int("error-threshold", 3, "backend error threshold")
	var gwServers multiFlag
	fs.Var(&gwServers, "gateway-server", "server routed via gateway")
	pkg, rest := splitPositional(args[1:])
	if err := fs.Parse(rest); err != nil || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprint(os.Stderr, mcpUsage)
		return 2
	}
	if pkg == "" && fs.NArg() == 1 {
		pkg = fs.Arg(0)
	}

	var inv *mcpaudit.Inventory
	var findings []schema.Finding
	rep := mcpReport{}
	switch {
	case pkg != "":
		if *profile != "" {
			fmt.Fprintln(os.Stderr, "use either a package or --profile, not both")
			return 2
		}
		i, extra, err := mcpaudit.ScanPackage(pkg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		inv = i
		findings = append(findings, extra...)
	default:
		root := *profile
		if root == "" {
			home, err := os.UserHomeDir()
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				return 1
			}
			root = home
		}
		if *gwLog != "" {
			fmt.Fprintln(os.Stderr, "--gateway-log needs a package (transcripts to correlate with)")
			return 2
		}
		if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
			fmt.Fprintf(os.Stderr, "profile root %s is not a directory\n", sanitize.Terminal(root))
			return 2
		}
		inv = mcpaudit.ScanProfile(root)
	}
	findings = append(findings, mcpaudit.Evaluate(inv)...)

	if *baseline != "" {
		b, err := mcpaudit.LoadBaseline(*baseline)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		findings = append(findings, mcpaudit.Compare(inv, b)...)
	}
	if *writeBase != "" {
		if err := mcpaudit.WriteBaseline(inv, *writeBase); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	if *gwLog != "" {
		m := mcpaudit.DefaultGatewayMap
		if *gwMap != "" {
			data, err := os.ReadFile(*gwMap)
			if err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				return 1
			}
			if err := json.Unmarshal(data, &m); err != nil {
				fmt.Fprintln(os.Stderr, "gateway map:", err)
				return 1
			}
		}
		records, unparsed, err := mcpaudit.LoadGatewayLog(*gwLog, m)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		res, err := normalize.ParsePackage(pkg)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		sum, gf := mcpaudit.CorrelateGateway(res.Events, records, gwServers, *errThresh)
		sum.Unparsed = unparsed
		rep.Gateway = &sum
		findings = append(findings, gf...)
	}
	sortFindings(findings)
	rep.Inventory, rep.Findings = inv, findings

	// Persist.
	dest := *out
	if dest == "" && pkg != "" {
		dest = filepath.Join(pkg, "detections", "mcp-audit.json")
	}
	if dest != "" {
		_ = os.MkdirAll(filepath.Dir(dest), 0o700)
		data, _ := json.MarshalIndent(rep, "", "  ")
		if err := os.WriteFile(dest, append(data, '\n'), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	if *asJSON {
		data, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(data))
		return exitFor(findings)
	}
	printMCPReport(rep, dest)
	return exitFor(findings)
}

func printMCPReport(rep mcpReport, dest string) {
	inv := rep.Inventory
	fmt.Printf("MCP audit — %s (%s mode)\n", sanitize.Terminal(inv.Source), inv.Mode)
	fmt.Printf("Configs scanned: %d   Servers: %d   Host settings: %d\n\n", len(inv.Configs), len(inv.Servers), len(inv.Settings))
	if len(inv.Servers) > 0 {
		fmt.Printf("  %-14s %-22s %-8s %-6s %-7s %s\n", "HOST", "SERVER", "SCOPE", "TRANS", "PINNED", "IDENTITY")
		for _, s := range inv.Servers {
			pin := "-"
			if s.Command != "" {
				pin = "yes"
				if !s.Pinned {
					pin = "NO"
				}
			}
			id := s.Identity()
			if s.Package != "" {
				id = s.PackageMgr + " " + s.Package
			}
			if r := []rune(id); len(r) > 60 {
				id = string(r[:60]) + "…"
			}
			flags := ""
			if s.Disabled {
				flags += " [disabled]"
			}
			if len(s.AutoAllow) > 0 {
				flags += " [auto-allow]"
			}
			if s.SHA256 != "" {
				flags += " sha256:" + s.SHA256[:12]
			}
			fmt.Printf("  %-14s %-22s %-8s %-6s %-7s %s%s\n", s.Host, trimTo(sanitize.Terminal(s.Name), 22), s.Scope, trimTo(s.Transport, 6), pin, sanitize.Terminal(id), flags)
		}
		fmt.Println()
	}
	for _, p := range inv.Problems {
		fmt.Printf("  problem: %s\n", sanitize.Terminal(p))
	}
	if g := rep.Gateway; g != nil {
		fmt.Printf("Gateway log: %d records, %d matched to transcript, %d gateway-only, %d transcript-only, %d denied, %d errors, p95 %d ms",
			g.Records, g.Matched, g.GatewayOnly, g.AgentOnly, g.Denied, g.Errors, g.P95LatencyMS)
		if g.Unparsed > 0 {
			fmt.Printf(", %d unparsed lines", g.Unparsed)
		}
		fmt.Println()
		if len(g.Backends) > 0 {
			bs := make([]string, 0, len(g.Backends))
			for b, n := range g.Backends {
				bs = append(bs, fmt.Sprintf("%s(%d)", b, n))
			}
			sort.Strings(bs)
			fmt.Printf("  backends: %s\n", sanitize.Terminal(strings.Join(bs, " ")))
		}
		fmt.Println()
	}
	fmt.Printf("%d finding(s):\n", len(rep.Findings))
	for _, f := range rep.Findings {
		fmt.Printf("%s — %s [%s]\n", f.Severity, f.Title, f.RuleID)
		fmt.Printf("  Finding: %s\n", sanitize.Terminal(f.Description))
		for _, r := range f.Related {
			if strings.HasPrefix(r, "host: ") || strings.HasPrefix(r, "transport: ") {
				continue
			}
			fmt.Printf("  Related: %s\n", sanitize.Terminal(r))
		}
		for _, e := range f.EvidenceRefs {
			fmt.Printf("  Evidence: %s\n", sanitize.Terminal(e))
		}
		if f.MitreATTACK != "" || f.MitreATLAS != "" {
			fmt.Printf("  MITRE: %s %s\n", f.MitreATTACK, f.MitreATLAS)
		}
	}
	if dest != "" {
		fmt.Printf("\nreport written to %s\n", dest)
	}
}

func sortFindings(f []schema.Finding) {
	rank := map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
	sort.SliceStable(f, func(i, j int) bool { return rank[f[i].Severity] > rank[f[j].Severity] })
}

// exitFor: 0 no findings, 3 findings present (scriptable), like triage.
func exitFor(f []schema.Finding) int {
	for _, x := range f {
		if x.Severity != "INFO" {
			return 3
		}
	}
	return 0
}

func trimTo(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }
