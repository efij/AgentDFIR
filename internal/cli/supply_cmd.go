package cli

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/baseline"
	"github.com/efij/AgentDFIR/v4/internal/crosscase"
	"github.com/efij/AgentDFIR/v4/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v4/internal/sanitize"
	"github.com/efij/AgentDFIR/v4/internal/supplychain"
)

const supplyUsage = `usage: agentdfir supply-chain [<case.adfir>] [--json] [--out file] [--since T] [--baseline file]... [--peer case]... [--window 10m]

The agent environment's supply chain: every skill, plugin, slash command,
sub-agent, hook, MCP server, IDE extension and instruction file, where it
came from (marketplace, npm/pypi package, git remote and commit, local
path), first and last seen with the clock each time came from, its hash
across the case's rounds and the baselines given, MCP tool-definition and
settings drift with permission expansion, and component → invocation →
command → process links. Verified links (hash-identical artifact, logged
invocation, explicit reference) and inferred links (time proximity, name
match) are listed apart and never mixed.
  --since     only activity at or after T (RFC 3339 or YYYY-MM-DD)
  --baseline  an MCP baseline (mcp audit --write-baseline) or a package
              snapshot (agentdfir baseline); repeatable
  --peer      another analyzed case: components with the same hash there
              (cross-host reuse); repeatable
  --out       write the report to a file instead of stdout
Default: this machine's case. Every analysis stores the report as
normalized/supplychain.json (docs/supply-chain.md).
`

// cmdSupplyChain is `agentdfir supply-chain`.
func cmdSupplyChain(args []string) int {
	fs := flag.NewFlagSet("supply-chain", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the structured report")
	out := fs.String("out", "", "write the report to this file")
	since := fs.String("since", "", "only activity at or after this time")
	window := fs.Duration("window", 0, "inference window for follow-on commands (default 10m)")
	var baselines, peers multiFlag
	fs.Var(&baselines, "baseline", "baseline file (repeatable)")
	fs.Var(&peers, "peer", "another analyzed case (repeatable)")
	pkg, ok := graphPackage(fs, args, supplyUsage)
	if !ok {
		return 2
	}
	var sinceT time.Time
	if *since != "" {
		t, err := parseSince(*since)
		if err != nil {
			fmt.Fprintf(os.Stderr, "--since: %s\n", sanitize.Terminal(err.Error()))
			return 2
		}
		sinceT = t
	}
	log := io.Writer(os.Stdout)
	if *asJSON || *out != "" {
		log = os.Stderr
	}
	if _, err := analysis.Ensure(pkg, log); err != nil {
		fmt.Fprintln(os.Stderr, "error:", sanitize.Terminal(err.Error()))
		return 1
	}
	var rep *supplychain.Report
	if len(baselines) == 0 && *window == 0 {
		rep = analysis.LoadSupplyChain(pkg)
	}
	if rep == nil {
		in := analysis.SupplyInput(pkg, nil, nil, nil, nil, nil)
		for _, f := range baselines {
			if err := addBaseline(&in, f); err != nil {
				fmt.Fprintf(os.Stderr, "--baseline %s: %s\n", sanitize.Terminal(f), sanitize.Terminal(err.Error()))
				return 2
			}
		}
		rep = supplychain.Build(in, supplychain.Options{Window: *window})
	}
	if len(peers) > 0 {
		var ps []supplychain.Peer
		for i, p := range peers {
			label := fmt.Sprintf("C%d", i+2)
			if why := analysis.StaleReason(p); why != "" {
				fmt.Fprintf(os.Stderr, "%s (%s): analysis is not current (%s). Run: agentdfir analyze %s\n", label, sanitize.Terminal(p), sanitize.Terminal(why), sanitize.Terminal(p))
				return 1
			}
			pr := analysis.LoadSupplyChain(p)
			if pr == nil {
				fmt.Fprintf(os.Stderr, "%s (%s): no supply-chain report; re-run agentdfir analyze %s\n", label, sanitize.Terminal(p), sanitize.Terminal(p))
				return 1
			}
			integ := crosscase.VerifyPackage(p)
			ps = append(ps, supplychain.Peer{Label: label, CaseID: pr.CaseID, Host: pr.Host, Report: pr, Unverified: integ.Result != "VERIFIED"})
			if integ.Result != "VERIFIED" {
				rep.Notes = append(rep.Notes, fmt.Sprintf("%s: seal does not verify (%s); its reuse entries are marked", label, strings.Join(integ.Problems, "; ")))
			}
		}
		supplychain.CrossCase(rep, ps)
	}
	if !sinceT.IsZero() {
		rep = supplychain.Since(rep, sinceT)
	}
	var buf bytes.Buffer
	if *asJSON {
		enc := json.NewEncoder(&buf)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	} else {
		supplychain.WriteText(&buf, rep)
	}
	if *out != "" {
		if err := os.WriteFile(*out, buf.Bytes(), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "error:", sanitize.Terminal(err.Error()))
			return 1
		}
		fmt.Fprintf(os.Stderr, "Supply-chain report written to %s\n", sanitize.Terminal(*out))
		return 0
	}
	_, _ = os.Stdout.Write(buf.Bytes())
	return 0
}

func parseSince(s string) (time.Time, error) {
	for _, f := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"} {
		if t, err := time.Parse(f, s); err == nil {
			return t.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("%q is not RFC 3339 or YYYY-MM-DD", s)
}

// addBaseline reads either baseline format: an MCP inventory baseline
// (has "servers") or a package snapshot (has "artifacts").
func addBaseline(in *supplychain.Input, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err != nil {
		return fmt.Errorf("not JSON: %v", err)
	}
	switch {
	case probe["servers"] != nil:
		b, err := mcpaudit.LoadBaseline(path)
		if err != nil {
			return err
		}
		in.MCPBaselines = append(in.MCPBaselines, supplychain.MCPBaseline{Label: "baseline " + path, B: b})
	case probe["artifacts"] != nil:
		b, err := baseline.Load(path)
		if err != nil {
			return err
		}
		in.Baselines = append(in.Baselines, supplychain.PackageBaseline{Label: "snapshot " + path, B: b})
	default:
		return fmt.Errorf("UNSUPPORTED baseline format: neither an MCP baseline (servers) nor a package snapshot (artifacts)")
	}
	return nil
}
