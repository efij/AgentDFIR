package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"

	"github.com/efij/AgentDFIR/v2/internal/catalog"
	"github.com/efij/AgentDFIR/v2/internal/chain"
	"github.com/efij/AgentDFIR/v2/internal/export"
	"github.com/efij/AgentDFIR/v2/internal/rulepack"
)

const rulesUsage = `usage:
  agentdfir rules list [--packs <dir>] [--json]  every detection (built-in + packs) with MITRE ATT&CK / ATLAS mapping
  agentdfir rules validate <dir>                 validate declarative rule packs and *.chains.json attack chains
  agentdfir rules export --sigma <dir> [--out d] convert rule packs to Sigma YAML (one file per rule)
`

// listedRule is one row of `rules list`: built-in rules come from the
// catalog, pack rules from the loaded packs, in one shape.
type listedRule struct {
	ID          string `json:"id"`
	Source      string `json:"source"` // "builtin" or the pack name
	Surface     string `json:"surface"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	MitreATTACK string `json:"mitre_attack,omitempty"`
	MitreATLAS  string `json:"mitre_atlas,omitempty"`
	ATLASName   string `json:"mitre_atlas_name,omitempty"`
}

func listRules(packDir string) ([]listedRule, error) {
	var out []listedRule
	for _, r := range catalog.Builtin {
		out = append(out, listedRule{ID: r.ID, Source: "builtin", Surface: r.Surface, Severity: r.MaxSeverity,
			Title: r.Title, MitreATTACK: r.MitreATTACK, MitreATLAS: r.MitreATLAS, ATLASName: rulepack.ATLASName(r.MitreATLAS)})
	}
	// The packs shipped inside the binary are part of the rule set by
	// default, so what `rules list` reports is what an analysis runs.
	packs, _, err := rulepack.Embedded()
	if err != nil {
		return nil, err
	}
	if packDir != "" {
		extra, err := rulepack.LoadDir(packDir)
		if err != nil {
			return nil, err
		}
		packs = append(packs, extra...)
	}
	packs, _ = rulepack.Dedupe(packs)
	for _, p := range packs {
		for _, r := range p.Rules {
			out = append(out, listedRule{ID: r.ID, Source: p.Pack, Surface: r.Match.Type, Severity: r.Severity,
				Title: r.Title, MitreATTACK: r.MitreATTACK, MitreATLAS: r.MitreATLAS, ATLASName: rulepack.ATLASName(r.MitreATLAS)})
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Source != out[j].Source {
			return out[i].Source == "builtin" || (out[j].Source != "builtin" && out[i].Source < out[j].Source)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// cmdRules validates declarative rule packs with the real loader — the
// same validation triage applies, so a pack that passes here will load —
// and converts them to Sigma for SIEM pipelines.
func cmdRules(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, rulesUsage)
		return 2
	}
	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("rules list", flag.ContinueOnError)
		packs := fs.String("packs", "", "rule-pack directory to include (e.g. ./rules)")
		asJSON := fs.Bool("json", false, "machine-readable output")
		if err := fs.Parse(args[1:]); err != nil {
			fmt.Fprint(os.Stderr, rulesUsage)
			return 2
		}
		rows, err := listRules(*packs)
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			return 1
		}
		if *asJSON {
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			if err := enc.Encode(map[string]any{"atlas_version": rulepack.ATLASVersion, "rules": rows}); err != nil {
				fmt.Fprintln(os.Stderr, "error:", err)
				return 1
			}
			return 0
		}
		fmt.Printf("%-9s %-34s %-11s %-11s %-14s %s\n", "SEVERITY", "RULE", "SURFACE", "ATT&CK", "ATLAS", "SOURCE")
		mapped := 0
		for _, r := range rows {
			if r.MitreATTACK != "" || r.MitreATLAS != "" {
				mapped++
			}
			fmt.Printf("%-9s %-34s %-11s %-11s %-14s %s\n", r.Severity, r.ID, r.Surface, dash(r.MitreATTACK), dash(r.MitreATLAS), r.Source)
		}
		fmt.Printf("\n%d rules, %d with a MITRE ATT&CK or ATLAS mapping (ATLAS %s).\n", len(rows), mapped, rulepack.ATLASVersion)
		return 0
	case "validate":
		if len(args) != 2 {
			fmt.Fprint(os.Stderr, rulesUsage)
			return 2
		}
		packs, err := rulepack.LoadDir(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			return 1
		}
		n := 0
		for _, p := range packs {
			n += len(p.Rules)
			fmt.Printf("OK  %s v%s (%d rules)\n", p.Pack, p.Version, len(p.Rules))
		}
		chains, err := chain.LoadDir(args[1])
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		for _, c := range chains {
			fmt.Printf("OK  chain %s [%s] %d steps\n", c.ID, c.Severity, len(c.Steps))
		}
		fmt.Printf("Validated %d pack(s), %d rule(s), %d attack chain(s).\n", len(packs), n, len(chains))
		return 0
	case "export":
		fs := flag.NewFlagSet("rules export", flag.ContinueOnError)
		sigma := fs.String("sigma", "", "rule-pack directory to convert")
		out := fs.String("out", "sigma", "output directory")
		if err := fs.Parse(args[1:]); err != nil || *sigma == "" {
			fmt.Fprint(os.Stderr, rulesUsage)
			return 2
		}
		packs, err := rulepack.LoadDir(*sigma)
		if err != nil {
			fmt.Fprintln(os.Stderr, "INVALID:", err)
			return 1
		}
		written, err := export.WriteSigmaDir(packs, *out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("Wrote %d Sigma rule(s) to %s\n", len(written), *out)
		fmt.Println("Note: command rules target process_creation/CommandLine (portable to EDR telemetry); summary/config/transcript rules need the AgentDFIR OCSF or OTel feed. Built-in stateful rules are not expressible in Sigma.")
		return 0
	default:
		fmt.Fprint(os.Stderr, rulesUsage)
		return 2
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
