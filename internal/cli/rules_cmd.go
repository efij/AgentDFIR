package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/efij/AgentDFIR/internal/export"
	"github.com/efij/AgentDFIR/internal/rulepack"
)

const rulesUsage = `usage:
  agentdfir rules validate <dir>                 validate declarative rule packs
  agentdfir rules export --sigma <dir> [--out d] convert rule packs to Sigma YAML (one file per rule)
`

// cmdRules validates declarative rule packs with the real loader — the
// same validation triage applies, so a pack that passes here will load —
// and converts them to Sigma for SIEM pipelines.
func cmdRules(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, rulesUsage)
		return 2
	}
	switch args[0] {
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
		fmt.Printf("Validated %d pack(s), %d rule(s).\n", len(packs), n)
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
