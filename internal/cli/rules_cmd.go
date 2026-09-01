package cli

import (
	"fmt"
	"os"

	"github.com/efij/AgentDFIR/internal/rulepack"
)

// cmdRules validates declarative rule packs with the real loader — the
// same validation triage applies, so a pack that passes here will load.
func cmdRules(args []string) int {
	if len(args) < 2 || args[0] != "validate" {
		fmt.Fprintln(os.Stderr, "usage: agentdfir rules validate <dir>")
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
}
