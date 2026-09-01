package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/efij/AgentDFIR/internal/report"
	"github.com/efij/AgentDFIR/internal/sanitize"
)

// inspectPatterns mirrors the detection patterns; values are printed
// only under --reveal-sensitive (explicit analyst action, plan §18).
var inspectPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"AWS_ACCESS_KEY", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GITHUB_TOKEN", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)},
	{"SLACK_TOKEN", regexp.MustCompile(`\bxox[bpars]-[A-Za-z0-9-]{10,}\b`)},
	{"ANTHROPIC_API_KEY", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{"OPENAI_API_KEY", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`)},
	{"PRIVATE_KEY_BLOCK", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

// cmdInspect lists a package's artifacts and sensitive-content matches.
// Secret values stay [REDACTED] unless --reveal-sensitive is passed.
func cmdInspect(args []string) int {
	fs := flag.NewFlagSet("inspect", flag.ContinueOnError)
	reveal := fs.Bool("reveal-sensitive", false, "print matched sensitive values (explicit analyst action)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir inspect <package-dir> [--reveal-sensitive]")
		return 2
	}
	pkg := fs.Arg(0)
	man, err := report.ReadManifest(pkg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	fmt.Printf("Case %s — %d artifact record(s)\n\n", sanitize.Terminal(man.CaseID), len(man.Artifacts))
	fmt.Printf("%-8s %-11s %-18s %s\n", "STATUS", "SIZE", "TYPE", "LOGICAL PATH")
	for _, a := range man.Artifacts {
		fmt.Printf("%-8s %-11d %-18s %s\n", a.Status, a.Size,
			sanitize.Terminal(a.ArtifactType), sanitize.Terminal(a.LogicalPath))
	}

	fmt.Println("\nSensitive-content scan (agent sessions, history, credentials):")
	if *reveal {
		fmt.Println("!! --reveal-sensitive active: values will be printed. Handle output as evidence.")
	}
	hits := 0
	for _, a := range man.Artifacts {
		if a.Status != "OK" {
			continue
		}
		switch a.ArtifactType {
		case "agent_session", "prompt_history", "credentials", "product_config":
		default:
			continue
		}
		data, err := os.ReadFile(filepath.Join(pkg, "raw", a.ArtifactID))
		if err != nil || len(data) > 16<<20 {
			continue
		}
		for _, p := range inspectPatterns {
			for _, loc := range p.re.FindAllIndex(data, 10) {
				hits++
				val := "[REDACTED]"
				if *reveal {
					val = sanitize.Terminal(string(data[loc[0]:loc[1]]))
				}
				fmt.Printf("  %s detected\n    Evidence: %s (artifact %.12s, offset %d)\n    Value: %s\n",
					p.name, sanitize.Terminal(a.LogicalPath), a.ArtifactID, loc[0], val)
			}
		}
	}
	if hits == 0 {
		fmt.Println("  none detected")
	} else if !*reveal {
		fmt.Println("\nValues are redacted by default; re-run with --reveal-sensitive to display them.")
	}
	return 0
}
