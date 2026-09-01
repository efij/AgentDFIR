package cli

import (
	"flag"
	"fmt"
	"os"

	"github.com/efij/AgentDFIR/internal/baseline"
	"github.com/efij/AgentDFIR/internal/sanitize"
)

// cmdDiff compares config-relevant state between two sealed packages.
func cmdDiff(args []string) int {
	if len(args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir diff <package-a> <package-b>")
		return 2
	}
	changes, err := baseline.Diff(args[0], args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if len(changes) == 0 {
		fmt.Println("No configuration drift between packages.")
		return 0
	}
	fmt.Printf("%d change(s) (%s -> %s):\n", len(changes), args[0], args[1])
	printChanges(changes)
	return 0
}

// cmdBaseline creates or checks org known-good profiles.
func cmdBaseline(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir baseline create|check [flags]")
		return 2
	}
	switch args[0] {
	case "create":
		fs := flag.NewFlagSet("baseline create", flag.ContinueOnError)
		out := fs.String("out", "baseline.json", "baseline output file")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "usage: agentdfir baseline create <package-dir> [--out baseline.json]")
			return 2
		}
		b, err := baseline.Snapshot(fs.Arg(0))
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if err := b.Save(*out); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("Baseline written to %s (%d config artifacts, %d MCP servers)\n",
			*out, len(b.Artifacts), len(b.MCPServers))
		return 0
	case "check":
		fs := flag.NewFlagSet("baseline check", flag.ContinueOnError)
		basePath := fs.String("baseline", "baseline.json", "baseline file")
		if err := fs.Parse(args[1:]); err != nil || fs.NArg() != 1 {
			fmt.Fprintln(os.Stderr, "usage: agentdfir baseline check <package-dir> [--baseline baseline.json]")
			return 2
		}
		b, err := baseline.Load(*basePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		changes, err := baseline.Check(fs.Arg(0), b)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		if len(changes) == 0 {
			fmt.Println("No drift from baseline.")
			return 0
		}
		fmt.Printf("%d drift item(s) from baseline %s:\n", len(changes), *basePath)
		printChanges(changes)
		return 1
	default:
		fmt.Fprintln(os.Stderr, "usage: agentdfir baseline create|check [flags]")
		return 2
	}
}

func printChanges(changes []baseline.Change) {
	for _, c := range changes {
		rule := baseline.RuleForChange(c)
		detail := c.Detail
		if detail != "" {
			detail = " — " + detail
		}
		fmt.Printf("  %-22s [%s] %s%s\n", c.Kind, rule,
			sanitize.Terminal(c.LogicalPath), sanitize.Terminal(detail))
	}
}
