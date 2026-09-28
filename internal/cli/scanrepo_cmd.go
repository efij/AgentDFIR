package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/export"
	"github.com/efij/AgentDFIR/v3/internal/reposcan"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
)

// cmdScanRepo checks a repository for the files that make an agent run
// something as soon as it opens the folder. Exit 1 when a finding at or
// above --fail-on is present (CI gate), 0 otherwise.
func cmdScanRepo(args []string) int {
	fs := flag.NewFlagSet("scan-repo", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print findings as JSON")
	sarif := fs.String("sarif", "", "write SARIF 2.1.0 to this file (- for stdout) for GitHub code scanning")
	failOn := fs.String("fail-on", "high", "exit 1 when a finding is at or above: critical | high | medium | low | none")
	maxMB := fs.Int("max-file-mb", 4, "largest file read per config (bigger ones are flagged and their prefix checked)")
	dir, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if dir == "" && fs.NArg() == 1 {
		dir = fs.Arg(0)
	}
	if dir == "" {
		dir = "."
	}
	threshold := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "none": 99}[strings.ToLower(*failOn)]
	if threshold == 0 {
		fmt.Fprintln(os.Stderr, "--fail-on must be critical, high, medium, low or none")
		return 2
	}
	res, err := reposcan.Scan(dir, reposcan.Options{MaxFileBytes: int64(*maxMB) << 20})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if *sarif != "" {
		doc := export.SARIF(res.Findings, "scan-repo")
		b, _ := json.MarshalIndent(doc, "", "  ")
		if *sarif == "-" {
			os.Stdout.Write(append(b, '\n'))
		} else if err := os.WriteFile(*sarif, append(b, '\n'), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
	}
	switch {
	case *asJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
	case *sarif != "-":
		printScanRepo(res)
	}
	rank := map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}
	for _, f := range res.Findings {
		if rank[f.Severity] >= threshold {
			return 1
		}
	}
	return 0
}

func printScanRepo(res *reposcan.Result) {
	fmt.Printf("scan-repo %s — %d agent-facing file(s) checked, %d finding(s)\n\n", sanitize.Terminal(res.Root), res.Files, len(res.Findings))
	if len(res.Findings) == 0 {
		fmt.Println("Nothing in this repository makes an agent run a command, load a remote instruction or skip its safety prompts.")
	}
	for _, f := range res.Findings {
		fmt.Printf("  %-8s %s\n", f.Severity, f.RuleID)
		fmt.Printf("           %s\n", sanitize.Terminal(f.Description))
	}
	for _, n := range res.Notes {
		fmt.Println("note:", sanitize.Terminal(n))
	}
	if len(res.Findings) > 0 {
		fmt.Println("\nNothing was executed. Read each file before opening the repository with an agent.")
	}
}
