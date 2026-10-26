package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/efij/AgentDFIR/v5/internal/analysis"
	"github.com/efij/AgentDFIR/v5/internal/proof"
)

const reportProofUsage = `usage: agentdfir report <package-dir> --format proof [--json] [--session ID] [--max N] [--out file]

Per recorded tool call: the claim, the evidence chain (human → agent → tool →
process → file/network → outcome) with source references, each step's state,
how each link is known (verified / corroborated / inferred), its limitations,
and the telemetry coverage and collection-health facts behind the state. The
--json form is independently checkable (docs/action-proof.md).
`

// isProofReport reports whether a report invocation asks for --format proof.
func isProofReport(args []string) bool {
	for i, a := range args {
		switch {
		case a == "--format=proof" || a == "-format=proof":
			return true
		case (a == "--format" || a == "-format") && i+1 < len(args) && args[i+1] == "proof":
			return true
		}
	}
	return false
}

func cmdReportProof(args []string) int {
	fs := flag.NewFlagSet("report proof", flag.ContinueOnError)
	fs.String("format", "proof", "proof")
	asJSON := fs.Bool("json", false, "print the report as JSON")
	session := fs.String("session", "", "only this session")
	max := fs.Int("max", proof.DefaultMaxActions, "at most this many tool calls")
	out := fs.String("out", "", "write to this file instead of standard output")
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || (pkg == "" && fs.NArg() != 1) || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprint(os.Stderr, reportProofUsage)
		return 2
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}
	// The report reads the analysis the analyst saw; progress goes to
	// stderr so the report itself stays clean on stdout.
	if _, err := analysis.Ensure(pkg, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	r, err := proof.Load(pkg, proof.Options{SessionID: *session, MaxActions: *max})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	var w io.Writer = os.Stdout
	if *out != "" {
		f, err := os.OpenFile(*out, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		defer f.Close()
		w = f
	}
	if *asJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		if err := enc.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		return 0
	}
	proof.WriteText(w, r)
	return 0
}
