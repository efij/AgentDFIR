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

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/crosscase"
	"github.com/efij/AgentDFIR/v4/internal/reconstruct"
	"github.com/efij/AgentDFIR/v4/internal/sanitize"
	"github.com/efij/AgentDFIR/v4/internal/store"
)

const reconstructUsage = `usage: agentdfir reconstruct <pkg|case> [<pkg|case> ...] [--json | --mermaid | --dot] [--out file]
                             [--allow-unverified] [--include-common] [--no-overlay] [--max-timeline N]

One incident across one or more analyzed cases: a merged timeline over hosts,
agents, sessions and users; delegation (subagents, agent CLIs launched from a
shell); hand-offs (a session resumed in another file or continued on another
host, the same conversation in a provider export and a transcript, a branch
pushed here and pulled there); links between hosts (shared destinations,
credential fingerprints, instruction files, MCP packages); attack stages in
kill-chain order, every stage edge labeled VERIFIED (explicit evidence) or
INFERRED (order in time and shared attributes); and what telemetry would
confirm or refute each segment and stage. Deterministic: no model writes any
of it. A case is a package path or a case name under the AgentDFIR home.
Packages are analyzed first when their analysis is missing or stale; every
seal is verified (refused unless --allow-unverified). The JSON is also stored
in each case as normalized/reconstruct.json for the explorer (--no-overlay
skips that). docs/reconstruct.md documents the JSON.
`

// cmdReconstruct is `agentdfir reconstruct`.
func cmdReconstruct(args []string) int {
	fs := flag.NewFlagSet("reconstruct", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the structured report")
	mermaid := fs.Bool("mermaid", false, "print a Mermaid flowchart")
	dot := fs.Bool("dot", false, "print Graphviz DOT")
	out := fs.String("out", "", "write the output to this file instead of stdout")
	allow := fs.Bool("allow-unverified", false, "include packages whose seal does not verify (results are marked)")
	common := fs.Bool("include-common", false, "also link allowlisted destinations (model providers, package registries)")
	noOverlay := fs.Bool("no-overlay", false, "do not store normalized/reconstruct.json in the cases")
	maxTL := fs.Int("max-timeline", 0, "timeline bound (default 5000)")
	var pkgs []string
	rest := args
	for len(rest) > 0 && !strings.HasPrefix(rest[0], "-") {
		pkgs = append(pkgs, rest[0])
		rest = rest[1:]
	}
	fs.SetOutput(io.Discard)
	if err := fs.Parse(rest); err != nil {
		fmt.Fprint(os.Stderr, reconstructUsage)
		return 2
	}
	pkgs = append(pkgs, fs.Args()...)
	n := 0
	for _, b := range []bool{*asJSON, *mermaid, *dot} {
		if b {
			n++
		}
	}
	if len(pkgs) == 0 || n > 1 {
		fmt.Fprint(os.Stderr, reconstructUsage)
		return 2
	}
	for i, p := range pkgs {
		r, err := resolveCaseArg(p)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", sanitize.Terminal(err.Error()))
			return 2
		}
		pkgs[i] = r
	}
	// Progress goes to stderr whenever stdout carries the report.
	log := io.Writer(os.Stderr)
	for _, p := range pkgs {
		if _, err := analysis.Ensure(p, log); err != nil {
			fmt.Fprintln(os.Stderr, "error:", sanitize.Terminal(err.Error()))
			return 1
		}
	}
	rep, err := reconstruct.Run(pkgs, reconstruct.Options{AllowUnverified: *allow, IncludeCommon: *common, MaxTimeline: *maxTL})
	if err != nil {
		var re *crosscase.RefusedError
		if errors.As(err, &re) {
			fmt.Fprintln(os.Stderr, "Cannot reconstruct from these cases:")
			for _, p := range re.Problems {
				fmt.Fprintln(os.Stderr, "  - "+sanitize.Terminal(p))
			}
			return 1
		}
		fmt.Fprintln(os.Stderr, "error:", sanitize.Terminal(err.Error()))
		return 2
	}
	if !*noOverlay {
		for _, p := range pkgs {
			if err := reconstruct.WriteOverlay(p, rep); err != nil {
				fmt.Fprintf(os.Stderr, "note: %s: reconstruct overlay not written: %s\n", sanitize.Terminal(p), sanitize.Terminal(err.Error()))
			}
		}
	}
	w := io.Writer(os.Stdout)
	var f *os.File
	if *out != "" {
		f, err = os.OpenFile(*out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", sanitize.Terminal(err.Error()))
			return 1
		}
		w = f
	}
	switch {
	case *asJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		err = enc.Encode(rep)
	case *mermaid:
		reconstruct.WriteMermaid(w, rep)
	case *dot:
		reconstruct.WriteDOT(w, rep)
	default:
		reconstruct.WriteText(w, rep)
	}
	if f != nil {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", sanitize.Terminal(err.Error()))
		return 1
	}
	if f != nil {
		fmt.Fprintln(os.Stderr, "Wrote", sanitize.Terminal(*out))
	}
	return 0
}

// resolveCaseArg accepts a package path, or a case name under the
// AgentDFIR home (cases/<name> or cases/<name>.adfir).
func resolveCaseArg(arg string) (string, error) {
	if _, err := os.Stat(filepath.Join(arg, "manifest.jsonl")); err == nil {
		return arg, nil
	}
	if !strings.ContainsAny(arg, `/\`) {
		if home, err := store.Home(); err == nil {
			for _, name := range []string{arg, arg + ".adfir"} {
				p := filepath.Join(home, "cases", name)
				if _, err := os.Stat(filepath.Join(p, "manifest.jsonl")); err == nil {
					return p, nil
				}
			}
		}
	}
	return "", fmt.Errorf("%s is not an evidence package or a case name under the AgentDFIR home", arg)
}
