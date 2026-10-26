package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/efij/AgentDFIR/v5/internal/benchmark"
)

// cmdBenchmark runs the synthetic accuracy benchmark: offline, against
// fixtures embedded in the binary. Exit 0 = every hard check held, 1 = at
// least one failed, 2 = usage.
func cmdBenchmark(args []string) int {
	fs := flag.NewFlagSet("benchmark", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print the report as JSON instead of Markdown")
	out := fs.String("out", "", "also write the report to this file (.json writes JSON, anything else Markdown)")
	quick := fs.Bool("quick", false, "fast subset: a sample of the corpus and scenarios, no performance case")
	noPerf := fs.Bool("no-perf", false, "skip the performance case")
	corpusDir := fs.String("corpus", "", "labeled corpus directory (benign/, attack/); default: the corpus built into the binary")
	sessions := fs.Int("perf-sessions", 0, "size of the generated performance case in sessions (default 400; the baseline is recorded at 400)")
	baselinePath := fs.String("baseline", "", "performance baseline JSON to compare against (default: the recorded one)")
	saveBaseline := fs.String("save-baseline", "", "write this run's performance numbers as a baseline JSON file")
	pyVerifier := fs.Bool("python-verifier", false, "run the Python verifier (tools/adfir-verify) from the checkout found from the working directory; implied by --repo")
	repo := fs.String("repo", "", "source checkout holding the disk-image, telemetry and interop fixtures and the Python verifier (default: searched from the working directory; without one those suites are skipped)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: agentdfir benchmark [--json] [--out report.md|report.json] [--quick] [--no-perf] [--corpus dir] [--baseline f] [--save-baseline f] [--repo checkout] [--python-verifier]")
		fmt.Fprintln(os.Stderr, "SYNTHETIC: measured on labeled synthetic fixtures; not evidence of real-world accuracy.")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		if err == nil {
			fs.Usage()
		}
		return 2
	}
	o := benchmark.Options{Quick: *quick, SkipPerf: *noPerf, CorpusDir: *corpusDir, PerfSessions: *sessions, Log: os.Stderr, RepoRoot: *repo, PythonVerifier: *pyVerifier}
	if *baselinePath != "" {
		data, err := os.ReadFile(*baselinePath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		var b benchmark.PerfNumbers
		if err := json.Unmarshal(data, &b); err != nil {
			fmt.Fprintln(os.Stderr, "error: baseline:", err)
			return 1
		}
		o.Baseline = &b
	}
	r, err := benchmark.Run(o)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	write := func(w io.Writer, js bool) error {
		if js {
			return r.WriteJSON(w)
		}
		return r.WriteMarkdown(w)
	}
	if err := write(os.Stdout, *asJSON); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *out != "" {
		f, err := os.Create(*out)
		if err == nil {
			err = write(f, len(*out) > 5 && (*out)[len(*out)-5:] == ".json")
			if cerr := f.Close(); err == nil {
				err = cerr
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	if *saveBaseline != "" {
		if r.Performance == nil {
			fmt.Fprintln(os.Stderr, "error: --save-baseline needs the performance case (drop --quick / --no-perf)")
			return 1
		}
		if err := benchmark.SaveBaseline(*saveBaseline, r); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	if !r.Passed() {
		fmt.Fprintf(os.Stderr, "benchmark: %d hard check(s) failed\n", len(r.Failures))
		return 1
	}
	return 0
}
