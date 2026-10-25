package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/sanitize"
	"github.com/efij/AgentDFIR/v4/internal/selfcheck"
)

const selfcheckUsage = `usage: agentdfir selfcheck --offline [--profile <dir>] [--scenario <id>] [--no-canary] [--json] [--keep]
       agentdfir selfcheck --canary          (internal: used inside the sandbox)

--offline  prove, on this machine, that an AgentDFIR collection and analysis
           opens no network socket, spawns no child process, and writes only
           inside the case and state directories. It runs this binary as the
           subject on a synthetic profile (or --profile <dir>) under the
           strongest containment the OS offers — sandbox-exec on macOS, a
           network namespace and strace on Linux, the in-process guard
           everywhere else — and reports which level of proof it reached:
           kernel-enforced, traced, or in-process. Non-zero exit on any
           violation.
--canary   try to reach a public address and print CONNECTED or BLOCKED. Run
           inside the sandbox by --offline to confirm the sandbox is enforcing;
           it sends nothing when run outside one on purpose.
`

func cmdSelfcheck(args []string) int {
	fs := flag.NewFlagSet("selfcheck", flag.ContinueOnError)
	offline := fs.Bool("offline", false, "run the full offline proof")
	canary := fs.Bool("canary", false, "connectivity canary (internal)")
	profile := fs.String("profile", "", "a real profile root to collect (default: a synthetic one)")
	scenario := fs.String("scenario", "toxic-chain", "synthetic scenario id for the subject profile")
	noCanary := fs.Bool("no-canary", false, "skip the connectivity canary")
	asJSON := fs.Bool("json", false, "machine-readable output")
	keep := fs.Bool("keep", false, "keep the scratch directory")
	if err := fs.Parse(args); err != nil {
		fmt.Fprint(os.Stderr, selfcheckUsage)
		return 2
	}
	if *canary {
		return runCanary()
	}
	if !*offline {
		fmt.Fprint(os.Stderr, selfcheckUsage)
		return 2
	}
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: cannot find this binary:", err)
		return 1
	}
	rep, err := selfcheck.Run(self, selfcheck.Options{Profile: *profile, Scenario: *scenario, NoCanary: *noCanary, Keep: *keep})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if *asJSON {
		b, _ := json.MarshalIndent(rep, "", "  ")
		fmt.Println(string(b))
	} else {
		printSelfcheck(rep)
	}
	if !rep.Pass {
		return 1
	}
	return 0
}

// runCanary tries one outbound connection and reports the result. It is
// run inside the sandbox by the offline check; outside a sandbox it would
// reach the address, which is why selfcheck only ever runs it within one.
func runCanary() int {
	c, err := net.DialTimeout("tcp", selfcheck.CanaryTarget, 2*time.Second)
	if err != nil {
		fmt.Printf("BLOCKED %s: %v\n", selfcheck.CanaryTarget, err)
		return 0
	}
	c.Close()
	fmt.Printf("CONNECTED %s\n", selfcheck.CanaryTarget)
	return 0
}

func printSelfcheck(r *selfcheck.Report) {
	fmt.Println("AgentDFIR offline self-check")
	fmt.Println("============================")
	fmt.Printf("Platform:     %s\n", r.OS)
	fmt.Printf("Containment:  %s\n", r.Containment)
	fmt.Printf("Proof level:  %s\n", r.Level)
	switch r.Level {
	case selfcheck.LevelKernel:
		fmt.Println("              (the OS blocked network, child processes and out-of-tree writes)")
	case selfcheck.LevelTraced:
		fmt.Println("              (every network and process syscall the subject made was traced)")
	case selfcheck.LevelInProcess:
		fmt.Println("              (the binary's own guard recorded and refused dials; no kernel enforcement here)")
	}
	if r.Canary != nil && r.Canary.Ran {
		state := "BLOCKED — the sandbox is enforcing"
		if r.Canary.Connected {
			state = "CONNECTED — the sandbox did NOT block it"
		}
		fmt.Printf("Canary:       %s\n", state)
	}
	fmt.Printf("Subject:      exit %d (%s)\n", r.Subject.ExitCode, firstLine(r.Subject.Command))
	fmt.Printf("Network:      %d non-loopback dial(s) observed\n", len(r.NetworkDials))
	for _, d := range r.NetworkDials {
		fmt.Printf("  - %s\n", sanitize.Terminal(d))
	}
	if r.Level == selfcheck.LevelTraced {
		fmt.Printf("Child execs:  %d after the subject itself\n", len(r.ChildExecs))
		for _, e := range r.ChildExecs {
			fmt.Printf("  - %s\n", sanitize.Terminal(e))
		}
		fmt.Printf("Writes out:   %d outside the case/state dirs\n", len(r.WritesOutside))
		for _, w := range r.WritesOutside {
			fmt.Printf("  - %s\n", sanitize.Terminal(w))
		}
	}
	for _, n := range r.Notes {
		fmt.Printf("note: %s\n", sanitize.Terminal(n))
	}
	if r.Subject.ExitCode != 0 && r.Subject.ExitCode != 3 && r.Subject.Stderr != "" {
		fmt.Printf("subject stderr: %s\n", sanitize.Terminal(r.Subject.Stderr))
	}
	if r.Pass {
		fmt.Println("\nResult:       PASS — nothing was sent, nothing was executed, nothing was written outside the case.")
	} else {
		fmt.Printf("\nResult:       FAIL — %d violation(s):\n", len(r.Violations))
		for _, v := range r.Violations {
			fmt.Printf("  - %s\n", sanitize.Terminal(v))
		}
	}
}

func firstLine(s string) string {
	if len(s) > 80 {
		return s[:80] + "…"
	}
	return s
}
