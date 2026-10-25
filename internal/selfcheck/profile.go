package selfcheck

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

// writeSyntheticProfile asks the AgentDFIR binary to write a synthetic
// scenario profile into dir, so the subject collects marked, synthetic
// evidence and never touches the real home. Reusing `agentdfir simulate`
// keeps the self-check honest: it runs the real collector over real
// (synthetic) files, not a stub.
func writeSyntheticProfile(self, scenario, dir string) error {
	cmd := exec.Command(self, "simulate", "--scenario", scenario, "--out", dir)
	cmd.Env = append(os.Environ(), "AGENTDFIR_SELFCHECK=")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// macProfile is a sandbox-exec (Seatbelt) profile that allows a normal
// read-only process but denies the three things a collection must never
// do: reach the network, run another program, or write outside its own
// scratch tree. A denied operation returns an error to the subject, which
// is what the self-check observes.
//
// sandbox-exec is deprecated by Apple but present on every macOS; the
// profile language is stable. self is allowed to exec itself (the subject
// is re-run for the canary), nothing else.
func macProfile(self, work string) string {
	esc := func(s string) string { return strings.ReplaceAll(s, `"`, `\"`) }
	var b strings.Builder
	b.WriteString("(version 1)\n")
	b.WriteString("(allow default)\n")
	b.WriteString("(deny network*)\n")
	b.WriteString("(deny network-outbound)\n")
	b.WriteString("(allow network* (local ip) (remote unix-socket))\n")
	b.WriteString("(deny process-exec*)\n")
	fmt.Fprintf(&b, "(allow process-exec (literal \"%s\"))\n", esc(self))
	b.WriteString("(allow process-fork)\n")
	b.WriteString("(deny file-write*)\n")
	fmt.Fprintf(&b, "(allow file-write* (subpath \"%s\"))\n", esc(work))
	b.WriteString("(allow file-write* (literal \"/dev/null\"))\n")
	b.WriteString("(allow file-write-data (literal \"/dev/dtracehelper\"))\n")
	return b.String()
}
