package selfcheck

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// Proof levels, strongest first.
const (
	LevelKernel    = "kernel-enforced" // the OS blocked network/exec/writes outright
	LevelTraced    = "traced"          // a syscall tracer recorded every network and exec call
	LevelInProcess = "in-process"      // the binary's own guard recorded and refused dials
)

// Options tune a self-check.
type Options struct {
	Profile  string // a real profile root to collect; "" means a synthetic one
	Scenario string // synthetic scenario id (default toxic-chain)
	WorkDir  string // scratch root; "" means a temp dir removed at the end
	NoCanary bool   // skip the connectivity canary
	Keep     bool   // keep the work dir
}

// Report is the outcome of a self-check.
type Report struct {
	GeneratedUTC  string        `json:"generated_utc"`
	OS            string        `json:"os"`
	Level         string        `json:"level"`
	Containment   string        `json:"containment"` // sandbox-exec | network-namespace+strace | network-namespace | in-process
	Canary        *CanaryResult `json:"canary,omitempty"`
	Subject       SubjectResult `json:"subject"`
	NetworkDials  []string      `json:"network_dials"`      // non-loopback dial/connect/sendto observed
	ChildExecs    []string      `json:"child_execs"`        // execve after the first (traced only)
	WritesOutside []string      `json:"writes_outside"`     // writes outside allowed dirs (traced only)
	GuardObserved []Observation `json:"guard_observations"` // what the in-process guard saw
	Notes         []string      `json:"notes"`
	Violations    []string      `json:"violations"`
	Pass          bool          `json:"pass"`
}

// CanaryResult is what the connectivity canary found.
type CanaryResult struct {
	Ran       bool   `json:"ran"`
	Connected bool   `json:"connected"` // true means the sandbox did NOT block it
	Detail    string `json:"detail"`
}

// SubjectResult is how the subject run went.
type SubjectResult struct {
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Findings int    `json:"findings_exit"` // whether the run reported findings (exit 3)
	Stderr   string `json:"stderr_excerpt,omitempty"`
}

// CanaryTarget is the public address the canary tries to reach from inside
// the sandbox. Reaching it means the sandbox is not enforcing.
const CanaryTarget = "1.1.1.1:443"

// Run performs a self-check and returns its report. self is the path to
// the AgentDFIR binary to use as the subject (normally os.Executable()).
func Run(self string, opts Options) (*Report, error) {
	if opts.Scenario == "" {
		opts.Scenario = "toxic-chain"
	}
	// The kernel sandbox matches the canonical binary path when it decides
	// whether the subject may exec itself, so resolve any symlink now.
	if real, err := filepath.EvalSymlinks(self); err == nil {
		self = real
	}
	work := opts.WorkDir
	if work == "" {
		d, err := os.MkdirTemp("", "agentdfir-selfcheck-*")
		if err != nil {
			return nil, err
		}
		work = d
		if !opts.Keep {
			defer os.RemoveAll(work)
		}
	}
	// Canonicalize: a kernel sandbox matches the real path, and on macOS the
	// temp dir is reached through the /var -> /private/var symlink, so an
	// allow rule written against the symlink path would deny every write.
	if real, err := filepath.EvalSymlinks(work); err == nil {
		work = real
	}
	profile := opts.Profile
	if profile == "" {
		profile = filepath.Join(work, "profile")
		if err := writeSyntheticProfile(self, opts.Scenario, profile); err != nil {
			return nil, fmt.Errorf("make synthetic profile: %w", err)
		}
	}
	home := filepath.Join(work, "home") // AGENTDFIR_HOME (keys, anchors, store)
	outCase := filepath.Join(work, "case.adfir")
	tmp := filepath.Join(work, "tmp")
	guardLog := filepath.Join(work, "guard.jsonl")
	for _, d := range []string{home, tmp} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}

	rep := &Report{GeneratedUTC: time.Now().UTC().Format(time.RFC3339), OS: runtime.GOOS, Pass: true}
	env := append(os.Environ(),
		"HOME="+profile, "USERPROFILE="+profile, "CLAUDE_CONFIG_DIR=",
		"AGENTDFIR_HOME="+home, "TMPDIR="+tmp, "TEMP="+tmp, "TMP="+tmp,
		"AGENTDFIR_MIN_FREE_GB=1",
		EnvGuard+"=1", EnvLog+"="+guardLog,
	)

	// Pick containment.
	con, contName, level, notes := containmentFor(self, work, outCase, home, tmp)
	rep.Containment, rep.Level, rep.Notes = contName, level, notes

	// Canary: confirm the sandbox actually blocks the network, from inside it.
	if !opts.NoCanary {
		rep.Canary = runCanary(self, con, env)
		if rep.Canary.Connected && level == LevelKernel {
			rep.Level = LevelInProcess
			rep.Containment += " (downgraded: canary connected, sandbox not enforcing)"
			rep.Notes = append(rep.Notes, "the connectivity canary reached "+CanaryTarget+" from inside the sandbox: the sandbox is not enforcing, so the result is the in-process guard only, never a pass on kernel enforcement.")
		}
	}

	// Run the subject: a full collect → analyze, no server.
	subjectArgs := []string{"run", "--no-serve", "--new", "--no-share", "--priority", "normal", "--out", outCase}
	rep.Subject = runSubject(self, con, env, subjectArgs)

	// Collect evidence of what the subject did.
	rep.GuardObserved = readGuardLog(guardLog)
	for _, o := range rep.GuardObserved {
		if !o.Allowed {
			rep.NetworkDials = append(rep.NetworkDials, o.Kind+" "+o.Address+" (refused by in-process guard)")
		}
	}
	// Allowed writes are everything under work plus the macOS per-user temp
	// the runtime uses; a write outside those, seen by the tracer, is a
	// violation.
	allowed := []string{work}
	if tr, ok := con.(traced); ok {
		dials, execs, writes := parseTrace(tr.tracePath, allowed)
		rep.NetworkDials = append(rep.NetworkDials, dials...)
		rep.ChildExecs = execs
		rep.WritesOutside = writes
	}

	// Decide.
	for _, d := range rep.NetworkDials {
		rep.Violations = append(rep.Violations, "network: "+d)
	}
	for _, e := range rep.ChildExecs {
		rep.Violations = append(rep.Violations, "child process: "+e)
	}
	for _, w := range rep.WritesOutside {
		rep.Violations = append(rep.Violations, "write outside the case/state dirs: "+w)
	}
	// Under kernel enforcement a forbidden op makes the subject fail; a
	// clean exit (0 collected, or 3 findings) with no observed violation is
	// the pass. A non-zero, non-findings exit on a kernel run is suspect.
	if len(rep.Violations) > 0 {
		rep.Pass = false
	}
	if rep.Subject.ExitCode != 0 && rep.Subject.ExitCode != 3 {
		rep.Notes = append(rep.Notes, fmt.Sprintf("the subject exited %d; under kernel containment this can mean a blocked operation stopped it — read the stderr excerpt.", rep.Subject.ExitCode))
		if len(rep.Violations) == 0 {
			// A subject that did not complete proves nothing about what a
			// complete run does: a denied op the kernel turned into an
			// error, or containment that never started. Not a pass.
			rep.Pass = false
			rep.Violations = append(rep.Violations, "the subject did not complete and the cause was not captured; treat as not proven")
		}
	}
	return rep, nil
}

// containment is a marker interface; traced carries the trace file path.
type containment interface {
	wrap(self string, args []string) (string, []string)
}

type plain struct{}

func (plain) wrap(self string, args []string) (string, []string) { return self, args }

type sandboxExec struct{ profilePath string }

func (s sandboxExec) wrap(self string, args []string) (string, []string) {
	return "sandbox-exec", append([]string{"-f", s.profilePath, self}, args...)
}

type traced struct {
	tracePath string
	nsArgs    []string // unshare flags that were probed to work; nil: no network namespace
}

func (t traced) wrap(self string, args []string) (string, []string) {
	// [unshare <ns> --] self args
	inner := append([]string{self}, args...)
	if t.nsArgs != nil {
		inner = append(append(append([]string{"unshare"}, t.nsArgs...), "--"), inner...)
	}
	if t.tracePath != "" {
		// strace -f -e trace=process,network -o <file> <inner>
		return "strace", append([]string{"-f", "-e", "trace=process,network", "-o", t.tracePath}, inner...)
	}
	return inner[0], inner[1:]
}

// netnsArgs finds unshare flags that can actually create a network
// namespace here. Unprivileged users need a user namespace too
// (--user --map-root-user); some hosts (CI runners, hardened kernels)
// refuse both, and then there is no namespace to promise.
func netnsArgs() []string {
	if _, err := exec.LookPath("unshare"); err != nil {
		return nil
	}
	for _, a := range [][]string{{"--user", "--map-root-user", "--net"}, {"--net"}} {
		if exec.Command("unshare", append(append([]string{}, a...), "--", "true")...).Run() == nil {
			return a
		}
	}
	return nil
}

// containmentFor chooses the strongest available containment.
func containmentFor(self, work, outCase, home, tmp string) (containment, string, string, []string) {
	var notes []string
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("sandbox-exec"); err == nil {
			p := filepath.Join(work, "selfcheck.sb")
			if err := os.WriteFile(p, []byte(macProfile(self, work)), 0o600); err == nil {
				return sandboxExec{p}, "sandbox-exec", LevelKernel, notes
			}
			notes = append(notes, "could not write the sandbox profile; falling back to the in-process guard")
		} else {
			notes = append(notes, "sandbox-exec is not present; falling back to the in-process guard")
		}
	case "linux":
		ns := netnsArgs()
		_, straceErr := exec.LookPath("strace")
		if ns == nil {
			notes = append(notes, "a network namespace could not be created here (unshare missing or refused for this user)")
		}
		switch {
		case straceErr == nil && ns != nil:
			return traced{tracePath: filepath.Join(work, "trace.out"), nsArgs: ns}, "network-namespace+strace", LevelTraced, notes
		case straceErr == nil:
			return traced{tracePath: filepath.Join(work, "trace.out")}, "strace", LevelTraced, notes
		case ns != nil:
			return traced{nsArgs: ns}, "network-namespace", LevelKernel, append(notes, "strace is not present: the network namespace blocks egress, but individual syscalls were not traced; install strace for a per-call trace.")
		default:
			notes = append(notes, "strace is not present either; falling back to the in-process guard")
		}
	default:
		notes = append(notes, runtime.GOOS+" has no kernel containment here; the in-process guard is the proof.")
	}
	return plain{}, "in-process", LevelInProcess, notes
}

// containmentFor returns a containment value; wrap() is called via the
// interface. runSubject/runCanary take it.
func runSubject(self string, c containment, env []string, args []string) SubjectResult {
	bin, full := c.wrap(self, args)
	cmd := exec.Command(bin, full...)
	cmd.Env = env
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = nil
	_ = cmd.Run()
	code := cmd.ProcessState.ExitCode()
	res := SubjectResult{Command: bin + " " + strings.Join(full, " "), ExitCode: code, Stderr: tail(stderr.String(), 1600)}
	if code == 3 {
		res.Findings = 3
	}
	return res
}

func runCanary(self string, c containment, env []string) *CanaryResult {
	bin, full := c.wrap(self, []string{"selfcheck", "--canary"})
	cmd := exec.Command(bin, full...)
	cmd.Env = env
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	err := cmd.Run()
	r := &CanaryResult{Ran: true, Detail: tail(strings.TrimSpace(out.String()), 300)}
	// The canary exits 0 and prints CONNECTED when it reached the target.
	r.Connected = err == nil && strings.Contains(out.String(), "CONNECTED")
	return r
}

func readGuardLog(path string) []Observation {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []Observation
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		var o Observation
		if json.Unmarshal(sc.Bytes(), &o) == nil {
			out = append(out, o)
		}
	}
	return out
}

func tail(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return "…" + s[len(s)-n:]
	}
	return s
}
