package selfcheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestParseTraceFlagsDialExecWrite(t *testing.T) {
	trace := `1 execve("/tmp/agentdfir", ["agentdfir", "run"], 0x7ff) = 0
2 connect(7, {sa_family=AF_UNIX, sun_path="/var/run/x"}, 110) = 0
3 connect(8, {sa_family=AF_INET, sin_port=htons(443), sin_addr=inet_addr("1.1.1.1")}, 16) = -1 EINPROGRESS
4 connect(9, {sa_family=AF_INET, sin_port=htons(53), sin_addr=inet_addr("127.0.0.53")}, 16) = 0
5 execve("/bin/sh", ["sh", "-c", "curl evil"], 0x1) = 0
6 openat(AT_FDCWD, "/home/u/.ssh/evil", O_WRONLY|O_CREAT, 0600) = 11
7 openat(AT_FDCWD, "/work/case.adfir/raw/ab", O_WRONLY|O_CREAT, 0600) = 12`
	dir := t.TempDir()
	p := filepath.Join(dir, "trace.out")
	if err := os.WriteFile(p, []byte(trace), 0o600); err != nil {
		t.Fatal(err)
	}
	dials, execs, writes := parseTrace(p, []string{"/work"})
	if len(dials) != 1 || !strings.Contains(dials[0], "1.1.1.1:443") {
		t.Errorf("dials = %v, want one to 1.1.1.1:443 (loopback and AF_UNIX excluded)", dials)
	}
	if len(execs) != 1 || !strings.Contains(execs[0], "/bin/sh") {
		t.Errorf("execs = %v, want /bin/sh (first execve is the subject)", execs)
	}
	if len(writes) != 1 || !strings.Contains(writes[0], "/home/u/.ssh/evil") {
		t.Errorf("writes = %v, want the out-of-tree write only", writes)
	}
}

func TestMacProfileDeniesTheThree(t *testing.T) {
	p := macProfile("/bin/agentdfir", "/work")
	for _, want := range []string{"(deny network*)", "(deny process-exec*)", "(deny file-write*)", `(subpath "/work")`, `(literal "/bin/agentdfir")`} {
		if !strings.Contains(p, want) {
			t.Errorf("profile missing %q:\n%s", want, p)
		}
	}
}

func TestGuardRefusesNonLoopback(t *testing.T) {
	t.Setenv(EnvGuard, "1")
	t.Setenv(EnvLog, filepath.Join(t.TempDir(), "g.jsonl"))
	InstallIfRequested()
	if _, err := GuardDial("tcp", "1.1.1.1:443"); err == nil {
		t.Error("guard allowed a dial to 1.1.1.1:443")
	}
	if !loopback("tcp", "127.0.0.1:8080") || !loopback("unix", "/tmp/x") || loopback("tcp", "8.8.8.8:53") {
		t.Error("loopback classification wrong")
	}
}

// TestOfflinePassesUnderContainment runs the real check with this test
// binary as the subject. The test binary is not the agentdfir CLI, so the
// subject run itself errors on an unknown command — but the check must
// still observe no network and no child exec, and under a kernel sandbox
// must confirm the canary is blocked.
func TestOfflineObservesNoNetwork(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("containment is darwin/linux")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// The subject here is the test binary; point it at an existing profile
	// dir so writeSyntheticProfile is skipped (the test binary is not the
	// CLI and cannot generate one).
	prof := t.TempDir()
	rep, err := Run(self, Options{Profile: prof, NoCanary: false})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.NetworkDials) != 0 {
		t.Errorf("observed network dials from a non-networking subject: %v", rep.NetworkDials)
	}
	if runtime.GOOS == "darwin" && rep.Level == LevelKernel && rep.Canary != nil && rep.Canary.Connected {
		t.Error("canary connected inside sandbox-exec: sandbox not enforcing")
	}
}

// TestOfflineFailsWhenSubjectDialsOut builds a copy of the agentdfir
// binary with the selfcheck_dialout tag, which dials out on startup, and
// confirms the offline check catches it and fails. This is the negative
// control: a subject that misbehaves must never pass.
func TestOfflineFailsWhenSubjectDialsOut(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode (builds a tagged binary)")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "agentdfir-dialout")
	build := exec.Command("go", "build", "-tags", "selfcheck_dialout", "-o", bin, "github.com/efij/AgentDFIR/v4/cmd/agentdfir")
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Skipf("could not build tagged binary: %v: %s", err, out)
	}
	rep, err := Run(bin, Options{NoCanary: true})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Pass {
		t.Errorf("offline check passed a subject that dialled out; violations=%v dials=%v", rep.Violations, rep.NetworkDials)
	}
	found := false
	for _, v := range rep.Violations {
		if strings.Contains(v, "network") {
			found = true
		}
	}
	if !found {
		t.Errorf("no network violation reported; report=%+v", rep)
	}
}
