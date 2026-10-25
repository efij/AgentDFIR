package endpoint

import (
	"path/filepath"
	"strings"
	"testing"
)

const fixtureCID = "551e161c47d8ff0eb665438a7bcd5b4e0e6d1f1a2b3c4d5e6f708192a3b4c5d6"

// loadFixture sniffs and loads one file from testdata/linuxtel.
func loadFixture(t *testing.T, name string, want Format) *LoadResult {
	t.Helper()
	p := filepath.Join("testdata", "linuxtel", name)
	f, err := Sniff(p)
	if err != nil || f != want {
		t.Fatalf("%s: sniffed %q (%v), want %q", name, f, err, want)
	}
	res, err := Load(p, FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func hasProblem(res *LoadResult, sub string) bool {
	for _, p := range res.Problems {
		if strings.Contains(p, sub) {
			return true
		}
	}
	return false
}

func TestTetragonImport(t *testing.T) {
	res := loadFixture(t, "tetragon.jsonl", FormatTetragon)
	kinds := map[string]int{}
	for _, r := range res.Records {
		kinds[r.Kind]++
		if r.Source != "tetragon" || IsSighting(r) {
			t.Fatalf("tetragon records give coverage: %+v", r)
		}
	}
	// 5 execs, tcp_connect, 2 file hooks, bpf_check, setns tracepoint, mount kprobe.
	if kinds["process"] != 5 || kinds["network"] != 1 || kinds["file"] != 2 || kinds["syscall"] != 3 {
		t.Fatalf("kinds %v", kinds)
	}
	// exit folded, rate limit, uprobe + loader unsupported, truncated line,
	// no process_* key, kprobe without process.
	if res.Skipped != 7 {
		t.Fatalf("skipped %d, problems %v", res.Skipped, res.Problems)
	}
	for _, want := range []string{"dropped 42 process event", "UNSUPPORTED: 1 process_uprobe", "UNSUPPORTED: 1 process_loader", "process_exit event(s) folded"} {
		if !hasProblem(res, want) {
			t.Errorf("missing problem %q in %v", want, res.Problems)
		}
	}
	curl := res.Records[2]
	if curl.Kind != "process" || curl.Exe != "/usr/bin/curl" || curl.Cmdline != "/usr/bin/curl -s https://example.org/install.sh -o /tmp/i.sh" ||
		curl.PID != 4101 || curl.PPID != 4100 || curl.ParentExe != "/bin/bash" || curl.User != "1000" || curl.Cwd != "/home/dev/proj" ||
		curl.ExecID != "bm9kZTE6NDEwMQ==" || curl.ParentExecID != "bm9kZTE6NDEwMA==" {
		t.Fatalf("exec: %+v", curl)
	}
	if curl.ContainerID != fixtureCID || curl.ContainerName != "coder" || curl.ContainerImage != "ghcr.io/example/coder:1.4" ||
		curl.Pod != "coder-7d9f" || curl.K8sNamespace != "agents" || curl.PIDNS != 4026532275 || curl.MntNS != 4026532272 || curl.NetNS != 4026532277 {
		t.Fatalf("attribution: %+v", curl)
	}
	var sawNet, sawWrite, sawFD, sawBPF, sawSetns, sawMount bool
	for _, r := range res.Records {
		switch {
		case r.Kind == "network" && r.DestIP == "93.184.216.34" && r.DestPort == 443 && r.PID == 4101:
			sawNet = true
		case r.Kind == "file" && r.FilePath == "/tmp/i.sh" && r.FileOp == "modify":
			sawWrite = true
		case r.Kind == "file" && r.FilePath == "/etc/ssl/certs/ca-certificates.crt" && r.FileOp == "open":
			sawFD = true
		case r.Kind == "syscall" && r.Operation == "bpf_check" && strings.Contains(r.Resource, "BPF_PROG_TYPE_KPROBE"):
			sawBPF = true
			if !strings.Contains(r.Caps, "CAP_BPF") {
				t.Errorf("caps: %+v", r)
			}
		case r.Kind == "syscall" && r.Operation == "syscalls/sys_enter_setns":
			sawSetns = true
		case r.Kind == "syscall" && r.Operation == "__x64_sys_mount" && strings.Contains(r.Resource, "/dev/sda1 /host"):
			sawMount = true
		}
	}
	if !sawNet || !sawWrite || !sawFD || !sawBPF || !sawSetns || !sawMount {
		t.Fatalf("net=%v write=%v fd=%v bpf=%v setns=%v mount=%v", sawNet, sawWrite, sawFD, sawBPF, sawSetns, sawMount)
	}
}

func TestFalcoImport(t *testing.T) {
	res := loadFixture(t, "falco.jsonl", FormatFalco)
	if len(res.Records) != 8 {
		t.Fatalf("records %d: %+v", len(res.Records), res.Records)
	}
	// k8s_audit plugin source, an object without rule, a truncated line.
	if res.Skipped != 3 || !hasProblem(res, "UNSUPPORTED: 1 falco source k8s_audit") {
		t.Fatalf("skipped %d problems %v", res.Skipped, res.Problems)
	}
	for _, r := range res.Records {
		if !IsSighting(r) || r.Source != "falco" || !strings.Contains(r.Detection, "third-party") {
			t.Fatalf("falco record must be a labelled sighting: %+v", r)
		}
	}
	sh := res.Records[0]
	if sh.Kind != "process" || sh.Cmdline != `bash -c "git status"` || sh.PID != 5100 || sh.ParentExe != "/usr/local/bin/claude" ||
		sh.ContainerID != "551e161c47d8" || sh.ContainerImage != "ghcr.io/example/coder:1.4" || sh.Pod != "coder-7d9f" || sh.K8sNamespace != "agents" || sh.TTY != "34816" {
		t.Fatalf("execve: %+v", sh)
	}
	if !strings.Contains(sh.Detection, `"Terminal shell in container"`) {
		t.Fatalf("detection: %q", sh.Detection)
	}
	byPID := map[int]Record{}
	for _, r := range res.Records {
		byPID[r.PID] = r
	}
	if r := byPID[5101]; r.Kind != "file" || r.FilePath != "/etc/shadow" || r.FileOp != "open" {
		t.Fatalf("openat: %+v", r)
	}
	if r := byPID[5102]; r.Kind != "file" || r.FilePath != "/var/run/docker.sock" {
		t.Fatalf("docker.sock: %+v", r)
	}
	if r := byPID[5103]; r.Kind != "network" || r.DestIP != "203.0.113.50" || r.DestPort != 4444 {
		t.Fatalf("connect: %+v", r)
	}
	if r := byPID[5104]; r.Kind != "syscall" || r.Operation != "setns" || !strings.Contains(r.Resource, "/proc/1/ns/mnt") {
		t.Fatalf("setns: %+v", r)
	}
	if r := byPID[5105]; r.Kind != "syscall" || r.Operation != "mount" || !strings.Contains(r.Resource, "dev=/dev/sda1") {
		t.Fatalf("mount: %+v", r)
	}
	if r := byPID[5106]; r.Kind != "process" || r.Cmdline != "x --serve" {
		t.Fatalf("no evt.type: %+v", r)
	}
	// One notice per distinct rule: 7 rules among 8 alerts.
	if len(res.Notices) != 7 || !strings.Contains(res.Notices[0], "not an AgentDFIR finding") {
		t.Fatalf("notices: %v", res.Notices)
	}
}

func TestBpftraceImport(t *testing.T) {
	res := loadFixture(t, "bpftrace.jsonl", FormatBpftrace)
	if len(res.Records) != 3 {
		t.Fatalf("records %+v problems %v", res.Records, res.Problems)
	}
	g := res.Records[0]
	if g.Kind != "process" || g.Cmdline != "git push origin main" || g.PID != 6100 || g.PPID != 6000 || g.ContainerID != fixtureCID || !IsSighting(g) {
		t.Fatalf("exec: %+v", g)
	}
	if n := res.Records[1]; n.Kind != "network" || n.DestIP != "198.51.100.20" || n.DestPort != 22 {
		t.Fatalf("connect: %+v", n)
	}
	if l := res.Records[2]; l.Cmdline != "ls -la /etc" || l.Time.Unix() != 1792922523 {
		t.Fatalf("array args / epoch ns: %+v", l)
	}
	for _, want := range []string{"17 lost event", "printf text", "no wall-clock time", "numeric time is not epoch nanoseconds", "UNSUPPORTED: 1 map", "UNSUPPORTED: 1 hist", "type brand_new_type"} {
		if !hasProblem(res, want) {
			t.Errorf("missing %q in %v", want, res.Problems)
		}
	}
	// attached_probes, lost_events, text, 2 contract misses, map, hist, unknown, truncated.
	if res.Skipped != 9 {
		t.Fatalf("skipped %d %v", res.Skipped, res.Problems)
	}
}

func TestContainerRuntimeEvents(t *testing.T) {
	res := loadFixture(t, "docker-events.jsonl", FormatDocker)
	if len(res.Records) != 7 {
		t.Fatalf("records %d %+v", len(res.Records), res.Records)
	}
	var exec *Record
	for i, r := range res.Records {
		if r.Kind != "container" || r.Source != "docker-events" || !IsSighting(r) || r.ContainerID != fixtureCID || r.ContainerName != "web" || r.ContainerImage != "alpine:3.19" {
			t.Fatalf("docker: %+v", r)
		}
		if r.Operation == "docker exec_start" {
			exec = &res.Records[i]
		}
	}
	if exec == nil || exec.Cmdline != "sh -c cat /etc/passwd" || exec.Exe != "sh" {
		t.Fatalf("exec_start: %+v", exec)
	}
	if d := res.Records[6]; d.Operation != "docker die" || d.Failed != "exit code 137" {
		t.Fatalf("die: %+v", d)
	}
	// health_status, network + image (unsupported), no Action, truncated.
	if res.Skipped != 5 || !hasProblem(res, "UNSUPPORTED: 1 docker network event") || !hasProblem(res, "UNSUPPORTED: 1 docker image event") {
		t.Fatalf("skipped %d %v", res.Skipped, res.Problems)
	}

	res = loadFixture(t, "podman-events.jsonl", FormatPodman)
	if len(res.Records) != 3 || res.Records[2].Failed != "exit code 1" || res.Records[0].ContainerName != "web" || res.Skipped != 2 {
		t.Fatalf("podman: %+v skipped %d %v", res.Records, res.Skipped, res.Problems)
	}
}

func TestContainerIDFromCgroup(t *testing.T) {
	for in, want := range map[string]string{
		"0::/system.slice/docker-" + fixtureCID + ".scope":                        fixtureCID,
		"12:pids:/docker/" + fixtureCID:                                           fixtureCID,
		"0::/kubepods.slice/kubepods-besteffort.slice/pod1/crio-" + fixtureCID:    fixtureCID,
		"/kubepods/burstable/pod7c1e/" + fixtureCID:                               fixtureCID,
		"containerd://" + fixtureCID:                                              fixtureCID,
		"0::/user.slice/user-1000.slice/session-2.scope":                          "",
		"0::/machine.slice/libpod-" + strings.ToUpper(fixtureCID) + ".scope/init": fixtureCID,
	} {
		if got := ContainerIDFromCgroup(in); got != want {
			t.Errorf("%q → %q, want %q", in, got, want)
		}
	}
}

func TestAuditdContainerAttribution(t *testing.T) {
	log := `type=SYSCALL msg=audit(1792922400.100:900): arch=c000003e syscall=59 success=yes exit=0 ppid=4000 pid=4100 auid=1000 uid=1000 comm="curl" exe="/usr/bin/curl"
type=EXECVE msg=audit(1792922400.100:900): argc=2 a0="curl" a1="https://example.org"
type=CWD msg=audit(1792922400.100:900): cwd="/home/dev"
type=CONTAINER_ID msg=audit(1792922400.100:900): contid=` + fixtureCID + `
type=SYSCALL msg=audit(1792922401.100:901): arch=c000003e syscall=59 success=yes exit=0 ppid=4000 pid=4101 auid=1000 uid=1000 comm="cat" exe="/usr/bin/cat"
type=EXECVE msg=audit(1792922401.100:901): argc=2 a0="cat" a1="/sys/fs/cgroup/system.slice/docker-` + fixtureCID + `.scope/memory.max"
`
	res := load(t, "audit.log", log, FormatAuditd)
	if len(res.Records) != 2 {
		t.Fatalf("records %+v", res.Records)
	}
	if r := res.Records[0]; r.ContainerID != fixtureCID || r.Cwd != "/home/dev" {
		t.Fatalf("contid: %+v", r)
	}
	if r := res.Records[1]; r.ContainerID != "" {
		t.Fatalf("a command naming a cgroup path is not inside it: %+v", r)
	}
}

func TestPrivilegeChanges(t *testing.T) {
	log := `Oct 25 10:00:00 host sudo:      dev : TTY=pts/0 ; PWD=/home/dev/proj ; USER=root ; COMMAND=/usr/bin/systemctl enable evil.service
Oct 25 10:00:01 host sudo: pam_unix(sudo:auth): authentication failure; logname=dev uid=1000 euid=0 tty=/dev/pts/0 ruser=dev rhost=  user=dev
Oct 25 10:00:02 host su[2300]: pam_unix(su:auth): authentication failure; logname=dev uid=1000 euid=0 tty=pts/0 ruser=dev rhost=  user=root
Oct 25 10:00:03 host sshd[2301]: pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=198.51.100.7  user=root
Oct 25 10:00:04 host pkexec[2400]: dev: Executing command [USER=root] [TTY=/dev/pts/0] [CWD=/home/dev] [COMMAND=/usr/bin/id -u]
Oct 25 10:00:05 host pkexec[2401]: dev: Error executing command as another user: Not authorized [USER=root] [TTY=unknown] [CWD=/home/dev] [COMMAND=/usr/bin/bash]
Oct 25 10:00:06 host polkitd[900]: Operator of unix-session:2 successfully authenticated as unix-user:root to gain TEMPORARY authorization for action org.freedesktop.policykit.exec for unix-process:2400:1 [bash] (owned by unix-user:dev)
Oct 25 10:00:07 host su[2302]: pam_unix(su:session): session opened for user root(uid=0) by dev(uid=1000)
`
	res := load(t, "auth.log", log, FormatAuthLog)
	type key struct{ kind, op string }
	got := map[key]Record{}
	for _, r := range res.Records {
		got[key{r.Kind, r.Operation}] = r
	}
	if s := got[key{"process", ""}]; s.Cmdline == "" {
		t.Fatalf("sudo process record kept: %+v", res.Records)
	}
	if a := got[key{"auth", "sudo"}]; a.PrivFrom != "dev" || a.PrivTo != "root" || a.Cmdline != "/usr/bin/systemctl enable evil.service" || a.TTY != "pts/0" || a.Cwd != "/home/dev/proj" {
		t.Fatalf("sudo auth: %+v", a)
	}
	if a := got[key{"auth", "pam-auth-fail sudo"}]; a.PrivFrom != "dev" || a.PrivTo != "dev" || a.Failed == "" {
		t.Fatalf("pam sudo: %+v", a)
	}
	if a := got[key{"auth", "pam-auth-fail su"}]; a.PrivFrom != "dev" || a.PrivTo != "root" {
		t.Fatalf("pam su: %+v", a)
	}
	if _, dup := got[key{"auth", "pam-auth-fail sshd"}]; dup {
		t.Fatal("sshd PAM failure duplicates the sshd Failed line mapping")
	}
	if a := got[key{"auth", "pkexec"}]; a.PrivFrom != "dev" || a.PrivTo != "root" {
		t.Fatalf("pkexec: %+v", a)
	}
	var pkOK, pkFail bool
	for _, r := range res.Records {
		if r.Kind == "process" && r.Cmdline == "/usr/bin/id -u" && r.Failed == "" && r.PrivTo == "root" {
			pkOK = true
		}
		if r.Kind == "process" && r.Cmdline == "/usr/bin/bash" && r.Failed == "Not authorized" {
			pkFail = true
		}
	}
	if !pkOK || !pkFail {
		t.Fatalf("pkexec process records: %+v", res.Records)
	}
	if a := got[key{"auth", "polkit org.freedesktop.policykit.exec"}]; a.PrivTo != "root" || a.Failed != "" {
		t.Fatalf("polkit: %+v", a)
	}
	if a := got[key{"auth", "su"}]; a.PrivFrom != "dev" || a.PrivTo != "root" || a.User != "dev" || a.Resource != "root" {
		t.Fatalf("su: %+v", a)
	}
}

// FuzzLinuxTelemetry: the JSON adapters never panic on hostile lines.
func FuzzLinuxTelemetry(f *testing.F) {
	for _, s := range []string{
		`{"process_exec":{"process":{"pid":1,"binary":"/bin/sh"}},"time":"2026-10-25T10:00:00Z"}`,
		`{"rule":"r","priority":"Warning","output":"o","output_fields":{"evt.type":"connect","fd.name":"a->b:1"},"time":"2026-10-25T10:00:00Z"}`,
		`{"type":"printf","data":"{\"time\":\"2026-10-25T10:00:00Z\",\"pid\":1,\"comm\":\"x\"}"}`,
		`{"Type":"container","Action":"exec_start: sh","Actor":{"ID":"x"},"timeNano":1}`,
		`{"ID":"x","Status":"start","Type":"container","Time":"2026-10-25T10:00:00Z","Name":"n"}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, line string) {
		p := write(t, "x.jsonl", line+"\n")
		for _, fm := range []Format{FormatTetragon, FormatFalco, FormatBpftrace, FormatDocker, FormatPodman} {
			_, _ = Load(p, fm)
		}
	})
}
