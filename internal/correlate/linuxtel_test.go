package correlate

import (
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// linuxFixture loads one synthetic eBPF / runtime fixture shared with the
// endpoint package (see internal/endpoint/testdata/linuxtel/README.md).
func linuxFixture(t *testing.T, name string) []endpoint.Record {
	t.Helper()
	res, err := endpoint.Load(filepath.Join("..", "endpoint", "testdata", "linuxtel", name), endpoint.FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	return res.Records
}

func stateOf(events []schema.Event, id string) string {
	for _, e := range events {
		if e.EventID == id {
			return e.Corroboration
		}
	}
	return ""
}

func TestTetragonCorroboratesLikeAuditd(t *testing.T) {
	events := []schema.Event{
		tc("t1", "2026-10-25T10:00:03Z", "Bash", "curl -s https://example.org/install.sh -o /tmp/i.sh"), // exec seen → CORROBORATED
		tc("t2", "2026-10-25T10:00:15Z", "Bash", "pytest -q"),                                           // inside coverage, no exec → CONTRADICTED
		tc("t3", "2026-10-25T12:00:00Z", "Bash", "make deploy"),                                         // outside coverage → unchanged
	}
	res, findings := Endpoint(events, linuxFixture(t, "tetragon.jsonl"), EndpointOptions{})
	if res.Corroborated != 1 || res.Contradicted != 1 || res.OutsideCover != 1 {
		t.Fatalf("summary %+v", res)
	}
	if stateOf(events, "t1") != schema.StateCorroborated || stateOf(events, "t2") != schema.StateContradicted || stateOf(events, "t3") != schema.StateObserved {
		t.Fatalf("states %s %s %s", stateOf(events, "t1"), stateOf(events, "t2"), stateOf(events, "t3"))
	}
	if !strings.Contains(events[0].Summary, "corroborated by tetragon process") {
		t.Fatalf("note: %s", events[0].Summary)
	}
	got := map[string]schema.Finding{}
	for _, f := range findings {
		got[f.RuleID] = f
	}
	if f, ok := got["AGENT_BPF_LOAD"]; !ok || f.MitreATTACK != "T1014" || len(f.Related) != 2 {
		t.Fatalf("bpf: %+v", f)
	}
	if f, ok := got["AGENT_NAMESPACE_ESCAPE"]; !ok || f.Severity != "CRITICAL" || len(f.Related) != 3 || !strings.Contains(strings.Join(f.Related, "\n"), "pod agents/coder-7d9f") {
		t.Fatalf("escape: %+v", f)
	}
}

func TestFalcoAndDockerCorroborateButNeverContradict(t *testing.T) {
	events := []schema.Event{
		tc("f1", "2026-10-25T10:01:01Z", "Bash", `bash -c "git status"`),                  // Falco execve alert
		tc("f2", "2026-10-25T10:01:30Z", "Bash", "make deploy"),                           // near Falco records, no match
		tc("d1", "2026-10-25T10:03:04Z", "Bash", "docker exec web sh -c cat /etc/passwd"), // docker exec_start
	}
	var recs []endpoint.Record
	recs = append(recs, linuxFixture(t, "falco.jsonl")...)
	recs = append(recs, linuxFixture(t, "docker-events.jsonl")...)
	res, _ := Endpoint(events, recs, EndpointOptions{})
	if stateOf(events, "f1") != schema.StateCorroborated || stateOf(events, "d1") != schema.StateCorroborated {
		t.Fatalf("states f1=%s d1=%s (%+v)", stateOf(events, "f1"), stateOf(events, "d1"), res)
	}
	if stateOf(events, "f2") != schema.StateObserved || res.Contradicted != 0 {
		t.Fatalf("a sighting-only miss must stay OBSERVED: %s %+v", stateOf(events, "f2"), res)
	}
	if res.WitnessCorroborated != 2 || !res.CoverageStart.IsZero() {
		t.Fatalf("sightings widened coverage or missed: %+v", res)
	}
}

// Adding Falco, bpftrace and container-runtime records to host telemetry
// must not change what lies outside the host coverage window.
func TestLinuxSightingsLeaveCoverageUnchanged(t *testing.T) {
	mk := func() []schema.Event {
		return []schema.Event{
			tc("o1", "2026-10-25T10:00:03Z", "Bash", "curl -s https://example.org/install.sh -o /tmp/i.sh"),
			tc("o2", "2026-10-25T10:01:40Z", "Bash", "terraform apply"), // after Tetragon coverage, near Falco/bpftrace/docker
			tc("o3", "2026-10-25T10:03:30Z", "Bash", "kubectl get pods"),
		}
	}
	host := linuxFixture(t, "tetragon.jsonl")
	base := mk()
	r1, _ := Endpoint(base, append([]endpoint.Record(nil), host...), EndpointOptions{})
	all := append([]endpoint.Record(nil), host...)
	for _, f := range []string{"falco.jsonl", "bpftrace.jsonl", "docker-events.jsonl", "podman-events.jsonl"} {
		all = append(all, linuxFixture(t, f)...)
	}
	with := mk()
	r2, _ := Endpoint(with, all, EndpointOptions{})
	if r1.OutsideCover != 2 || r2.OutsideCover != r1.OutsideCover || r2.Contradicted != r1.Contradicted ||
		!r2.CoverageStart.Equal(r1.CoverageStart) || !r2.CoverageEnd.Equal(r1.CoverageEnd) {
		t.Fatalf("coverage changed: %+v vs %+v", r1, r2)
	}
	for i := range base {
		if base[i].Corroboration != with[i].Corroboration {
			t.Fatalf("%s: %s → %s", base[i].EventID, base[i].Corroboration, with[i].Corroboration)
		}
	}
}

func TestLinuxAgentRules(t *testing.T) {
	agent := endpoint.Record{Time: ts("2026-10-25T10:00:00Z"), Kind: "process", PID: 100, PPID: 1, Exe: "/usr/local/bin/claude", Cmdline: "claude", Source: "auditd", Ref: "a:1"}
	child := func(sec int, kind string, mod func(*endpoint.Record)) endpoint.Record {
		r := endpoint.Record{Time: agent.Time.Add(timeSec(sec)), Kind: kind, PID: 200 + sec, PPID: 100, Source: "auditd", Ref: "a:x"}
		mod(&r)
		return r
	}
	attack := []endpoint.Record{agent,
		child(1, "file", func(r *endpoint.Record) { r.FilePath, r.FileOp = "/etc/systemd/system/backdoor.service", "create" }),
		child(2, "process", func(r *endpoint.Record) { r.Cmdline = "systemctl --user enable --now miner.timer" }),
		child(3, "file", func(r *endpoint.Record) { r.FilePath, r.FileOp = "/var/spool/cron/crontabs/dev", "modify" }),
		child(4, "process", func(r *endpoint.Record) { r.Cmdline = "crontab /tmp/c" }),
		child(5, "file", func(r *endpoint.Record) {
			r.Kind, r.FilePath, r.FileOp, r.ContainerID = "file", "/var/run/docker.sock", "open", "abc"
		}),
	}
	_, f := Endpoint(nil, attack, EndpointOptions{})
	got := map[string]schema.Finding{}
	for _, x := range f {
		got[x.RuleID] = x
	}
	if s := got["AGENT_SYSTEMD_PERSISTENCE"]; len(s.Related) != 2 || s.MitreATTACK != "T1053.006" {
		t.Fatalf("systemd: %+v", s)
	}
	if c := got["AGENT_CRONTAB_MODIFIED"]; len(c.Related) != 2 || c.MitreATTACK != "T1053.003" {
		t.Fatalf("cron: %+v", c)
	}
	if e := got["AGENT_NAMESPACE_ESCAPE"]; len(e.Related) != 1 {
		t.Fatalf("docker.sock: %+v", e)
	}

	// Benign shapes: reading, listing, status queries, a host-side socket
	// and the same writes by a process outside the agent's tree.
	benign := []endpoint.Record{agent,
		child(1, "process", func(r *endpoint.Record) { r.Cmdline = "crontab -l" }),
		child(2, "process", func(r *endpoint.Record) { r.Cmdline = "systemctl status nginx" }),
		child(3, "file", func(r *endpoint.Record) { r.FilePath, r.FileOp = "/etc/systemd/system/nginx.service", "open" }),
		child(4, "file", func(r *endpoint.Record) { r.FilePath, r.FileOp = "/var/run/docker.sock", "open" }), // not in a container
		child(5, "process", func(r *endpoint.Record) { r.Cmdline = "bpftool prog list" }),
		child(6, "process", func(r *endpoint.Record) { r.Cmdline = "nsenter --help" }),
		{Time: agent.Time.Add(timeSec(7)), Kind: "file", PID: 900, PPID: 1, Exe: "/usr/bin/dpkg", FilePath: "/etc/systemd/system/x.service", FileOp: "create", Source: "auditd", Ref: "a:9"},
		{Time: agent.Time.Add(timeSec(8)), Kind: "process", PID: 901, PPID: 1, Exe: "/usr/bin/crontab", Cmdline: "crontab -e", Source: "auditd", Ref: "a:10"},
	}
	_, f = Endpoint(nil, benign, EndpointOptions{})
	for _, x := range f {
		if strings.HasPrefix(x.RuleID, "AGENT_") {
			t.Fatalf("benign fired %s: %+v", x.RuleID, x.Related)
		}
	}
}

func TestCrontabWrites(t *testing.T) {
	for cmd, want := range map[string]bool{
		"crontab /tmp/x": true, "crontab -": true, "crontab -e": true, "crontab -r": true, "crontab": true,
		"crontab -l": false, "crontab -u root -l": false, "/usr/bin/crontab -u dev /tmp/c": true, "ls": false,
		// -l ends only its own invocation.
		"crontab -l; crontab evil.txt": true, "crontab -l;crontab evil.txt": true, "crontab -l && crontab -": true,
		"crontab -l | grep x": false, "crontab -l || crontab -r": true,
		// Exec argv is not shell text; only a shell's -c script is.
		"bash -c echo '* * * * * x' | crontab": true, "sh -c crontab -l;crontab evil.txt": true,
		"crontab 'x;y'": true, `"crontab" -e`: true, `cr\ontab -l`: false,
	} {
		if got := crontabWrites(cmd); got != want {
			t.Errorf("%q: %v", cmd, got)
		}
	}
}

func timeSec(n int) time.Duration { return time.Duration(n) * time.Second }

func TestSystemctlAndNsenterArgv(t *testing.T) {
	for cmd, want := range map[string]bool{
		"systemctl enable x": true, "systemctl -q enable x": true, "systemctl --user --now enable x.timer": true,
		"systemctl -H host enable x": true, "sudo systemctl -qf link /tmp/x.service": true, "systemctl status x": false,
		"systemctl -t service list-units": false, "systemctl is-enabled x": false, "echo enable; systemctl status": false,
		`systemctl 'enable' x`: true, `"systemctl" --now enable x`: true, "sh -c 'true; systemctl -q enable x'": true,
	} {
		if got := systemctlEnables(cmd); got != want {
			t.Errorf("systemctl %q: %v", cmd, got)
		}
	}
	for cmd, want := range map[string]bool{
		"nsenter -t 1 -m sh": true, "nsenter -t1 -a": true, "nsenter -at1": true, "nsenter -a -t 1 sh": true,
		"nsenter --target 1 --mount": true, "nsenter --target=1 -a": true, "/usr/bin/nsenter -m -t 1": true,
		"nsenter -t 12 -m": false, "nsenter --help": false, "nsenter -mt1": false, // -m consumes "t1" as its file
		"nsenter -t 4242 -n ip a; echo -t 1": true, // the original regex stays as a fallback and is conservative "nsenter -S 0 -t 1 -a": true,
		// An argv element with ';' must not hide the target (exec records).
		"nsenter --wd=a;b -t 1 sh": true, "sh -c 'nsenter --ta=1 -a'": true,
		"nsenter --targ 01 -m": true, "nsenter -t +1 -m": true, `nsenter -t "1" -a`: true, `"nsenter" --target=1`: true,
		"nsenter --t 1": false, "nsenter -t 10": false,
	} {
		if got := nsenterTargetsInit(cmd); got != want {
			t.Errorf("nsenter %q: %v", cmd, got)
		}
	}
}

func FuzzCommandParsers(f *testing.F) {
	for _, s := range []string{"crontab -l; crontab x", `sh -c 'nsenter --ta=1'`, `systemctl "enable`, `a\`, `'`, `"\`} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, cmd string) {
		_ = crontabWrites(cmd)
		_ = systemctlEnables(cmd)
		_ = nsenterTargetsInit(cmd)
	})
}
