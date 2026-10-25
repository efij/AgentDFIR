package endpoint

import (
	"fmt"
	"strings"
	"testing"
	"time"

	w "github.com/efij/AgentDFIR/v4/internal/endpoint/evtx/evtxtest"
)

// All fixtures here are synthetic (internal/endpoint/evtx/evtxtest): real
// provider names, channels and field layouts, no record from a real host.

var host = w.Host{Computer: "DESK-01", UserSID: "S-1-5-21-1-2-3-1001"}

const (
	runKey   = `HKU\S-1-5-21-1-2-3-1001\Software\Microsoft\Windows\CurrentVersion\Run`
	agentExe = `C:\Users\dev\AppData\Local\Programs\claude\claude.exe`
	wmiCause = `Binding EventFilter: instance of __EventFilter { EventNamespace = "root\\cimv2"; Name = "Updater"; Query = "SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'"; QueryLanguage = "WQL"; }; Perm. Consumer: instance of CommandLineEventConsumer { CommandLineTemplate = "C:\\Users\\dev\\AppData\\Roaming\\u.exe"; Name = "Updater"; };`
)

func contextEvents() []w.Event {
	t := func(s int) time.Time { return at0.Add(time.Duration(s) * time.Second) }
	return []w.Event{
		host.SysmonProcessTerminated(1, t(0), 4411, `C:\Windows\System32\cmd.exe`, `DESK\dev`),
		host.SysmonRegistry(2, 12, t(1), "CreateKey", 4412, `C:\Windows\System32\reg.exe`, `HKLM\System\CurrentControlSet\Services\updsvc`, "", `DESK\dev`),
		host.SysmonRegistry(3, 13, t(2), "SetValue", 4412, `C:\Windows\System32\reg.exe`, runKey+`\Updater`, `C:\Users\dev\AppData\Roaming\u.exe`, `DESK\dev`),
		host.SysmonRegistry(4, 14, t(3), "RenameKey", 4412, `C:\Windows\regedit.exe`, `HKCU\Software\Old`, `HKCU\Software\New`, `DESK\dev`),
		host.Security4689(5, t(4), "S-1-5-21-1-2-3-1001", "dev", "DESK", 0x113c, `C:\Windows\System32\cmd.exe`, 0),
		host.Security4625(6, t(5), "admin", "DESK", 3, "10.0.0.9", "ATTACKER", 0, "-"),
		host.Security4648(7, t(6), "S-1-5-21-1-2-3-1001", "dev", "DESK", "svc_backup", "CORP", "fileserver.corp.example", 0x1a2c, `C:\Windows\System32\net.exe`, "-"),
		host.Security4672(8, t(7), "S-1-5-21-1-2-3-1001", "dev", "DESK", "SeDebugPrivilege\r\n\t\t\tSeBackupPrivilege"),
		host.Security4697(9, t(8), "S-1-5-21-1-2-3-1001", "dev", "DESK", "updsvc", `C:\Users\dev\AppData\Roaming\u.exe`, "LocalSystem"),
		host.PowerShell4103(10, t(9), 6000, "Remove-Item", "CommandInvocation(Remove-Item): \"Remove-Item\"\r\nParameterBinding(Remove-Item): name=\"Path\"; value=\"build\""),
		host.TaskScheduler(11, 106, t(10), `\Updater`, `DESK\dev`, "", 0),
		host.TaskScheduler(12, 140, t(11), `\Updater`, `DESK\dev`, "", 0),
		host.TaskScheduler(13, 141, t(12), `\Updater`, `DESK\dev`, "", 0),
		host.TaskScheduler(14, 200, t(13), `\Updater`, "", `C:\Users\dev\AppData\Roaming\u.exe`, 1288),
		host.TaskScheduler(15, 201, t(14), `\Updater`, "", `C:\Users\dev\AppData\Roaming\u.exe`, 1288),
		host.WMIActivity(16, 5857, t(15), w.F("ProviderName", w.String("CIMWin32")), w.F("Code", w.String("0x0")), w.F("HostProcess", w.String("wmiprvse.exe")),
			w.F("ProcessID", w.String("2412")), w.F("ProviderPath", w.String(`%systemroot%\system32\wbem\cimwin32.dll`))),
		host.WMIActivity(17, 5858, t(16), w.F("Id", w.String("{00000000-0000-0000-0000-000000000000}")), w.F("ClientMachine", w.String("DESK-01")), w.F("User", w.String(`DESK\dev`)),
			w.F("ClientProcessId", w.String("4412")), w.F("Component", w.String("Unknown")), w.F("Operation", w.String("Start IWbemServices::ExecQuery - root\\cimv2 : SELECT * FROM Win32_Nope")),
			w.F("ResultCode", w.String("0x80041010")), w.F("PossibleCause", w.String("Unknown"))),
		host.WMIActivity(18, 5859, t(17), w.F("NamespaceName", w.String("//./root/CIMV2")), w.F("Query", w.String("SELECT * FROM __InstanceCreationEvent WITHIN 5 WHERE TargetInstance ISA 'Win32_Process'")),
			w.F("User", w.String(`NT AUTHORITY\SYSTEM`)), w.F("processid", w.String("1500")), w.F("Provider", w.String("WMI Kernel Trace Event Provider")), w.F("queryid", w.String("0")), w.F("PossibleCause", w.String("Permanent"))),
		host.WMIActivity(19, 5860, t(18), w.F("NamespaceName", w.String("//./root/CIMV2")), w.F("Query", w.String("SELECT * FROM Win32_ProcessStartTrace")),
			w.F("User", w.String(`DESK\dev`)), w.F("processid", w.String("4412")), w.F("MachineName", w.String("DESK-01")), w.F("PossibleCause", w.String("Temporary"))),
		host.WMIActivity(20, 5861, t(19), w.F("Namespace", w.String("//./root/subscription")), w.F("ESS", w.String("Updater")),
			w.F("CONSUMER", w.String(`CommandLineEventConsumer="Updater"`)), w.F("PossibleCause", w.String(wmiCause))),
	}
}

func TestEVTXContextKinds(t *testing.T) {
	res, err := Load(writeBytes(t, "Ctx.evtx", w.Build(w.Events(contextEvents()), w.Options{RecordsPerChunk: 7})), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if res.Skipped != 0 || len(res.Records) != 20 || len(res.Problems) != 0 {
		t.Fatalf("skipped=%d records=%d problems=%v", res.Skipped, len(res.Records), res.Problems)
	}
	by := map[string]Record{}
	for _, r := range res.Records {
		head, _, _ := strings.Cut(r.Ref, ",")
		by[head] = r
		if !strings.Contains(r.Ref, "file Ctx.evtx, offset ") {
			t.Errorf("provenance missing: %s", r.Ref)
		}
	}
	chk := func(key string, ok func(Record) bool) {
		t.Helper()
		if r, found := by[key]; !found || !ok(r) {
			t.Errorf("%s: %+v (found %v)", key, r, found)
		}
	}
	chk("sysmon:5 (record 1", func(r Record) bool {
		return r.Kind == KindProcessExit && r.PID == 4411 && baseName(r.Exe) == "cmd.exe" && r.Time.Equal(at0)
	})
	chk("sysmon:12 (record 2", func(r Record) bool {
		return r.Kind == KindRegistry && r.Operation == "create-key" && strings.HasSuffix(r.Resource, `Services\updsvc`) && r.ValueName == "" && r.PID == 4412
	})
	chk("sysmon:13 (record 3", func(r Record) bool {
		return r.Kind == KindRegistry && r.Operation == "set-value" && r.Resource == runKey && r.ValueName == "Updater" && strings.HasSuffix(r.Details, `u.exe`)
	})
	chk("sysmon:14 (record 4", func(r Record) bool { return r.Operation == "rename-key" && r.Details == `HKCU\Software\New` })
	chk("security:4689 (record 5", func(r Record) bool {
		return r.Kind == KindProcessExit && r.PID == 0x113c && r.User == `DESK\dev` && r.Details == ""
	})
	chk("security:4625 (record 6", func(r Record) bool {
		return r.Kind == KindAuth && r.Operation == "logon-failed" && r.User == `DESK\admin` && r.LogonType == "3" && r.SourceIP == "10.0.0.9" && r.Failed == "%%2313"
	})
	chk("security:4648 (record 7", func(r Record) bool {
		return r.Kind == KindAuth && r.Operation == "explicit-credentials" && r.User == `CORP\svc_backup` && r.SubjectUser == `DESK\dev` &&
			r.PID == 0x1a2c && baseName(r.Exe) == "net.exe" && r.Resource == "fileserver.corp.example" && r.SourceIP == ""
	})
	chk("security:4672 (record 8", func(r Record) bool {
		return r.Operation == "special-privileges" && r.User == `DESK\dev` && r.Details == "SeDebugPrivilege SeBackupPrivilege"
	})
	chk("security:4697 (record 9", func(r Record) bool {
		return r.Kind == "service" && strings.HasSuffix(r.Exe, "u.exe") && r.User == "LocalSystem"
	})
	chk("powershell:4103 (record 10", func(r Record) bool {
		return r.Kind == "script" && r.Operation == "module" && r.PID == 6000 && strings.Contains(r.Cmdline, `value="build"`) && strings.Contains(r.Ref, "module Remove-Item")
	})
	chk("taskscheduler:106 (record 11", func(r Record) bool {
		return r.Kind == KindScheduledTask && r.Operation == "registered" && r.Resource == `\Updater` && r.User == `DESK\dev`
	})
	chk("taskscheduler:140 (record 12", func(r Record) bool { return r.Operation == "updated" })
	chk("taskscheduler:141 (record 13", func(r Record) bool { return r.Operation == "deleted" })
	chk("taskscheduler:200 (record 14", func(r Record) bool {
		return r.Operation == "action-started" && baseName(r.Exe) == "u.exe" && r.PID == 1288
	})
	chk("taskscheduler:201 (record 15", func(r Record) bool { return r.Operation == "action-completed" && r.Failed == "" })
	chk("wmi:5857 (record 16", func(r Record) bool {
		return r.Kind == KindWMI && r.Operation == "provider-started" && r.Resource == "CIMWin32"
	})
	chk("wmi:5858 (record 17", func(r Record) bool {
		return r.Operation == "client-failure" && r.Failed == "0x80041010" && r.PID == 4412
	})
	chk("wmi:5859 (record 18", func(r Record) bool {
		return r.Operation == "permanent-subscription" && strings.Contains(r.Details, "Win32_Process") && r.PID == 1500
	})
	chk("wmi:5860 (record 19", func(r Record) bool { return r.Operation == "temporary-subscription" })
	chk("wmi:5861 (record 20", func(r Record) bool {
		return r.Operation == "consumer-binding" && strings.Contains(r.Resource, `CommandLineEventConsumer="Updater"`) && strings.Contains(r.Details, "CommandLineTemplate")
	})
	notices := strings.Join(res.Notices, "\n")
	for _, want := range []string{`service "updsvc" installed`, `scheduled task "\\Updater" registered`, `scheduled task "\\Updater" deleted`, "WMI permanent event consumer bound"} {
		if !strings.Contains(notices, want) {
			t.Errorf("notice %q missing:\n%s", want, notices)
		}
	}
	for _, r := range res.Records {
		if want := r.Kind != "service" && r.Kind != "script"; IsContext(r) != want {
			t.Errorf("IsContext(%s) = %v", r.Ref, !want)
		}
	}
	if IsContext(Record{Kind: "auth", Source: "authlog"}) {
		t.Error("auth.log records are sightings, not context")
	}
}

// stripProvenance drops the input-specific tail (file, offset or line)
// so records from the three inputs compare equal.
func stripProvenance(rs []Record) []Record {
	out := make([]Record, len(rs))
	for i, r := range rs {
		if j := strings.Index(r.Ref, ", file "); j >= 0 {
			r.Ref = r.Ref[:j] + ")"
		} else if j := strings.LastIndex(r.Ref, ", "); j >= 0 {
			r.Ref = r.Ref[:j] + ")"
		}
		out[i] = r
	}
	return out
}

// The same context events read from a native .evtx file, a wevtutil XML
// export and evtx_dump JSON give the same records.
func TestContextKindsSameAcrossInputs(t *testing.T) {
	all := contextEvents()
	pick := []w.Event{all[2], all[6], all[10], all[19]} // Sysmon 13, Security 4648, Task 106, WMI 5861
	fromEVTX, err := Load(writeBytes(t, "Ctx.evtx", w.Build(w.Events(pick), w.Options{})), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	ft := func(s int) string {
		return at0.Add(time.Duration(s) * time.Second).Format("2006-01-02T15:04:05.0000000Z")
	}
	esc := func(s string) string {
		return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
	}
	xmlDoc := `<?xml version="1.0" encoding="utf-8"?>
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Sysmon" Guid="{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"/><EventID>13</EventID><TimeCreated SystemTime="` + ft(2) + `"/><EventRecordID>3</EventRecordID><Execution ProcessID="3056" ThreadID="4012"/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>DESK-01</Computer></System>
<EventData><Data Name="RuleName">-</Data><Data Name="EventType">SetValue</Data><Data Name="UtcTime">` + at0.Add(2*time.Second).Format("2006-01-02 15:04:05.000") + `</Data><Data Name="ProcessGuid">{7E2B4F11-113C-6720-0000-00100000113C}</Data><Data Name="ProcessId">4412</Data><Data Name="Image">C:\Windows\System32\reg.exe</Data><Data Name="TargetObject">` + runKey + `\Updater</Data><Data Name="Details">C:\Users\dev\AppData\Roaming\u.exe</Data><Data Name="User">DESK\dev</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}"/><EventID>4648</EventID><TimeCreated SystemTime="` + ft(6) + `"/><EventRecordID>7</EventRecordID><Execution ProcessID="4" ThreadID="120"/><Channel>Security</Channel><Computer>DESK-01</Computer></System>
<EventData><Data Name="SubjectUserSid">S-1-5-21-1-2-3-1001</Data><Data Name="SubjectUserName">dev</Data><Data Name="SubjectDomainName">DESK</Data><Data Name="SubjectLogonId">0x5c1d2</Data><Data Name="LogonGuid">{00000000-0000-0000-0000-000000000000}</Data><Data Name="TargetUserName">svc_backup</Data><Data Name="TargetDomainName">CORP</Data><Data Name="TargetLogonGuid">{00000000-0000-0000-0000-000000000000}</Data><Data Name="TargetServerName">fileserver.corp.example</Data><Data Name="TargetInfo">fileserver.corp.example</Data><Data Name="ProcessId">0x1a2c</Data><Data Name="ProcessName">C:\Windows\System32\net.exe</Data><Data Name="IpAddress">-</Data><Data Name="IpPort">0</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-TaskScheduler" Guid="{DE7B24EA-73C8-4A09-985D-5BDADCFA9017}"/><EventID>106</EventID><TimeCreated SystemTime="` + ft(10) + `"/><EventRecordID>11</EventRecordID><Execution ProcessID="3056" ThreadID="4012"/><Channel>Microsoft-Windows-TaskScheduler/Operational</Channel><Computer>DESK-01</Computer></System>
<EventData Name="TaskRegisteredEvent"><Data Name="TaskName">\Updater</Data><Data Name="UserContext">DESK\dev</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><Provider Name="Microsoft-Windows-WMI-Activity" Guid="{1418EF04-B0B4-4623-BF7E-D74AB47BBDAA}"/><EventID>5861</EventID><TimeCreated SystemTime="` + ft(19) + `"/><EventRecordID>20</EventRecordID><Execution ProcessID="3056" ThreadID="4012"/><Channel>Microsoft-Windows-WMI-Activity/Operational</Channel><Computer>DESK-01</Computer></System>
<UserData><Operation_ESStoConsumerBinding xmlns="http://manifests.microsoft.com/win/2006/windows/WMI"><Namespace>//./root/subscription</Namespace><ESS>Updater</ESS><CONSUMER>` + esc(`CommandLineEventConsumer="Updater"`) + `</CONSUMER><PossibleCause>` + esc(wmiCause) + `</PossibleCause></Operation_ESStoConsumerBinding></UserData></Event>
</Events>
`
	fromXML, err := Load(write(t, "export.xml", xmlDoc), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	jsonl := fmt.Sprintf(`{"Event":{"#attributes":{"xmlns":"http://schemas.microsoft.com/win/2004/08/events/event"},"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Sysmon","Guid":"{5770385F-C22A-43E0-BF4C-06F5698FFBD9}"}},"EventID":13,"TimeCreated":{"#attributes":{"SystemTime":"%s"}},"EventRecordID":3,"Execution":{"#attributes":{"ProcessID":3056,"ThreadID":4012}},"Channel":"Microsoft-Windows-Sysmon/Operational","Computer":"DESK-01"},"EventData":{"RuleName":"-","EventType":"SetValue","UtcTime":"%s","ProcessId":4412,"Image":"C:\\Windows\\System32\\reg.exe","TargetObject":%q,"Details":"C:\\Users\\dev\\AppData\\Roaming\\u.exe","User":"DESK\\dev"}}}
{"Event":{"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-Security-Auditing"}},"EventID":4648,"TimeCreated":{"#attributes":{"SystemTime":"%s"}},"EventRecordID":7,"Execution":{"#attributes":{"ProcessID":4,"ThreadID":120}},"Channel":"Security"},"EventData":{"SubjectUserSid":"S-1-5-21-1-2-3-1001","SubjectUserName":"dev","SubjectDomainName":"DESK","TargetUserName":"svc_backup","TargetDomainName":"CORP","TargetServerName":"fileserver.corp.example","TargetInfo":"fileserver.corp.example","ProcessId":"0x1a2c","ProcessName":"C:\\Windows\\System32\\net.exe","IpAddress":"-","IpPort":"0"}}}
{"Event":{"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-TaskScheduler"}},"EventID":106,"TimeCreated":{"#attributes":{"SystemTime":"%s"}},"EventRecordID":11,"Channel":"Microsoft-Windows-TaskScheduler/Operational"},"EventData":{"#attributes":{"Name":"TaskRegisteredEvent"},"TaskName":"\\Updater","UserContext":"DESK\\dev"}}}
{"Event":{"System":{"Provider":{"#attributes":{"Name":"Microsoft-Windows-WMI-Activity"}},"EventID":5861,"TimeCreated":{"#attributes":{"SystemTime":"%s"}},"EventRecordID":20,"Channel":"Microsoft-Windows-WMI-Activity/Operational"},"UserData":{"Operation_ESStoConsumerBinding":{"#attributes":{"xmlns":"http://manifests.microsoft.com/win/2006/windows/WMI"},"Namespace":"//./root/subscription","ESS":"Updater","CONSUMER":"CommandLineEventConsumer=\"Updater\"","PossibleCause":%q}}}}
`, ft(2), at0.Add(2*time.Second).Format("2006-01-02 15:04:05.000"), runKey+`\Updater`, ft(6), ft(10), ft(19), wmiCause)
	fromJSON, err := Load(write(t, "evtx_dump.jsonl", jsonl), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	a, b, c := stripProvenance(fromEVTX.Records), stripProvenance(fromXML.Records), stripProvenance(fromJSON.Records)
	if len(a) != 4 || len(b) != 4 || len(c) != 4 {
		t.Fatalf("records evtx=%d xml=%d json=%d\nxml problems %v\njson problems %v", len(a), len(b), len(c), fromXML.Problems, fromJSON.Problems)
	}
	for i := range a {
		if fmt.Sprintf("%+v", a[i]) != fmt.Sprintf("%+v", b[i]) {
			t.Errorf("evtx vs xml %d:\n%+v\n%+v", i, a[i], b[i])
		}
		if fmt.Sprintf("%+v", a[i]) != fmt.Sprintf("%+v", c[i]) {
			t.Errorf("evtx vs json %d:\n%+v\n%+v", i, a[i], c[i])
		}
	}
	if !strings.Contains(fromXML.Records[0].Ref, "file export.xml") || !strings.Contains(fromJSON.Records[0].Ref, "evtx_dump.jsonl:1") {
		t.Errorf("provenance: %q / %q", fromXML.Records[0].Ref, fromJSON.Records[0].Ref)
	}
}

// Malformed context events become recorded problems, not records, and
// never stop the file.
func TestContextKindsMalformed(t *testing.T) {
	bad := []w.Event{
		host.SysmonRegistry(1, 13, at0, "SetValue", 10, `C:\x.exe`, "", "data", `DESK\dev`), // no TargetObject
		host.TaskScheduler(2, 106, at0, "", `DESK\dev`, "", 0),                              // no TaskName
		host.PowerShell4103(3, at0, 6000, "Get-Item", ""),                                   // no payload
		host.SysmonProcessTerminated(4, at0, 11, `C:\ok.exe`, `DESK\dev`),
	}
	res, err := Load(writeBytes(t, "bad.evtx", w.Build(w.Events(bad), w.Options{})), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	probs := strings.Join(res.Problems, "\n")
	if len(res.Records) != 1 || res.Skipped != 3 || !strings.Contains(probs, "without TargetObject") || !strings.Contains(probs, "without TaskName") || !strings.Contains(probs, "without payload") {
		t.Fatalf("records=%d skipped=%d problems=%v", len(res.Records), res.Skipped, res.Problems)
	}
	// An XML event with no usable time.
	res, err = Load(write(t, "x.xml", `<Event><System><Provider Name="Microsoft-Windows-TaskScheduler"/><EventID>106</EventID><EventRecordID>9</EventRecordID></System><EventData><Data Name="TaskName">\T</Data></EventData></Event>`), FormatAuto)
	if err != nil || len(res.Records) != 0 || res.Skipped != 1 || !strings.Contains(strings.Join(res.Problems, ""), "taskscheduler:106 (record 9, file x.xml): no timestamp") {
		t.Fatalf("no time: %v %+v", err, res)
	}
}

// Free text is cut at maxContextDetail and records past the per-kind
// bound are counted as skipped with one note.
func TestContextKindsBounded(t *testing.T) {
	long := strings.Repeat("A", maxContextDetail+100)
	old := maxContextPerKind
	maxContextPerKind = 2
	defer func() { maxContextPerKind = old }()
	var evs []w.Event
	for i := 0; i < 4; i++ {
		evs = append(evs, host.SysmonRegistry(uint64(i+1), 13, at0.Add(time.Duration(i)*time.Second), "SetValue", 10, `C:\x.exe`, `HKCU\Software\X\V`, long, `DESK\dev`))
	}
	evs = append(evs, host.SysmonProcessTerminated(9, at0, 11, `C:\ok.exe`, `DESK\dev`))
	res, err := Load(writeBytes(t, "big.evtx", w.Build(w.Events(evs), w.Options{RecordsPerChunk: 2})), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 3 || res.Skipped != 2 || !strings.Contains(strings.Join(res.Problems, ""), "more than 2 registry record(s) in one file") {
		t.Fatalf("records=%d skipped=%d problems=%v", len(res.Records), res.Skipped, res.Problems)
	}
	for _, r := range res.Records {
		if r.Kind == KindRegistry && (len(r.Details) > maxContextDetail+40 || !strings.HasSuffix(r.Details, "…[100 bytes cut]")) {
			t.Fatalf("details not bounded: %d %q", len(r.Details), r.Details[len(r.Details)-30:])
		}
	}
}

// FuzzContextXML: arbitrary Windows XML exports never panic the context
// mapping and every kept record has a kind and a time.
func FuzzContextXML(f *testing.F) {
	f.Add(`<Event><System><Provider Name="Microsoft-Windows-WMI-Activity"/><EventID>5861</EventID><TimeCreated SystemTime="2026-08-30T10:00:00Z"/></System><UserData><X><CONSUMER>a</CONSUMER></X></UserData></Event>`)
	f.Add(`<Event><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>13</EventID></System><EventData><Data Name="UtcTime">2026-08-30 10:00:00.000</Data><Data Name="TargetObject">HKCU\x</Data></EventData></Event>`)
	f.Fuzz(func(t *testing.T, doc string) {
		p := write(t, "f.xml", doc)
		res, err := Load(p, FormatSysmon)
		if err != nil {
			return
		}
		for _, r := range res.Records {
			if r.Kind == "" || r.Time.IsZero() || len(r.Details) > maxContextDetail+64 {
				t.Fatalf("bad record %+v", r)
			}
		}
	})
}

// Records the Windows rules act on are kept past the per-kind bound, so
// a flood of noise cannot push evidence out; the bound marks coverage
// incomplete.
func TestContextCapKeepsActionable(t *testing.T) {
	old := maxContextPerKind
	maxContextPerKind = 2
	defer func() { maxContextPerKind = old }()
	var evs []w.Event
	for i := 0; i < 10; i++ {
		evs = append(evs, host.SysmonRegistry(uint64(i+1), 13, at0.Add(time.Duration(i)*time.Millisecond), "SetValue", 10, `C:\x.exe`, `HKCU\Software\Noise\V`, "1", `DESK\dev`))
	}
	evs = append(evs,
		host.SysmonRegistry(20, 13, at0.Add(time.Second), "SetValue", 10, `C:\x.exe`, runKey+`\Updater`, `C:\u.exe`, `DESK\dev`),
		host.SysmonRegistry(21, 12, at0.Add(time.Second), "CreateKey", 10, `C:\x.exe`, `HKLM\System\CurrentControlSet\Services\evil`, "", `DESK\dev`))
	for i := 0; i < 5; i++ {
		evs = append(evs, host.TaskScheduler(uint64(30+i), 201, at0.Add(time.Second), `\Noise`, "", `C:\n.exe`, 1))
	}
	evs = append(evs, host.TaskScheduler(40, 106, at0.Add(2*time.Second), `\Updater`, `DESK\dev`, "", 0),
		host.Security4648(41, at0.Add(2*time.Second), "S-1-5-21-1", "dev", "DESK", "svc", "CORP", "srv", 0x10, `C:\net.exe`, "-"),
		host.WMIActivity(42, 5861, at0.Add(2*time.Second), w.F("Namespace", w.String("//./root/subscription")), w.F("ESS", w.String("F")), w.F("CONSUMER", w.String(`CommandLineEventConsumer="C"`))))
	res, err := Load(writeBytes(t, "flood.evtx", w.Build(w.Events(evs), w.Options{})), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	kept := map[string]bool{}
	for _, r := range res.Records {
		head, _, _ := strings.Cut(r.Ref, ",")
		kept[head] = true
	}
	for _, want := range []string{"sysmon:13 (record 20", "sysmon:12 (record 21", "taskscheduler:106 (record 40", "security:4648 (record 41", "wmi:5861 (record 42"} {
		if !kept[want] {
			t.Errorf("actionable record %s dropped", want)
		}
	}
	if res.ContextDropped[KindRegistry] != 8 || res.ContextDropped[KindScheduledTask] != 3 || !strings.Contains(strings.Join(res.Problems, "\n"), "registry coverage is INCOMPLETE") {
		t.Fatalf("dropped %v problems %v", res.ContextDropped, res.Problems)
	}
}

// Notices have per-category bounds: task churn cannot crowd out a
// cleared log or a service install, and 140 (updated) gets no notice.
func TestNoticeCategories(t *testing.T) {
	var evs []w.Event
	for i := 0; i < 300; i++ {
		evs = append(evs, host.TaskScheduler(uint64(i+1), 140, at0, fmt.Sprintf(`\T%d`, i), `DESK\dev`, "", 0))
	}
	for i := 0; i < 80; i++ {
		evs = append(evs, host.TaskScheduler(uint64(1000+i), 106, at0, fmt.Sprintf(`\R%d`, i), `DESK\dev`, "", 0))
	}
	evs = append(evs, host.Security4697(2000, at0, "S-1-5-21-1", "dev", "DESK", "updsvc", `C:\u.exe`, "LocalSystem"),
		w.Event{Provider: "Microsoft-Windows-Eventlog", EventID: 1102, Qualifiers: -1, Time: at0, RecordID: 2001, Channel: "Security", Computer: "DESK-01",
			UserDataElement: "LogFileCleared", UserDataNS: "http://manifests.microsoft.com/win/2004/08/windows/eventlog",
			UserData: []w.KV{w.F("SubjectUserName", w.String("dev")), w.F("SubjectDomainName", w.String("DESK"))}})
	res, err := Load(writeBytes(t, "churn.evtx", w.Build(w.Events(evs), w.Options{})), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	all := strings.Join(res.Notices, "\n")
	if strings.Contains(all, " updated by ") || strings.Count(all, " registered by ") != 50 || !strings.Contains(all, "more scheduled-task notices not shown") ||
		!strings.Contains(all, `service "updsvc" installed`) || !strings.Contains(all, `event log "Security" cleared`) {
		t.Fatalf("%d notices:\n%s", len(res.Notices), all)
	}
}
