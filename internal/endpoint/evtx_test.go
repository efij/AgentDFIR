package endpoint

import (
	"encoding/binary"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	w "github.com/efij/AgentDFIR/v4/internal/endpoint/evtx/evtxtest"
)

const sysmonProv, sysmonChan = "Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational"

func sysmonEv(id uint64, eid uint16, at time.Time, data ...w.KV) w.Event {
	data = append([]w.KV{w.F("UtcTime", w.String(at.Format("2006-01-02 15:04:05.000")))}, data...)
	return w.Event{Provider: sysmonProv, ProviderGUID: "{5770385F-C22A-43E0-BF4C-06F5698FFBD9}", EventID: eid, Qualifiers: -1, Version: 5, Level: 4,
		Time: at, RecordID: id, PID: 3056, TID: 4012, Channel: sysmonChan, Computer: "DESK-01", UserSID: "S-1-5-18", Data: data}
}

func writeBytes(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

var at0 = time.Date(2026, 8, 30, 10, 0, 7, 123000000, time.UTC)

func TestEVTXMapping(t *testing.T) {
	evs := []w.Event{
		sysmonEv(77, 1, at0, w.F("ProcessId", w.Uint32(4411)), w.F("Image", w.String(`C:\Windows\System32\cmd.exe`)), w.F("CommandLine", w.String("cmd.exe /c rmdir /s /q build")),
			w.F("User", w.String(`DESK\dev`)), w.F("ParentProcessId", w.Uint32(4400)), w.F("ParentImage", w.String(`C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe`))),
		sysmonEv(78, 3, at0.Add(3*time.Second), w.F("ProcessId", w.Uint32(4412)), w.F("Image", w.String(`C:\Program Files\nodejs\node.exe`)),
			w.F("DestinationIp", w.String("185.10.10.10")), w.F("DestinationPort", w.Uint16(4444)), w.F("DestinationHostname", w.String("-"))),
		sysmonEv(79, 11, at0.Add(5*time.Second), w.F("ProcessId", w.Uint32(4413)), w.F("Image", w.String(`C:\Program Files\nodejs\node.exe`)), w.F("TargetFilename", w.String(`C:\Users\dev\.ssh\authorized_keys`))),
		sysmonEv(80, 22, at0.Add(6*time.Second), w.F("ProcessId", w.Uint32(4412)), w.F("Image", w.String(`C:\Program Files\nodejs\node.exe`)), w.F("QueryName", w.String("evil.example")), w.F("QueryResults", w.String("::ffff:185.10.10.10;"))),
		sysmonEv(81, 26, at0.Add(7*time.Second), w.F("ProcessId", w.Uint32(4413)), w.F("Image", w.String(`C:\Windows\System32\cmd.exe`)), w.F("TargetFilename", w.String(`C:\proj\build\out.dll`))),
		sysmonEv(82, 13, at0.Add(8*time.Second), w.F("TargetObject", w.String(`HKLM\Software\x`))), // registry (see evtxkinds_test.go)
		sysmonEv(83, 5, at0.Add(9*time.Second), w.F("ProcessId", w.Uint32(4411))),                  // process exit
		{Provider: "Microsoft-Windows-Security-Auditing", ProviderGUID: "{54849625-5478-4994-A5BA-3E3B0328C30D}", EventID: 4688, Qualifiers: -1, Version: 2, Task: 13312,
			Keywords: 0x8020000000000000, Time: at0.Add(10 * time.Second), RecordID: 5001, PID: 4, TID: 120, Channel: "Security", Computer: "DESK-01",
			Data: []w.KV{w.F("SubjectUserSid", w.SID("S-1-5-21-1-2-3-1001")), w.F("SubjectUserName", w.String("dev")), w.F("SubjectDomainName", w.String("DESK")),
				w.F("NewProcessId", w.Hex64(0x1a2b)), w.F("NewProcessName", w.String(`C:\Windows\System32\whoami.exe`)), w.F("ProcessId", w.Hex64(0x113c)),
				w.F("CommandLine", w.String("whoami /all")), w.F("TargetUserName", w.String("-")), w.F("TargetDomainName", w.String("-")), w.F("ParentProcessName", w.String(`C:\Windows\System32\cmd.exe`))}},
		{Provider: "Microsoft-Windows-Security-Auditing", EventID: 4624, Qualifiers: -1, Time: at0.Add(11 * time.Second), RecordID: 5002, Channel: "Security", Computer: "DESK-01",
			Data: []w.KV{w.F("TargetUserName", w.String("dev")), w.F("LogonType", w.Uint32(2))}},
		{Provider: "Microsoft-Windows-PowerShell", EventID: 4104, Qualifiers: -1, Level: 5, Time: at0.Add(12 * time.Second), RecordID: 900, PID: 6000, TID: 6001,
			Channel: "Microsoft-Windows-PowerShell/Operational", Computer: "DESK-01", UserSID: "S-1-5-21-1-2-3-1001",
			Data: []w.KV{w.F("MessageNumber", w.Int32(1)), w.F("MessageTotal", w.Int32(1)), w.F("ScriptBlockText", w.String("Remove-Item -Recurse -Force build")),
				w.F("ScriptBlockId", w.GUID("{11111111-2222-3333-4444-555555555555}")), w.F("Path", w.String(""))}},
		{Provider: "Service Control Manager", ProviderGUID: "{555908D1-A6D7-4695-8E1E-26931D2012F4}", EventID: 7045, Qualifiers: 16384, Time: at0.Add(13 * time.Second),
			RecordID: 300, PID: 700, TID: 701, Channel: "System", Computer: "DESK-01", UserSID: "S-1-5-21-1-2-3-1001",
			Data: []w.KV{w.F("ServiceName", w.String("updsvc")), w.F("ImagePath", w.String(`C:\Users\dev\AppData\Local\Temp\u.exe`)), w.F("ServiceType", w.String("user mode service")),
				w.F("StartType", w.String("auto start")), w.F("AccountName", w.String("LocalSystem"))}},
		{Provider: "Microsoft-Windows-Eventlog", EventID: 1102, Qualifiers: -1, Time: at0.Add(14 * time.Second), RecordID: 5003, PID: 1100, TID: 1200, Channel: "Security", Computer: "DESK-01",
			UserDataElement: "LogFileCleared", UserDataNS: "http://manifests.microsoft.com/win/2004/08/windows/eventlog",
			UserData: []w.KV{w.F("SubjectUserSid", w.String("S-1-5-21-1-2-3-1001")), w.F("SubjectUserName", w.String("dev")), w.F("SubjectDomainName", w.String("DESK")), w.F("SubjectLogonId", w.String("0x3e7"))}},
		{Provider: "Microsoft-Windows-Eventlog", EventID: 104, Qualifiers: -1, Time: at0.Add(15 * time.Second), RecordID: 301, Channel: "System", Computer: "DESK-01",
			UserDataElement: "LogFileCleared", UserDataNS: "http://manifests.microsoft.com/win/2004/08/windows/eventlog",
			UserData: []w.KV{w.F("SubjectUserName", w.String("dev")), w.F("SubjectDomainName", w.String("DESK")), w.F("Channel", w.String("Microsoft-Windows-Sysmon/Operational")), w.F("BackupPath", w.String(""))}},
	}
	p := writeBytes(t, "mixed.evtx", w.Build(w.Events(evs), w.Options{RecordsPerChunk: 5}))
	if f, err := Sniff(p); err != nil || f != FormatEVTX {
		t.Fatalf("sniff: %v %s", err, f)
	}
	res, err := Load(p, FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != FormatEVTX || res.Skipped != 0 || len(res.Records) != 12 {
		t.Fatalf("format=%s skipped=%d records=%d problems=%v\n%+v", res.Format, res.Skipped, len(res.Records), res.Problems, res.Records)
	}
	by := map[string]Record{}
	for _, r := range res.Records {
		by[r.Ref] = r
	}
	if r := by["sysmon:1 (record 77)"]; r.Kind != "process" || r.Cmdline != "cmd.exe /c rmdir /s /q build" || r.PID != 4411 || r.PPID != 4400 || baseName(r.ParentExe) != "Cursor.exe" || r.User != `DESK\dev` || !r.Time.Equal(at0) {
		t.Fatalf("sysmon 1: %+v", r)
	}
	if r := by["sysmon:3 (record 78)"]; r.Kind != "network" || r.DestIP != "185.10.10.10" || r.DestPort != 4444 {
		t.Fatalf("sysmon 3: %+v", r)
	}
	if r := by["sysmon:11 (record 79)"]; r.Kind != "file" || r.FileOp != "create" || r.FilePath != `C:\Users\dev\.ssh\authorized_keys` {
		t.Fatalf("sysmon 11: %+v", r)
	}
	if r := by["sysmon:22 (record 80, dns)"]; r.Kind != "network" || r.DestHost != "evil.example" || r.PID != 4412 {
		t.Fatalf("sysmon 22: %+v", r)
	}
	if r := by["sysmon:26 (record 81)"]; r.Kind != "file" || r.FileOp != "delete" {
		t.Fatalf("sysmon 26: %+v", r)
	}
	if r := by["security:4688 (record 5001)"]; r.Kind != "process" || r.PID != 0x1a2b || r.PPID != 0x113c || r.Cmdline != "whoami /all" || r.User != `DESK\dev` || baseName(r.ParentExe) != "cmd.exe" {
		t.Fatalf("4688: %+v", r)
	}
	if r := by["powershell:4104 (record 900)"]; r.Kind != "script" || r.Cmdline != "Remove-Item -Recurse -Force build" || r.PID != 6000 || r.Exe != "powershell.exe" {
		t.Fatalf("4104: %+v", r)
	}
	if r := by["system:7045 (record 300, service updsvc)"]; r.Kind != "service" || !strings.HasSuffix(r.Exe, `Temp\u.exe`) || r.User != "LocalSystem" {
		t.Fatalf("7045: %+v", r)
	}
	if r := by["eventlog:1102 (record 5003, channel Security)"]; r.Kind != "log-clear" || r.User != `DESK\dev` {
		t.Fatalf("1102: %+v", r)
	}
	if r := by["eventlog:104 (record 301, channel Microsoft-Windows-Sysmon/Operational)"]; r.Kind != "log-clear" {
		t.Fatalf("104: %+v", r)
	}
	notices := strings.Join(res.Notices, "\n")
	if len(res.Notices) != 3 || !strings.Contains(notices, `service "updsvc" installed`) || !strings.Contains(notices, `event log "Security" cleared by DESK\dev`) ||
		!strings.Contains(notices, `"Microsoft-Windows-Sysmon/Operational" cleared`) {
		t.Fatalf("notices: %v", res.Notices)
	}
	if probs := strings.Join(res.Problems, "\n"); !strings.Contains(probs, "1 event(s) of 1 unused provider/event id(s) not mapped (most common: Microsoft-Windows-Security-Auditing 4624 ×1)") {
		t.Fatalf("unmapped summary: %v", res.Problems)
	}
	// --format evtx forces the adapter.
	if res2, err := Load(p, FormatEVTX); err != nil || len(res2.Records) != 12 {
		t.Fatalf("forced: %v", err)
	}
}

// The same Sysmon events as an XML export and as a native .evtx file
// produce identical Records.
func TestEVTXMatchesSysmonXML(t *testing.T) {
	xmlDoc := `<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><TimeCreated SystemTime="2026-08-30T10:00:07.1230000Z"/><EventRecordID>77</EventRecordID></System>
<EventData><Data Name="UtcTime">2026-08-30 10:00:07.123</Data><Data Name="ProcessId">4411</Data><Data Name="Image">C:\Windows\System32\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c rmdir /s /q build</Data><Data Name="ParentProcessId">4400</Data><Data Name="ParentImage">C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe</Data><Data Name="User">DESK\dev</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>3</EventID><TimeCreated SystemTime="2026-08-30T10:00:10.0000000Z"/><EventRecordID>78</EventRecordID></System>
<EventData><Data Name="UtcTime">2026-08-30 10:00:10.000</Data><Data Name="ProcessId">4412</Data><Data Name="Image">C:\Program Files\nodejs\node.exe</Data><Data Name="DestinationIp">185.10.10.10</Data><Data Name="DestinationPort">4444</Data><Data Name="DestinationHostname">-</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>23</EventID><TimeCreated SystemTime="2026-08-30T10:00:12.0000000Z"/><EventRecordID>79</EventRecordID></System>
<EventData><Data Name="UtcTime">2026-08-30 10:00:12.000</Data><Data Name="ProcessId">4413</Data><Data Name="Image">C:\Program Files\nodejs\node.exe</Data><Data Name="TargetFilename">C:\Users\dev\.ssh\authorized_keys</Data></EventData></Event>
`
	evs := []w.Event{
		sysmonEv(77, 1, at0, w.F("ProcessId", w.Uint32(4411)), w.F("Image", w.String(`C:\Windows\System32\cmd.exe`)), w.F("CommandLine", w.String("cmd.exe /c rmdir /s /q build")),
			w.F("ParentProcessId", w.Uint32(4400)), w.F("ParentImage", w.String(`C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe`)), w.F("User", w.String(`DESK\dev`))),
		sysmonEv(78, 3, time.Date(2026, 8, 30, 10, 0, 10, 0, time.UTC), w.F("ProcessId", w.Uint32(4412)), w.F("Image", w.String(`C:\Program Files\nodejs\node.exe`)),
			w.F("DestinationIp", w.String("185.10.10.10")), w.F("DestinationPort", w.Uint16(4444)), w.F("DestinationHostname", w.String("-"))),
		sysmonEv(79, 23, time.Date(2026, 8, 30, 10, 0, 12, 0, time.UTC), w.F("ProcessId", w.Uint32(4413)), w.F("Image", w.String(`C:\Program Files\nodejs\node.exe`)),
			w.F("TargetFilename", w.String(`C:\Users\dev\.ssh\authorized_keys`))),
	}
	fromXML, err := Load(write(t, "sysmon.xml", xmlDoc), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	fromEVTX, err := Load(writeBytes(t, "Sysmon.evtx", w.Build(w.Events(evs), w.Options{})), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if len(fromXML.Records) != 3 || !reflect.DeepEqual(fromXML.Records, fromEVTX.Records) {
		t.Fatalf("xml vs evtx differ:\n%+v\n%+v", fromXML.Records, fromEVTX.Records)
	}
}

func TestEVTXCorruptChunkReported(t *testing.T) {
	var evs []w.Event
	for i := 0; i < 6; i++ {
		evs = append(evs, sysmonEv(uint64(i+1), 1, at0.Add(time.Duration(i)*time.Second), w.F("ProcessId", w.Uint32(uint32(100+i))), w.F("CommandLine", w.String("cmd.exe /c echo"))))
	}
	img := w.Build(w.Events(evs), w.Options{RecordsPerChunk: 2, Dirty: true})
	copy(img[4096+65536:], "garbage!")                               // chunk 1 signature
	binary.LittleEndian.PutUint32(img[4096+2*65536+52:], 0xdeadbeef) // chunk 2 records checksum
	res, err := Load(writeBytes(t, "bad.evtx", img), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	probs := strings.Join(res.Problems, "\n")
	if len(res.Records) != 4 || res.Skipped != 2 || !strings.Contains(probs, "chunk 1: bad signature") || !strings.Contains(probs, "chunk 2: event records checksum mismatch") || !strings.Contains(probs, "dirty flag") {
		t.Fatalf("records=%d skipped=%d problems=%v", len(res.Records), res.Skipped, res.Problems)
	}
	if !strings.HasSuffix(res.Records[3].Ref, "chunk checksum mismatch)") || strings.Contains(res.Records[0].Ref, "mismatch") {
		t.Fatalf("unverified refs: %q %q", res.Records[0].Ref, res.Records[3].Ref)
	}
}
