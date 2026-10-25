package correlate

import (
	"reflect"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	w "github.com/efij/AgentDFIR/v4/internal/endpoint/evtx/evtxtest"
)

// Sysmon event 22 is a process-attributed DNS query. Read from the XML
// export or from Sysmon.evtx it becomes the same kind "network" record,
// and a lookup made by the agent process with no tool call behind it
// raises UNLOGGED_AGENT_NETWORK in both.
func TestSysmonDNSQueryXMLAndEVTXAgree(t *testing.T) {
	const cursor = `C:\Users\dev\AppData\Local\Programs\cursor\Cursor.exe`
	xmlDoc := `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>22</EventID><TimeCreated SystemTime="2026-08-30T10:00:07.0000000Z"/><EventRecordID>80</EventRecordID></System>
<EventData><Data Name="UtcTime">2026-08-30 10:00:07.000</Data><Data Name="ProcessId">4400</Data><Data Name="Image">` + cursor + `</Data><Data Name="QueryName">c2.example</Data><Data Name="User">DESK\dev</Data></EventData></Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>22</EventID><TimeCreated SystemTime="2026-08-30T10:00:08.0000000Z"/><EventRecordID>81</EventRecordID></System>
<EventData><Data Name="UtcTime">2026-08-30 10:00:08.000</Data><Data Name="ProcessId">4400</Data><Data Name="Image">` + cursor + `</Data></EventData></Event>
`
	at := ts("2026-08-30T10:00:07Z")
	ev := func(id uint64, data ...w.KV) w.Event {
		return w.Event{Provider: "Microsoft-Windows-Sysmon", EventID: 22, Qualifiers: -1, Version: 5, Level: 4, Time: at, RecordID: id, PID: 3056, TID: 4012,
			Channel: "Microsoft-Windows-Sysmon/Operational", Computer: "DESK-01", UserSID: "S-1-5-18", Data: data}
	}
	img := w.Build(w.Events([]w.Event{
		ev(80, w.KV{Name: "UtcTime", Value: w.String("2026-08-30 10:00:07.000")}, w.KV{Name: "ProcessId", Value: w.Uint32(4400)},
			w.KV{Name: "Image", Value: w.String(cursor)}, w.KV{Name: "QueryName", Value: w.String("c2.example")}, w.KV{Name: "User", Value: w.String(`DESK\dev`)}),
	}), w.Options{})

	load := func(name string, b []byte) []endpoint.Record {
		lr, err := endpoint.Load(writeFile(t, name, b), endpoint.FormatAuto)
		if err != nil {
			t.Fatal(err)
		}
		return lr.Records
	}
	xr, er := load("sysmon.xml", []byte(xmlDoc)), load("Sysmon.evtx", img)
	if len(xr) != 1 || len(er) != 1 {
		t.Fatalf("records xml %+v evtx %+v (a query without a name is a problem, not a record)", xr, er)
	}
	if xr[0].Kind != "network" || xr[0].DestHost != "c2.example" || xr[0].PID != 4400 || xr[0].Ref != "sysmon:22 (record 80, dns)" {
		t.Fatalf("xml record: %+v", xr[0])
	}
	if !reflect.DeepEqual(xr, er) {
		t.Fatalf("xml and evtx disagree:\n%+v\n%+v", xr, er)
	}
	_, f := Endpoint(nil, xr, EndpointOptions{})
	if len(f) != 1 || f[0].RuleID != "UNLOGGED_AGENT_NETWORK" {
		t.Fatalf("findings: %+v", f)
	}
}
