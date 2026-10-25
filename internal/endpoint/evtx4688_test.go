package endpoint

import (
	"testing"
	"time"

	w "github.com/efij/AgentDFIR/v4/internal/endpoint/evtx/evtxtest"
)

// Security 4688 without command-line auditing becomes a "process-image"
// record (program only); 4688 with a command line in the same file stays
// an ordinary process record.
func TestEVTX4688WithoutCommandLine(t *testing.T) {
	proc := func(id uint64, at time.Time, image, cmd string) w.Event {
		return w.Event{Provider: "Microsoft-Windows-Security-Auditing", EventID: 4688, Qualifiers: -1, Time: at, RecordID: id, Channel: "Security", Computer: "DESK-01",
			Data: []w.KV{w.F("NewProcessId", w.Hex64(0x10+id)), w.F("NewProcessName", w.String(image)), w.F("ProcessId", w.Hex64(0x4)), w.F("CommandLine", w.String(cmd))}}
	}
	img := w.Build(w.Events([]w.Event{
		proc(1, at0, `C:\Program Files\Git\cmd\git.exe`, ""),
		proc(2, at0.Add(time.Second), `C:\Windows\System32\whoami.exe`, "whoami /all"),
	}), w.Options{})
	res, err := Load(writeBytes(t, "Security.evtx", img), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 {
		t.Fatalf("records: %+v", res.Records)
	}
	if r := res.Records[0]; r.Kind != KindProcessImage || r.Cmdline != "" || baseName(r.Exe) != "git.exe" || r.PID != 0x11 {
		t.Fatalf("no command line: %+v", r)
	}
	if r := res.Records[1]; r.Kind != "process" || r.Cmdline != "whoami /all" {
		t.Fatalf("with command line: %+v", r)
	}
}
