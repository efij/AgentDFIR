package analysis

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	w "github.com/efij/AgentDFIR/v5/internal/endpoint/evtx/evtxtest"
)

// analyze --endpoint Sysmon.evtx: the native file is sniffed and drives
// the same CORROBORATED / CONTRADICTED states as an auditd log.
func TestRunWithNativeEVTX(t *testing.T) {
	pkg := buildPkg(t)
	proc := func(id uint64, at time.Time, pid uint32, image, cmd string) w.Event {
		return w.Event{Provider: "Microsoft-Windows-Sysmon", EventID: 1, Qualifiers: -1, Time: at, RecordID: id, Channel: "Microsoft-Windows-Sysmon/Operational", Computer: "DESK-01",
			Data: []w.KV{{Name: "UtcTime", Value: w.String(at.Format("2006-01-02 15:04:05.000"))}, {Name: "ProcessId", Value: w.Uint32(pid)},
				{Name: "Image", Value: w.String(image)}, {Name: "CommandLine", Value: w.String(cmd)}, {Name: "ParentProcessId", Value: w.Uint32(1)}}}
	}
	img := w.Build(w.Events([]w.Event{
		proc(1, time.Date(2026, 8, 30, 10, 0, 5, 300e6, time.UTC), 4411, `C:\Program Files\Git\bin\bash.exe`, `bash.exe -c "rm -rf build/"`),
		proc(2, time.Date(2026, 8, 30, 10, 1, 0, 0, time.UTC), 9000, `C:\Windows\System32\svchost.exe`, `svchost.exe -k netsvcs`),
	}), w.Options{})
	p := filepath.Join(t.TempDir(), "Sysmon.evtx")
	if err := os.WriteFile(p, img, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Run(pkg, Options{EndpointLogs: []string{p}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Correlation == nil || res.Correlation.Corroborated != 1 || res.Correlation.Contradicted != 1 || res.Correlation.Records != 2 {
		t.Fatalf("correlation: %+v", res.Correlation)
	}
	if rules(res.Findings)["ENDPOINT_CONTRADICTED_COMMAND"] != 1 {
		t.Fatalf("findings: %v", rules(res.Findings))
	}
}
