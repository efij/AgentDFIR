package correlate

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	w "github.com/efij/AgentDFIR/v4/internal/endpoint/evtx/evtxtest"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

func decisionOf(res *EndpointResult, id string) CoverageDecision {
	for _, d := range res.Decisions {
		if d.EventID == id {
			return d
		}
	}
	return CoverageDecision{}
}

func procRec(at, cmd, origin string) endpoint.Record {
	return endpoint.Record{Time: ts(at), Kind: "process", PID: 100, Exe: "/usr/bin/" + strings.Fields(cmd)[0], Cmdline: cmd, Source: "auditd", Ref: "audit.log:" + at, Origin: origin}
}

// Regression for the v4 defect: one coverage window across all kinds let
// network telemetry stretch process coverage, so a command at a time only
// network records covered was DISPROVED by process telemetry that had
// already ended.
func TestNetworkTelemetryDoesNotWidenProcessCoverage(t *testing.T) {
	events := []schema.Event{tc("e1", "2026-08-30T10:05:00Z", "Bash", "make deploy")}
	recs := []endpoint.Record{
		procRec("2026-08-30T10:00:00Z", "make build", "proc.log"),
		procRec("2026-08-30T10:00:05Z", "make test", "proc.log"),
		{Time: ts("2026-08-30T10:00:00Z"), Kind: "network", DestIP: "10.0.0.1", Source: "auditd", Ref: "net.log:1", Origin: "net.log"},
		{Time: ts("2026-08-30T10:10:00Z"), Kind: "network", DestIP: "10.0.0.2", Source: "auditd", Ref: "net.log:2", Origin: "net.log"},
	}
	res, f := Endpoint(events, recs, EndpointOptions{})
	if events[0].Corroboration != schema.StateObserved || res.Contradicted != 0 || len(f) != 0 {
		t.Fatalf("command outside process coverage must not be DISPROVED: %+v %+v", events[0], res)
	}
	if d := decisionOf(res, "e1"); d.Coverage != CoverOutside || res.OutsideReasons[CoverOutside] != 1 {
		t.Fatalf("decision %+v reasons %v", d, res.OutsideReasons)
	}
	// The union stays as before, for compatibility.
	if !res.CoverageEnd.Equal(ts("2026-08-30T10:10:00Z")) {
		t.Fatalf("coverage_end %v", res.CoverageEnd)
	}
}

// Process-only telemetry says nothing about a network claim.
func TestProcessOnlyTelemetryDoesNotContradictNetworkClaim(t *testing.T) {
	ev := schema.Event{EventID: "n1", EventType: schema.EventToolCall, Tool: "WebFetch", NetworkDest: "https://exfil.example/x",
		Timestamp: "2026-08-30T10:00:05Z", Corroboration: schema.StateObserved, SessionID: "s1", AgentID: "main:s1"}
	events := []schema.Event{ev}
	recs := []endpoint.Record{procRec("2026-08-30T10:00:00Z", "ls", ""), procRec("2026-08-30T10:00:10Z", "pwd", "")}
	res, _ := Endpoint(events, recs, EndpointOptions{})
	if events[0].Corroboration != schema.StateObserved || res.Contradicted != 0 {
		t.Fatalf("network claim lowered by process telemetry: %+v", events[0])
	}
	if d := decisionOf(res, "n1"); d.Needs != "network" || d.Coverage != CoverNoKind {
		t.Fatalf("decision %+v", d)
	}
}

// Telemetry that names several hosts covers only the matching one.
func TestOtherHostTelemetryDoesNotContradict(t *testing.T) {
	e := tc("e1", "2026-08-30T10:00:05Z", "Bash", "pytest -q")
	e.Host = "laptop.local"
	events := []schema.Event{e}
	a, b := procRec("2026-08-30T10:00:00Z", "ls", "a"), procRec("2026-08-30T10:00:10Z", "pwd", "b")
	a.Host, b.Host = "web-1", "web-2"
	res, _ := Endpoint(events, []endpoint.Record{a, b}, EndpointOptions{})
	if events[0].Corroboration != schema.StateObserved || decisionOf(res, "e1").Coverage != CoverNoKind {
		t.Fatalf("other hosts' telemetry contradicted the call: %+v %+v", events[0], res.Decisions)
	}
	// One named host is taken as the agent's machine, and the decision says so.
	events = []schema.Event{e}
	a.Host, b.Host, b.Origin = "web-1", "web-1", "a"
	res, _ = Endpoint(events, []endpoint.Record{a, b}, EndpointOptions{})
	if events[0].Corroboration != schema.StateContradicted || !strings.Contains(decisionOf(res, "e1").Reason, "host attribution unverified") {
		t.Fatalf("single-host telemetry: %+v %+v", events[0], res.Decisions)
	}
}

func evtxProcFile(t *testing.T, ids []uint64, start time.Time) string {
	var evs []w.Event
	for i, id := range ids {
		evs = append(evs, sysmonCreate(id, start.Add(time.Duration(i)*10*time.Second), uint32(4000+i), 1, `C:\Windows\System32\whoami.exe`, fmt.Sprintf("whoami /n%d", i), `C:\x\cursor.exe`))
	}
	return writeFile(t, "Sysmon.evtx", w.Build(w.Events(evs), w.Options{}))
}

func loadWithHealth(t *testing.T, path string) ([]endpoint.Record, EndpointOptions) {
	t.Helper()
	lr, err := endpoint.Load(path, endpoint.FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	return lr.Records, EndpointOptions{Health: []*endpoint.SourceHealth{lr.Health}}
}

// Contiguous EVTX record ids and a missing process: still DISPROVED, and
// the decision says the coverage was HEALTHY.
func TestHealthyEVTXStillContradicts(t *testing.T) {
	start := ts("2026-08-30T10:00:00Z")
	recs, opts := loadWithHealth(t, evtxProcFile(t, []uint64{1, 2, 3, 4, 5}, start))
	events := []schema.Event{tc("e1", "2026-08-30T10:00:15Z", "Bash", "pytest -q")}
	res, _ := Endpoint(events, recs, opts)
	if events[0].Corroboration != schema.StateContradicted || res.Contradicted != 1 {
		t.Fatalf("want CONTRADICTED: %+v", events[0])
	}
	if d := decisionOf(res, "e1"); d.Coverage != CoverHealthy {
		t.Fatalf("decision %+v", d)
	}
	if len(res.Health) != 1 || res.Health[0].Verdict != endpoint.HealthHealthy || res.Health[0].SHA256 == "" {
		t.Fatalf("health %+v", res.Health)
	}
}

// A record-id gap inside the window demotes process coverage to PARTIAL
// there, and PARTIAL never disproves.
func TestEVTXRecordGapIsPartial(t *testing.T) {
	start := ts("2026-08-30T10:00:00Z")
	// ids 3..6 are missing between 10:00:10 and 10:00:20
	recs, opts := loadWithHealth(t, evtxProcFile(t, []uint64{1, 2, 7, 8}, start))
	events := []schema.Event{
		tc("e1", "2026-08-30T10:00:15Z", "Bash", "pytest -q"), // inside the gap
		tc("e2", "2026-08-30T10:00:30Z", "Bash", "go vet"),    // after it, healthy
	}
	res, _ := Endpoint(events, recs, opts)
	if events[0].Corroboration != schema.StateObserved {
		t.Fatalf("claim inside a record-id gap was lowered: %+v", events[0])
	}
	d := decisionOf(res, "e1")
	if d.Coverage != CoverPartial || !strings.Contains(d.Reason, "4 missing after 2") || !strings.Contains(events[0].Summary, "not checked for absence") {
		t.Fatalf("decision %+v summary %q", d, events[0].Summary)
	}
	if events[1].Corroboration != schema.StateContradicted {
		t.Fatalf("claim outside the gap should still be checked: %+v", events[1])
	}
	if res.Health[0].Verdict != endpoint.HealthPartial || res.Health[0].Gaps != 1 || res.OutsideReasons[CoverPartial] != 1 {
		t.Fatalf("health %+v reasons %v", res.Health, res.OutsideReasons)
	}
	var kc *KindCoverage
	for i := range res.KindCoverage {
		if res.KindCoverage[i].Kind == "process" && res.KindCoverage[i].CountsAsCoverage {
			kc = &res.KindCoverage[i]
		}
	}
	if kc == nil || kc.Health != endpoint.HealthPartial || kc.Host != "desk-01" || len(kc.Partial) != 1 {
		t.Fatalf("kind coverage %+v", res.KindCoverage)
	}
}

func esLine(at time.Time, seq, global uint64, pid int, args ...string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = fmt.Sprintf("%q", a)
	}
	return fmt.Sprintf(`{"schema_version":1,"version":7,"time":%q,"seq_num":%d,"global_seq_num":%d,"process":{"audit_token":{"pid":90},"ppid":1,"executable":{"path":"/bin/zsh"}},"event":{"exec":{"target":{"audit_token":{"pid":%d},"ppid":90,"executable":{"path":"/usr/bin/%s"}},"args":[%s]}}}`,
		at.Format(time.RFC3339Nano), seq, global, pid, args[0], strings.Join(q, ","))
}

func esFile(t *testing.T, seqs []uint64) string {
	start := ts("2026-10-20T09:00:00Z")
	var lines []string
	for i, s := range seqs {
		lines = append(lines, esLine(start.Add(time.Duration(i)*10*time.Second), s, 1000+s, 5000+i, "true", fmt.Sprint(i)))
	}
	return writeFile(t, "eslogger.jsonl", []byte(strings.Join(lines, "\n")+"\n"))
}

// eslogger: a seq_num jump inside the window is PARTIAL; contiguous
// numbers keep the contradiction.
func TestESLoggerSeqGap(t *testing.T) {
	recs, opts := loadWithHealth(t, esFile(t, []uint64{1, 2, 9, 10}))
	events := []schema.Event{tc("e1", "2026-10-20T09:00:15Z", "Bash", "curl -s https://x.example")}
	res, _ := Endpoint(events, recs, opts)
	if events[0].Corroboration != schema.StateObserved || decisionOf(res, "e1").Coverage != CoverPartial {
		t.Fatalf("eslogger gap: %+v %+v", events[0], res.Decisions)
	}
	recs, opts = loadWithHealth(t, esFile(t, []uint64{1, 2, 3, 4}))
	events = []schema.Event{tc("e1", "2026-10-20T09:00:15Z", "Bash", "curl -s https://x.example")}
	res, _ = Endpoint(events, recs, opts)
	if events[0].Corroboration != schema.StateContradicted || decisionOf(res, "e1").Coverage != CoverHealthy {
		t.Fatalf("eslogger contiguous: %+v %+v", events[0], res.Decisions)
	}
}

// A cleared event log inside the window: everything before the clear may
// be gone, for every EVTX source of that host.
func TestLogClearInWindowIsPartial(t *testing.T) {
	var recs []endpoint.Record
	for i := 0; i < 5; i++ {
		recs = append(recs, endpoint.Record{Time: ts("2026-08-30T10:00:00Z").Add(time.Duration(i) * 10 * time.Second), Kind: "process", Cmdline: fmt.Sprintf("whoami /n%d", i),
			Source: "sysmon", Ref: fmt.Sprintf("sysmon:1 (record %d)", i+1), Seq: uint64(i + 1), SeqDomain: "evtx/Microsoft-Windows-Sysmon/Operational", Host: "DESK-01", Origin: "Sysmon.evtx"})
	}
	recs = append(recs, endpoint.Record{Time: ts("2026-08-30T10:00:25Z"), Kind: "log-clear", Source: "eventlog", Ref: "eventlog:104 (record 9)",
		Seq: 9, SeqDomain: "evtx/System", Host: "DESK-01", Origin: "System.evtx"})
	events := []schema.Event{
		tc("e1", "2026-08-30T10:00:15Z", "Bash", "pytest -q"), // before the clear
		tc("e2", "2026-08-30T10:00:35Z", "Bash", "go vet"),    // after it
	}
	res, _ := Endpoint(events, recs, EndpointOptions{})
	if events[0].Corroboration != schema.StateObserved || !strings.Contains(decisionOf(res, "e1").Reason, "log-clear") {
		t.Fatalf("claim before a log clear: %+v %+v", events[0], res.Decisions)
	}
	if events[1].Corroboration != schema.StateContradicted {
		t.Fatalf("claim after the clear: %+v", events[1])
	}
}

// Context records past the per-file bound make that kind PARTIAL.
func TestContextDroppedIsPartial(t *testing.T) {
	h := &endpoint.SourceHealth{Origin: "Security.evtx", File: "Security.evtx",
		Drops: []endpoint.DropSignal{{Signal: "context-bound", Count: 3, Kinds: []string{"registry"}, Detail: "3 registry record(s) past the per-file bound"}}}
	recs := []endpoint.Record{
		{Time: ts("2026-08-30T10:00:00Z"), Kind: "registry", Source: "sysmon", Ref: "sysmon:13 (record 1)", Origin: "Security.evtx"},
		procRec("2026-08-30T10:00:00Z", "ls", "Security.evtx"),
		procRec("2026-08-30T10:00:20Z", "pwd", "Security.evtx"),
	}
	events := []schema.Event{tc("e1", "2026-08-30T10:00:10Z", "Bash", "pytest -q")}
	res, _ := Endpoint(events, recs, EndpointOptions{Health: []*endpoint.SourceHealth{h}})
	got := map[string]string{}
	for _, kc := range res.KindCoverage {
		got[kc.Kind] = kc.Health
	}
	if got["registry"] != endpoint.HealthPartial || got["process"] != endpoint.HealthUnknown {
		t.Fatalf("kind health %v", got)
	}
	// The bound only touches registry records: the command is still checked.
	if events[0].Corroboration != schema.StateContradicted || decisionOf(res, "e1").Coverage != CoverUnverified {
		t.Fatalf("%+v %+v", events[0], res.Decisions)
	}
}
