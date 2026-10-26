package endpoint

import (
	"fmt"
	"strings"
	"testing"
	"time"

	w "github.com/efij/AgentDFIR/v5/internal/endpoint/evtx/evtxtest"
)

func auditExec(serial int, sec int64, pid int, cmd string) string {
	return fmt.Sprintf("type=SYSCALL msg=audit(%d.000:%d): arch=c000003e syscall=59 success=yes exit=0 pid=%d ppid=1 uid=1000 exe=\"/usr/bin/x\"\n"+
		"type=EXECVE msg=audit(%d.000:%d): argc=1 a0=\"%s\"\n", sec, serial, pid, sec, serial, cmd)
}

// The audit serial is tracked for every event; a jump is a gap placed
// between the events on either side, and the records carry the serial.
func TestAuditdSerialGap(t *testing.T) {
	log := auditExec(100, 1790000000, 10, "a") + auditExec(101, 1790000010, 11, "b") +
		"type=USER_LOGIN msg=audit(1790000015.000:102): pid=1 uid=0 res=success\n" + // used by no mapping: still no gap
		auditExec(106, 1790000020, 12, "c")
	lr, err := Load(write(t, "audit.log", log), FormatAuditd)
	if err != nil {
		t.Fatal(err)
	}
	h := lr.Health
	if h.Verdict != HealthPartial || h.Gaps != 1 || len(h.Domains) != 1 {
		t.Fatalf("health %+v", h)
	}
	g := h.Domains[0].GapRanges[0]
	if g.After != 102 || g.Before != 106 || g.Missing != 3 || !g.Start.Equal(time.Unix(1790000015, 0).UTC()) {
		t.Fatalf("gap %+v", g)
	}
	if lr.Records[0].Seq != 100 || lr.Records[0].SeqDomain != "auditd/audit.log" || lr.Records[0].Origin == "" {
		t.Fatalf("record %+v", lr.Records[0])
	}
	if h.SHA256 == "" || h.File != "audit.log" {
		t.Fatalf("source identity %+v", h)
	}
}

func TestAuditdLostCounterIsDrop(t *testing.T) {
	log := auditExec(1, 1790000000, 10, "a") + "type=DAEMON_ERR msg=audit(1790000005.000:2): op=error lost=7\n" + auditExec(3, 1790000010, 11, "b")
	lr, err := Load(write(t, "audit.log", log), FormatAuditd)
	if err != nil {
		t.Fatal(err)
	}
	if lr.Health.Verdict != HealthPartial || len(lr.Health.Drops) != 1 || lr.Health.Drops[0].Signal != "daemon" {
		t.Fatalf("health %+v", lr.Health)
	}
}

// Unmapped EVTX events still count for the record-id sequence; a missing
// id is a gap; the records carry the id, channel domain and computer.
func TestEVTXRecordIDHealth(t *testing.T) {
	at := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	ev := func(id uint64, eid uint16, s int) w.Event {
		return w.Event{Provider: "Microsoft-Windows-Sysmon", EventID: eid, Qualifiers: -1, Time: at.Add(time.Duration(s) * time.Second), RecordID: id,
			Channel: "Microsoft-Windows-Sysmon/Operational", Computer: "DESK-01",
			Data: []w.KV{{Name: "UtcTime", Value: w.String(at.Add(time.Duration(s) * time.Second).Format("2006-01-02 15:04:05.000"))}, {Name: "ProcessId", Value: w.Uint32(1)},
				{Name: "Image", Value: w.String(`C:\x.exe`)}, {Name: "CommandLine", Value: w.String("x")}}}
	}
	// 7 (image loaded) is not mapped; it must not look like a gap.
	img := w.Build(w.Events([]w.Event{ev(1, 1, 0), ev(2, 7, 1), ev(3, 1, 2)}), w.Options{})
	lr, err := Load(writeBytes(t, "Sysmon.evtx", img), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if lr.Health.Verdict != HealthHealthy || len(lr.Records) != 2 || lr.Records[1].Seq != 3 || lr.Records[1].Host != "DESK-01" ||
		lr.Records[1].SeqDomain != "evtx/Microsoft-Windows-Sysmon/Operational" {
		t.Fatalf("health %+v records %+v", lr.Health, lr.Records)
	}
	img = w.Build(w.Events([]w.Event{ev(1, 1, 0), ev(4, 1, 2)}), w.Options{})
	lr, err = Load(writeBytes(t, "Sysmon.evtx", img), FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if lr.Health.Verdict != HealthPartial || lr.Health.Domains[0].Missing != 2 {
		t.Fatalf("health %+v", lr.Health)
	}
}

// eslogger: per-type seq_num restarts are collector restarts; close
// events the adapter drops still count.
func TestESLoggerSequenceRestart(t *testing.T) {
	line := func(sec int, seq, g uint64, typ string) string {
		body := `{"exec":{"target":{"audit_token":{"pid":5},"executable":{"path":"/usr/bin/true"}},"args":["true"]}}`
		if typ == "close" {
			body = `{"close":{"modified":false,"target":{"path":"/tmp/x"}}}`
		}
		return fmt.Sprintf(`{"schema_version":1,"version":7,"time":"2026-10-20T09:00:%02dZ","seq_num":%d,"global_seq_num":%d,"process":{"audit_token":{"pid":4},"executable":{"path":"/bin/zsh"}},"event":%s}`, sec, seq, g, body)
	}
	ok := strings.Join([]string{line(0, 1, 1, "exec"), line(1, 1, 2, "close"), line(2, 2, 3, "exec")}, "\n")
	lr, err := Load(write(t, "es.jsonl", ok), FormatESLogger)
	if err != nil {
		t.Fatal(err)
	}
	if lr.Health.Verdict != HealthHealthy {
		t.Fatalf("contiguous stream: %+v", lr.Health)
	}
	restart := strings.Join([]string{line(0, 5, 5, "exec"), line(1, 6, 6, "exec"), line(9, 1, 1, "exec")}, "\n")
	lr, err = Load(write(t, "es.jsonl", restart), FormatESLogger)
	if err != nil {
		t.Fatal(err)
	}
	if lr.Health.Verdict != HealthPartial || !lr.Health.Domains[0].GapRanges[0].Restart {
		t.Fatalf("restart: %+v", lr.Health)
	}
}

func TestTetragonRateLimitIsDrop(t *testing.T) {
	lr, err := Load("testdata/linuxtel/tetragon.jsonl", FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range lr.Health.Drops {
		found = found || d.Signal == "rate-limit"
	}
	if !found || lr.Health.Verdict != HealthPartial || len(lr.Health.Hosts) == 0 {
		t.Fatalf("health %+v", lr.Health)
	}
}

// No sequence numbers at all: UNKNOWN, and it says completeness is not established.
func TestNoSequenceIsUnknown(t *testing.T) {
	lr, err := Load(write(t, "p.jsonl", `{"timestamp":"2026-08-30T10:00:00Z","event_type":"process","pid":1,"cmdline":"ls"}`+"\n"), FormatJSONL)
	if err != nil {
		t.Fatal(err)
	}
	if lr.Health.Verdict != HealthUnknown || !strings.Contains(lr.Health.Note, "not established") {
		t.Fatalf("health %+v", lr.Health)
	}
}

func TestContextDroppedVerdict(t *testing.T) {
	res := &LoadResult{ContextDropped: map[string]int{"registry": 4}}
	h := res.health("Security.evtx")
	if h.Verdict != HealthPartial || len(h.Drops) != 1 || h.Drops[0].Kinds[0] != "registry" {
		t.Fatalf("health %+v", h)
	}
}

func TestRecordsHealthFromSeqFields(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	recs := []Record{{Time: t0, Kind: "process", Seq: 1, SeqDomain: "auditd/x"}, {Time: t0.Add(time.Second), Kind: "process", Seq: 3, SeqDomain: "auditd/x"}}
	h := RecordsHealth("x", recs)
	if h.Verdict != HealthPartial || h.Gaps != 1 || h.Domains[0].Kinds[0] != "process" {
		t.Fatalf("health %+v", h)
	}
}
