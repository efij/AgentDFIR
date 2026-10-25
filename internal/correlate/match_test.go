package correlate

import (
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/endpoint"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// Every corroboration is backed by a recorded pairing that says which
// record, on what basis, and how far apart the two clocks put them.
func TestMatchesRecordBasisAndRelatedByPID(t *testing.T) {
	events := []schema.Event{
		tc("e1", "2026-08-30T10:00:07Z", "Bash", "python3 build.py"),
	}
	recs := []endpoint.Record{
		{Time: ts("2026-08-30T10:00:08Z"), Kind: "process", PID: 50, PPID: 1, Exe: "/bin/sh", Cmdline: "/bin/sh -c python3 build.py", Source: "auditd", Ref: "audit.log:1"},
		{Time: ts("2026-08-30T10:00:09Z"), Kind: "network", PID: 50, DestHost: "pkg.example", DestPort: 443, Source: "auditd", Ref: "audit.log:2"},
		{Time: ts("2026-08-30T10:00:10Z"), Kind: "process", PID: 51, PPID: 50, Exe: "/usr/bin/git", Cmdline: "git status", Source: "auditd", Ref: "audit.log:3"},
		// same pid long after: a recycled pid, never related
		{Time: ts("2026-08-30T11:00:00Z"), Kind: "network", PID: 50, DestHost: "other.example", Source: "auditd", Ref: "audit.log:4"},
		// same pid BEFORE the process started: another process
		{Time: ts("2026-08-30T09:59:00Z"), Kind: "file", PID: 50, FilePath: "/tmp/x", Source: "auditd", Ref: "audit.log:5"},
	}
	res, _ := Endpoint(events, recs, EndpointOptions{})
	if len(res.Matches) != 1 {
		t.Fatalf("matches = %d, want 1: %+v", len(res.Matches), res.Matches)
	}
	m := res.Matches[0]
	if m.EventID != "e1" || m.Witness != "endpoint" || m.Score != 90 || m.Confidence != "HIGH" || m.Basis == "" {
		t.Fatalf("match: %+v", m)
	}
	if m.DeltaMS != 1000 || m.WindowMS != 3000 {
		t.Fatalf("delta/window: %d/%d", m.DeltaMS, m.WindowMS)
	}
	if len(m.Related) != 2 {
		t.Fatalf("related = %+v, want the network record (pid) and the child (ppid)", m.Related)
	}
	if m.Related[0].Basis != "endpoint pid" || m.Related[0].Record.Ref != "audit.log:2" ||
		m.Related[1].Basis != "endpoint ppid" || m.Related[1].Record.Ref != "audit.log:3" {
		t.Fatalf("related: %+v", m.Related)
	}
}

func TestMatchBasisLadder(t *testing.T) {
	cases := []struct {
		kind  string
		score int
		conf  string
	}{
		{"process", 100, "HIGH"}, {"process", 90, "HIGH"}, {"process", 70, "MEDIUM"}, {"process", 60, "LOW"},
		{"file", 80, "MEDIUM"}, {"network", 80, "MEDIUM"},
		{"cloud", 95, "HIGH"}, {"cloud", 75, "MEDIUM"}, {"cloud", 70, "LOW"},
		{"process", 0, ""}, {"unknown", 100, ""},
	}
	for _, c := range cases {
		b, conf := MatchBasis(c.kind, c.score)
		if conf != c.conf || (c.conf != "" && b == "") {
			t.Errorf("%s/%d: basis %q confidence %q, want confidence %q", c.kind, c.score, b, conf, c.conf)
		}
	}
}

func TestMatchesBounded(t *testing.T) {
	res := &EndpointResult{}
	ev := tc("e", "2026-08-30T10:00:00Z", "Bash", "x")
	r := endpoint.Record{Time: ts("2026-08-30T10:00:00Z"), Kind: "process"}
	for i := 0; i < MaxMatches+5; i++ {
		addMatch(res, "endpoint", &ev, r, 100, 0, nil)
	}
	if len(res.Matches) != MaxMatches || res.MatchesOmitted != 5 {
		t.Fatalf("matches %d omitted %d", len(res.Matches), res.MatchesOmitted)
	}
}
