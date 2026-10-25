package correlate

import (
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

func loadES(t *testing.T) []endpoint.Record {
	t.Helper()
	lr, err := endpoint.Load("../endpoint/testdata/macos/eslogger_synthetic.jsonl", endpoint.FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	return lr.Records
}

func findingsBy(fs []schema.Finding) map[string][]schema.Finding {
	by := map[string][]schema.Finding{}
	for _, f := range fs {
		by[f.RuleID] = append(by[f.RuleID], f)
	}
	return by
}

// eslogger exec and file records corroborate claimed commands and writes;
// a claim outside the capture stays as it was.
func TestESLoggerCorroboratesClaims(t *testing.T) {
	events := []schema.Event{
		tc("e1", "2026-10-20T09:00:05Z", "Bash", "git status"),
		{EventID: "e2", EventType: schema.EventToolCall, Tool: "Write", File: "/Users/user/proj/notes.md", Timestamp: "2026-10-20T09:00:08Z", Corroboration: schema.StateObserved, SessionID: "s1"},
		tc("e3", "2026-10-20T12:00:00Z", "Bash", "make deploy"),
		tc("e4", "2026-10-20T09:00:15Z", "Bash", "pytest -q"),
	}
	res, findings := Endpoint(events, loadES(t), EndpointOptions{})
	states := map[string]string{}
	for _, e := range events {
		states[e.EventID] = e.Corroboration
	}
	want := map[string]string{"e1": schema.StateCorroborated, "e2": schema.StateCorroborated, "e3": schema.StateObserved, "e4": schema.StateContradicted}
	for id, w := range want {
		if states[id] != w {
			t.Errorf("%s: got %s want %s (%s)", id, states[id], w, events[0].Summary)
		}
	}
	if res.OutsideCover != 1 || res.Corroborated != 2 {
		t.Fatalf("summary %+v", res)
	}
	if !strings.Contains(events[0].Summary, "corroborated by eslogger process") || !strings.Contains(events[1].Summary, "corroborated by eslogger file") {
		t.Fatalf("notes: %q / %q", events[0].Summary, events[1].Summary)
	}
	if len(res.Matches) == 0 || res.Matches[0].Record.SigningID == "" {
		t.Fatalf("match should carry the ES signing identity: %+v", res.Matches)
	}
	by := findingsBy(findings)
	// The fixture's agent-descended zsh registers a LaunchAgent and is the
	// instigator of a TCC grant.
	if l := by["MACOS_LAUNCHD_PERSISTENCE_BY_AGENT"]; len(l) != 1 || !strings.Contains(l[0].Description, "com.example.helper.plist") || l[0].MitreATTACK != "T1543.001" {
		t.Fatalf("launchd: %+v", l)
	}
	if l := by["MACOS_TCC_MODIFIED_BY_AGENT"]; len(l) != 1 || l[0].Severity != "HIGH" || !strings.Contains(l[0].Description, "kTCCServiceSystemPolicyAllFiles") {
		t.Fatalf("tcc: %+v", l)
	}
	if l := by["MACOS_KEYCHAIN_ACCESS_BY_AGENT"]; len(l) != 0 {
		t.Fatalf("keychain fired without keychain access: %+v", l)
	}
}

func TestMacOSRulesLineageAndBenign(t *testing.T) {
	agent := endpoint.Record{Time: ts("2026-10-20T09:00:00Z"), Kind: "process", PID: 100, PPID: 1, Exe: "/Users/u/.local/share/claude/versions/2.1.0", Cmdline: "claude", Source: "eslogger", Ref: "a"}
	shell := endpoint.Record{Time: ts("2026-10-20T09:00:01Z"), Kind: "process", PID: 110, PPID: 100, Exe: "/bin/zsh", Cmdline: "/bin/zsh -c npm test", Source: "eslogger", Ref: "b"}
	user := endpoint.Record{Time: ts("2026-10-20T09:00:01Z"), Kind: "process", PID: 210, PPID: 200, Exe: "/bin/zsh", Cmdline: "-zsh", Source: "eslogger", Ref: "u"}
	recs := []endpoint.Record{agent, shell, user,
		{Time: ts("2026-10-20T09:00:02Z"), Kind: "process", PID: 111, PPID: 110, Exe: "/usr/bin/security", Cmdline: "security find-generic-password -s github.com -w", Source: "eslogger", Ref: "k1"},
		{Time: ts("2026-10-20T09:00:02Z"), Kind: "file", FileOp: "open", PID: 110, PPID: 100, Exe: "/usr/bin/python3", FilePath: "/Users/u/Library/Keychains/login.keychain-db", Source: "eslogger", Ref: "k2"},
		{Time: ts("2026-10-20T09:00:03Z"), Kind: "file", FileOp: "modify", PID: 110, PPID: 100, Exe: "/bin/zsh", FilePath: "/Library/Application Support/com.apple.TCC/TCC.db", Source: "eslogger", Ref: "t1"},
		{Time: ts("2026-10-20T09:00:04Z"), Kind: "file", FileOp: "create", PID: 110, PPID: 100, Exe: "/bin/zsh", FilePath: "/Library/LaunchDaemons/com.x.plist", Source: "eslogger", Ref: "l1"},
		// Benign: the same acts by the user's own shell, a lookup without
		// -w, securityd opening the keychain, and a read of a plist.
		{Time: ts("2026-10-20T09:00:05Z"), Kind: "process", PID: 211, PPID: 210, Exe: "/usr/bin/security", Cmdline: "security find-generic-password -s pg -w", Source: "eslogger", Ref: "n1"},
		{Time: ts("2026-10-20T09:00:05Z"), Kind: "process", PID: 112, PPID: 110, Exe: "/usr/bin/security", Cmdline: "security find-generic-password -s github.com", Source: "eslogger", Ref: "n2"},
		{Time: ts("2026-10-20T09:00:05Z"), Kind: "file", FileOp: "open", PID: 414, PPID: 1, Exe: "/usr/sbin/securityd", FilePath: "/Users/u/Library/Keychains/login.keychain-db", Source: "eslogger", Ref: "n3"},
		{Time: ts("2026-10-20T09:00:06Z"), Kind: "file", FileOp: "open", PID: 110, PPID: 100, Exe: "/bin/zsh", FilePath: "/Users/u/Library/LaunchAgents/com.y.plist", Source: "eslogger", Ref: "n4"},
		{Time: ts("2026-10-20T09:00:06Z"), Kind: "file", FileOp: "create", PID: 210, PPID: 200, Exe: "/bin/zsh", FilePath: "/Users/u/Library/LaunchAgents/homebrew.mxcl.redis.plist", Source: "eslogger", Ref: "n5"},
	}
	_, findings := Endpoint(nil, recs, EndpointOptions{})
	by := findingsBy(findings)
	if k := by["MACOS_KEYCHAIN_ACCESS_BY_AGENT"]; len(k) != 2 || k[0].EvidenceRefs[0] != "k1" || k[1].EvidenceRefs[0] != "k2" {
		t.Fatalf("keychain: %+v", k)
	}
	if l := by["MACOS_TCC_MODIFIED_BY_AGENT"]; len(l) != 1 || l[0].EvidenceRefs[0] != "t1" {
		t.Fatalf("tcc db write: %+v", l)
	}
	if l := by["MACOS_LAUNCHD_PERSISTENCE_BY_AGENT"]; len(l) != 1 || l[0].EvidenceRefs[0] != "l1" {
		t.Fatalf("launchd: %+v", l)
	}
}

func TestTCCTimeOverlapIsMediumOnly(t *testing.T) {
	events := []schema.Event{
		tc("e1", "2026-10-20T09:00:00Z", "Bash", "ls"),
		tc("e2", "2026-10-20T09:10:00Z", "Bash", "ls -la"),
	}
	rows := []endpoint.Record{
		{Time: ts("2026-10-20T09:05:00Z"), Kind: endpoint.KindTCC, Source: "tcc-db", Resource: "kTCCServiceScreenCapture", Exe: "com.example.rec", Message: "auth_value=2", Ref: "TCC.db access row 7"},
		{Time: ts("2026-10-20T11:00:00Z"), Kind: endpoint.KindTCC, Source: "tcc-db", Resource: "kTCCServiceCamera", Exe: "us.zoom.xos", Ref: "TCC.db access row 8"},
	}
	fs := HostState(events, rows)
	if len(fs) != 1 || fs[0].Severity != "MEDIUM" || fs[0].SessionID != "s1" || !strings.Contains(fs[0].Description, "time overlap, not attribution") {
		t.Fatalf("host state: %+v", fs)
	}
	// No transcript, no session: nothing to overlap with.
	if fs := HostState(nil, rows); len(fs) != 0 {
		t.Fatalf("without sessions: %+v", fs)
	}
}
