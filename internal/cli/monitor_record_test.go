package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/journal"
	"github.com/efij/AgentDFIR/v5/internal/recorder"
)

func recAuditLines(serial, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		s := serial + i
		fmt.Fprintf(&b, "type=SYSCALL msg=audit(1788084005.300:%d): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=%d uid=1000 comm=\"zsh\" exe=\"/bin/zsh\"\n", s, 4000+s)
		fmt.Fprintf(&b, "type=EXECVE msg=audit(1788084005.300:%d): argc=3 a0=\"/bin/zsh\" a1=\"-c\" a2=\"echo %d\"\n", s, s)
	}
	return b.String()
}

// An end-to-end recording: monitor --record with an auditd source, then
// status, journal verify (intact → pruned → deleted) and replay, all
// offline on the state directory.
func TestMonitorRecordStatusVerifyReplay(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	sessions := filepath.Join(home, "sessions")
	_ = os.MkdirAll(sessions, 0o700)
	audit := filepath.Join(home, "audit.log")
	all := recAuditLines(1, 5) + recAuditLines(10, 1) // serials 6-9 never logged: a gap
	if err := os.WriteFile(audit, []byte(all), 0o600); err != nil {
		t.Fatal(err)
	}
	// Live growth and rotation are covered in internal/recorder; here the
	// whole file is recorded (--tail-from-start) so timing cannot matter.
	code, out := capture(t, "monitor", sessions, "--record", "--auditd", audit, "--tail-from-start", "--retain", "7d,1GB", "--quiet", "--cycles", "2", "--interval", "10ms")
	if code != 0 {
		t.Fatalf("monitor exit %d:\n%s", code, out)
	}
	dir := recorder.Dir(home)
	caps, _ := filepath.Glob(filepath.Join(dir, "auditd-*.log"))
	if len(caps) != 1 {
		t.Fatalf("auditd captures: %v\n%s", caps, out)
	}
	if b, _ := os.ReadFile(caps[0]); string(b) != all {
		t.Fatalf("capture content:\n%s", b)
	}

	code, out = capture(t, "monitor", "status")
	if code != 0 {
		t.Fatalf("status exit %d:\n%s", code, out)
	}
	for _, want := range []string{"STOPPED", "auditd", "transcripts", "mcp-config", "retention: 7d,1GB", "chain intact", "format auditd"} {
		if !strings.Contains(out, want) {
			t.Errorf("status lacks %q:\n%s", want, out)
		}
	}
	code, out = capture(t, "monitor", "status", "--json", "--dir", dir)
	var js monitorStatusOut
	if code != 0 || json.Unmarshal([]byte(out), &js) != nil || js.Status == nil {
		t.Fatalf("status --json exit %d:\n%s", code, out)
	}
	var au *recorder.SourceStatus
	for i := range js.Status.Sources {
		if js.Status.Sources[i].Name == "auditd" {
			au = &js.Status.Sources[i]
		}
	}
	if au == nil || au.Records != 12 || au.Gaps != 1 || au.MissingSeq != 4 || au.SeqKind != recorder.SeqAuditSerial || !js.Journal.Intact || js.Running {
		t.Fatalf("auditd status: %+v journal %+v", au, js.Journal)
	}

	jp := filepath.Join(dir, "journal.jsonl")
	if code, out = capture(t, "journal", "verify", jp); code != 0 || !strings.Contains(out, "1 intact") {
		t.Fatalf("verify intact: %d\n%s", code, out)
	}

	// Replay the recording offline.
	code, out = capture(t, "replay", dir, "--all")
	if code != 0 || !strings.Contains(out, "echo 10") || !strings.Contains(out, "replayed 6 recorded OS record(s)") {
		t.Fatalf("replay exit %d:\n%s", code, out)
	}

	// Deleting the capture by hand: verify fails.
	data, _ := os.ReadFile(caps[0])
	_ = os.Remove(caps[0])
	if code, out = capture(t, "journal", "verify", jp); code != 1 || !strings.Contains(out, "DELETED") {
		t.Fatalf("unjournaled deletion not flagged: %d\n%s", code, out)
	}
	_ = os.WriteFile(caps[0], data, 0o600)

	// Retention deletes a capture created 30 days ago (journaled): verify
	// passes again. Age comes from the creation stamp, not the mtime.
	jn, err := journal.Open(jp)
	if err != nil {
		t.Fatal(err)
	}
	created := time.Now().Add(-30 * 24 * time.Hour)
	oc := recorder.NewCapture(dir, "tail-old", ".jsonl", jn, nil)
	oc.SetClock(func() time.Time { return created })
	_, _ = oc.Write([]byte("{\"x\":1}\n"))
	_ = oc.Close()
	_ = jn.Close()
	oldCap := oc.Path()
	if code, out = capture(t, "monitor", sessions, "--record", "--retain", "7d", "--quiet", "--cycles", "1", "--interval", "10ms"); code != 0 {
		t.Fatalf("monitor (prune) exit %d:\n%s", code, out)
	}
	if _, err := os.Stat(oldCap); err == nil {
		t.Fatal("retention did not prune the 30-day-old capture")
	}
	code, out = capture(t, "journal", "verify", jp)
	if code != 0 || !strings.Contains(out, "PRUNED") || !strings.Contains(out, "1 pruned by retention") {
		t.Fatalf("pruned capture must verify: %d\n%s", code, out)
	}
}

func TestMonitorStatusWithoutState(t *testing.T) {
	code, out := capture(t, "monitor", "status", "--dir", t.TempDir())
	if code != 1 || !strings.Contains(out, "no recorder status") {
		t.Fatalf("exit %d:\n%s", code, out)
	}
}

func TestMonitorRejectsBadRetention(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	code, _ := capture(t, "monitor", home, "--retain", "forever", "--cycles", "1")
	if code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
}

func TestEndpointDirExpansion(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "auditd-20261001T000000Z.log"), []byte(recAuditLines(1, 1)), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "mcp-config-20261001T000000Z.jsonl"), []byte("{}\n"), 0o600)
	got, err := expandEndpointDirs([]string{"/x/audit.log", dir})
	if err != nil || len(got) != 2 || got[0] != "/x/audit.log" || filepath.Base(got[1]) != "auditd-20261001T000000Z.log" {
		t.Fatalf("expanded %v %v", got, err)
	}
	if _, err := expandEndpointDirs([]string{t.TempDir()}); err == nil {
		t.Fatal("an empty directory must be an error, not a silent no-op")
	}
}

// The anchor file checked by `monitor status` comes from the flag, never
// from status.json (writable by the monitored user); anchor lines match
// on the full journal path.
func TestMonitorStatusAnchorFromFlagOnly(t *testing.T) {
	dir := t.TempDir()
	jp := filepath.Join(dir, "journal.jsonl")
	jn, err := journal.Open(jp)
	if err != nil {
		t.Fatal(err)
	}
	_ = jn.Close()
	head, _ := journal.Head(jp)
	anchor := filepath.Join(t.TempDir(), "anchor.log")
	other := filepath.Join(t.TempDir(), "elsewhere", "journal.jsonl")
	_ = os.WriteFile(anchor, []byte("2026-10-01T00:00:00Z "+jp+" "+head+"\n2026-10-01T00:00:01Z "+other+" ffff\n"), 0o600)
	forged := filepath.Join(t.TempDir(), "forged.log")
	r := recorder.New(dir, nil)
	r.AnchorFile = forged
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	_, out := capture(t, "monitor", "status", "--dir", dir)
	if !strings.Contains(out, "not checked") || strings.Contains(out, "anchored (") {
		t.Fatalf("status.json anchor was trusted:\n%s", out)
	}
	_, out = capture(t, "monitor", "status", "--dir", dir, "--journal-anchor", anchor)
	if !strings.Contains(out, "anchored (") || !strings.Contains(out, "status.json names anchor file") {
		t.Fatalf("flag anchor not checked or mismatch not warned:\n%s", out)
	}
	// A head recorded for another journal path does not count.
	_ = os.WriteFile(anchor, []byte("2026-10-01T00:00:00Z "+other+" "+head+"\n"), 0o600)
	_, out = capture(t, "monitor", "status", "--dir", dir, "--journal-anchor", anchor)
	if strings.Contains(out, "anchored (") {
		t.Fatalf("head for another journal path accepted:\n%s", out)
	}
}
