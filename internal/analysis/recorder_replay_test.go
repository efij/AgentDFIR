package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/collector"
	"github.com/efij/AgentDFIR/v4/internal/products"
	"github.com/efij/AgentDFIR/v4/internal/schema"

	"github.com/efij/AgentDFIR/v4/internal/journal"
	"github.com/efij/AgentDFIR/v4/internal/recorder"
)

// A black-box recording replayed into an investigation: auditd records
// captured by the recorder (tailed, journaled) are expanded from the
// state directory and correlated with the agent's transcript, exactly as
// `agentdfir run --endpoint ~/.agentdfir/monitor` does.
func TestRecordingReplaysIntoFindings(t *testing.T) {
	pkg := buildPkg(t)
	dir := t.TempDir()
	in := filepath.Join(dir, "audit.log")
	_ = os.WriteFile(in, nil, 0o600)
	state := filepath.Join(dir, "monitor")
	jn, err := journal.Open(filepath.Join(state, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	r := recorder.New(state, jn)
	r.AddTail(in, "auditd", false)
	r.Tick()
	f, _ := os.OpenFile(in, os.O_APPEND|os.O_WRONLY, 0)
	f.WriteString("type=SYSCALL msg=audit(1788084005.300:101): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=4411 uid=1000 comm=\"zsh\" exe=\"/bin/zsh\"\n" +
		"type=EXECVE msg=audit(1788084005.300:101): argc=3 a0=\"/bin/zsh\" a1=\"-c\" a2=\"rm -rf build/\"\n" +
		"type=SYSCALL msg=audit(1788084060.000:102): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=9000 uid=0 comm=\"cron\" exe=\"/usr/sbin/cron\"\n" +
		"type=EXECVE msg=audit(1788084060.000:102): argc=1 a0=\"cron\"\n")
	f.Close()
	r.Tick()
	r.Stop()
	_ = jn.Close()

	files, _ := recorder.EndpointFiles(state)
	if len(files) != 1 {
		t.Fatalf("recorded captures: %v", files)
	}
	res, err := Run(pkg, Options{EndpointLogs: files})
	if err != nil {
		t.Fatal(err)
	}
	if res.Correlation == nil || res.Correlation.Corroborated != 1 || res.Correlation.Contradicted != 1 {
		t.Fatalf("correlation over the recording: %+v", res.Correlation)
	}
	if rules(res.Findings)["ENDPOINT_CONTRADICTED_COMMAND"] != 1 {
		t.Fatalf("findings: %v", rules(res.Findings))
	}
}

// A case collected from a host with a recorder state dir: the pruned
// capture is accounted for by its prune record, the capture deleted by
// hand is a HIGH finding, the intact one verifies silently.
func TestCaseCheckSeparatesPruningFromDeletion(t *testing.T) {
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, ".claude", "projects", "p"), 0o755)
	_ = os.WriteFile(filepath.Join(root, ".claude", "projects", "p", "s1.jsonl"),
		[]byte(`{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-08-30T10:00:00Z","message":{"role":"user","content":"hi"}}`+"\n"), 0o644)
	state := filepath.Join(root, ".agentdfir", "monitor")
	jn, err := journal.Open(filepath.Join(state, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	var paths []string
	for _, src := range []string{"auditd", "tail-falco", "tail-tetragon"} {
		c := recorder.NewCapture(state, src, ".log", jn, nil)
		_, _ = c.Write([]byte("type=SYSCALL msg=audit(1788084005.300:1): pid=1 exe=\"/bin/sh\"\n"))
		_ = c.Close()
		paths = append(paths, c.Path())
	}
	old := time.Now().Add(-30 * 24 * time.Hour)
	_ = os.Chtimes(paths[0], old, old)
	if pruned, _ := (recorder.Retention{MaxAge: 7 * 24 * time.Hour}).Prune(state, nil, jn, time.Now()); len(pruned) != 1 {
		t.Fatalf("pruned %v", pruned)
	}
	_ = jn.Close()
	_ = os.Remove(paths[1]) // deleted without a prune record

	pkg := filepath.Join(t.TempDir(), "c.adfir")
	b, err := casepkg.New(pkg, "BB", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	man, _ := products.ManifestAllPlatforms("claude-code")
	if _, err := collector.Run(b, man, collector.Options{ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"), SystemRoot: root, Product: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	res, err := Run(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	var deleted []schema.Finding
	for _, f := range res.Findings {
		switch f.RuleID {
		case "TRANSCRIPT_DELETED":
			deleted = append(deleted, f)
		case "TRANSCRIPT_REWRITTEN", "TRANSCRIPT_TRUNCATED", "JOURNAL_TAMPERED":
			t.Errorf("unexpected %s: %s", f.RuleID, f.Description)
		}
	}
	if len(deleted) != 1 || deleted[0].Severity != "HIGH" || !strings.Contains(deleted[0].Description, filepath.Base(paths[1])) {
		t.Fatalf("deletion findings: %+v", deleted)
	}
}

// collectRoot collects a profile root into a sealed case and analyzes it.
func collectRoot(t *testing.T, root string) *Result {
	t.Helper()
	pkg := filepath.Join(t.TempDir(), "c.adfir")
	b, err := casepkg.New(pkg, "BB", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	man, _ := products.ManifestAllPlatforms("claude-code")
	if _, err := collector.Run(b, man, collector.Options{ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"), SystemRoot: root, Product: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	res, err := Run(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return res
}

// A forged prune record cannot launder a deleted transcript, and a capture
// edited before retention deleted it is caught by its prune hash.
func TestCaseCheckRejectsForgedOrMismatchedPrune(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(root, ".claude", "projects", "p")
	_ = os.MkdirAll(proj, 0o755)
	keep := filepath.Join(proj, "keep.jsonl")
	gone := filepath.Join(proj, "gone.jsonl")
	line := `{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-08-30T10:00:00Z","message":{"role":"user","content":"hi"}}` + "\n"
	_ = os.WriteFile(keep, []byte(line), 0o644)
	_ = os.WriteFile(gone, []byte(line), 0o644)
	state := filepath.Join(root, ".agentdfir", "monitor")
	jn, err := journal.Open(filepath.Join(state, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	jn.Baseline(gone)
	jn.Prune(gone, int64(len(line)), "00", "retention: forged") // not a capture
	_ = os.Remove(gone)

	c := recorder.NewCapture(state, "auditd", ".log", jn, nil)
	_, _ = c.Write([]byte("type=SYSCALL msg=audit(1788084005.300:1): pid=1 exe=\"/bin/sh\"\n"))
	_ = c.Close()
	data, _ := os.ReadFile(c.Path())
	data[20] ^= 1 // edited, same size
	_ = os.WriteFile(c.Path(), data, 0o600)
	old := time.Now().Add(-30 * 24 * time.Hour)
	_ = os.Chtimes(c.Path(), old, old)
	if p, _ := (recorder.Retention{MaxAge: 24 * time.Hour}).Prune(state, nil, jn, time.Now()); len(p) != 1 {
		t.Fatalf("pruned %v", p)
	}
	_ = jn.Close()

	titles := map[string]string{}
	for _, f := range collectRoot(t, root).Findings {
		if f.RuleID == "TRANSCRIPT_DELETED" {
			titles[f.Title] = f.Severity
		}
	}
	if titles["Prune Record for a File the Recorder Does Not Own"] != "HIGH" || titles["Pruned Capture Does Not Match What Was Journaled"] != "HIGH" {
		t.Fatalf("findings: %v", titles)
	}
}
