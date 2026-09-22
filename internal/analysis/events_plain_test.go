package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/index"
	"github.com/efij/AgentDFIR/v2/internal/overlay"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// auditLog is an endpoint log that corroborates the fixture's rm, which is
// enough to make correlation rewrite the overlay with its verdicts.
func auditLog(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(p, []byte(
		"type=SYSCALL msg=audit(1788084005.300:101): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=4411 uid=1000 comm=\"zsh\" exe=\"/bin/zsh\"\n"+
			"type=EXECVE msg=audit(1788084005.300:101): argc=3 a0=\"/bin/zsh\" a1=\"-c\" a2=\"rm -rf build/\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// A stage that rewrites the overlay must leave it in the one form the index
// can address. Writing it compressed cost the case its index and made
// `agentdfir serve` refuse to open the package at all — with no error the
// analyst would connect to the endpoint log they had just supplied.
func TestOverlayStaysPlaintextAfterRewritingStages(t *testing.T) {
	pkg := buildPkg(t)
	res, err := Run(pkg, Options{EndpointLogs: []string{auditLog(t)}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Correlation == nil || res.Correlation.Corroborated == 0 {
		t.Fatalf("fixture no longer exercises the rewrite: %+v", res.Correlation)
	}
	ev := filepath.Join(pkg, "normalized", "events.jsonl")
	if _, err := os.Stat(ev); err != nil {
		t.Fatalf("events.jsonl must stay plaintext for the index: %v", err)
	}
	if _, err := os.Stat(ev + overlay.Suffix); err == nil {
		t.Fatal("events.jsonl.gz must not exist alongside the plaintext form")
	}
	for _, n := range res.StageNotes {
		if strings.Contains(n, "event index") {
			t.Fatalf("index skipped: %s", n)
		}
	}
	x, err := index.Open(pkg)
	if err != nil {
		t.Fatalf("index unreadable after analysis: %v", err)
	}
	defer x.Close()
	if x.Len() != res.Events {
		t.Fatalf("index holds %d events, analysis reported %d", x.Len(), res.Events)
	}
	// The states the rewrite existed to persist must have survived it.
	states := 0
	for _, e := range LoadEvents(pkg) {
		if e.Corroboration == schema.StateCorroborated {
			states++
		}
	}
	if states == 0 {
		t.Fatal("corroboration states lost")
	}
}

// The same, through the host witness, which needs no endpoint log and so
// fires on ordinary cases.
func TestOverlayStaysPlaintextAfterHostWitness(t *testing.T) {
	pkg := buildPkgWithWitness(t, "/Users/dev/.claude/CLAUDE.md")
	res, err := Run(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Witness == nil || res.Witness.Checked == 0 {
		t.Fatalf("fixture no longer exercises the witness rewrite: %+v", res.Witness)
	}
	ev := filepath.Join(pkg, "normalized", "events.jsonl")
	if _, err := os.Stat(ev); err != nil {
		t.Fatalf("events.jsonl must stay plaintext for the index: %v", err)
	}
	if _, err := os.Stat(ev + overlay.Suffix); err == nil {
		t.Fatal("events.jsonl.gz must not exist alongside the plaintext form")
	}
	x, err := index.Open(pkg)
	if err != nil {
		t.Fatalf("index unreadable after analysis: %v", err)
	}
	defer x.Close()
	if x.Len() != res.Events {
		t.Fatalf("index holds %d events, analysis reported %d", x.Len(), res.Events)
	}
}

// A package left compressed by 2.1.0–2.2.1 must heal the next time anything
// opens its index, without a re-parse.
func TestCompressedOverlayFromOlderVersionIsRestored(t *testing.T) {
	pkg := buildPkg(t)
	if _, err := Run(pkg, Options{}); err != nil {
		t.Fatal(err)
	}
	ev := filepath.Join(pkg, "normalized", "events.jsonl")
	want, err := os.ReadFile(ev)
	if err != nil {
		t.Fatal(err)
	}
	// Reproduce the damaged state exactly: compressed form only, plus an
	// index that no longer matches.
	if _, err := overlay.Compress(ev); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(ev); err == nil {
		t.Fatal("setup did not remove the plaintext form")
	}
	_ = os.Remove(filepath.Join(pkg, index.Dir, index.File))

	x, err := index.Open(pkg)
	if err != nil {
		t.Fatalf("index must recover a compressed overlay: %v", err)
	}
	defer x.Close()
	got, err := os.ReadFile(ev)
	if err != nil {
		t.Fatalf("plaintext form not restored: %v", err)
	}
	if string(got) != string(want) {
		t.Fatal("restored overlay differs from the original bytes")
	}
	if _, err := os.Stat(ev + overlay.Suffix); err == nil {
		t.Fatal("compressed form not removed after restore")
	}
	if x.Len() == 0 {
		t.Fatal("index empty after recovery")
	}
}
