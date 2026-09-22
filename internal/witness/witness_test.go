package witness

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/internal/schema"
)

// TestConfirmsAWriteThatLanded is the state the tool could never produce
// before: the transcript claims a write, and something outside the
// transcript agrees.
func TestConfirmsAWriteThatLanded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{"ok":true}`), 0o644); err != nil {
		t.Fatal(err)
	}
	events := []schema.Event{{
		EventID: "e1", EventType: schema.EventToolCall, Action: "write_file",
		File: path, Corroboration: schema.StateObserved,
	}}
	rec := Gather(events, "host", 1, DefaultLimits)
	if len(rec.Files) != 1 || !rec.Files[0].Exists || rec.Files[0].SHA256 == "" {
		t.Fatalf("witness did not record the file: %+v", rec.Files)
	}
	res, _ := Apply(events, rec)
	if res.Confirmed != 1 {
		t.Fatalf("confirmed = %d, want 1", res.Confirmed)
	}
	if events[0].Corroboration != schema.StateCorroborated {
		t.Fatalf("event state = %s, want %s", events[0].Corroboration, schema.StateCorroborated)
	}
	if events[0].WitnessNote == "" {
		t.Error("no note naming the witness")
	}
}

// TestAbsenceIsNotDisproof: a file can be removed by anything between the
// action and the acquisition, so a missing file must not be reported as the
// agent having lied.
func TestAbsenceIsNotDisproof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gone.txt")
	events := []schema.Event{{
		EventID: "e1", EventType: schema.EventToolCall, Action: "write_file",
		File: path, Corroboration: schema.StateObserved,
	}}
	rec := Gather(events, "host", 1, DefaultLimits)
	res, findings := Apply(events, rec)
	if res.Absent != 1 {
		t.Fatalf("absent = %d, want 1", res.Absent)
	}
	if events[0].Corroboration != schema.StateObserved {
		t.Errorf("state changed to %s on a missing file", events[0].Corroboration)
	}
	if len(findings) != 0 {
		t.Errorf("absence produced %d finding(s); it is not disproof", len(findings))
	}
	if events[0].WitnessNote == "" {
		t.Error("absence should still be noted")
	}
}

// TestGatherIsReadOnlyAndBounded: the paths come from evidence, which is
// hostile input.
func TestGatherIsReadOnlyAndBounded(t *testing.T) {
	dir := t.TempDir()
	big := filepath.Join(dir, "big.bin")
	if err := os.WriteFile(big, make([]byte, 2048), 0o644); err != nil {
		t.Fatal(err)
	}
	events := []schema.Event{
		{Action: "write_file", File: big},
		{Action: "write_file", File: "relative/path.txt"}, // not absolute: ignored
		{Action: "shell_execution", Command: "ls"},        // claims no write
	}
	rec := Gather(events, "host", 1, Limits{MaxFiles: 10, MaxFileBytes: 1024, MaxRepos: 5})
	if len(rec.Files) != 1 {
		t.Fatalf("recorded %d files, want only the absolute write target", len(rec.Files))
	}
	if !rec.Files[0].Truncated || rec.Files[0].SHA256 != "" {
		t.Error("a file over the byte bound was hashed anyway")
	}
	// Nothing on disk changed.
	if info, err := os.Stat(big); err != nil || info.Size() != 2048 {
		t.Error("witness pass modified the host")
	}
}

// TestRepoReflogIsReadWithoutExecutingGit: this tool does not run binaries
// it finds on a host under investigation.
func TestRepoReflogIsReadWithoutExecutingGit(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, ".git", "logs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".git", "logs", "HEAD"),
		[]byte("0000 abcd Efi <e@x> 1 +0000\tcommit: add thing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := filepath.Join(dir, "src.go")
	if err := os.WriteFile(f, []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rec := Gather([]schema.Event{{Action: "edit_file", File: f}}, "host", 1, DefaultLimits)
	if len(rec.Repos) != 1 || len(rec.Repos[0].HeadLog) != 1 {
		t.Fatalf("reflog not captured: %+v", rec.Repos)
	}
}
