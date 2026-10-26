package cli

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/journal"
)

func TestMonitorESNotAvailableContinues(t *testing.T) {
	home := t.TempDir()
	l := endpoint.NewESLauncher()
	l.GOOS = "linux"
	h := &esHandle{}
	startES(l, "", true, nil, home, h)
	h.Stop() // nothing started: a no-op
	if m, _ := filepath.Glob(filepath.Join(home, ".agentdfir", "monitor", "eslogger-*.jsonl")); len(m) != 0 {
		t.Fatalf("capture file created without eslogger: %v", m)
	}
}

func TestMonitorESCapturesAndJournals(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses /bin/cat as a stand-in eslogger")
	}
	fixture, _ := filepath.Abs(filepath.Join("..", "endpoint", "testdata", "macos", "eslogger_synthetic.jsonl"))
	home := t.TempDir()
	l := endpoint.NewESLauncher()
	l.GOOS, l.Euid, l.OSMajor = "darwin", func() int { return 0 }, func() int { return 15 }
	l.Stat = func(string) (os.FileInfo, error) { return nil, nil }
	l.Command = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if len(args) == 1 && args[0] == "--list-events" {
			return exec.CommandContext(ctx, "/bin/echo", "exec fork exit create close")
		}
		return exec.CommandContext(ctx, "/bin/cat", fixture)
	}
	jp := filepath.Join(home, "journal.jsonl")
	jn, err := journal.Open(jp)
	if err != nil {
		t.Fatal(err)
	}
	h := &esHandle{}
	startES(l, "exec,fork", true, jn, home, h)
	<-h.Done() // the stand-in exits after the fixture
	h.Stop()
	_ = jn.Close()
	m, _ := filepath.Glob(filepath.Join(home, ".agentdfir", "monitor", "eslogger-*.jsonl"))
	if len(m) != 1 {
		t.Fatalf("capture files: %v", m)
	}
	got, _ := os.ReadFile(m[0])
	want, _ := os.ReadFile(fixture)
	if string(got) != string(want) {
		t.Fatalf("capture %d bytes, eslogger wrote %d", len(got), len(want))
	}
	if lr, err := endpoint.Load(m[0], endpoint.FormatAuto); err != nil || lr.Format != endpoint.FormatESLogger || len(lr.Records) == 0 {
		t.Fatalf("capture not importable with --endpoint: %v", err)
	}
	jdata, _ := os.ReadFile(jp)
	if !strings.Contains(string(jdata), `"kind":"append"`) || !strings.Contains(string(jdata), "eslogger-") {
		t.Fatalf("capture not journaled: %s", jdata)
	}
}
