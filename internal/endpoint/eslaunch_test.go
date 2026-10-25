package endpoint

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// TestHelperESLogger stands in for /usr/bin/eslogger when the test binary
// is re-run with ADFIR_FAKE_ESLOGGER set.
func TestHelperESLogger(t *testing.T) {
	mode := os.Getenv("ADFIR_FAKE_ESLOGGER")
	if mode == "" {
		t.Skip("helper process")
	}
	switch mode {
	case "list":
		fmt.Println("exec\nfork\nexit\nclose\ncreate\nbtm_launch_item_add")
	case "stream":
		data, _ := os.ReadFile(esFixture)
		os.Stdout.Write(data)
	case "denied":
		fmt.Fprintln(os.Stderr, "ERROR: Failed to create new Endpoint Security client! ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED")
		os.Exit(71)
	case "hang":
		fmt.Println(`{"schema_version":1,"time":"2026-10-20T09:00:00Z","event":{"exit":{"stat":0}},"process":{"audit_token":{"pid":1},"executable":{"path":"/x"}}}`)
		time.Sleep(time.Minute)
	}
	os.Exit(0)
}

func fakeLauncher(mode string) *ESLauncher {
	l := NewESLauncher()
	l.GOOS, l.Euid, l.OSMajor = "darwin", func() int { return 0 }, func() int { return 15 }
	l.Stat = func(string) (os.FileInfo, error) { return nil, nil }
	l.Command = func(ctx context.Context, name string, args ...string) *exec.Cmd {
		m := mode
		if len(args) == 1 && args[0] == "--list-events" {
			m = "list"
		}
		cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=TestHelperESLogger")
		cmd.Env = append(os.Environ(), "ADFIR_FAKE_ESLOGGER="+m)
		return cmd
	}
	return l
}

func TestESLauncherCheckReasons(t *testing.T) {
	ctx := context.Background()
	l := fakeLauncher("stream")
	l.GOOS = "linux"
	if _, err := l.Check(ctx); err == nil || !strings.Contains(err.Error(), "macOS only") {
		t.Fatalf("linux: %v", err)
	}
	l = fakeLauncher("stream")
	l.OSMajor = func() int { return 12 }
	if _, err := l.Check(ctx); err == nil || !strings.Contains(err.Error(), "macOS 13") {
		t.Fatalf("old macOS: %v", err)
	}
	l = fakeLauncher("stream")
	l.Euid = func() int { return 501 }
	if _, err := l.Check(ctx); err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("non-root: %v", err)
	}
	l = fakeLauncher("stream")
	l.Stat = func(string) (os.FileInfo, error) { return nil, errors.New("no such file") }
	if _, err := l.Check(ctx); err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing binary: %v", err)
	}
	// Event list intersected with what this macOS offers.
	evs, err := fakeLauncher("stream").Check(ctx)
	if err != nil || strings.Join(evs, ",") != "exec,fork,exit,create,close,btm_launch_item_add" {
		t.Fatalf("events %v, %v", evs, err)
	}
}

func TestESLauncherStreams(t *testing.T) {
	l := fakeLauncher("stream")
	var raw strings.Builder
	var got []Record
	res, err := l.Run(context.Background(), []string{"exec"}, &raw, func(r Record) { got = append(got, r) })
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 || len(got) != len(res.Records) || res.Unsupported["mmap"] != 2 {
		t.Fatalf("streamed %d records, result %d, unsupported %v", len(got), len(res.Records), res.Unsupported)
	}
	data, _ := os.ReadFile(esFixture)
	if raw.String() != string(data) {
		t.Fatal("raw capture differs from eslogger output")
	}
}

func TestESLauncherPermissionAndKill(t *testing.T) {
	_, err := fakeLauncher("denied").Run(context.Background(), []string{"exec"}, nil, nil)
	if err == nil || !strings.Contains(err.Error(), "Full Disk Access") {
		t.Fatalf("denied: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := fakeLauncher("hang").Run(ctx, []string{"exit"}, nil, func(Record) { cancel() })
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("stopped launcher returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("child not killed on cancel")
	}
}
