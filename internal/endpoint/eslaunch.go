package endpoint

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// `monitor --es`: run Apple's /usr/bin/eslogger as a child process and
// stream its JSON through ESParser. eslogger is Apple's own, entitled
// Endpoint Security client, so AgentDFIR needs no entitlement and no
// native code; it does need root, macOS 13 or later, and Full Disk Access
// for the terminal that starts it. When any of that is missing the
// launcher says why and the monitor carries on without it. eslogger is
// local only (no network), and the child is killed when the monitor's
// context ends.

// ESLoggerPath is where macOS ships eslogger.
const ESLoggerPath = "/usr/bin/eslogger"

// DefaultESEvents are subscribed by default: process lifecycle, file
// changes (close carries the modified flag; plain write and open are left
// out for volume), persistence, TCC, authentication, XProtect and
// UNIX-socket connects. Types the running macOS does not offer are
// dropped after asking eslogger --list-events.
var DefaultESEvents = []string{
	"exec", "fork", "exit",
	"create", "close", "rename", "unlink", "truncate", "clone", "link",
	"btm_launch_item_add", "btm_launch_item_remove", "tcc_modify",
	"authentication", "openssh_login", "login_login", "sudo", "su",
	"xp_malware_detected", "uipc_connect",
}

// ESLauncher starts eslogger. Every host dependency is a field so tests
// can stand in for a Mac running as root.
type ESLauncher struct {
	Path    string
	Events  []string
	Command func(ctx context.Context, name string, args ...string) *exec.Cmd
	GOOS    string
	Euid    func() int
	OSMajor func() int // 0 when unknown
	Stat    func(string) (os.FileInfo, error)
}

// NewESLauncher returns a launcher for the running host.
func NewESLauncher() *ESLauncher {
	return &ESLauncher{Path: ESLoggerPath, Events: DefaultESEvents, Command: exec.CommandContext,
		GOOS: runtime.GOOS, Euid: os.Geteuid, OSMajor: macOSMajor, Stat: os.Stat}
}

// Check returns the event list eslogger will be started with, or the
// reason it cannot run here.
func (l *ESLauncher) Check(ctx context.Context) ([]string, error) {
	if l.GOOS != "darwin" {
		return nil, fmt.Errorf("Endpoint Security is macOS only (this is %s)", l.GOOS)
	}
	if v := l.OSMajor(); v != 0 && v < 13 {
		return nil, fmt.Errorf("eslogger needs macOS 13 or later (this is macOS %d)", v)
	}
	if _, err := l.Stat(l.Path); err != nil {
		return nil, fmt.Errorf("%s not found (macOS 13+ ships it): %v", l.Path, err)
	}
	if l.Euid() != 0 {
		return nil, errors.New("eslogger must run as root: start the monitor with sudo (the terminal also needs Full Disk Access)")
	}
	lctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	out, err := l.Command(lctx, l.Path, "--list-events").Output()
	if err != nil {
		return nil, fmt.Errorf("eslogger --list-events failed: %v", err)
	}
	offered := map[string]bool{}
	for _, f := range strings.Fields(string(out)) {
		offered[f] = true
	}
	var events []string
	for _, e := range l.Events {
		if offered[e] {
			events = append(events, e)
		}
	}
	if len(events) == 0 {
		return nil, errors.New("none of the requested event types is offered by this macOS's eslogger")
	}
	return events, nil
}

// limitedBuffer keeps the first n bytes written to it.
type limitedBuffer struct {
	bytes.Buffer
	n int
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := b.n - b.Len(); room > 0 {
		if len(p) > room {
			b.Buffer.Write(p[:room])
		} else {
			b.Buffer.Write(p)
		}
	}
	return len(p), nil
}

// Run starts eslogger with events and streams it until ctx ends or the
// child exits. Every raw line goes to raw (the capture file, importable
// later with --endpoint); every parsed record goes to onRecord. The
// returned result carries the stream's counts and UNSUPPORTED types.
func (l *ESLauncher) Run(ctx context.Context, events []string, raw io.Writer, onRecord func(Record)) (*LoadResult, error) {
	p := NewESParser()
	args := append([]string{"--format", "json"}, events...)
	cmd := l.Command(ctx, l.Path, args...)
	cmd.Cancel = func() error { return cmd.Process.Kill() }
	cmd.WaitDelay = 3 * time.Second
	stderr := &limitedBuffer{n: 8 << 10}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return p.Finish(), err
	}
	if err := cmd.Start(); err != nil {
		return p.Finish(), fmt.Errorf("start eslogger: %w", err)
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64<<10), maxLineBytes)
	n := 0
	for sc.Scan() {
		n++
		line := sc.Bytes()
		if raw != nil {
			_, _ = raw.Write(append(append([]byte{}, line...), '\n'))
		}
		if r, ok := p.Line(line, fmt.Sprintf("eslogger-live:%d", n)); ok && onRecord != nil {
			onRecord(r)
		}
	}
	scanErr := sc.Err()
	waitErr := cmd.Wait()
	res := p.Finish()
	if ctx.Err() != nil {
		return res, nil // stopped by the monitor
	}
	if waitErr != nil {
		msg := strings.TrimSpace(stderr.String())
		hint := ""
		if strings.Contains(msg, "NOT_PERMITTED") || strings.Contains(strings.ToLower(msg), "full disk access") {
			hint = " (grant Full Disk Access to the terminal running the monitor)"
		}
		return res, fmt.Errorf("eslogger exited: %v: %s%s", waitErr, msg, hint)
	}
	if scanErr != nil {
		return res, fmt.Errorf("reading eslogger output: %w", scanErr)
	}
	return res, nil
}
