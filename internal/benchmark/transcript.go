package benchmark

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// session writes a synthetic Claude Code transcript, one JSON object per
// line, in the shape the real CLI writes. Everything in it is invented.
type session struct {
	id    string
	t0    time.Time
	n     int
	lines []string
}

func newSession(id string, t0 time.Time) *session { return &session{id: id, t0: t0} }

func (s *session) at(sec float64) string {
	return s.t0.Add(time.Duration(sec * float64(time.Second))).UTC().Format(time.RFC3339Nano)
}

func (s *session) emit(kind string, sec float64, msg map[string]any) {
	s.n++
	rec := map[string]any{
		"type": kind, "uuid": fmt.Sprintf("%s-%04d", kind[:1], s.n), "sessionId": s.id,
		"timestamp": s.at(sec), "isSidechain": false, "version": "2.1.0", "cwd": "/home/dev/app",
		"message": msg,
	}
	b, _ := json.Marshal(rec)
	s.lines = append(s.lines, string(b))
}

func (s *session) user(sec float64, text string) {
	s.emit("user", sec, map[string]any{"role": "user", "content": text})
}

func (s *session) say(sec float64, text string) {
	s.emit("assistant", sec, map[string]any{"role": "assistant", "model": "claude-sonnet-5",
		"content": []any{map[string]any{"type": "text", "text": text}}})
}

// bash records a Bash tool call at sec and its result one second later.
func (s *session) bash(sec float64, cmd, result string) {
	id := fmt.Sprintf("toolu_%s_%04d", s.id[:8], s.n+1)
	s.emit("assistant", sec, map[string]any{"role": "assistant", "model": "claude-sonnet-5",
		"content": []any{map[string]any{"type": "tool_use", "id": id, "name": "Bash", "input": map[string]any{"command": cmd}}}})
	s.emit("user", sec+1, map[string]any{"role": "user",
		"content": []any{map[string]any{"type": "tool_result", "tool_use_id": id, "content": result}}})
}

// raw appends a line as is (malformed input for the robustness cases).
func (s *session) raw(line string) { s.lines = append(s.lines, line) }

func (s *session) bytes() []byte { return []byte(strings.Join(s.lines, "\n") + "\n") }

// write puts the transcript where Claude Code keeps it under profile.
func (s *session) write(profile string) (string, error) {
	return writeTranscript(profile, s.id, s.bytes())
}

func writeTranscript(profile, id string, data []byte) (string, error) {
	dir := filepath.Join(profile, ".claude", "projects", "-home-dev-app")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	p := filepath.Join(dir, id+".jsonl")
	return p, os.WriteFile(p, data, 0o644)
}

// ---- endpoint telemetry in the formats internal/endpoint reads today

// auditd renders execve records the way auditd logs them: a SYSCALL line
// and an EXECVE line per process, arguments with spaces hex-encoded.
type auditd struct {
	serial int
	lines  []string
}

func (a *auditd) exec(t time.Time, pid, ppid int, exe string, argv ...string) {
	a.serial++
	stamp := fmt.Sprintf("%d.%03d:%d", t.Unix(), t.Nanosecond()/1e6, a.serial)
	a.lines = append(a.lines, fmt.Sprintf(`type=SYSCALL msg=audit(%s): arch=c000003e syscall=59 success=yes exit=0 ppid=%d pid=%d auid=1000 uid=1000 comm="%s" exe="%s" key="exec"`,
		stamp, ppid, pid, filepath.Base(exe), exe))
	args := []string{fmt.Sprintf("argc=%d", len(argv))}
	for i, v := range argv {
		if strings.ContainsAny(v, " \"'\t") {
			args = append(args, fmt.Sprintf("a%d=%s", i, strings.ToUpper(hex.EncodeToString([]byte(v)))))
		} else {
			args = append(args, fmt.Sprintf(`a%d="%s"`, i, v))
		}
	}
	a.lines = append(a.lines, fmt.Sprintf("type=EXECVE msg=audit(%s): %s", stamp, strings.Join(args, " ")))
}

func (a *auditd) text() string { return strings.Join(a.lines, "\n") + "\n" }

// sysmonExec renders one Sysmon event 1 (process create).
func sysmonExec(t time.Time, rec, pid, ppid int, image, cmdline string) string {
	return fmt.Sprintf(`<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System><EventID>1</EventID><TimeCreated SystemTime="%s"/><EventRecordID>%d</EventRecordID></System>`+
		`<EventData><Data Name="UtcTime">%s</Data><Data Name="ProcessId">%d</Data><Data Name="Image">%s</Data><Data Name="CommandLine">%s</Data><Data Name="ParentProcessId">%d</Data></EventData></Event>`,
		t.UTC().Format("2006-01-02T15:04:05.0000000Z"), rec, t.UTC().Format("2006-01-02 15:04:05.000"), pid, xmlEscape(image), xmlEscape(cmdline), ppid)
}

func xmlEscape(s string) string {
	return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;").Replace(s)
}

// jsonlExec renders one generic process record (Velociraptor/osquery shape).
func jsonlExec(t time.Time, pid, ppid int, exe, cmdline string) string {
	b, _ := json.Marshal(map[string]any{"Timestamp": t.UTC().Format(time.RFC3339Nano), "Pid": pid, "Ppid": ppid, "Exe": exe, "CommandLine": cmdline, "Username": "dev"})
	return string(b)
}
