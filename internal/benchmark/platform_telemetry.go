package benchmark

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	w "github.com/efij/AgentDFIR/v4/internal/endpoint/evtx/evtxtest"
)

// Telemetry writers for the per-OS corroboration suite. Each renders the
// minimum of one source's documented output shape that its adapter in
// internal/endpoint reads: synthetic records, never copied from a host.
//
// A writer numbers its records the way the source does (EVTX
// EventRecordID, audit serial, eslogger seq_num / global_seq_num), and
// skip(n) leaves n numbers out: a collection gap.

type telemetry interface {
	proc(t time.Time, pid, ppid int, exe string, argv ...string)
	file(t time.Time, pid int, exe, path string)
	net(t time.Time, pid int, exe, host, ip string, port int)
	skip(n int)
	name() string
	bytes() []byte
}

// ---- Windows: Sysmon in a native .evtx file

type sysmonEVTX struct {
	fname string
	rec   uint64
	evs   []w.Event
}

func newSysmonEVTX(name string, firstRecord uint64) *sysmonEVTX {
	return &sysmonEVTX{fname: name, rec: firstRecord - 1}
}

func (s *sysmonEVTX) ev(id uint16, t time.Time, data ...w.KV) {
	s.rec++
	s.evs = append(s.evs, w.Event{Provider: "Microsoft-Windows-Sysmon", EventID: id, Qualifiers: -1, Version: 5, Level: 4, Time: t, RecordID: s.rec,
		PID: 3056, TID: 4012, Channel: "Microsoft-Windows-Sysmon/Operational", Computer: "DESK-01", UserSID: "S-1-5-18",
		Data: append([]w.KV{w.F("UtcTime", w.String(t.UTC().Format("2006-01-02 15:04:05.000")))}, data...)})
}

func (s *sysmonEVTX) proc(t time.Time, pid, ppid int, exe string, argv ...string) {
	s.ev(1, t, w.F("ProcessId", w.Uint32(uint32(pid))), w.F("Image", w.String(exe)), w.F("CommandLine", w.String(strings.Join(argv, " "))),
		w.F("User", w.String(`DESK\dev`)), w.F("ParentProcessId", w.Uint32(uint32(ppid))), w.F("ParentImage", w.String(`C:\Windows\explorer.exe`)))
}

func (s *sysmonEVTX) file(t time.Time, pid int, exe, path string) {
	s.ev(11, t, w.F("ProcessId", w.Uint32(uint32(pid))), w.F("Image", w.String(exe)), w.F("TargetFilename", w.String(path)),
		w.F("CreationUtcTime", w.String(t.UTC().Format("2006-01-02 15:04:05.000"))), w.F("User", w.String(`DESK\dev`)))
}

func (s *sysmonEVTX) net(t time.Time, pid int, exe, host, ip string, port int) {
	s.ev(3, t, w.F("ProcessId", w.Uint32(uint32(pid))), w.F("Image", w.String(exe)), w.F("User", w.String(`DESK\dev`)),
		w.F("Protocol", w.String("tcp")), w.F("Initiated", w.String("true")), w.F("DestinationIp", w.String(ip)),
		w.F("DestinationHostname", w.String(host)), w.F("DestinationPort", w.String(fmt.Sprint(port))))
}

func (s *sysmonEVTX) skip(n int)    { s.rec += uint64(n) }
func (s *sysmonEVTX) name() string  { return s.fname }
func (s *sysmonEVTX) bytes() []byte { return w.Build(w.Events(s.evs), w.Options{}) }

// ---- macOS: eslogger --format json

type eslogger struct {
	fname  string
	global uint64
	seq    map[string]uint64
	lines  []string
}

func newESLogger(name string) *eslogger {
	return &eslogger{fname: name, global: 1000, seq: map[string]uint64{}}
}

func esProc(pid, ppid int, exe string) map[string]any {
	return map[string]any{"audit_token": map[string]any{"pid": pid, "ruid": 501, "euid": 501}, "ppid": ppid, "original_ppid": ppid,
		"executable": map[string]any{"path": exe, "truncated": false}, "is_platform_binary": strings.HasPrefix(exe, "/bin/") || strings.HasPrefix(exe, "/usr/bin/"),
		"signing_id": nil, "team_id": nil, "session_id": 900}
}

func (e *eslogger) msg(typ string, evType int, t time.Time, actor map[string]any, body map[string]any) {
	e.global++
	e.seq[typ]++
	b, _ := json.Marshal(map[string]any{"schema_version": 1, "version": 7, "event_type": evType, "mach_time": t.UnixNano(),
		"seq_num": e.seq[typ], "global_seq_num": e.global, "time": t.UTC().Format("2006-01-02T15:04:05.000000000Z"),
		"process": actor, "event": map[string]any{typ: body}, "action_type": 1})
	e.lines = append(e.lines, string(b))
}

func (e *eslogger) proc(t time.Time, pid, ppid int, exe string, argv ...string) {
	e.msg("exec", 9, t, esProc(ppid, 1, "/bin/zsh"), map[string]any{"target": esProc(pid, ppid, exe), "args": argv,
		"cwd": map[string]any{"path": "/Users/dev/app", "truncated": false}})
}

func (e *eslogger) file(t time.Time, pid int, exe, path string) {
	e.msg("write", 33, t, esProc(pid, 1, exe), map[string]any{"target": map[string]any{"path": path, "truncated": false}})
}

// net: Endpoint Security has no network-connection event; eslogger
// cannot witness one, and a scenario that needs it does not call this.
func (e *eslogger) net(time.Time, int, string, string, string, int) {}

// skip drops n exec messages: both counters jump.
func (e *eslogger) skip(n int) {
	e.global += uint64(n)
	e.seq["exec"] += uint64(n)
}

func (e *eslogger) name() string  { return e.fname }
func (e *eslogger) bytes() []byte { return []byte(strings.Join(e.lines, "\n") + "\n") }

// ---- Linux: auditd (execve, file PATH records)

type auditLog struct {
	fname string
	a     auditd
}

func newAuditLog(name string) *auditLog { return &auditLog{fname: name} }

func (l *auditLog) proc(t time.Time, pid, ppid int, exe string, argv ...string) {
	l.a.exec(t, pid, ppid, exe, argv...)
}

// file writes an openat(O_CREAT) SYSCALL record with a CREATE PATH item.
func (l *auditLog) file(t time.Time, pid int, exe, path string) {
	l.a.serial++
	stamp := fmt.Sprintf("%d.%03d:%d", t.Unix(), t.Nanosecond()/1e6, l.a.serial)
	l.a.lines = append(l.a.lines,
		fmt.Sprintf(`type=SYSCALL msg=audit(%s): arch=c000003e syscall=257 success=yes exit=3 a2=241 ppid=1 pid=%d auid=1000 uid=1000 comm="%s" exe="%s" key="write"`, stamp, pid, filepath.Base(exe), exe),
		fmt.Sprintf(`type=CWD msg=audit(%s): cwd="/home/dev/app"`, stamp),
		fmt.Sprintf(`type=PATH msg=audit(%s): item=0 name="%s" inode=0 nametype=CREATE`, stamp, path))
}

// net writes a connect() SYSCALL record with its SOCKADDR (AF_INET).
func (l *auditLog) net(t time.Time, pid int, exe, _ string, ip string, port int) {
	l.a.serial++
	stamp := fmt.Sprintf("%d.%03d:%d", t.Unix(), t.Nanosecond()/1e6, l.a.serial)
	var b [4]byte
	fmt.Sscanf(ip, "%d.%d.%d.%d", &b[0], &b[1], &b[2], &b[3])
	saddr := fmt.Sprintf("0200%04X%s0000000000000000", port, strings.ToUpper(hex.EncodeToString(b[:])))
	l.a.lines = append(l.a.lines,
		fmt.Sprintf(`type=SYSCALL msg=audit(%s): arch=c000003e syscall=42 success=yes exit=0 ppid=1 pid=%d auid=1000 uid=1000 comm="%s" exe="%s" key="net"`, stamp, pid, filepath.Base(exe), exe),
		fmt.Sprintf(`type=SOCKADDR msg=audit(%s): saddr=%s`, stamp, saddr))
}

func (l *auditLog) skip(n int)    { l.a.serial += n }
func (l *auditLog) name() string  { return l.fname }
func (l *auditLog) bytes() []byte { return []byte(l.a.text()) }

// ---- Linux: Tetragon GetEventsResponse JSON

type tetragon struct {
	fname string
	lines []string
}

func newTetragon(name string) *tetragon { return &tetragon{fname: name} }

func tetraProc(pid int, exe string, args []string) map[string]any {
	return map[string]any{"exec_id": fmt.Sprintf("bm9kZTE6%d", pid), "pid": pid, "uid": 1000, "cwd": "/home/dev/app", "binary": exe,
		"arguments": strings.Join(args, " "), "flags": "execve clone", "start_time": "2026-09-20T09:00:00Z", "auid": 1000}
}

// event writes one line with the event key first: the sniffer and the
// export both put it there.
func (g *tetragon) event(key string, t time.Time, body map[string]any) {
	b, _ := json.Marshal(body)
	g.lines = append(g.lines, fmt.Sprintf(`{%q: %s, "node_name": "node1", "time": %q}`, key, b, t.UTC().Format("2006-01-02T15:04:05.000000Z")))
}

func (g *tetragon) proc(t time.Time, pid, ppid int, exe string, argv ...string) {
	args := argv
	if len(args) > 0 {
		args = args[1:]
	}
	g.event("process_exec", t, map[string]any{"process": tetraProc(pid, exe, args), "parent": tetraProc(ppid, "/bin/bash", nil)})
}

func (g *tetragon) file(t time.Time, pid int, exe, path string) {
	g.event("process_kprobe", t, map[string]any{"process": tetraProc(pid, exe, nil), "function_name": "security_file_permission",
		"args": []any{map[string]any{"file_arg": map[string]any{"path": path}}, map[string]any{"int_arg": 2}}, "action": "KPROBE_ACTION_POST"})
}

func (g *tetragon) net(t time.Time, pid int, exe, _ string, ip string, port int) {
	g.event("process_kprobe", t, map[string]any{"process": tetraProc(pid, exe, nil), "function_name": "tcp_connect",
		"args":   []any{map[string]any{"sock_arg": map[string]any{"family": "AF_INET", "daddr": ip, "dport": port, "saddr": "10.0.0.5", "sport": 40000}}},
		"action": "KPROBE_ACTION_POST"})
}

// skip: Tetragon export lines carry no sequence number.
func (g *tetragon) skip(int)      {}
func (g *tetragon) name() string  { return g.fname }
func (g *tetragon) bytes() []byte { return []byte(strings.Join(g.lines, "\n") + "\n") }

// ---- Linux sightings: Falco alerts and docker events

func falcoExec(t time.Time, pid, ppid int, exe, cmdline string) string {
	b, _ := json.Marshal(map[string]any{"time": t.UTC().Format(time.RFC3339Nano), "rule": "Terminal shell in container", "priority": "Notice", "source": "syscall",
		"output": "Notice A shell was spawned in a container (cmdline=" + cmdline + ")", "hostname": "node1",
		"output_fields": map[string]any{"evt.type": "execve", "proc.pid": pid, "proc.ppid": ppid, "proc.exepath": exe, "proc.name": filepath.Base(exe),
			"proc.cmdline": cmdline, "user.name": "dev", "container.id": "551e161c47d8", "evt.time": t.UnixNano()}})
	return string(b)
}

func dockerExec(t time.Time, container, cmd string) string {
	id := strings.Repeat("551e161c47d8", 6)[:64]
	b, _ := json.Marshal(map[string]any{"status": "exec_start: " + cmd, "id": id, "from": "alpine:3.19", "Type": "container", "Action": "exec_start: " + cmd,
		"Actor": map[string]any{"ID": id, "Attributes": map[string]any{"image": "alpine:3.19", "name": container, "execID": "e1"}},
		"scope": "local", "time": t.Unix(), "timeNano": t.UnixNano()})
	return string(b)
}

// ---- macOS sighting: unified log (log show --style ndjson)

func unifiedLogLine(t time.Time, proc, msg string) string {
	b, _ := json.Marshal(map[string]any{"timestamp": t.UTC().Format("2006-01-02 15:04:05.000000-0700"), "eventMessage": msg, "processImagePath": proc,
		"eventType": "logEvent", "messageType": "Default", "subsystem": "com.apple.example", "category": "general", "processID": 300, "userID": 0})
	return string(b)
}
