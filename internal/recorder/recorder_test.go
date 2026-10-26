package recorder

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/hashchain"
	"github.com/efij/AgentDFIR/v5/internal/journal"
)

// auditLines returns n auditd SYSCALL+EXECVE event pairs starting at serial.
func auditLines(serial, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		s := serial + i
		fmt.Fprintf(&b, "type=SYSCALL msg=audit(1788084005.%03d:%d): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=%d uid=1000 comm=\"sh\" exe=\"/bin/sh\"\n", i%1000, s, 4000+s)
		fmt.Fprintf(&b, "type=EXECVE msg=audit(1788084005.%03d:%d): argc=3 a0=\"/bin/sh\" a1=\"-c\" a2=\"echo %d\"\n", i%1000, s, s)
	}
	return b.String()
}

func appendFile(t *testing.T, p, s string) {
	t.Helper()
	f, err := os.OpenFile(p, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(s); err != nil {
		t.Fatal(err)
	}
	f.Close()
}

// resolveIn accepts the capture files of one state dir (what the CLI's
// resolver does for a live state dir).
func resolveIn(dir string) func(string) (string, bool) {
	return func(p string) (string, bool) {
		if filepath.Dir(p) != dir || !IsCaptureName(filepath.Base(p)) {
			return "", false
		}
		return p, true
	}
}

func openJournal(t *testing.T, dir string) (*journal.Journal, string) {
	t.Helper()
	jp := filepath.Join(dir, "journal.jsonl")
	jn, err := journal.Open(jp)
	if err != nil {
		t.Fatal(err)
	}
	return jn, jp
}

func TestCaptureChunksAreJournaled(t *testing.T) {
	dir := t.TempDir()
	jn, jp := openJournal(t, dir)
	src := NewSource("tail-x", "tail", "x")
	c := NewCapture(dir, "tail-x", ".jsonl", jn, src)
	c.RollBytes = 100
	for i := 0; i < 10; i++ {
		fmt.Fprintf(c, "{\"n\":%d,\"pad\":\"%s\"}\n", i, strings.Repeat("a", 20))
		if i%3 == 0 {
			c.Flush()
		}
	}
	_ = c.Close()
	_ = jn.Close()
	if len(c.Paths()) < 2 {
		t.Fatalf("capture did not roll over at 100 bytes: %v", c.Paths())
	}
	if n, err := hashchain.VerifyFile(jp); err != nil || n == 0 {
		t.Fatalf("journal chain: %d %v", n, err)
	}
	rep, err := journal.VerifyFiles(jp, resolveIn(dir))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Problems != 0 || rep.OK != len(c.Paths()) {
		t.Fatalf("verify: %+v", rep)
	}
	if s := src.Snapshot(); s.Records != 10 {
		t.Fatalf("records = %d, want 10", s.Records)
	}
	// Every file starts at a line boundary.
	for _, p := range c.Paths() {
		b, _ := os.ReadFile(p)
		if len(b) == 0 || b[0] != '{' || b[len(b)-1] != '\n' {
			t.Fatalf("%s not line-aligned: %q", p, b)
		}
	}
	// Editing a journaled capture is caught.
	p := c.Paths()[0]
	b, _ := os.ReadFile(p)
	b[5] ^= 1
	_ = os.WriteFile(p, b, 0o600)
	rep, _ = journal.VerifyFiles(jp, resolveIn(dir))
	if rep.Problems != 1 {
		t.Fatalf("edit not caught: %+v", rep.Files)
	}
	for _, f := range rep.Files {
		if (f.Path == p) != (f.State == journal.FileRewritten) {
			t.Fatalf("%s: %s", filepath.Base(f.Path), f.State)
		}
	}
}

// makeCaptures writes n one-line captures created 29.5, 28.5, ... days
// ago (the creation stamp is in the name), each last written a minute
// after it was created.
func makeCaptures(t *testing.T, dir string, jn Journal, n int) []string {
	t.Helper()
	c := NewCapture(dir, "auditd", ".log", jn, nil)
	c.RollBytes = 1
	var cur time.Time
	c.SetClock(func() time.Time { return cur })
	base := time.Now().UTC().Add(-30*24*time.Hour + 12*time.Hour).Truncate(time.Second)
	for i := 0; i < n; i++ {
		cur = base.Add(time.Duration(i) * 24 * time.Hour)
		_, _ = c.Write([]byte(auditLines(100+i, 1)))
	}
	_ = c.Close()
	ps := c.Paths()
	if len(ps) != n {
		t.Fatalf("captures: %v", ps)
	}
	for i, p := range ps {
		mt := base.Add(time.Duration(i)*24*time.Hour + time.Minute)
		_ = os.Chtimes(p, mt, mt)
	}
	return ps
}

// known is the retention scope from the journal in dir.
func known(t *testing.T, dir string) map[string]journal.JournaledFile {
	t.Helper()
	m, err := journal.JournaledPaths(filepath.Join(dir, "journal.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func TestRetentionPruneIsJournaledAndVerifies(t *testing.T) {
	dir := t.TempDir()
	jn, jp := openJournal(t, dir)
	ps := makeCaptures(t, dir, jn, 5) // last written 29.5..25.5 days ago
	ret, err := ParseRetention("28d")
	if err != nil {
		t.Fatal(err)
	}
	pruned, problems := ret.Prune(dir, known(t, dir), map[string]bool{}, jn, time.Now())
	if len(problems) != 0 || len(pruned) != 2 {
		t.Fatalf("pruned %v problems %v", pruned, problems)
	}
	for _, p := range ps[:2] {
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("%s not pruned", p)
		}
	}
	// Size bound: two files fit; the active one is never touched.
	fi, _ := os.Stat(ps[4])
	bySize := Retention{MaxBytes: 2*fi.Size() + 1}
	pruned, _ = bySize.Prune(dir, known(t, dir), map[string]bool{ps[3]: true}, jn, time.Now())
	if len(pruned) != 1 || pruned[0].Path != ps[2] {
		t.Fatalf("size prune must take the oldest inactive file: %v", pruned)
	}
	_ = jn.Close()
	if _, err := hashchain.VerifyFile(jp); err != nil {
		t.Fatalf("chain after pruning: %v", err)
	}
	rep, err := journal.VerifyFiles(jp, resolveIn(dir))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Problems != 0 || rep.Pruned != 3 || rep.OK != 2 {
		t.Fatalf("verify after pruning: %+v", rep)
	}
	for _, f := range rep.Files {
		if f.State == journal.FilePruned && !strings.Contains(f.Detail, "matches the journal") {
			t.Fatalf("prune hash not tied to the journal: %+v", f)
		}
	}
	b, _ := os.ReadFile(jp)
	if strings.Count(string(b), `"kind":"prune"`) != 3 || !strings.Contains(string(b), `"reason":"retention: created`) {
		t.Fatalf("prune records: %s", b)
	}
}

func TestUnjournaledDeletionFailsVerify(t *testing.T) {
	dir := t.TempDir()
	jn, jp := openJournal(t, dir)
	ps := makeCaptures(t, dir, jn, 3)
	_ = jn.Close()
	if err := os.Remove(ps[1]); err != nil {
		t.Fatal(err)
	}
	rep, err := journal.VerifyFiles(jp, resolveIn(dir))
	if err != nil {
		t.Fatal(err)
	}
	if rep.Problems != 1 {
		t.Fatalf("deletion not flagged: %+v", rep)
	}
	for _, f := range rep.Files {
		if f.Path == ps[1] && f.State != journal.FileDeleted {
			t.Fatalf("state %s", f.State)
		}
	}
}

func TestPruneOfEditedCaptureIsFlagged(t *testing.T) {
	dir := t.TempDir()
	jn, jp := openJournal(t, dir)
	ps := makeCaptures(t, dir, jn, 2)
	// Edit (same size) then let retention delete it: the prune hash no
	// longer matches the journaled content.
	b, _ := os.ReadFile(ps[0])
	b[10] ^= 1
	_ = os.WriteFile(ps[0], b, 0o600)
	pruned, _ := Retention{MaxAge: 29 * 24 * time.Hour}.Prune(dir, known(t, dir), nil, jn, time.Now())
	_ = jn.Close()
	if len(pruned) != 1 {
		t.Fatalf("pruned %v", pruned)
	}
	rep, _ := journal.VerifyFiles(jp, resolveIn(dir))
	if rep.Problems != 1 || rep.Files[0].State != journal.FilePruneMismatch {
		t.Fatalf("edited-then-pruned not flagged: %+v", rep.Files)
	}
}

func TestRetentionWithoutJournalDeletesNothing(t *testing.T) {
	dir := t.TempDir()
	ps := makeCaptures(t, dir, nil, 2)
	pruned, problems := Retention{MaxAge: time.Hour}.Prune(dir, map[string]journal.JournaledFile{ps[0]: {}, ps[1]: {}}, nil, nil, time.Now())
	if len(pruned) != 0 || len(problems) == 0 {
		t.Fatalf("pruned without a journal: %v %v", pruned, problems)
	}
	for _, p := range ps {
		if _, err := os.Stat(p); err != nil {
			t.Fatal("file deleted without a journal")
		}
	}
}

func TestParseRetention(t *testing.T) {
	for spec, want := range map[string]Retention{
		"7d":       {MaxAge: 7 * 24 * time.Hour},
		"12h":      {MaxAge: 12 * time.Hour},
		"2GB":      {MaxBytes: 2 << 30},
		"500mb":    {MaxBytes: 500 << 20},
		"7d, 2GB":  {MaxAge: 7 * 24 * time.Hour, MaxBytes: 2 << 30},
		"1w,1.5G":  {MaxAge: 7 * 24 * time.Hour, MaxBytes: 3 << 29},
		"30m,100K": {MaxAge: 30 * time.Minute, MaxBytes: 100 << 10},
	} {
		got, err := ParseRetention(spec)
		if err != nil || got.MaxAge != want.MaxAge || got.MaxBytes != want.MaxBytes {
			t.Errorf("%q: %+v %v", spec, got, err)
		}
	}
	for _, bad := range []string{"", "lots", "-1d", "0GB", "7x", "99999999999999999999GB"} {
		if _, err := ParseRetention(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestTailFollowsRotationAndTruncation(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "audit.log")
	appendFile(t, in, auditLines(1, 2)) // history before the monitor starts
	out := filepath.Join(dir, "out")
	jn, jp := openJournal(t, out)
	r := New(out, jn)
	src := r.AddTail(in, "auditd", false)
	r.Tick()
	appendFile(t, in, auditLines(3, 2))
	r.Tick()
	// logrotate (create): rename, new file; one more line lands in the old
	// file after the rename, before auditd reopens.
	appendFile(t, in, auditLines(5, 1))
	if err := os.Rename(in, in+".1"); err != nil {
		t.Fatal(err)
	}
	appendFile(t, in+".1", auditLines(6, 1))
	appendFile(t, in, auditLines(7, 2))
	r.Tick()
	// copytruncate: same file cut to zero, then new records.
	if err := os.Truncate(in, 0); err != nil {
		t.Fatal(err)
	}
	appendFile(t, in, auditLines(12, 1)) // serials 9..11 never logged: a gap
	r.Tick()
	r.Stop()
	_ = jn.Close()

	caps := CaptureFiles(out)
	var got strings.Builder
	for _, p := range caps {
		if CaptureSource(filepath.Base(p)) == "auditd" {
			b, _ := os.ReadFile(p)
			got.Write(b)
			if !strings.HasSuffix(p, ".log") {
				t.Errorf("auditd capture %s: want .log", p)
			}
		}
	}
	want := auditLines(3, 2) + auditLines(5, 1) + auditLines(6, 1) + auditLines(7, 2) + auditLines(12, 1)
	if got.String() != want {
		t.Fatalf("capture differs:\n got %q\nwant %q", got.String(), want)
	}
	s := src.Snapshot()
	if s.Rotations != 2 || s.Format != "auditd" || s.State != "stopped" {
		t.Fatalf("status: %+v", s)
	}
	if s.Records != 14 || s.Gaps != 1 || s.MissingSeq != 3 {
		t.Fatalf("records/gaps: %+v", s)
	}
	rep, _ := journal.VerifyFiles(jp, resolveIn(out))
	if rep.Problems != 0 || rep.OK == 0 {
		t.Fatalf("captures not journaled intact: %+v", rep)
	}
}

func TestTailPermissionAndMissingInput(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("needs POSIX permissions and a non-root user")
	}
	dir := t.TempDir()
	locked := filepath.Join(dir, "audit.log")
	appendFile(t, locked, auditLines(1, 1))
	_ = os.Chmod(locked, 0)
	defer os.Chmod(locked, 0o600)
	r := New(filepath.Join(dir, "out"), nil)
	src := r.AddTail(locked, "auditd", false)
	miss := r.AddTail(filepath.Join(dir, "not-yet.json"), "tail", false)
	r.Tick()
	s := src.Snapshot()
	if s.State != "error" || len(s.Problems) == 0 || !strings.Contains(s.Problems[0], "permission denied") {
		t.Fatalf("permission problem not reported: %+v", s)
	}
	m := miss.Snapshot()
	if m.State != "waiting" || len(m.Notes) == 0 {
		t.Fatalf("missing input: %+v", m)
	}
	// The file appears: recording starts from its first byte.
	appendFile(t, filepath.Join(dir, "not-yet.json"), `{"process_exec":{"process":{"binary":"/bin/ls"}},"time":"2026-10-01T00:00:00Z"}`+"\n")
	r.Tick()
	if m = miss.Snapshot(); m.State != "running" || m.Records != 0 {
		// Existing content at the first open is history; only later appends count.
		t.Fatalf("after appear: %+v", m)
	}
	r.Stop()
}

func TestSequenceGapsToleratesInterleaving(t *testing.T) {
	s := NewSource("auditd", "auditd", "")
	s.SetSeq(SeqAuditSerial)
	// Records of events 11 and 12 interleave; 13 and 14 never arrive.
	lines := []int{10, 10, 12, 11, 12, 11, 15, 16}
	for _, n := range lines {
		s.Observe([]byte(fmt.Sprintf("type=SYSCALL msg=audit(1.000:%d): x=1\n", n)))
	}
	st := s.Snapshot()
	if st.Gaps != 1 || st.MissingSeq != 2 || st.Records != 8 {
		t.Fatalf("gaps: %+v", st)
	}
	// A reboot restarts the serial: a reset, not a gap.
	rb := NewSource("auditd", "auditd", "")
	rb.SetSeq(SeqAuditSerial)
	for _, n := range []int{100000, 100001, 3, 4} {
		rb.Observe([]byte(fmt.Sprintf("type=SYSCALL msg=audit(1.000:%d): x=1\n", n)))
	}
	if st = rb.Snapshot(); st.SeqResets != 1 || st.Gaps != 0 {
		t.Fatalf("resets: %+v", st)
	}

	es := NewSource("eslogger", "eslogger", "")
	es.SetSeq(SeqESGlobal)
	// Split across writes: the parser must join partial lines.
	es.Observe([]byte(`{"global_seq_num":1,"seq_num":1}` + "\n" + `{"global_seq_num":`))
	es.Observe([]byte(`2}` + "\n" + `{"global_seq_num": 6}` + "\n"))
	if st = es.Snapshot(); st.Gaps != 1 || st.MissingSeq != 3 || st.Records != 3 || len(st.GapSamples) != 1 {
		t.Fatalf("eslogger gaps: %+v", st)
	}
}

func TestMCPConfigChangesRecorded(t *testing.T) {
	home := t.TempDir()
	cfg := filepath.Join(home, ".cursor", "mcp.json")
	_ = os.MkdirAll(filepath.Dir(cfg), 0o700)
	_ = os.WriteFile(cfg, []byte(`{"mcpServers":{"a":{"command":"x","env":{"TOKEN":"sk-secret"}}}}`), 0o600)
	out := filepath.Join(home, "state")
	jn, jp := openJournal(t, out)
	r := New(out, jn)
	r.AddMCPConfig([]string{filepath.Join(home, ".cursor", "*.json"), filepath.Join(home, ".claude.json")})
	r.Tick()
	_ = os.WriteFile(cfg, []byte(`{"mcpServers":{"b":{"command":"evil"}}}`), 0o600)
	later := time.Now().Add(time.Minute)
	_ = os.Chtimes(cfg, later, later)
	_ = os.WriteFile(filepath.Join(home, ".claude.json"), []byte(`{}`), 0o600)
	r.Tick()
	_ = os.Remove(cfg)
	r.Tick()
	r.Stop()
	_ = jn.Close()
	var data string
	for _, p := range CaptureFiles(out) {
		b, _ := os.ReadFile(p)
		data += string(b)
	}
	for _, want := range []string{`"event":"present"`, `"event":"changed"`, `"event":"created"`, `"event":"removed"`} {
		if !strings.Contains(data, want) {
			t.Errorf("missing %s in %s", want, data)
		}
	}
	if strings.Contains(data, "sk-secret") || strings.Contains(data, "evil") {
		t.Fatal("config content must not be copied into the capture")
	}
	rep, _ := journal.VerifyFiles(jp, resolveIn(out))
	if rep.Problems != 0 || rep.OK != 1 {
		t.Fatalf("mcp-config capture not journaled: %+v", rep)
	}
}

func TestStatusFileLifecycle(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "falco.json")
	appendFile(t, in, "")
	out := filepath.Join(dir, "state")
	jn, _ := openJournal(t, out)
	r := New(out, jn)
	r.Interval = time.Second
	ret, _ := ParseRetention("7d,1GB")
	r.Retention = &ret
	r.AddTail(in, "tail", false)
	r.Tick()
	appendFile(t, in, `{"output":"x","priority":"Warning","rule":"Terminal shell in container","time":"2026-10-01T00:00:00.000000000Z","output_fields":{"proc.cmdline":"bash"}}`+"\n")
	r.Tick()
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	st, err := LoadStatus(out)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Live(time.Now()) || st.Schema != StatusSchema || st.Retention == nil || st.Retention.Policy != "7d,1GB" {
		t.Fatalf("status: %+v", st)
	}
	if len(st.Sources) != 1 || st.Sources[0].Name != "tail-falco" || st.Sources[0].Records != 1 || st.Sources[0].Format != "falco" {
		t.Fatalf("source: %+v", st.Sources)
	}
	if st.Live(time.Now().Add(time.Hour)) {
		t.Fatal("an hour-old status must not count as running")
	}
	r.Stop()
	_ = jn.Close()
	st, _ = LoadStatus(out)
	if st.StoppedUTC == "" || st.Live(time.Now()) || st.Sources[0].State != "stopped" {
		t.Fatalf("after stop: %+v", st)
	}
}

func TestEndpointFilesReportsWhatItSkips(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) { _ = os.WriteFile(filepath.Join(dir, name), []byte(s), 0o600) }
	write("auditd-20261001T000000Z.log", auditLines(1, 1))
	write("mcp-config-20261001T000000Z.jsonl", `{"event":"present"}`+"\n")
	write("tail-x-20261001T000000Z.jsonl", "")
	write("tail-y-20261001T000000Z.log", "\x00\x01 binary junk without structure\n")
	write("journal.broken-20261001T000000Z.jsonl", "{}\n")
	write("notes.txt", "x")
	files, notices := EndpointFiles(dir)
	if len(files) != 1 || !strings.HasSuffix(files[0], "auditd-20261001T000000Z.log") {
		t.Fatalf("files: %v", files)
	}
	joined := strings.Join(notices, "\n")
	for _, want := range []string{"mcp-config", "empty capture", "UNSUPPORTED"} {
		if !strings.Contains(joined, want) {
			t.Errorf("notice %q missing: %v", want, notices)
		}
	}
	if !IsStateDir(dir) || IsCaptureName("journal.broken-20261001T000000Z.jsonl") {
		t.Fatal("state-dir / capture-name detection")
	}
}

// FuzzSourceObserve: hostile bytes from a tailed file never panic the
// line and sequence accounting, and every newline is one record.
func FuzzSourceObserve(f *testing.F) {
	f.Add([]byte("type=SYSCALL msg=audit(1.000:5): x\ntype=X msg=audit(1.000:3"), uint8(7))
	f.Add([]byte(`{"global_seq_num":18446744073709551615}`+"\n"+`{"global_seq_num":0}`+"\n"), uint8(3))
	f.Fuzz(func(t *testing.T, data []byte, split uint8) {
		for _, k := range []string{SeqAuditSerial, SeqESGlobal} {
			s := NewSource("x", "tail", "")
			s.SetSeq(k)
			cut := int(split) % (len(data) + 1)
			s.Observe(data[:cut])
			s.Observe(data[cut:])
			st := s.Snapshot()
			if want := int64(strings.Count(string(data), "\n")); st.Records != want {
				t.Fatalf("records %d, want %d", st.Records, want)
			}
		}
	})
}
