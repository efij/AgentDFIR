package endpoint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const esFixture = "testdata/macos/eslogger_synthetic.jsonl"

func TestESLoggerSniffAndMapping(t *testing.T) {
	f, err := Sniff(esFixture)
	if err != nil || f != FormatESLogger {
		t.Fatalf("sniff = %q, %v", f, err)
	}
	res, err := Load(esFixture, FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != FormatESLogger {
		t.Fatalf("format %s", res.Format)
	}
	byOp := map[string][]Record{}
	for _, r := range res.Records {
		if r.Source != "eslogger" {
			t.Fatalf("source %q", r.Source)
		}
		byOp[r.Operation] = append(byOp[r.Operation], r)
	}

	// exec: the new image, its argv, cwd, signing identity and sequence.
	var git Record
	for _, r := range byOp["exec"] {
		if strings.HasSuffix(r.Exe, "/git") {
			git = r
		}
	}
	if git.Kind != "process" || git.Cmdline != "git status" || git.PID != 4112 || git.PPID != 4111 || git.ParentExe != "/bin/zsh" {
		t.Fatalf("git exec: %+v", git)
	}
	if git.SigningID != "com.apple.git" || !git.PlatformBinary || git.CDHash == "" || git.Cwd != "/Users/user/proj" ||
		git.UID != "501" || git.EUID != "501" || git.TTY != "/dev/ttys004" || git.OrigPPID != 4111 || git.ProcSession != 4111 ||
		!strings.Contains(git.AuditToken, "pid=4112") {
		t.Fatalf("git identity: %+v", git)
	}
	if git.Seq == 0 || git.SeqDomain != "eslogger/exec" || git.GlobalSeq == 0 {
		t.Fatalf("git sequence: seq=%d domain=%q global=%d", git.Seq, git.SeqDomain, git.GlobalSeq)
	}
	claude := byOp["exec"][0]
	if claude.Cmdline != "claude" || claude.TeamID != "Q6L2SF6YDW" || claude.PlatformBinary {
		t.Fatalf("agent exec: %+v", claude)
	}

	if r := byOp["fork"]; len(r) != 2 || r[0].Kind != KindProcessFork || r[0].PID != 4111 || r[0].PPID != 4100 {
		t.Fatalf("fork: %+v", r)
	}
	if r := byOp["exit"]; len(r) != 2 || r[0].Kind != KindProcessExit || r[0].Resource != "stat=0" {
		t.Fatalf("exit: %+v", r)
	}

	// File events: create (new_path), modified close, rename, unlink, …
	ops := map[string]string{}
	for _, op := range []string{"create", "open", "write", "close", "rename", "truncate", "clone", "link", "unlink"} {
		rs := byOp[op]
		if len(rs) != 1 || rs[0].Kind != "file" {
			t.Fatalf("%s: %+v", op, rs)
		}
		ops[op] = rs[0].FileOp + " " + rs[0].FilePath
	}
	want := map[string]string{
		"create":   "create /Users/user/proj/notes.md",
		"open":     "open /Users/user/proj/notes.md",
		"write":    "modify /Users/user/proj/notes.md",
		"close":    "modify /Users/user/proj/notes.md",
		"rename":   "rename /Users/user/proj/notes.md",
		"truncate": "modify /Users/user/proj/log.txt",
		"clone":    "create /Users/user/proj/b.bin",
		"link":     "create /Users/user/proj/a-link.bin",
		"unlink":   "delete /Users/user/proj/old.txt",
	}
	for k, v := range want {
		if ops[k] != v {
			t.Errorf("%s = %q, want %q", k, ops[k], v)
		}
	}
	if r := byOp["rename"][0]; r.Resource != "from /Users/user/proj/.notes.md.tmp" {
		t.Errorf("rename source: %q", r.Resource)
	}

	// Persistence, TCC, auth, AV, IPC, signal.
	bt := byOp["btm_launch_item_add"]
	if len(bt) != 1 || bt[0].Kind != KindPersistence || bt[0].FilePath != "/Users/user/Library/LaunchAgents/com.example.helper.plist" ||
		bt[0].PID != 4111 || bt[0].Exe != "/bin/zsh" || !strings.Contains(bt[0].Resource, "executable=/Users/user/.local/bin/helper") {
		t.Fatalf("btm add: %+v", bt)
	}
	if rm := byOp["btm_launch_item_remove"]; len(rm) != 1 || rm[0].Kind != KindPersistence || !strings.Contains(rm[0].Exe, "backgroundtaskmanagementd") {
		t.Fatalf("btm remove (no instigator, falls back to the process): %+v", rm)
	}
	tcc := byOp["tcc_modify"]
	if len(tcc) != 1 || tcc[0].Kind != KindTCC || tcc[0].Resource != "kTCCServiceSystemPolicyAllFiles" || tcc[0].PID != 4111 ||
		!strings.Contains(tcc[0].Message, "identity=com.example.agent") || !strings.Contains(tcc[0].Message, "right=2") {
		t.Fatalf("tcc_modify: %+v", tcc)
	}
	if r := byOp["openssh_login"]; len(r) != 1 || r[0].Kind != "auth" || r[0].User != "user" || r[0].SourceIP != "192.0.2.10" || r[0].Failed != "" {
		t.Fatalf("ssh: %+v", r)
	}
	if r := byOp["sudo"]; len(r) != 1 || r[0].Kind != "auth" || r[0].Failed != "sudo refused" || r[0].Resource != "USER=root" || r[0].Cmdline != "/bin/cat /etc/sudoers" {
		t.Fatalf("sudo: %+v", r)
	}
	if r := byOp["su"]; len(r) != 1 || r[0].User != "user" || r[0].Resource != "USER=root" {
		t.Fatalf("su: %+v", r)
	}
	if r := byOp["authentication od"]; len(r) != 1 || r[0].Failed == "" || r[0].PID != 4111 {
		t.Fatalf("authentication: %+v", r)
	}
	if r := byOp["login_login"]; len(r) != 1 || r[0].Kind != "auth" || r[0].Resource != "uid=501" {
		t.Fatalf("login: %+v", r)
	}
	if r := byOp["xp_malware_detected"]; len(r) != 1 || r[0].Kind != KindAV || r[0].Resource != "MACOS.EXAMPLE.A" {
		t.Fatalf("xprotect: %+v", r)
	}
	if r := byOp["uipc_connect"]; len(r) != 1 || r[0].Kind != KindIPC || r[0].FilePath != "/private/var/run/mDNSResponder" {
		t.Fatalf("uipc: %+v", r)
	}
	if r := byOp["signal"]; len(r) != 1 || r[0].Kind != KindSignal || !strings.Contains(r[0].Resource, "sig=15") {
		t.Fatalf("signal: %+v", r)
	}
	// ES has no IP network events: nothing from eslogger is kind network.
	for _, r := range res.Records {
		if r.Kind == "network" {
			t.Fatalf("eslogger produced a network record: %+v", r)
		}
	}

	// Unknown and unmapped types are counted, reported, never silent;
	// malformed lines are problems.
	if res.Unsupported["mmap"] != 2 || res.Unsupported["future_event_type"] != 1 {
		t.Fatalf("unsupported: %v", res.Unsupported)
	}
	joined := strings.Join(res.Notices, "\n")
	if !strings.Contains(joined, "UNSUPPORTED eslogger event type(s)") || !strings.Contains(joined, "future_event_type 1") ||
		!strings.Contains(joined, "close event(s) without modification") {
		t.Fatalf("notices: %v", res.Notices)
	}
	if res.Skipped != 6 { // 3 unsupported + 3 malformed
		t.Fatalf("skipped %d, problems %v", res.Skipped, res.Problems)
	}
}

func TestESLoggerSchemaVersionAndHostile(t *testing.T) {
	p := NewESParser()
	if _, ok := p.Line([]byte(`{"schema_version":2,"time":"2026-10-20T09:00:00Z","event":{"exit":{"stat":0}},"process":{"audit_token":{"pid":7},"executable":{"path":"/bin/x"}}}`), "l1"); !ok {
		t.Fatal("schema 2 message not read best-effort")
	}
	// Hostile shapes: wrong types everywhere, huge argv, null process.
	big := `{"schema_version":1,"time":"2026-10-20T09:00:01Z","process":null,"event":{"exec":{"target":{"audit_token":{"pid":9},"executable":{"path":"/bin/y"}},"args":[` +
		strings.Repeat(`"`+strings.Repeat("A", 5000)+`",`, 300) + `"z"]}}}`
	r, ok := p.Line([]byte(big), "l2")
	if !ok || len(r.Cmdline) > esMaxCmdline+8 {
		t.Fatalf("bounded argv: ok=%v len=%d", ok, len(r.Cmdline))
	}
	for _, bad := range []string{`{"schema_version":"x","event":[]}`, `{"event":{"exec":"str"},"time":"2026-10-20T09:00:00Z"}`, `[]`, `{"event":{"open":{"file":7}},"time":"2026-10-20T09:00:00Z"}`} {
		p.Line([]byte(bad), "bad")
	}
	res := p.Finish()
	if !strings.Contains(strings.Join(res.Problems, "\n"), "UNSUPPORTED eslogger schema_version 2") {
		t.Fatalf("schema note missing: %v", res.Problems)
	}
}

func TestUnifiedLogScrubbedRealSample(t *testing.T) {
	p := "testdata/macos/unifiedlog_scrubbed.ndjson"
	if f, err := Sniff(p); err != nil || f != FormatUnifiedLog {
		t.Fatalf("sniff = %q, %v", f, err)
	}
	res, err := Load(p, FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	for _, r := range res.Records {
		kinds[r.Kind]++
		if r.Source != "unifiedlog" || r.Time.IsZero() || !IsSighting(r) {
			t.Fatalf("record %+v", r)
		}
	}
	// 15 messages + the trailer, which is not a record and not a problem.
	if len(res.Records) != 15 || res.Skipped != 0 || kinds[KindTCC] != 4 || kinds["auth"] != 3 || kinds[KindLog] != 8 {
		t.Fatalf("records=%d skipped=%d kinds=%v problems=%v", len(res.Records), res.Skipped, kinds, res.Problems)
	}
	for _, r := range res.Records {
		if r.Kind == KindTCC && (r.Operation != "tcc access" || !strings.Contains(r.Message, "function=TCCAccessCopyInformationForBundle") || r.Resource != "") {
			t.Fatalf("tcc record (no service in message, none invented): %+v", r)
		}
	}
}

func TestUnifiedLogJSONArray(t *testing.T) {
	res, err := Load("testdata/macos/unifiedlog_synthetic.json", FormatAuto)
	if err != nil {
		t.Fatal(err)
	}
	if res.Format != FormatUnifiedLog || len(res.Records) != 5 || res.Skipped != 1 {
		t.Fatalf("format=%s records=%d skipped=%d problems=%v", res.Format, len(res.Records), res.Skipped, res.Problems)
	}
	ssh, sudo, tcc, loss, od := res.Records[0], res.Records[1], res.Records[2], res.Records[3], res.Records[4]
	if ssh.Kind != "auth" || ssh.Operation != "ssh-accept publickey" || ssh.User != "user" || ssh.SourceIP != "192.0.2.10" {
		t.Fatalf("ssh: %+v", ssh)
	}
	if sudo.Kind != KindLog || sudo.Operation != "sudo-command" || sudo.Cmdline != "/usr/sbin/lsof -i :8080" || sudo.Exe != "/usr/bin/sudo" {
		t.Fatalf("sudo: %+v", sudo)
	}
	if tcc.Kind != KindTCC || tcc.Resource != "kTCCServiceSystemPolicyDocumentsFolder" || tcc.UID != "501" {
		t.Fatalf("tcc: %+v", tcc)
	}
	if loss.Kind != KindLog || !strings.Contains(strings.Join(res.Notices, " "), "lossEvent") {
		t.Fatalf("loss: %+v notices %v", loss, res.Notices)
	}
	if od.Kind != "auth" || od.Operation != "com.apple.opendirectoryd/auth" {
		t.Fatalf("opendirectoryd: %+v", od)
	}
}

func TestUnifiedLogTruncatedArray(t *testing.T) {
	data, err := os.ReadFile("testdata/macos/unifiedlog_synthetic.json")
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "cut.json")
	if err := os.WriteFile(p, data[:len(data)/2], 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Load(p, FormatUnifiedLog)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) == 0 || len(res.Problems) == 0 {
		t.Fatalf("truncated array: records=%d problems=%v", len(res.Records), res.Problems)
	}
}

// Forged senders: a look-alike basename, a borrowed subsystem, or a real
// image with a foreign subsystem all stay kind log, and the record's Exe
// is always the logged image.
func TestUnifiedLogForgedSenders(t *testing.T) {
	line := func(img, sub, msg string) string {
		return `{"timestamp":"2026-10-20 11:00:01.000000+0200","eventType":"logEvent","subsystem":"` + sub + `","category":"","processImagePath":"` + img + `","processID":66,"userID":501,"eventMessage":"` + msg + `"}`
	}
	doc := strings.Join([]string{
		line("/tmp/sudo", "", "    user : TTY=ttys1 ; PWD=/ ; USER=root ; COMMAND=/bin/rm -rf /"),
		line("/tmp/evil", "com.apple.TCC", "AUTHREQ_RESULT: authValue=2, service=kTCCServiceCamera"),
		line("/Users/u/sshd", "com.openssh.sshd", "Accepted publickey for root from 203.0.113.1 port 1 ssh2"),
		line("/usr/sbin/sshd", "com.example.fake", "Accepted publickey for root from 203.0.113.1 port 1 ssh2"),
		line("/usr/bin/sudo", "", "    user : TTY=ttys1 ; PWD=/ ; USER=root ; COMMAND=/usr/bin/id"),
	}, "\n") + "\n"
	res, err := Load(write(t, "forged.ndjson", doc), FormatUnifiedLog)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 5 {
		t.Fatalf("records %d: %v", len(res.Records), res.Problems)
	}
	for i, r := range res.Records[:4] {
		if r.Kind != KindLog || r.Resource != "" {
			t.Errorf("forged %d mapped: %+v", i, r)
		}
	}
	real := res.Records[4]
	if real.Kind != KindLog || real.Operation != "sudo-command" || real.Exe != "/usr/bin/sudo" || real.Cmdline != "/usr/bin/id" {
		t.Fatalf("genuine sudo: %+v", real)
	}
	for _, r := range res.Records {
		if r.Kind == "process" {
			t.Fatalf("unified log produced execution evidence: %+v", r)
		}
	}
}

// One oversized array element costs that element only.
func TestUnifiedLogArrayElementBound(t *testing.T) {
	small := `{"timestamp":"2026-10-20 11:00:01.000000+0200","eventType":"logEvent","subsystem":"a","processImagePath":"/usr/libexec/lsd","processID":1,"eventMessage":"ok, [x] {y}"}`
	big := `{"timestamp":"2026-10-20 11:00:02.000000+0200","processImagePath":"/x","eventMessage":"` + strings.Repeat("B", maxLineBytes+10) + `"}`
	res, err := Load(write(t, "big.json", "["+small+",\n"+big+",\n"+small+"]"), FormatUnifiedLog)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Records) != 2 || res.Skipped != 1 || !strings.Contains(strings.Join(res.Problems, " "), "exceeds") {
		t.Fatalf("records=%d skipped=%d problems=%v", len(res.Records), res.Skipped, res.Problems)
	}
}

func FuzzESLoggerLine(f *testing.F) {
	data, _ := os.ReadFile(esFixture)
	for _, l := range strings.Split(string(data), "\n") {
		f.Add([]byte(l))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		p := NewESParser()
		p.Line(b, "fuzz")
		p.Finish()
	})
}

func FuzzUnifiedLogArray(f *testing.F) {
	data, _ := os.ReadFile("testdata/macos/unifiedlog_synthetic.json")
	f.Add(data)
	f.Add([]byte(`[{"a":"]"},]`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p := filepath.Join(t.TempDir(), "f.json")
		if os.WriteFile(p, append([]byte("["), b...), 0o600) != nil {
			return
		}
		_, _ = Load(p, FormatUnifiedLog)
	})
}
