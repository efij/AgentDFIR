package mitigate

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/catalog"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

func write(t *testing.T, p, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func read(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestJSONRoundTripKeepsOrderNumbersAndUnknownKeys(t *testing.T) {
	in := "{\n  \"zeta\": 1.50,\n  \"alpha\": {\"b\": [1, 2e3, null], \"a\": true},\n  \"html\": \"<a&b>\",\n  \"n\": 12345678901234567890\n}\n"
	v, err := ParseJSON([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	out, err := MarshalJSON(v, DetectStyle([]byte(in)))
	if err != nil {
		t.Fatal(err)
	}
	s := string(out)
	for _, want := range []string{`"zeta": 1.50`, `2e3`, `"<a&b>"`, `12345678901234567890`} {
		if !strings.Contains(s, want) {
			t.Errorf("round trip lost %q:\n%s", want, s)
		}
	}
	if strings.Index(s, "zeta") > strings.Index(s, "alpha") {
		t.Errorf("key order changed:\n%s", s)
	}
}

func claudeEnv(t *testing.T) Env {
	home := t.TempDir()
	write(t, filepath.Join(home, ".claude", "settings.json"), "{\n  \"model\": \"opus\",\n  \"permissions\": {\n    \"allow\": [\"Bash(ls)\"]\n  },\n  \"theme\": \"dark\"\n}\n")
	return Env{Home: home, StateDir: filepath.Join(home, ".agentdfir", "mitigations"), GuardCommand: "/usr/local/bin/agentdfir guard log"}
}

func TestClaudePlanIsIdempotentAndPreservesTheFile(t *testing.T) {
	env := claudeEnv(t)
	pl, err := BuildPlan(env, Selection{Packs: DefaultPacks()})
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Changes) != 1 {
		t.Fatalf("want one change, got %d (%v)", len(pl.Changes), pl.Refused)
	}
	c := pl.Changes[0]
	after := string(c.After)
	for _, want := range []string{`"Read(~/.aws/**)"`, `"Write(~/.claude/projects/**/*.jsonl)"`, `"Bash(ls)"`, `"model": "opus"`, `"theme": "dark"`, `guard log`, `"matcher": "Bash|Write|Edit|MultiEdit"`} {
		if !strings.Contains(after, want) {
			t.Errorf("after is missing %s:\n%s", want, after)
		}
	}
	if strings.Contains(after, `"Write(~/.claude/projects/**)"`) {
		t.Error("log-protect must not deny the whole projects tree: Claude keeps memory files there")
	}
	again, err := Render(c.Kind, c.After, c.Items)
	if err != nil || !bytes.Equal(again, c.After) {
		t.Fatalf("second render changed the file:\n%s", again)
	}
	if !strings.Contains(c.Diff, "+") || !strings.Contains(c.Diff, "@@") {
		t.Errorf("diff looks empty:\n%s", c.Diff)
	}
}

func TestAskPackGoesToAskAndDenyOverrideMovesIt(t *testing.T) {
	env := claudeEnv(t)
	pl, _ := BuildPlan(env, Selection{Packs: []string{"outbound-upload"}})
	if !strings.Contains(string(pl.Changes[0].After), "\"ask\": [") {
		t.Fatalf("outbound-upload should render into permissions.ask:\n%s", pl.Changes[0].After)
	}
	pl, _ = BuildPlan(env, Selection{Packs: []string{"outbound-upload"}, Deny: map[string]bool{"outbound-upload": true}})
	if !strings.Contains(string(pl.Changes[0].After), "\"deny\": [") {
		t.Fatalf("--deny should move it to permissions.deny:\n%s", pl.Changes[0].After)
	}
}

func TestHookIsNotAddedTwice(t *testing.T) {
	env := claudeEnv(t)
	pl, _ := BuildPlan(env, Selection{Packs: []string{"log-protect"}})
	res := Apply(env, pl)
	if res[0].Err != nil {
		t.Fatal(res[0].Err)
	}
	// a different binary path later must not add a second guard hook
	env.GuardCommand = "/opt/other/agentdfir guard log"
	pl, _ = BuildPlan(env, Selection{Packs: []string{"log-protect"}})
	if len(pl.Changes) != 0 {
		t.Fatalf("second plan should be empty, got diff:\n%s", pl.Changes[0].Diff)
	}
}

func TestApplyStatusDriftRevert(t *testing.T) {
	env := claudeEnv(t)
	target := filepath.Join(env.Home, ".claude", "settings.json")
	orig := read(t, target)
	pl, _ := BuildPlan(env, Selection{Packs: DefaultPacks()})
	res := Apply(env, pl)
	if res[0].Err != nil || res[0].ID == "" {
		t.Fatalf("apply: %+v", res[0])
	}
	st, err := Status(env)
	if err != nil || len(st) != 1 || st[0].State != "in_place" {
		t.Fatalf("status after apply: %+v %v", st, err)
	}
	// an agent removes one deny rule: drift
	drifted := strings.Replace(read(t, target), `"Read(~/.aws/**)",`, "", 1)
	write(t, target, drifted)
	st, _ = Status(env)
	if st[0].State != "drifted" || len(st[0].Missing) != 1 {
		t.Fatalf("want drifted with one missing item, got %+v", st[0])
	}
	// revert refuses to throw the later edit away …
	if err := Revert(env, res[0].ID, false); err == nil {
		t.Fatal("revert over a changed file must refuse without --force")
	}
	// … and restores byte-exact with force
	if err := Revert(env, res[0].ID, true); err != nil {
		t.Fatal(err)
	}
	if read(t, target) != orig {
		t.Fatal("revert did not restore the original bytes")
	}
	st, _ = Status(env)
	if st[0].State != "reverted" {
		t.Fatalf("want reverted, got %s", st[0].State)
	}
	if _, err := Ledger(env); err != nil {
		t.Fatalf("ledger chain: %v", err)
	}
}

func TestRevertAllRemovesCreatedFiles(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	os.MkdirAll(filepath.Join(home, ".codex"), 0o700)
	env := Env{Home: home, StateDir: filepath.Join(home, "state")}
	pl, err := BuildPlan(env, Selection{Packs: []string{"secret-paths", "destructive"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Changes) != 2 {
		t.Fatalf("want claude + codex, got %d", len(pl.Changes))
	}
	for _, r := range Apply(env, pl) {
		if r.Err != nil {
			t.Fatal(r.Err)
		}
	}
	rules := read(t, filepath.Join(home, ".codex", "rules", "agentdfir.rules"))
	if !strings.Contains(rules, `decision = "forbidden"`) || !strings.Contains(rules, `decision = "prompt"`) {
		t.Fatalf("codex rules:\n%s", rules)
	}
	if !strings.Contains(rules, `["security", "dump-keychain"]`) {
		t.Fatalf("codex rule pattern not rendered:\n%s", rules)
	}
	n, errs := RevertAll(env, false)
	if n != 2 || len(errs) != 0 {
		t.Fatalf("revert-all: %d %v", n, errs)
	}
	for _, p := range []string{".claude/settings.json", ".codex/rules/agentdfir.rules"} {
		if _, err := os.Stat(filepath.Join(home, p)); !os.IsNotExist(err) {
			t.Errorf("%s should be gone after revert-all", p)
		}
	}
}

func TestSymlinkTargetIsRefused(t *testing.T) {
	home := t.TempDir()
	os.MkdirAll(filepath.Join(home, ".claude"), 0o700)
	real := filepath.Join(home, "elsewhere.json")
	write(t, real, "{}")
	if err := os.Symlink(real, filepath.Join(home, ".claude", "settings.json")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	pl, _ := BuildPlan(Env{Home: home, StateDir: filepath.Join(home, "s")}, Selection{Packs: []string{"secret-paths"}})
	if len(pl.Changes) != 0 || len(pl.Refused) != 1 {
		t.Fatalf("symlinked settings must be refused: %+v", pl)
	}
}

func TestMCPPinFromNpxCacheAndAutoApprove(t *testing.T) {
	home := t.TempDir()
	write(t, filepath.Join(home, ".npm", "_npx", "abc", "node_modules", "@21st-dev", "magic", "package.json"), `{"name":"@21st-dev/magic","version":"0.1.7"}`)
	cfg := `{
  "numStartups": 3,
  "mcpServers": {
    "magic": {"command": "npx", "args": ["-y", "@21st-dev/magic@latest"]},
    "pinned": {"command": "npx", "args": ["-y", "left-pad@1.3.0"]},
    "nocache": {"command": "npx", "args": ["some-unknown-pkg"]}
  },
  "projects": {"/Users/x/app": {"mcpServers": {"fetch": {"command": "uvx", "args": ["mcp-server-fetch"], "autoApprove": ["fetch"]}}}}
}
`
	write(t, filepath.Join(home, ".claude.json"), cfg)
	env := Env{Home: home, StateDir: filepath.Join(home, "s")}
	pl, err := BuildPlan(env, Selection{Fix: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(pl.Changes) != 1 {
		t.Fatalf("want one mcp change: %+v", pl)
	}
	after := string(pl.Changes[0].After)
	for _, want := range []string{`"@21st-dev/magic@0.1.7"`, `"left-pad@1.3.0"`, `"some-unknown-pkg"`, `"autoApprove": []`, `"numStartups": 3`} {
		if !strings.Contains(after, want) {
			t.Errorf("missing %s:\n%s", want, after)
		}
	}
	recs := MCPRecommendations(env)
	if len(recs) != 1 || !strings.Contains(recs[0], "some-unknown-pkg") {
		t.Errorf("uncached server should be a recommendation: %v", recs)
	}
}

func TestGuardLog(t *testing.T) {
	cases := []struct {
		tool, cmd, file string
		block           bool
	}{
		{"Bash", "rm -rf ~/.claude/projects", "", true},
		{"Bash", "rm ~/.claude/projects/-Users-x/abc.jsonl", "", true},
		{"Bash", "find ~/.codex/sessions -name '*.jsonl' -delete", "", true},
		{"Bash", ": > ~/.claude/history.jsonl", "", true},
		{"Bash", "echo x > /Users/me/.claude/projects/p/s.jsonl", "", true},
		{"Bash", "cd /tmp && rm -rf ~/.codex", "", true},
		{"Bash", "cat ~/.claude/projects/p/s.jsonl > /tmp/copy.jsonl", "", false},
		{"Bash", "rm -rf node_modules", "", false},
		{"Bash", "rm ~/.claude/projects/p/memory/old-note.md", "", false},
		{"Bash", "ls ~/.claude/projects", "", false},
		{"Bash", "go test ./... > /tmp/out.txt", "", false},
		{"Write", "", "/Users/me/.claude/projects/p/s.jsonl", true},
		{"Write", "", "/Users/me/.claude/projects/p/memory/MEMORY.md", false},
		{"Read", "", "/Users/me/.claude/projects/p/s.jsonl", false},
	}
	for _, c := range cases {
		var in GuardInput
		in.ToolName = c.tool
		in.ToolInput.Command = c.cmd
		in.ToolInput.FilePath = c.file
		if got := GuardLog(in).Block; got != c.block {
			t.Errorf("%s %q %q: block=%v want %v", c.tool, c.cmd, c.file, got, c.block)
		}
	}
	var out bytes.Buffer
	if code := RunGuard(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"rm -rf ~/.claude/projects"},"transcript_path":"/Users/me/.claude/projects/p/s.jsonl"}`), &out); code != 2 || out.Len() == 0 {
		t.Fatalf("RunGuard: code %d, stderr %q", code, out.String())
	}
	if code := RunGuard(strings.NewReader(`{"tool_name":"Bash","tool_input":{"command":"ls"},"transcript_path":"/Users/me/.claude/projects/p/s.jsonl"}`), &out); code != 0 {
		t.Fatal("transcript_path in the payload must not trigger the guard")
	}
	if code := RunGuard(strings.NewReader(`not json`), &out); code != 0 {
		t.Fatal("malformed input must be allowed, not block every tool call")
	}
}

func TestEveryPackRuleExists(t *testing.T) {
	known := map[string]bool{}
	for _, r := range catalog.Builtin {
		known[r.ID] = true
	}
	files, _ := filepath.Glob(filepath.Join("..", "..", "rules", "*.json"))
	for _, f := range files {
		var pack struct {
			Rules []struct {
				ID string `json:"id"`
			} `json:"rules"`
		}
		data, _ := os.ReadFile(f)
		json.Unmarshal(data, &pack)
		for _, r := range pack.Rules {
			known[r.ID] = true
		}
	}
	if len(known) < 100 {
		t.Fatalf("rule index looks incomplete (%d)", len(known))
	}
	check := func(where, id string) {
		if !known[id] {
			t.Errorf("%s names unknown rule %s", where, id)
		}
	}
	for _, p := range Packs {
		for _, r := range p.Rules {
			check("pack "+p.ID, r)
		}
	}
	for r := range fixRules {
		check("fixRules", r)
	}
	for r := range noneRules {
		check("noneRules", r)
	}
	for r := range manualSteps {
		check("manualSteps", r)
	}
	for _, r := range catalog.Builtin {
		if ModeOf(r.ID) == "" {
			t.Errorf("%s has no mode", r.ID)
		}
	}
}

func TestAssessSinceWindowAndVerdicts(t *testing.T) {
	fs := []schema.Finding{
		{RuleID: "SECRET_ACCESS", Severity: "HIGH", Timestamp: "2026-09-01T10:00:00Z"},
		{RuleID: "SECRET_ACCESS", Severity: "HIGH", Timestamp: "2026-09-20T10:00:00Z"},
		{RuleID: "SECRET_ACCESS", Severity: "HIGH", Timestamp: "2026-09-21T10:00:00Z", Title: "cleared"},
		{RuleID: "ORPHAN_AGENT", Severity: "HIGH"},
		{RuleID: "SHELL_EXECUTION", Severity: "INFO"},
	}
	st := []State{{State: "in_place", Record: Record{TS: "2026-09-10T00:00:00Z", Packs: []string{"secret-paths"}, Rules: []string{"SECRET_ACCESS"}}}}
	a := Assess(fs, func(f schema.Finding) bool { return f.Title == "cleared" }, st)
	var sec *RuleRow
	for i := range a.Rules {
		if a.Rules[i].Rule == "SECRET_ACCESS" {
			sec = &a.Rules[i]
		}
		if a.Rules[i].Rule == "SHELL_EXECUTION" {
			t.Error("building blocks must not appear")
		}
	}
	if sec == nil || sec.Total != 2 || sec.Excluded != 1 || sec.Since == nil || *sec.Since != 1 || sec.Mode != Prevent {
		t.Fatalf("SECRET_ACCESS row: %+v", sec)
	}
	for _, p := range a.Packs {
		if p.ID == "secret-paths" && (p.State != "in_place" || p.Findings != 2) {
			t.Fatalf("secret-paths pack row: %+v", p)
		}
	}
}

func TestUnifiedDiffShowsOnlyTheChange(t *testing.T) {
	var a, b strings.Builder
	for i := 0; i < 200; i++ {
		a.WriteString("line\n")
		b.WriteString("line\n")
		if i == 100 {
			b.WriteString("added\n")
		}
	}
	d := UnifiedDiff("f", []byte(a.String()), []byte(b.String()))
	if strings.Count(d, "\n") > 12 || !strings.Contains(d, "+added") {
		t.Fatalf("diff:\n%s", d)
	}
}
