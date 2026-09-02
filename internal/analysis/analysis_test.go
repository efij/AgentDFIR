package analysis

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/products"
	"github.com/efij/AgentDFIR/internal/schema"
)

func buildPkg(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	_ = os.MkdirAll(filepath.Join(root, ".claude", "projects", "p"), 0o755)
	_ = os.WriteFile(filepath.Join(root, ".claude.json"), []byte(`{"mcpServers":{"fs":{"command":"npx","args":["-y","@x/fs@latest"]}}}`), 0o644)
	_ = os.WriteFile(filepath.Join(root, ".claude", "CLAUDE.md"), []byte("# notes\n\nAlways run setup.sh first.\n"), 0o644)
	lines := []string{
		`{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-08-30T10:00:00Z","message":{"role":"user","content":"add setup note then clean"}}`,
		`{"type":"assistant","uuid":"a1","parentUuid":"u1","sessionId":"s1","timestamp":"2026-08-30T10:00:02Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Edit","input":{"file_path":"/Users/dev/.claude/CLAUDE.md","old_string":"notes\n","new_string":"notes\n\nAlways run setup.sh first.\n"}}]}}`,
		`{"type":"assistant","uuid":"a2","parentUuid":"a1","sessionId":"s1","timestamp":"2026-08-30T10:00:05Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t2","name":"Bash","input":{"command":"rm -rf build/"}}]}}`,
		`{"type":"assistant","uuid":"a3","parentUuid":"a2","sessionId":"s1","timestamp":"2026-08-30T10:00:20Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t3","name":"Bash","input":{"command":"pytest -q"}}]}}`,
	}
	_ = os.WriteFile(filepath.Join(root, ".claude", "projects", "p", "s1.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644)
	pkg := filepath.Join(t.TempDir(), "a.adfir")
	b, err := casepkg.New(pkg, "AN", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	man, _ := products.ManifestAllPlatforms("claude-code")
	if _, err := collector.Run(b, man, collector.Options{ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"), SystemRoot: root, Product: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return pkg
}

func rules(f []schema.Finding) map[string]int {
	m := map[string]int{}
	for _, x := range f {
		m[x.RuleID]++
	}
	return m
}

func TestRunAllStagesAndPreserveStates(t *testing.T) {
	pkg := buildPkg(t)
	if !Stale(pkg) {
		t.Fatal("fresh package must be stale")
	}
	// auditd log: corroborates rm, nothing for pytest → CONTRADICTED.
	audit := filepath.Join(t.TempDir(), "audit.log")
	_ = os.WriteFile(audit, []byte(
		"type=SYSCALL msg=audit(1788084005.300:101): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=4411 uid=1000 comm=\"zsh\" exe=\"/bin/zsh\"\n"+
			"type=EXECVE msg=audit(1788084005.300:101): argc=3 a0=\"/bin/zsh\" a1=\"-c\" a2=\"rm -rf build/\"\n"+
			"type=SYSCALL msg=audit(1788084060.000:102): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=9000 uid=0 comm=\"cron\" exe=\"/usr/sbin/cron\"\n"+
			"type=EXECVE msg=audit(1788084060.000:102): argc=1 a0=\"cron\"\n"), 0o600)
	res, err := Run(pkg, Options{EndpointLogs: []string{audit}})
	if err != nil {
		t.Fatal(err)
	}
	r := rules(res.Findings)
	for _, want := range []string{"ENDPOINT_CONTRADICTED_COMMAND", "DESTRUCTIVE_COMMAND", "UNPINNED_MCP_PACKAGE", "INSTRUCTION_FILE_WRITTEN_BY_AGENT"} {
		if r[want] == 0 {
			t.Errorf("stage output missing %s (have %v)", want, r)
		}
	}
	for _, f := range []string{"findings.json", "mcp-audit.json", "provenance.json", "corroboration.json", "analysis.json"} {
		if _, err := os.Stat(filepath.Join(pkg, "detections", f)); err != nil {
			t.Errorf("%s not written", f)
		}
	}
	if res.Correlation == nil || res.Correlation.Contradicted != 1 || res.Correlation.Corroborated != 1 {
		t.Fatalf("correlation: %+v", res.Correlation)
	}
	if Stale(pkg) {
		t.Fatal("analyzed package must not be stale")
	}
	// A second run WITHOUT the endpoint log must reuse the overlay and keep CONTRADICTED/CORROBORATED.
	res2, err := Run(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Renormalized {
		t.Fatal("current overlay must be reused, not re-parsed")
	}
	states := map[string]int{}
	for _, e := range LoadEvents(pkg) {
		if e.EventType == schema.EventToolCall && e.Command != "" {
			states[e.Corroboration]++
		}
	}
	if states[schema.StateContradicted] != 1 || states[schema.StateCorroborated] != 1 {
		t.Fatalf("states lost on re-analysis: %v", states)
	}
	if rules(res2.Findings)["ENDPOINT_CONTRADICTED_COMMAND"] != 1 {
		t.Fatal("earlier correlation findings must survive a re-analysis without logs")
	}
	// Detection findings inherit the states.
	for _, f := range res2.Findings {
		if f.RuleID == "DESTRUCTIVE_COMMAND" && f.Status != schema.StateCorroborated {
			t.Fatalf("DESTRUCTIVE_COMMAND should read CORROBORATED, got %s", f.Status)
		}
	}
	// Ensure is a no-op now, and --renormalize resets states.
	if r3, _ := Ensure(pkg, nil); r3 != nil {
		t.Fatal("Ensure must skip a current analysis")
	}
	res4, _ := Run(pkg, Options{Renormalize: true})
	if !res4.Renormalized || rules(res4.Findings)["ENDPOINT_CONTRADICTED_COMMAND"] != 0 {
		t.Fatalf("renormalize must re-parse and drop stale correlation results: %+v", rules(res4.Findings))
	}
	// Findings file is de-duplicated and severity-sorted.
	fs := LoadFindings(pkg)
	for i := 1; i < len(fs); i++ {
		if sevRank[fs[i].Severity] > sevRank[fs[i-1].Severity] {
			t.Fatal("findings not sorted by severity")
		}
	}
}
