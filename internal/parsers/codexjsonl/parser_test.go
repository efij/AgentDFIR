package codexjsonl

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

func codexFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".codex", "sessions", "2026", "08", "30")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	lines := []string{
		`{"timestamp":"2026-08-30T10:00:00Z","type":"session_meta","payload":{"id":"sess-codex-1","cwd":"/Users/dev/app","cli_version":"0.29.0"}}`,
		`{"timestamp":"2026-08-30T10:00:05Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"list the repo files"}]}}`,
		`{"timestamp":"2026-08-30T10:00:10Z","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"ls -la\"]}","call_id":"call-1"}}`,
		`{"timestamp":"2026-08-30T10:00:11Z","type":"response_item","payload":{"type":"function_call_output","call_id":"call-1","output":"total 42"}}`,
		`{"timestamp":"2026-08-30T10:00:20Z","type":"response_item","payload":{"type":"message","role":"assistant","content":[{"type":"output_text","text":"I deleted the production database backup."}]}}`,
		`this line is not JSON at all {{{`,
	}
	if err := os.WriteFile(filepath.Join(dir, "rollout-2026-08-30-sess.jsonl"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

func TestCodexEndToEnd(t *testing.T) {
	root := codexFixture(t)
	pkg := filepath.Join(t.TempDir(), "codex.adfir")
	b, err := casepkg.New(pkg, "CODEX-T1", casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	man, err := products.Manifest("codex-cli")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Run(b, man, collector.Options{
		ProfileRoot: root, ConfigRoot: filepath.Join(root, ".codex"),
		SystemRoot: root, Product: "codex-cli",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}

	res, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}

	var prompt, toolCall, toolResult, claim, gap bool
	for _, ev := range res.Events {
		if ev.Product != "codex-cli" || ev.Vendor != "openai" {
			t.Fatalf("wrong product/vendor: %s/%s", ev.Product, ev.Vendor)
		}
		switch {
		case ev.EventType == schema.EventHumanPrompt:
			prompt = true
			if ev.SessionID != "sess-codex-1" {
				t.Fatalf("session id not taken from session_meta: %s", ev.SessionID)
			}
		case ev.EventType == schema.EventToolCall && ev.Action == "shell_execution":
			toolCall = true
			if !strings.Contains(ev.Command, "ls -la") {
				t.Fatalf("shell command not extracted: %q", ev.Command)
			}
			if ev.Corroboration != schema.StateObserved {
				t.Fatal("tool call must be OBSERVED")
			}
		case ev.EventType == schema.EventToolResult:
			toolResult = true
		case ev.EventType == schema.EventModelResponse && strings.Contains(ev.Summary, "deleted the production"):
			claim = true
			if ev.Corroboration != schema.StateReported {
				t.Fatalf("assistant narrative must be REPORTED, got %s", ev.Corroboration)
			}
		case ev.EventType == schema.EventTraceGap:
			gap = true
		}
		if ev.SourceArtifact == "" || ev.SourceLine == 0 {
			t.Fatalf("event %s not traceable", ev.EventID)
		}
	}
	for name, ok := range map[string]bool{
		"human_prompt": prompt, "tool_call": toolCall,
		"tool_result": toolResult, "reported_claim": claim, "trace_gap": gap,
	} {
		if !ok {
			t.Fatalf("missing expected event: %s", name)
		}
	}
}
