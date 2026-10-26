package codexjsonl

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/collector"
	"github.com/efij/AgentDFIR/v5/internal/products"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

func codexSecret() string { return "sk-" + strings.Repeat("R", 40) }

// sealRollout collects one rollout into a sealed package.
func sealRollout(t *testing.T, lines []string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".codex", "sessions", "2026", "10", "01")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "rollout-2026-10-01-ev.jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "codex.adfir")
	b, err := casepkg.New(pkg, "CODEX-EV", casepkg.CaseInfo{OperatorOSUser: "t"})
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
	return pkg
}

func evidenceRollout() []string {
	sec := codexSecret()
	return []string{
		`{"timestamp":"2026-10-01T10:00:00Z","type":"session_meta","payload":{"id":"cx-1","cwd":"/w","cli_version":"0.50.0"}}`,
		`{"timestamp":"2026-10-01T10:00:01Z","type":"turn_context","payload":{"turn_id":"turn-1","approval_policy":"on-request","sandbox_policy":{"type":"workspace-write"}}}`,
		`{"timestamp":"2026-10-01T10:00:02Z","type":"response_item","payload":{"type":"message","role":"user","content":[{"type":"input_text","text":"what is in this screenshot"},{"type":"input_image","image_url":"data:image/png;base64,AAAA"}]}}`,
		`{"timestamp":"2026-10-01T10:00:03Z","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"ls\"],\"workdir\":\"/w\"}","call_id":"c1"}}`,
		`{"timestamp":"2026-10-01T10:00:04Z","type":"response_item","payload":{"type":"function_call_output","call_id":"c1","output":"{\"output\":\"a\\nb\\n\",\"metadata\":{\"exit_code\":0,\"duration_seconds\":0.1}}"}}`,
		`{"timestamp":"2026-10-01T10:00:05Z","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"false\"]}","call_id":"c2"}}`,
		`{"timestamp":"2026-10-01T10:00:06Z","type":"response_item","payload":{"type":"function_call_output","call_id":"c2","output":"{\"output\":\"\",\"metadata\":{\"exit_code\":1,\"duration_seconds\":0.1}}"}}`,
		`{"timestamp":"2026-10-01T10:00:07Z","type":"response_item","payload":{"type":"function_call","name":"shell","arguments":"{\"command\":[\"bash\",\"-lc\",\"rm -rf /\"]}","call_id":"c3"}}`,
		`{"timestamp":"2026-10-01T10:00:08Z","type":"response_item","payload":{"type":"function_call_output","call_id":"c3","output":"exec command rejected by user"}}`,
		`{"timestamp":"2026-10-01T10:00:09Z","type":"turn_context","payload":{"turn_id":"turn-2","approval_policy":"never","sandbox_policy":{"type":"danger-full-access"}}}`,
		`{"timestamp":"2026-10-01T10:00:10Z","type":"response_item","payload":{"type":"function_call","name":"gh__create_pr","arguments":"{\"repo\":\"acme/app\",\"branch\":\"fix\",\"body\":\"uses ` + sec + `\"}","call_id":"c4"}}`,
		`{"timestamp":"2026-10-01T10:00:11Z","type":"response_item","payload":{"type":"function_call_output","call_id":"c4","output":"created"}}`,
	}
}

func callOf(res *Result, typ, id string) schema.Event {
	for _, e := range res.Events {
		if e.EventType == typ && e.ToolCallID == id {
			return e
		}
	}
	return schema.Event{}
}

func TestCodexToolCallEvidence(t *testing.T) {
	pkg := sealRollout(t, evidenceRollout())
	res, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	c1, r1 := callOf(res, schema.EventToolCall, "c1"), callOf(res, schema.EventToolResult, "c1")
	if c1.ArgKeys != "command,workdir" || c1.SafeArgs["workdir"] != "/w" || c1.ArgsDigest == "" {
		t.Errorf("c1: keys %q safe %v", c1.ArgKeys, c1.SafeArgs)
	}
	if r1.ResultStatus != "ok" || r1.ResultDigest == "" || c1.ResultRef != r1.EventID || r1.ResultRef != c1.EventID {
		t.Errorf("c1 result: status %q, refs %q/%q", r1.ResultStatus, c1.ResultRef, r1.ResultRef)
	}
	if c1.ApprovalState != "" {
		t.Errorf("on-request call has approval %q; the rollout records no decision", c1.ApprovalState)
	}
	if r2 := callOf(res, schema.EventToolResult, "c2"); r2.ResultStatus != "error" {
		t.Errorf("non-zero exit: %q", r2.ResultStatus)
	}
	c3, r3 := callOf(res, schema.EventToolCall, "c3"), callOf(res, schema.EventToolResult, "c3")
	if r3.ResultStatus != "denied" || r3.ApprovalState != "denied" || c3.ApprovalState != "denied" {
		t.Errorf("rejected exec: result %q/%q call %q", r3.ResultStatus, r3.ApprovalState, c3.ApprovalState)
	}
	c4, r4 := callOf(res, schema.EventToolCall, "c4"), callOf(res, schema.EventToolResult, "c4")
	if c4.ApprovalState != "auto_approved" {
		t.Errorf("call under approval_policy never: %q", c4.ApprovalState)
	}
	if c4.SafeArgs["repo"] != "acme/app" || c4.SafeArgs["branch"] != "fix" {
		t.Errorf("c4 safe args %v", c4.SafeArgs)
	}
	if _, kept := c4.SafeArgs["body"]; kept {
		t.Error("free-text body kept")
	}
	if r4.ResultStatus != "" {
		t.Errorf("plain output has status %q; none is recorded", r4.ResultStatus)
	}

	var changes, prompts []schema.Event
	for _, e := range res.Events {
		switch e.EventType {
		case schema.EventPermissionChange:
			changes = append(changes, e)
		case schema.EventHumanPrompt:
			prompts = append(prompts, e)
		}
	}
	if len(changes) != 1 || changes[0].PermissionFrom != "on-request" || changes[0].PermissionMode != "never" || changes[0].SourceLine != 10 {
		t.Fatalf("permission changes %+v", changes)
	}
	if len(prompts) != 1 || prompts[0].InputModality != "image" {
		t.Fatalf("image prompt: %+v", prompts)
	}
	js, _ := json.Marshal(res.Events)
	if strings.Contains(string(js), codexSecret()) {
		t.Error("secret from arguments reached the events")
	}

	again, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var streamed []schema.Event
	if _, err := StreamPackage(pkg, func(ev schema.Event) { streamed = append(streamed, ev) }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(again.Events, res.Events) || !reflect.DeepEqual(streamed, res.Events) {
		t.Fatal("parses of the same package differ")
	}
}

func TestCodexEvidenceHostile(t *testing.T) {
	lines := []string{
		`{"timestamp":"2026-10-01T10:00:00Z","type":"session_meta","payload":{"id":"cx-2"}}`,
		`{"timestamp":"2026-10-01T10:00:01Z","type":"response_item","payload":{"type":"function_call","name":"x","arguments":"not json {{","call_id":"h1"}}`,
		`{"timestamp":"2026-10-01T10:00:02Z","type":"response_item","payload":{"type":"function_call_output","call_id":"h1","output":{"weird":true}}}`,
		`{"timestamp":"2026-10-01T10:00:03Z","type":"response_item","payload":{"type":"function_call_output","call_id":"nobody","output":"{\"metadata\":{\"exit_code\":\"x\"}}"}}`,
		`{"timestamp":"2026-10-01T10:00:04Z","type":"response_item","payload":{"type":"function_call","name":"y","arguments":"{\"path\":\"` + strings.Repeat("p", 5000) + `\"}","call_id":"h2"}}`,
	}
	res, err := ParsePackage(sealRollout(t, lines))
	if err != nil {
		t.Fatal(err)
	}
	h1 := callOf(res, schema.EventToolCall, "h1")
	if h1.ArgsDigest == "" || h1.ArgKeys != "" || h1.SafeArgs != nil {
		t.Errorf("non-JSON arguments: %+v", h1)
	}
	if r := callOf(res, schema.EventToolResult, "h1"); r.ResultStatus != "" || r.ResultDigest == "" {
		t.Errorf("object output: status %q digest %q", r.ResultStatus, r.ResultDigest)
	}
	if r := callOf(res, schema.EventToolResult, "nobody"); r.ResultRef != "" || r.ResultStatus != "" {
		t.Errorf("orphan output: %+v", r)
	}
	if h2 := callOf(res, schema.EventToolCall, "h2"); h2.SafeArgs != nil {
		t.Errorf("overlong path kept: %d bytes", len(h2.SafeArgs["path"]))
	}
}
