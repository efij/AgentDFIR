package claudejsonl

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

// evidenceSecret is credential-shaped, built at run time.
func evidenceSecret() string { return "ghp_" + strings.Repeat("Z", 36) }

// sealSessions collects session files into a sealed package and returns
// its path.
func sealSessions(t *testing.T, sessions map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, content := range sessions {
		p := filepath.Join(root, ".claude", "projects", "-p", name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg := filepath.Join(t.TempDir(), "c.adfir")
	b, err := casepkg.New(pkg, "EVID", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	man, _ := products.Manifest("claude-code")
	if _, err := collector.Run(b, man, collector.Options{
		ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"),
		SystemRoot: root, Product: "claude-code",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return pkg
}

func evidenceTranscript() string {
	sec := evidenceSecret()
	lines := []string{
		// 1: prompt with an image, mode default.
		`{"type":"user","sessionId":"s1","uuid":"u1","permissionMode":"default","timestamp":"2026-10-01T10:00:00Z","message":{"role":"user","content":[{"type":"text","text":"fix it"},{"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0KGgo="}}]}}`,
		// 2: two calls, no mode on the assistant line.
		`{"type":"assistant","sessionId":"s1","uuid":"a1","parentUuid":"u1","timestamp":"2026-10-01T10:00:01Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls","description":"list"}},{"type":"tool_use","id":"t2","name":"Write","input":{"file_path":"/p/a.go","content":"token = ` + sec + `"}}]}}`,
		// 3: mode switches to acceptEdits; t1 result ok.
		`{"type":"user","sessionId":"s1","uuid":"u2","parentUuid":"a1","permissionMode":"acceptEdits","timestamp":"2026-10-01T10:00:02Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"a.go"}]}}`,
		// 4: t2 rejected by the user.
		`{"type":"user","sessionId":"s1","uuid":"u3","parentUuid":"u2","timestamp":"2026-10-01T10:00:03Z","toolUseResult":"User rejected tool use","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t2","is_error":true,"content":"The user doesn't want to proceed with this tool use. The tool use was rejected (eg. if it was a file edit, the new_string was NOT written to the file). STOP what you are doing and wait for the user to tell you how to proceed."}]}}`,
		// 5: an edit under acceptEdits.
		`{"type":"assistant","sessionId":"s1","uuid":"a2","parentUuid":"u3","timestamp":"2026-10-01T10:00:04Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t3","name":"Edit","input":{"file_path":"/p/b.go","old_string":"x","new_string":"` + sec + `"}}]}}`,
		// 6: t3 failed.
		`{"type":"user","sessionId":"s1","uuid":"u4","parentUuid":"a2","timestamp":"2026-10-01T10:00:05Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t3","is_error":true,"content":"File does not exist."}]}}`,
		// 7: an MCP call that never got a result.
		`{"type":"assistant","sessionId":"s1","uuid":"a3","parentUuid":"u4","timestamp":"2026-10-01T10:00:06Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t4","name":"mcp__web__fetch","input":{"url":"https://h.example/items?key=` + sec + `","method":"get"}}]}}`,
		// 8: a subagent line in the audit dialect names its launching call.
		`{"type":"assistant","session_id":"s1","uuid":"a4","parent_tool_use_id":"task-9","timestamp":"2026-10-01T10:00:07Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t5","name":"Read","input":{"file_path":"/p/c.go"}}]}}`,
		// 9: a file whose content is a refusal sentence, read without is_error.
		`{"type":"user","sessionId":"s1","uuid":"u5","parentUuid":"a4","timestamp":"2026-10-01T10:00:08Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t5","content":"The user doesn't want to proceed with this tool use."}]}}`,
	}
	return strings.Join(lines, "\n") + "\n"
}

func byCall(res *Result, typ, id string) schema.Event {
	for _, e := range res.Events {
		if e.EventType == typ && e.ToolCallID == id {
			return e
		}
	}
	return schema.Event{}
}

func TestToolCallEvidenceFields(t *testing.T) {
	pkg := sealSessions(t, map[string]string{"s1.jsonl": evidenceTranscript()})
	res, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}

	c1, r1 := byCall(res, schema.EventToolCall, "t1"), byCall(res, schema.EventToolResult, "t1")
	if c1.ArgsDigest == "" || c1.ArgKeys != "command,description" || c1.SafeArgs != nil {
		t.Errorf("t1 call: digest %q keys %q safe %v", c1.ArgsDigest, c1.ArgKeys, c1.SafeArgs)
	}
	if c1.ResultRef != r1.EventID || r1.ResultRef != c1.EventID {
		t.Errorf("t1 pairing: call→%q (result %s), result→%q (call %s)", c1.ResultRef, r1.EventID, r1.ResultRef, c1.EventID)
	}
	if r1.ResultStatus != "ok" || r1.ResultDigest == "" || r1.ApprovalState != "" {
		t.Errorf("t1 result: status %q digest %q approval %q", r1.ResultStatus, r1.ResultDigest, r1.ApprovalState)
	}
	if c1.ApprovalState != "" {
		t.Errorf("default-mode Bash call has approval %q; nothing recorded one", c1.ApprovalState)
	}

	c2, r2 := byCall(res, schema.EventToolCall, "t2"), byCall(res, schema.EventToolResult, "t2")
	if c2.SafeArgs["file_path"] != "/p/a.go" || c2.ArgKeys != "content,file_path" {
		t.Errorf("t2 call: safe %v keys %q", c2.SafeArgs, c2.ArgKeys)
	}
	if r2.ResultStatus != "denied" || r2.ApprovalState != "denied" || c2.ApprovalState != "denied" {
		t.Errorf("t2 rejection: result %q/%q, call %q", r2.ResultStatus, r2.ApprovalState, c2.ApprovalState)
	}

	c3, r3 := byCall(res, schema.EventToolCall, "t3"), byCall(res, schema.EventToolResult, "t3")
	if c3.ApprovalState != "auto_approved" {
		t.Errorf("Edit under acceptEdits: approval %q", c3.ApprovalState)
	}
	if r3.ResultStatus != "error" || r3.ApprovalState != "" {
		t.Errorf("t3 failure: status %q approval %q", r3.ResultStatus, r3.ApprovalState)
	}

	c4 := byCall(res, schema.EventToolCall, "t4")
	if c4.SafeArgs["url"] != "https://h.example" || c4.SafeArgs["method"] != "GET" {
		t.Errorf("t4 safe args %v", c4.SafeArgs)
	}
	if c4.ResultRef != "" || c4.ResultStatus != "" {
		t.Errorf("unanswered call: ref %q status %q", c4.ResultRef, c4.ResultStatus)
	}

	c5, r5 := byCall(res, schema.EventToolCall, "t5"), byCall(res, schema.EventToolResult, "t5")
	if c5.ParentToolCallID != "task-9" {
		t.Errorf("subagent call parent %q", c5.ParentToolCallID)
	}
	if r5.ResultStatus != "ok" || r5.ApprovalState != "" {
		t.Errorf("refusal text without is_error read as %q/%q", r5.ResultStatus, r5.ApprovalState)
	}

	var changes []schema.Event
	var prompt schema.Event
	for _, e := range res.Events {
		switch e.EventType {
		case schema.EventPermissionChange:
			changes = append(changes, e)
		case schema.EventHumanPrompt:
			if prompt.EventID == "" {
				prompt = e
			}
		}
	}
	if len(changes) != 1 || changes[0].PermissionFrom != "default" || changes[0].PermissionMode != "acceptEdits" || changes[0].SourceLine != 3 {
		t.Fatalf("permission changes: %+v", changes)
	}
	if prompt.InputModality != "image" {
		t.Errorf("prompt with an image block: modality %q", prompt.InputModality)
	}
	if c1.InputModality != "" || r1.InputModality != "" {
		t.Error("text-only events carry a modality")
	}

	js, _ := json.Marshal(res.Events)
	for _, leak := range []string{evidenceSecret(), "key=", "/items", "token ="} {
		if strings.Contains(string(js), leak) {
			t.Errorf("events carry %q", leak)
		}
	}
}

func TestToolCallEvidenceDeterministic(t *testing.T) {
	pkg := sealSessions(t, map[string]string{"s1.jsonl": evidenceTranscript()})
	a, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	ja, _ := json.Marshal(a.Events)
	jb, _ := json.Marshal(b.Events)
	if string(ja) != string(jb) {
		t.Fatal("two parses of the same package differ")
	}
	var streamed []schema.Event
	if _, err := StreamPackage(pkg, func(ev schema.Event) { streamed = append(streamed, ev) }); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(streamed, a.Events) {
		t.Fatal("streamed events differ from the accumulated parse")
	}
	for i, e := range a.Events {
		if e.Sequence != i {
			t.Fatalf("event %d has sequence %d: pairing reordered events", i, e.Sequence)
		}
	}
}

func TestToolCallEvidenceMissing(t *testing.T) {
	// A transcript with no modes, no results and empty inputs leaves every
	// structured field empty.
	content := `{"type":"assistant","sessionId":"s2","timestamp":"2026-10-01T10:00:00Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"x1","name":"Bash"}]}}` + "\n"
	pkg := sealSessions(t, map[string]string{"s2.jsonl": content})
	res, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	c := byCall(res, schema.EventToolCall, "x1")
	if c.EventID == "" {
		t.Fatal("call not parsed")
	}
	if c.ArgsDigest != "" || c.ArgKeys != "" || c.SafeArgs != nil || c.ResultRef != "" || c.ResultStatus != "" ||
		c.ApprovalState != "" || c.ParentToolCallID != "" || c.InputModality != "" || c.PermissionFrom != "" {
		t.Fatalf("missing evidence produced fields: %+v", c)
	}
}

func TestToolCallEvidenceHostile(t *testing.T) {
	var b strings.Builder
	b.WriteString(`{"type":"assistant","sessionId":"s3","timestamp":"2026-10-01T10:00:00Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"h1","name":"mcp__x__y","input":{`)
	for i := 0; i < 2000; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(`"k` + strings.Repeat("q", 10) + string(rune('a'+i%26)) + itoa(i) + `":"v"`)
	}
	b.WriteString(`,"path":"/bad` + "\xff" + `","blob":"` + strings.Repeat("z", 1<<20) + `"}}]}}` + "\n")
	// Deep nesting inside the input.
	b.WriteString(`{"type":"assistant","sessionId":"s3","timestamp":"2026-10-01T10:00:01Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"h2","name":"Bash","input":{"a":` +
		strings.Repeat("[", 5000) + strings.Repeat("]", 5000) + `}}]}}` + "\n")
	pkg := sealSessions(t, map[string]string{"s3.jsonl": b.String()})
	res, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	h1 := byCall(res, schema.EventToolCall, "h1")
	if h1.ArgsDigest == "" || len(h1.ArgKeys) > 70*65 || len(h1.SafeArgs) > 16 {
		t.Fatalf("huge input not bounded: keys %d bytes, %d safe", len(h1.ArgKeys), len(h1.SafeArgs))
	}
	if h1.SafeArgs["path"] != "/bad�" {
		t.Fatalf("invalid UTF-8 path %q", h1.SafeArgs["path"])
	}
	if h2 := byCall(res, schema.EventToolCall, "h2"); h2.EventID != "" && h2.ArgKeys != "a" {
		t.Fatalf("deeply nested input keys %q", h2.ArgKeys)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var d []byte
	for ; i > 0; i /= 10 {
		d = append([]byte{byte('0' + i%10)}, d...)
	}
	return string(d)
}
