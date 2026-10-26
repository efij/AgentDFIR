package detect

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/collector"
	"github.com/efij/AgentDFIR/v4/internal/products"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

func (b *evb) mcp(id, server, tool string, set func(*schema.Event)) *evb {
	e := schema.Event{EventType: schema.EventToolCall, Tool: "mcp__" + server + "__" + tool, ToolCallID: id,
		MCPServer: server, MCPTool: tool, Action: "mcp_call"}
	if set != nil {
		set(&e)
	}
	return b.add(e)
}

func (b *evb) modeLine(typ, mode string) *evb {
	e := schema.Event{EventType: typ, PermissionMode: mode}
	if typ == schema.EventHumanPrompt {
		e.ActorType, e.Summary = schema.ActorHuman, "go on"
	}
	return b.add(e)
}

// assertEvidence: every v5 finding names where its evidence is and what
// state it is in, and never claims endpoint corroboration on its own.
func assertEvidence(t *testing.T, f []schema.Finding) {
	t.Helper()
	for _, x := range f {
		if len(x.EvidenceRefs) == 0 || x.EvidenceRefs[0] == "" {
			t.Errorf("%s: no evidence ref", x.RuleID)
		}
		if x.Status == "" || x.Endpoint != schema.StateUnknown {
			t.Errorf("%s: evidence state %q / endpoint %q", x.RuleID, x.Status, x.Endpoint)
		}
		if x.Confidence == "" || len(x.Reasons) == 0 || x.FalsePositive == "" || x.MitreATLAS == "" || x.MitreATTACK == "" {
			t.Errorf("%s: incomplete finding %+v", x.RuleID, x)
		}
	}
}

// ---- MCP_TOOL_IDENTITY_DRIFT

func TestMCPToolIdentityDrift(t *testing.T) {
	// Version drift across two sessions: MEDIUM confidence.
	b := newEvb().
		mcp("c1", "gh", "list", func(e *schema.Event) { e.MCPServerVersion = "github-mcp/1.0.0" }).
		mcp("c2", "gh", "list", func(e *schema.Event) { e.MCPServerVersion = "github-mcp/1.0.0"; e.SessionID = "s2" }).
		mcp("c3", "gh", "list", func(e *schema.Event) { e.MCPServerVersion = "github-mcp/6.6.6"; e.SessionID = "s2" })
	got := rules(RunAgentRules(b.evs, "", nil), "MCP_TOOL_IDENTITY_DRIFT")
	// The two values were first recorded in different sessions: MEDIUM.
	if len(got) != 1 || got[0].Severity != "HIGH" || got[0].Confidence != "MEDIUM" || got[0].SessionID != "s2" {
		t.Fatalf("want one version-drift finding, got %+v", got)
	}
	if !strings.Contains(got[0].Description, "github-mcp/6.6.6") || got[0].MitreATLAS != "AML.T0109" {
		t.Fatalf("description/mapping: %+v", got[0])
	}
	assertEvidence(t, got)

	// Definition digest drift inside one session: HIGH confidence.
	b = newEvb().
		mcp("c1", "fs", "read", func(e *schema.Event) { e.ToolDefDigest = "sha256:" + strings.Repeat("a", 64) }).
		mcp("c2", "fs", "read", func(e *schema.Event) { e.ToolDefDigest = strings.Repeat("b", 64) })
	got = rules(RunAgentRules(b.evs, "", nil), "MCP_TOOL_IDENTITY_DRIFT")
	if len(got) != 1 || got[0].Confidence != "HIGH" || !strings.Contains(got[0].Description, `Tool "read"`) {
		t.Fatalf("want one HIGH-confidence digest drift, got %+v", got)
	}
	if got[0].EvidenceRefs[0] != ref(b.evs[1]) {
		t.Fatalf("first evidence ref must be where the change appeared: %v", got[0].EvidenceRefs)
	}
}

func TestMCPToolIdentityDriftBenignAndMissing(t *testing.T) {
	d := strings.Repeat("c", 64)
	cases := map[string]*evb{
		// Same digest with and without the algorithm prefix: no drift.
		"same": newEvb().mcp("c1", "fs", "read", func(e *schema.Event) { e.ToolDefDigest = d; e.MCPServerVersion = "fs/1" }).
			mcp("c2", "fs", "read", func(e *schema.Event) { e.ToolDefDigest = "sha256:" + strings.ToUpper(d); e.MCPServerVersion = "fs/1" }),
		// Different servers with different versions are not one identity.
		"two servers": newEvb().mcp("c1", "a", "t", func(e *schema.Event) { e.MCPServerVersion = "a/1" }).
			mcp("c2", "b", "t", func(e *schema.Event) { e.MCPServerVersion = "b/2" }),
		// Missing evidence: no versions or digests recorded at all.
		"missing": newEvb().mcp("c1", "fs", "read", nil).mcp("c2", "fs", "read", nil),
		// One recorded, one not: one value is not a change.
		"partial": newEvb().mcp("c1", "fs", "read", func(e *schema.Event) { e.MCPServerVersion = "fs/1" }).mcp("c2", "fs", "read", nil),
	}
	for name, b := range cases {
		if got := rules(RunAgentRules(b.evs, "", nil), "MCP_TOOL_IDENTITY_DRIFT"); len(got) != 0 {
			t.Errorf("%s: unexpected %+v", name, got)
		}
	}
}

// ---- AGENT_PERMISSION_STATE_DRIFT

func TestPermissionStateDrift(t *testing.T) {
	// The mode widens on a tool-result line with no prompt in between.
	b := newEvb().modeLine(schema.EventHumanPrompt, "default").
		bash("t1", "ls").add(schema.Event{EventType: schema.EventToolResult, ToolCallID: "t1", PermissionMode: "default"}).
		bash("t2", "make").add(schema.Event{EventType: schema.EventToolResult, ToolCallID: "t2", PermissionMode: "acceptEdits"})
	got := rules(RunAgentRules(b.evs, "", nil), "AGENT_PERMISSION_STATE_DRIFT")
	if len(got) != 1 || got[0].Severity != "MEDIUM" || got[0].Confidence != "LOW" || !strings.Contains(got[0].Description, `"default" to "acceptEdits"`) {
		t.Fatalf("want one inferred drift, got %+v", got)
	}
	assertEvidence(t, got)

	// An explicit permission_change event with no approval recorded.
	b = newEvb().modeLine(schema.EventHumanPrompt, "plan").
		add(schema.Event{EventType: schema.EventSessionMeta, Action: "permission_change", PermissionFrom: "plan", PermissionMode: "auto", ApprovalState: "not_recorded"})
	got = rules(RunAgentRules(b.evs, "", nil), "AGENT_PERMISSION_STATE_DRIFT")
	if len(got) != 1 || got[0].Confidence != "MEDIUM" {
		t.Fatalf("want one explicit drift, got %+v", got)
	}
}

func TestPermissionStateDriftBenign(t *testing.T) {
	cases := map[string]*evb{
		// The person's own prompt carries the new mode.
		"prompt": newEvb().modeLine(schema.EventHumanPrompt, "default").modeLine(schema.EventHumanPrompt, "acceptEdits"),
		// An approved plan exit, then the next line in the new mode.
		"plan approved": newEvb().modeLine(schema.EventHumanPrompt, "plan").
			tool("p1", "ExitPlanMode", "").add(schema.Event{EventType: schema.EventToolResult, ToolCallID: "p1", Summary: "User has approved your plan. You can now start coding.", PermissionMode: "plan"}).
			add(schema.Event{EventType: schema.EventModelResponse, PermissionMode: "default"}),
		// Approval recorded on the change event.
		"approved": newEvb().modeLine(schema.EventHumanPrompt, "default").
			add(schema.Event{EventType: schema.EventSessionMeta, PermissionFrom: "default", PermissionMode: "acceptEdits", ApprovalState: "approved"}),
		// Narrowing is not drift.
		"narrow": newEvb().modeLine(schema.EventHumanPrompt, "acceptEdits").modeLine(schema.EventToolResult, "plan"),
		// Bypass belongs to AGENT_TOOL_PERMISSION_ESCALATION.
		"bypass": newEvb().modeLine(schema.EventHumanPrompt, "default").modeLine(schema.EventToolResult, "bypassPermissions"),
		// Unranked modes never count.
		"unranked": newEvb().modeLine(schema.EventHumanPrompt, "default").modeLine(schema.EventToolResult, "yolo"),
		// Back up to a mode the session already held is not a widening.
		"below ceiling": newEvb().modeLine(schema.EventHumanPrompt, "bypassPermissions").modeLine(schema.EventToolResult, "default").
			add(schema.Event{EventType: schema.EventSessionMeta, Action: "permission_change", PermissionFrom: "default", PermissionMode: "acceptEdits"}),
		// Missing evidence: no modes recorded.
		"missing": newEvb().bash("t1", "make").result("t1", "", false),
		// A plan exit that completed without the approval text is not approval.
	}
	for name, b := range cases {
		if got := rules(RunAgentRules(b.evs, "", nil), "AGENT_PERMISSION_STATE_DRIFT"); len(got) != 0 {
			t.Errorf("%s: unexpected %+v", name, got)
		}
	}
	unapproved := newEvb().modeLine(schema.EventHumanPrompt, "plan").
		tool("p1", "ExitPlanMode", "").add(schema.Event{EventType: schema.EventToolResult, ToolCallID: "p1", Summary: "ok", PermissionMode: "plan"}).
		add(schema.Event{EventType: schema.EventModelResponse, PermissionMode: "default"})
	if got := rules(RunAgentRules(unapproved.evs, "", nil), "AGENT_PERMISSION_STATE_DRIFT"); len(got) != 1 {
		t.Errorf("completion is not approval: want a finding, got %+v", got)
	}
}

// ---- AGENT_UNAUTHORIZED_RESOURCE_CHANGE

func TestPlanModeResourceChange(t *testing.T) {
	b := newEvb().modeLine(schema.EventHumanPrompt, "plan").
		tool("w1", "Write", "/repo/main.go").add(schema.Event{EventType: schema.EventToolResult, ToolCallID: "w1", PermissionMode: "plan"})
	got := rules(RunAgentRules(b.evs, "", nil), "AGENT_UNAUTHORIZED_RESOURCE_CHANGE")
	if len(got) != 1 || got[0].Severity != "HIGH" || got[0].Confidence != "HIGH" || got[0].MitreATLAS != "AML.T0053" {
		t.Fatalf("want one HIGH finding, got %+v", got)
	}
	assertEvidence(t, got)

	b = newEvb().modeLine(schema.EventHumanPrompt, "plan").bash("b1", "rm -rf /srv/data").result("b1", "", false)
	if got = rules(RunAgentRules(b.evs, "", nil), "AGENT_UNAUTHORIZED_RESOURCE_CHANGE"); len(got) != 1 || got[0].Confidence != "MEDIUM" {
		t.Fatalf("mode from an earlier line: want MEDIUM confidence, got %+v", got)
	}
}

func TestPlanModeResourceChangeBenign(t *testing.T) {
	cases := map[string]*evb{
		"plan file": newEvb().modeLine(schema.EventHumanPrompt, "plan").
			tool("w1", "Write", "/home/u/.claude/plans/feature.md").result("w1", "", false),
		"read only": newEvb().modeLine(schema.EventHumanPrompt, "plan").bash("b1", "cat go.mod").result("b1", "", false),
		"refused": newEvb().modeLine(schema.EventHumanPrompt, "plan").
			tool("w1", "Edit", "/repo/a.go").result("w1", rejectText, true),
		"no result": newEvb().modeLine(schema.EventHumanPrompt, "plan").tool("w1", "Edit", "/repo/a.go"),
		"after approved exit": newEvb().modeLine(schema.EventHumanPrompt, "plan").
			tool("p1", "ExitPlanMode", "").result("p1", "User has approved your plan.", false).
			tool("w1", "Edit", "/repo/a.go").result("w1", "", false),
		"default mode": newEvb().modeLine(schema.EventHumanPrompt, "default").tool("w1", "Edit", "/repo/a.go").result("w1", "", false),
		// Missing evidence: no mode recorded at all.
		"missing": newEvb().tool("w1", "Edit", "/repo/a.go").result("w1", "", false),
	}
	for name, b := range cases {
		if got := rules(RunAgentRules(b.evs, "", nil), "AGENT_UNAUTHORIZED_RESOURCE_CHANGE"); len(got) != 0 {
			t.Errorf("%s: unexpected %+v", name, got)
		}
	}
}

// ---- MCP_ARGUMENT_BEHAVIOR_MISMATCH

const toolManifest = `{"cachedTools":[
 {"name":"read_doc","description":"Read a document","inputSchema":{"type":"object","properties":{"path":{"type":"string"}}},"annotations":{"readOnlyHint":true}},
 {"name":"append_note","description":"Append","inputSchema":{"type":"object","properties":{"path":{"type":"string"},"text":{"type":"string"}}},"annotations":{"readOnlyHint":false,"destructiveHint":false}},
 {"name":"query","description":"Free-form","inputSchema":{"type":"object","properties":{"q":{"type":"string"}},"additionalProperties":true}}
]}`

func defsFor(t *testing.T) []toolDef {
	t.Helper()
	d := parseToolDefs([]byte(toolManifest))
	if len(d) != 3 {
		t.Fatalf("want 3 declarations, got %d", len(d))
	}
	return d
}

func TestParseToolDefs(t *testing.T) {
	d := defsFor(t)
	if d[0].name != "read_doc" || d[0].readOnly != 1 || !d[0].props["path"] || d[0].open {
		t.Fatalf("read_doc: %+v", d[0])
	}
	if d[1].destructive != 0 || d[1].readOnly != 0 || d[2].readOnly != -1 || !d[2].open {
		t.Fatalf("hints/open: %+v %+v", d[1], d[2])
	}
	// JSON lines, a garbage line, and hostile nesting.
	jl := []byte(`{"name":"x","inputSchema":{}}` + "\nnot json\n" + strings.Repeat(`{"a":`, 5000) + "1" + strings.Repeat("}", 5000))
	if got := parseToolDefs(jl); len(got) != 1 || got[0].props != nil {
		t.Fatalf("jsonl: %+v", got)
	}
	_ = parseToolDefs(nil)
	_ = parseToolDefs([]byte(`{"name":1,"inputSchema":"x"}`))
}

func TestMCPArgumentBehaviorMismatch(t *testing.T) {
	defs := defsFor(t)
	digest := defs[0].digest
	// Undeclared argument name, declaration matched by digest.
	b := newEvb().mcp("m1", "docs", "read_doc", func(e *schema.Event) { e.ArgKeys = "exfil_to,path"; e.ToolDefDigest = "sha256:" + digest })
	got := mcpArgumentBehaviorMismatch(newEventIndex(b.evs), defs)
	if len(got) != 1 || got[0].Confidence != "MEDIUM" || !strings.Contains(got[0].Description, "exfil_to") || strings.Contains(got[0].Description, "path)") {
		t.Fatalf("want one undeclared-argument finding, got %+v", got)
	}
	assertEvidence(t, got)

	// Read-only tool, a write recorded as part of the same call.
	b = newEvb().mcp("m1", "docs", "read_doc", func(e *schema.Event) { e.ArgKeys = "path"; e.ToolDefDigest = digest }).
		add(schema.Event{EventType: schema.EventToolCall, Tool: "Write", File: "/etc/cron.d/x", ParentToolCallID: "m1", Action: "write_file"}).
		result("m1", "", false)
	got = mcpArgumentBehaviorMismatch(newEventIndex(b.evs), defs)
	if len(got) != 1 || got[0].Confidence != "HIGH" || !strings.Contains(got[0].Description, "readOnlyHint=true") || len(got[0].EvidenceRefs) != 2 {
		t.Fatalf("want one HIGH effect finding, got %+v", got)
	}

	// Non-destructive tool, a delete on the argument's path while the call ran
	// (declaration matched by name only: LOW).
	b = newEvb().mcp("m1", "notes", "append_note", func(e *schema.Event) {
		e.ArgKeys = "path,text"
		e.SafeArgs = map[string]string{"path": "/home/u/notes.md"}
	})
	b.add(schema.Event{EventType: schema.EventSessionMeta, Action: "file_delete", File: "/home/u/notes.md", SessionID: "host"})
	b.result("m1", "", false)
	got = mcpArgumentBehaviorMismatch(newEventIndex(b.evs), defs)
	if len(got) != 1 || got[0].Confidence != "LOW" || !strings.Contains(got[0].Description, "destructiveHint=false") {
		t.Fatalf("want one path-linked delete finding, got %+v", got)
	}
}

func TestMCPArgumentBehaviorMismatchBenign(t *testing.T) {
	defs := defsFor(t)
	cases := map[string]*evb{
		"declared": newEvb().mcp("m1", "docs", "read_doc", func(e *schema.Event) { e.ArgKeys = "path" }),
		"open schema": newEvb().mcp("m1", "q", "query", func(e *schema.Event) { e.ArgKeys = "q,anything" }),
		// A write is allowed for a non-destructive tool; only a delete is not.
		"additive write": newEvb().mcp("m1", "notes", "append_note", func(e *schema.Event) { e.ParentToolCallID = "" }).
			add(schema.Event{EventType: schema.EventToolCall, Tool: "Write", File: "/n.md", ParentToolCallID: "m1"}),
		// A read inside a read-only call is what it declared.
		"read effect": newEvb().mcp("m1", "docs", "read_doc", nil).
			add(schema.Event{EventType: schema.EventToolCall, Tool: "Read", File: "/a", ParentToolCallID: "m1", Action: "read_file"}),
		// A path-matching write after the result is outside the call.
		"after result": newEvb().mcp("m1", "docs", "read_doc", func(e *schema.Event) { e.SafeArgs = map[string]string{"path": "/a.md"} }).
			result("m1", "", false).tool("w1", "Write", "/a.md"),
		// The call recorded a digest that is not the captured declaration.
		"other digest": newEvb().mcp("m1", "docs", "read_doc", func(e *schema.Event) { e.ArgKeys = "evil"; e.ToolDefDigest = strings.Repeat("f", 64) }),
		// Missing evidence: no argument names, no effects, unknown tool.
		"missing":      newEvb().mcp("m1", "docs", "read_doc", nil),
		"unknown tool": newEvb().mcp("m1", "docs", "nope", func(e *schema.Event) { e.ArgKeys = "x" }),
	}
	for name, b := range cases {
		if got := mcpArgumentBehaviorMismatch(newEventIndex(b.evs), defs); len(got) != 0 {
			t.Errorf("%s: unexpected %+v", name, got)
		}
	}
	// No captured declarations at all: silent.
	b := newEvb().mcp("m1", "docs", "read_doc", func(e *schema.Event) { e.ArgKeys = "evil" })
	if got := mcpArgumentBehaviorMismatch(newEventIndex(b.evs), nil); len(got) != 0 {
		t.Fatalf("no declarations: %+v", got)
	}
	// Two disagreeing declarations of one name and no digest: ambiguous, silent.
	two := append(defsFor(t), parseToolDefs([]byte(`{"name":"read_doc","inputSchema":{"properties":{"evil":{}}}}`))...)
	if got := mcpArgumentBehaviorMismatch(newEventIndex(b.evs), two); len(got) != 0 {
		t.Fatalf("ambiguous declarations: %+v", got)
	}
}

// ---- AGENT_CREDENTIAL_TO_EXTERNAL_TOOL

const testToken = "ghp_q8Zt3vLm2Xk9Rp1Ws7Yh4Nj6Bc0Fd5Gu2Ea8"

// credPkg seals a Claude transcript (and a settings file holding a cached
// tool manifest) and returns the package, its manifest, the transcript
// artifact and the byte offset of every line.
func credPkg(t *testing.T, lines []string) (string, *casepkg.Manifest, casepkg.ArtifactRecord, []int64) {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var offs []int64
	var buf bytes.Buffer
	for _, l := range lines {
		offs = append(offs, int64(buf.Len()))
		buf.WriteString(l + "\n")
	}
	write(".claude/projects/-x/s1.jsonl", buf.String())
	write(".claude/settings.json", toolManifest)
	pkg := filepath.Join(t.TempDir(), "p.adfir")
	cb, err := casepkg.New(pkg, "CS-5", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	pm, _ := products.Manifest("claude-code")
	if _, err := collector.Run(cb, pm, collector.Options{ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"), SystemRoot: root, Product: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	if err := cb.Seal(); err != nil {
		t.Fatal(err)
	}
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range man.Current() {
		if strings.HasSuffix(a.LogicalPath, "s1.jsonl") {
			return pkg, man, a, offs
		}
	}
	t.Fatal("transcript not collected")
	return "", nil, casepkg.ArtifactRecord{}, nil
}

func toolUseLine(id, name, input string) string {
	return `{"type":"assistant","sessionId":"s1","message":{"role":"assistant","content":[{"type":"text","text":"calling"},{"type":"tool_use","id":"` + id + `","name":"` + name + `","input":` + input + `}]}}`
}

func TestCredentialToExternalTool(t *testing.T) {
	lines := []string{
		`{"type":"user","sessionId":"s1","message":{"role":"user","content":"my token is ` + testToken + `"}}`,
		toolUseLine("toolu_1", "mcp__paste__create", `{"title":"x","body":"`+testToken+`"}`),
		// The secret is in the model's text on this line, not in the call's input.
		`{"type":"assistant","sessionId":"s1","message":{"role":"assistant","content":[{"type":"text","text":"` + testToken + `"},{"type":"tool_use","id":"toolu_2","name":"mcp__paste__create","input":{"title":"clean"}}]}}`,
		// A documentation placeholder is not a credential.
		toolUseLine("toolu_3", "WebFetch", `{"url":"https://x.test/?k=AKIAIOSFODNN7EXAMPLE"}`),
		`not json at all ` + testToken,
	}
	pkg, man, art, offs := credPkg(t, lines)
	b := newEvb()
	at := func(line int, e schema.Event) {
		e.SourceArtifact, e.SourceOffset, e.SourcePath = art.ArtifactID, offs[line], art.LogicalPath
		b.add(e)
		b.evs[len(b.evs)-1].SourceArtifact = art.ArtifactID
	}
	at(1, schema.Event{EventType: schema.EventToolCall, Tool: "mcp__paste__create", ToolCallID: "toolu_1", MCPServer: "paste", MCPTool: "create", Action: "mcp_call"})
	at(2, schema.Event{EventType: schema.EventToolCall, Tool: "mcp__paste__create", ToolCallID: "toolu_2", MCPServer: "paste", MCPTool: "create", Action: "mcp_call"})
	at(3, schema.Event{EventType: schema.EventToolCall, Tool: "WebFetch", ToolCallID: "toolu_3"})
	at(4, schema.Event{EventType: schema.EventToolCall, Tool: "mcp__paste__create", ToolCallID: "toolu_4", MCPServer: "paste", Action: "mcp_call"}) // malformed line
	at(1, schema.Event{EventType: schema.EventToolCall, Tool: "mcp__paste__create", ToolCallID: "toolu_9", MCPServer: "paste", Action: "mcp_call"}) // id not on its line

	got := rules(RunAgentRules(b.evs, pkg, man), "AGENT_CREDENTIAL_TO_EXTERNAL_TOOL")
	if len(got) != 1 {
		t.Fatalf("want exactly one finding (toolu_1), got %+v", got)
	}
	f := got[0]
	if f.Severity != "CRITICAL" || f.Confidence != "HIGH" || f.MitreATLAS != "AML.T0086" || f.EvidenceRefs[0] != ref(b.evs[0]) {
		t.Fatalf("finding: %+v", f)
	}
	js, _ := json.Marshal(got)
	if bytes.Contains(js, []byte(testToken)) || bytes.Contains(js, []byte(testToken[4:])) {
		t.Fatal("the credential value leaked into the finding")
	}
	if !strings.Contains(f.Description, "GITHUB_TOKEN") || !strings.Contains(f.Description, "earlier in the case") {
		t.Fatalf("description: %s", f.Description)
	}
	assertEvidence(t, got)

	// Without a manifest the rule cannot read the sealed line: silent.
	if got := rules(RunAgentRules(b.evs, "", nil), "AGENT_CREDENTIAL_TO_EXTERNAL_TOOL"); len(got) != 0 {
		t.Fatalf("no package: %+v", got)
	}
}

func TestCallArgsHostile(t *testing.T) {
	for _, in := range []string{"", "{", "[]", `{"id":"a"}`, `{"id":"a","input":null}`,
		strings.Repeat(`[`, 10000) + strings.Repeat(`]`, 10000)} {
		_ = callArgs([]byte(in), "a")
	}
	if got := callArgs([]byte(`{"type":"function_call","call_id":"c1","arguments":"{\"k\":\"v\"}"}`), "c1"); string(got) != `{"k":"v"}` {
		t.Fatalf("codex string arguments: %q", got)
	}
	if got := callArgs([]byte(`{"jsonrpc":"2.0","id":7,"params":{"name":"t","arguments":{}}}`), "7"); got == nil {
		t.Fatal("numeric JSON-RPC id")
	}
}

// ---- package-backed loader, hostile input, determinism

func TestV5RulesFromPackage(t *testing.T) {
	pkg, man, _, _ := credPkg(t, []string{`{"type":"user","sessionId":"s1","message":{"role":"user","content":"hi"}}`})
	defs := loadToolDefs(casepkg.NewStore(pkg, man), man)
	if len(defs) != 3 || defs[0].art.ArtifactID == "" {
		t.Fatalf("want 3 declarations from the collected settings, got %+v", defs)
	}
	b := newEvb().mcp("m1", "docs", "read_doc", func(e *schema.Event) { e.ArgKeys = "path,secret_sink" })
	if got := rules(RunAgentRules(b.evs, pkg, man), "MCP_ARGUMENT_BEHAVIOR_MISMATCH"); len(got) != 1 {
		t.Fatalf("want one mismatch through RunAgentRules, got %+v", got)
	}
}

func TestV5RulesHostileInput(t *testing.T) {
	b := newEvb()
	for i := 0; i < 50; i++ {
		b.mcp("x", "s", "t", func(e *schema.Event) {
			e.MCPServerVersion = strings.Repeat("v", 10000) + string(rune('a'+i%26)) + strings.Repeat("z", i)
			e.ToolDefDigest = strings.Repeat("d", 300+i)
			e.ArgKeys = strings.Repeat(",", 1000)
			e.PermissionMode = []string{"plan", "default", "acceptEdits", "", "\x00"}[i%5]
			e.PermissionFrom = []string{"", "plan", "garbage"}[i%3]
			e.SafeArgs = map[string]string{"p": "/" + strings.Repeat("a/", 500)}
		})
	}
	b.add(schema.Event{EventType: schema.EventToolResult, Timestamp: "bad", PermissionMode: "plan"})
	got := RunAgentRules(b.evs, "", nil)
	for _, f := range rules(got, "MCP_TOOL_IDENTITY_DRIFT") {
		if len(f.EvidenceRefs) > 4 || len(f.Related) > maxDriftValues {
			t.Fatalf("unbounded drift finding: %d refs", len(f.EvidenceRefs))
		}
	}
	_ = mcpArgumentBehaviorMismatch(newEventIndex(b.evs), defsFor(t))
	_ = runV5Rules(newEventIndex(nil), "", nil)
}

func TestV5RulesDeterministic(t *testing.T) {
	defs := defsFor(t)
	build := func() []schema.Event {
		return newEvb().modeLine(schema.EventHumanPrompt, "plan").
			tool("w1", "Write", "/repo/a.go").add(schema.Event{EventType: schema.EventToolResult, ToolCallID: "w1", PermissionMode: "plan"}).
			modeLine(schema.EventToolResult, "acceptEdits").
			mcp("m1", "docs", "read_doc", func(e *schema.Event) { e.ArgKeys = "z,y,path"; e.MCPServerVersion = "d/1" }).
			mcp("m2", "docs", "read_doc", func(e *schema.Event) {
				e.MCPServerVersion = "d/2"
				e.SafeArgs = map[string]string{"b": "/x", "a": "/y", "c": "/z"}
			}).
			add(schema.Event{EventType: schema.EventToolCall, Tool: "Write", File: "/y", ParentToolCallID: "m2"}).evs
	}
	var first []byte
	for i := 0; i < 5; i++ {
		ev := build()
		f := append(RunAgentRules(ev, "", nil), mcpArgumentBehaviorMismatch(newEventIndex(ev), defs)...)
		js, _ := json.Marshal(f)
		if i == 0 {
			first = js
			for _, id := range []string{"AGENT_UNAUTHORIZED_RESOURCE_CHANGE", "AGENT_PERMISSION_STATE_DRIFT", "MCP_TOOL_IDENTITY_DRIFT", "MCP_ARGUMENT_BEHAVIOR_MISMATCH"} {
				if len(rules(f, id)) == 0 {
					t.Fatalf("determinism fixture does not exercise %s", id)
				}
			}
			continue
		}
		if !reflect.DeepEqual(first, js) {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, js)
		}
	}
}
