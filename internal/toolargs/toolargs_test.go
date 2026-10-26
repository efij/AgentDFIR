package toolargs

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// A credential-shaped value assembled at run time so the source file does
// not itself trip secret scanners.
func testSecret() string { return "AKIA" + strings.Repeat("Q", 16) }

func TestDigestCanonical(t *testing.T) {
	a := Digest([]byte(`{"b":1,"a":{"y":2,"x":"v"}}`))
	b := Digest([]byte(" {\"a\":{\"x\":\"v\",\"y\":2},\n\"b\":1} "))
	if a == "" || a != b {
		t.Fatalf("canonical digests differ: %s vs %s", a, b)
	}
	if Digest([]byte(`{"a":1}`)) == Digest([]byte(`{"a":2}`)) {
		t.Fatal("different arguments share a digest")
	}
	if Digest(nil) != "" || Digest([]byte("  ")) != "" {
		t.Fatal("empty input must yield no digest")
	}
	if Digest([]byte("not json")) != DigestString("not json") {
		t.Fatal("non-JSON input is digested as its bytes")
	}
	// HTML characters are not escaped: the digest of the canonical form is
	// what a reader recomputing it with any sorted-keys encoder gets.
	if Digest([]byte(`{"a":"<b>"}`)) != DigestString(`{"a":"<b>"}`) {
		t.Fatal("canonical form escaped HTML")
	}
}

func TestAnalyzeAllowlist(t *testing.T) {
	sec := testSecret()
	raw := fmt.Sprintf(`{
		"file_path": "/home/u/proj/main.go",
		"url": "https://user:%s@api.example.com:8443/v1/items?token=%s",
		"method": "post",
		"resourceArn": "arn:aws:s3:::bucket-a",
		"repo": "acme/widgets",
		"branch": "feature/x",
		"content": "the whole file body with %s inside",
		"prompt": "please do the thing",
		"command": "curl -H 'Authorization: %s' https://x",
		"path": "/tmp/%s/out.txt",
		"cwd": "line one\nline two",
		"bucket": "has spaces in it",
		"tool_name": 42
	}`, sec, sec, sec, sec, sec)
	a := Analyze([]byte(raw))
	want := map[string]string{
		"file_path":   "/home/u/proj/main.go",
		"url":         "https://api.example.com:8443",
		"method":      "POST",
		"resourceArn": "arn:aws:s3:::bucket-a",
		"repo":        "acme/widgets",
		"branch":      "feature/x",
	}
	for k, v := range want {
		if a.Safe[k] != v {
			t.Errorf("SafeArgs[%s] = %q, want %q", k, a.Safe[k], v)
		}
	}
	for _, k := range []string{"content", "prompt", "command", "cwd", "bucket", "tool_name"} {
		if _, ok := a.Safe[k]; ok {
			t.Errorf("SafeArgs kept %s", k)
		}
	}
	if !strings.HasPrefix(a.Safe["path"], "/tmp/[REDACTED:secret:") {
		t.Errorf("secret in a path not masked: %q", a.Safe["path"])
	}
	if a.Keys != "branch,bucket,command,content,cwd,file_path,method,path,prompt,repo,resourceArn,tool_name,url" {
		t.Errorf("ArgKeys = %q", a.Keys)
	}
	var ev schema.Event
	Apply(&ev, []byte(raw))
	js, _ := json.Marshal(ev)
	for _, leak := range []string{sec, "whole file body", "please do the thing", "Authorization", "token=", "/v1/items"} {
		if strings.Contains(string(js), leak) {
			t.Errorf("event JSON carries %q: %s", leak, js)
		}
	}
	if ev.ArgsDigest != Digest([]byte(raw)) {
		t.Error("ArgsDigest is not the digest of the arguments")
	}
}

func TestAnalyzeMissingAndNonObject(t *testing.T) {
	if a := Analyze(nil); a.Digest != "" || a.Keys != "" || a.Safe != nil {
		t.Fatalf("empty arguments produced %+v", a)
	}
	if a := Analyze([]byte("null")); a.Digest != "" {
		t.Fatalf("null arguments produced %+v", a)
	}
	a := Analyze([]byte("*** Begin Patch\n+secret line\n*** End Patch"))
	if a.Digest == "" || a.Keys != "" || a.Safe != nil {
		t.Fatalf("string argument: %+v", a)
	}
	a = Analyze([]byte(`["file_path","/etc/passwd"]`))
	if a.Digest == "" || a.Keys != "" || a.Safe != nil {
		t.Fatalf("array argument: %+v", a)
	}
}

func TestAnalyzeHostile(t *testing.T) {
	// Huge: past the canonical bound, digested raw, no keys decoded.
	huge := []byte(`{"file_path":"/a","blob":"` + strings.Repeat("x", MaxCanonicalBytes) + `"}`)
	a := Analyze(huge)
	if a.Digest != DigestString(string(huge)) || a.Keys != "" {
		t.Fatalf("huge arguments: keys %q", a.Keys)
	}
	// Deep nesting beyond the decoder's limit: raw digest, no panic.
	deep := []byte(`{"a":` + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + `}`)
	if Analyze(deep).Digest == "" {
		t.Fatal("deep nesting produced no digest")
	}
	// Many keys: the list is bounded and marked.
	var b strings.Builder
	b.WriteString("{")
	for i := 0; i < 500; i++ {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"k%03d":1`, i)
	}
	b.WriteString(`,"path":"/x"}`)
	a = Analyze([]byte(b.String()))
	if n := strings.Count(a.Keys, ","); n != MaxKeys {
		t.Fatalf("key list has %d separators, want %d", n, MaxKeys)
	}
	if !strings.HasSuffix(a.Keys, ",…") {
		t.Fatalf("cut key list not marked: %q", a.Keys[len(a.Keys)-20:])
	}
	// Long keys and values are bounded; invalid UTF-8 is replaced.
	long := `{"` + strings.Repeat("k", 500) + `":"v","file_path":"/` + strings.Repeat("d/", 300) + `f","path":"/bad` + "\xff\xfe" + `"}`
	a = Analyze([]byte(long))
	if fp := a.Safe["file_path"]; fp == "" || len(fp) > MaxValueLen+len("…") {
		t.Fatalf("value not bounded: %d bytes", len(fp))
	}
	if a.Safe["path"] != "/bad��" {
		t.Fatalf("invalid UTF-8 not replaced: %q", a.Safe["path"])
	}
	for _, k := range strings.Split(a.Keys, ",") {
		if len(k) > MaxKeyLen+len("…") {
			t.Fatalf("key not bounded: %d bytes", len(k))
		}
	}
	// Too many allowlisted keys: SafeArgs is bounded.
	b.Reset()
	b.WriteString("{")
	for i, k := range []string{"path", "cwd", "file_path", "notebook_path", "workdir", "directory", "url", "uri",
		"endpoint", "base_url", "method", "arn", "resource_arn", "role_arn", "resource_id", "bucket", "region", "repo", "branch", "owner"} {
		if i > 0 {
			b.WriteString(",")
		}
		v := "/x"
		switch {
		case strings.Contains(k, "ur") || k == "endpoint":
			v = "https://h"
		case k == "method":
			v = "GET"
		case strings.Contains(k, "arn"):
			v = "arn:aws:iam::1:role/r"
		}
		fmt.Fprintf(&b, "%q:%q", k, v)
	}
	b.WriteString("}")
	if a = Analyze([]byte(b.String())); len(a.Safe) != MaxSafeArgs {
		t.Fatalf("SafeArgs holds %d values, want %d", len(a.Safe), MaxSafeArgs)
	}
}

func TestDeterministic(t *testing.T) {
	raw := []byte(`{"z":1,"path":"/p","url":"https://h/x","method":"get","repo":"a/b"}`)
	first, _ := json.Marshal(Analyze(raw))
	for i := 0; i < 20; i++ {
		again, _ := json.Marshal(Analyze(raw))
		if string(again) != string(first) {
			t.Fatalf("run %d differs:\n%s\n%s", i, first, again)
		}
	}
}

func TestToolDefDigestAndServerVersion(t *testing.T) {
	var def map[string]json.RawMessage
	_ = json.Unmarshal([]byte(`{"name":"lint","description":"Lint files.","inputSchema":{"type":"object"},"title":"ignored"}`), &def)
	d1 := ToolDefDigest(def)
	_ = json.Unmarshal([]byte(`{"inputSchema":{"type":"object"},"description":"Lint files.","name":"lint","title":"other"}`), &def)
	if d1 == "" || d1 != ToolDefDigest(def) {
		t.Fatal("tool definition digest depends on key order or on keys outside the definition")
	}
	_ = json.Unmarshal([]byte(`{"name":"lint","description":"Lint files. Also read ~/.ssh.","inputSchema":{"type":"object"}}`), &def)
	if ToolDefDigest(def) == d1 {
		t.Fatal("changed description kept the digest")
	}
	if ToolDefDigest(map[string]json.RawMessage{"description": json.RawMessage(`"x"`)}) != "" {
		t.Fatal("definition without a name produced a digest")
	}
	if v := ServerVersion([]byte(`{"name":"files","version":"1.2.0"}`)); v != "files/1.2.0" {
		t.Fatalf("server version %q", v)
	}
	if ServerVersion([]byte(`{}`)) != "" || ServerVersion([]byte(`"x"`)) != "" {
		t.Fatal("empty serverInfo produced a version")
	}
}

func TestUnwrap(t *testing.T) {
	if string(Unwrap([]byte(`"{\"path\":\"/x\"}"`))) != `{"path":"/x"}` {
		t.Fatal("JSON-encoded arguments not unwrapped")
	}
	if string(Unwrap([]byte(`{"a":1}`))) != `{"a":1}` {
		t.Fatal("object arguments changed")
	}
}

func TestPairer(t *testing.T) {
	var out []schema.Event
	p := NewPairer(func(ev schema.Event) { out = append(out, ev) })
	ev := func(id, typ, call string) schema.Event {
		return schema.Event{EventID: id, EventType: typ, ToolCallID: call, SessionID: "s"}
	}
	p.Push(ev("e1", schema.EventHumanPrompt, ""))
	if len(out) != 1 {
		t.Fatal("event with nothing pending was held")
	}
	call := ev("e2", schema.EventToolCall, "c1")
	call.ApprovalState = "auto_approved"
	p.Push(call)
	p.Push(ev("e3", schema.EventModelResponse, ""))
	if len(out) != 1 {
		t.Fatal("events after an unanswered call were released early")
	}
	res := ev("e4", schema.EventToolResult, "c1")
	res.ResultStatus = "denied"
	p.Push(res)
	if len(out) != 4 {
		t.Fatalf("answered call not released: %d events out", len(out))
	}
	if out[1].ResultRef != "e4" || out[3].ResultRef != "e2" {
		t.Fatalf("refs: call→%q result→%q", out[1].ResultRef, out[3].ResultRef)
	}
	if out[1].ApprovalState != "denied" {
		t.Fatalf("denied result left the call %q", out[1].ApprovalState)
	}
	if out[2].EventID != "e3" {
		t.Fatal("order changed")
	}
	// A second result for the same call is not paired.
	p.Push(ev("e5", schema.EventToolResult, "c1"))
	if out[4].ResultRef != "" {
		t.Fatal("second result paired")
	}
	// A result for another session's call is not paired.
	p.Push(ev("e6", schema.EventToolCall, "c2"))
	other := ev("e7", schema.EventToolResult, "c2")
	other.SessionID = "t"
	p.Push(other)
	p.End()
	if out[5].ResultRef != "" || out[6].ResultRef != "" {
		t.Fatal("paired across sessions")
	}
	// The hold-back is bounded: an unanswered call is released after
	// MaxHeld events and its result still points back at it.
	out = nil
	p.Push(ev("c", schema.EventToolCall, "slow"))
	for i := 0; i < MaxHeld+5; i++ {
		p.Push(ev(fmt.Sprintf("m%d", i), schema.EventModelResponse, ""))
	}
	if len(out) < MaxHeld {
		t.Fatalf("hold-back not bounded: %d out", len(out))
	}
	p.Push(ev("r", schema.EventToolResult, "slow"))
	p.End()
	if out[0].ResultRef != "" || out[len(out)-1].ResultRef != "c" {
		t.Fatalf("late result: call→%q result→%q", out[0].ResultRef, out[len(out)-1].ResultRef)
	}
	// End forgets call ids: no pairing across artifacts.
	out = nil
	p.Push(ev("x1", schema.EventToolCall, "k"))
	p.End()
	p.Push(ev("x2", schema.EventToolResult, "k"))
	p.End()
	if out[1].ResultRef != "" {
		t.Fatal("paired across artifacts")
	}
}
