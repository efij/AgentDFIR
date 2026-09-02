package genericchat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/schema"
)

// Archive fallback: loose conversations.json (Claude.ai + ChatGPT shapes)
// and a stray Claude Code JSONL preserved as archive.sessions.
func TestArchiveFallbackAndExports(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"export/claude/conversations.json": `[{"uuid":"c1","name":"x","chat_messages":[
			{"uuid":"m1","sender":"human","text":"delete the prod database","created_at":"2026-08-30T10:00:00Z"},
			{"uuid":"m2","sender":"assistant","text":"I ran DROP DATABASE prod.","created_at":"2026-08-30T10:00:05Z"}]}]`,
		"export/chatgpt/conversations.json": `[{"title":"t","create_time":1788084000,"mapping":{
			"a":{"message":{"author":{"role":"user"},"create_time":1788084000,"content":{"content_type":"text","parts":["hello there"]}}},
			"b":{"message":{"author":{"role":"assistant"},"create_time":1788084005,"content":{"content_type":"text","parts":["hi"]}}},
			"c":{"message":null}}}]`,
		"run/logs/agent.jsonl": `{"role":"user","content":"do it"}` + "\n" + `{"role":"assistant","content":[{"type":"tool_use","id":"x","name":"bash","input":{"command":"rm -rf build"}}]}` + "\n",
		"run/logs/readme.txt":  "ignored",
	}
	for rel, c := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg := filepath.Join(t.TempDir(), "arc.adfir")
	b, err := casepkg.New(pkg, "ARC", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := collector.IngestLooseSessions(b, root, collector.Options{ProfileRoot: root, ConfigRoot: root, SystemRoot: root, Product: "ci-archive"})
	if err != nil || st.Acquired != 3 {
		t.Fatalf("loose ingest: %v %+v", err, st)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	res, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	k := kinds(res)
	if k[schema.EventHumanPrompt] != 3 || k[schema.EventModelResponse] != 2 || k[schema.EventToolCall] != 1 {
		t.Fatalf("event mix: %v (events=%d)", k, len(res.Events))
	}
	var sawExport, sawTool bool
	for _, ev := range res.Events {
		if ev.Product != "ci-archive" {
			t.Fatalf("product: %s", ev.Product)
		}
		if ev.Result == "export" && ev.EventType == schema.EventModelResponse && ev.Corroboration != schema.StateReported {
			t.Fatal("export model text must be REPORTED")
		}
		if ev.Result == "export" {
			sawExport = true
		}
		if ev.EventType == schema.EventToolCall && ev.Command == "rm -rf build" {
			sawTool = true
		}
		if ev.SessionID == "c1" && ev.EventType == schema.EventHumanPrompt && ev.Timestamp != "2026-08-30T10:00:00Z" {
			t.Fatalf("claude export timestamp: %+v", ev)
		}
	}
	if !sawExport || !sawTool {
		t.Fatalf("export=%v tool=%v", sawExport, sawTool)
	}
}
