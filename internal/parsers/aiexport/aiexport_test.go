package aiexport

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/collector"
	"github.com/efij/AgentDFIR/v4/internal/products"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// runtimeSecret builds a credential-shaped string at test time. Fixtures
// carry the placeholder @@RUNTIME_SECRET@@ instead of a key-shaped
// literal, which repository push protection would (rightly) refuse.
func runtimeSecret() string {
	sum := sha256.Sum256([]byte("agentdfir aiexport synthetic fixture"))
	return "gh" + "p_" + hex.EncodeToString(sum[:])[:36]
}

// stage copies a fixture tree into a temp dir, substituting the runtime
// secret.
func stage(t *testing.T, fixture string) string {
	t.Helper()
	dst := t.TempDir()
	src := filepath.Join("testdata", fixture)
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		out := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(out, 0o755)
		}
		data, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		data = bytes.ReplaceAll(data, []byte("@@RUNTIME_SECRET@@"), []byte(runtimeSecret()))
		return os.WriteFile(out, data, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

// sealTree plans a tree the way `collect --ai-export` does, seals it and
// returns the package path.
func sealTree(t *testing.T, root string, mode PlanMode) (string, *Plan) {
	t.Helper()
	pl, err := PlanTree(root, mode, nil)
	if err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "x.adfir")
	b, err := casepkg.New(pkg, "AIX", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	var specs []collector.FileSpec
	for _, f := range pl.Files {
		specs = append(specs, collector.FileSpec{Path: f.Path, Product: f.Product,
			Entry: products.ManifestEntry{ID: f.Rule, Category: f.Type, Sensitivity: "high"}})
	}
	if _, err := collector.IngestFiles(b, specs, collector.Options{ProfileRoot: pl.Root, SystemRoot: pl.Root}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return pkg, pl
}

func parseFixture(t *testing.T, fixture string) (*schema.Normalized, string) {
	t.Helper()
	pkg, _ := sealTree(t, stage(t, fixture), PlanAll)
	res, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return res, pkg
}

func byPointer(res *schema.Normalized, path, ptr string) []schema.Event {
	var out []schema.Event
	for _, ev := range res.Events {
		if ev.SourceJSONPath == ptr && (path == "" || ev.SourcePath == path) {
			out = append(out, ev)
		}
	}
	return out
}

func one(t *testing.T, res *schema.Normalized, path, ptr string) schema.Event {
	t.Helper()
	evs := byPointer(res, path, ptr)
	if len(evs) != 1 {
		t.Fatalf("%s %s: want 1 event, got %d", path, ptr, len(evs))
	}
	return evs[0]
}

func gaps(res *schema.Normalized) []schema.Event {
	var out []schema.Event
	for _, ev := range res.Events {
		if ev.EventType == schema.EventTraceGap {
			out = append(out, ev)
		}
	}
	return out
}

// sealedBytes returns an artifact's sealed plaintext.
func sealedBytes(t *testing.T, pkg, id string) []byte {
	t.Helper()
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := casepkg.NewStore(pkg, man).Open(id)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return b
}

func TestChatGPTExport(t *testing.T) {
	res, pkg := parseFixture(t, "chatgpt")
	if g := gaps(res); len(g) != 0 {
		t.Fatalf("unexpected trace gaps: %+v", g)
	}
	const conv = "conversations.json"

	// Branches: the regenerated answer is kept and marked.
	old := one(t, res, conv, "/0/mapping/a-1-old/message")
	if old.Result != resultAlternate || old.EventType != schema.EventModelResponse {
		t.Fatalf("alternate branch: %+v", old)
	}
	act := one(t, res, conv, "/0/mapping/a-1/message")
	if act.Result != resultActive || act.Corroboration != schema.StateReported || act.Model != "gpt-4o" {
		t.Fatalf("active branch: %+v", act)
	}

	// The pasted credential is an ASKED prompt with exact provenance.
	u2 := one(t, res, conv, "/0/mapping/u-2/message")
	if u2.EventType != schema.EventHumanPrompt || u2.Corroboration != schema.StateRequested || u2.ActorType != schema.ActorHuman {
		t.Fatalf("prompt: %+v", u2)
	}
	if !strings.Contains(u2.Summary, runtimeSecret()) {
		t.Fatalf("prompt text: %q", u2.Summary)
	}
	data := sealedBytes(t, pkg, u2.SourceArtifact)
	var node mappingNode
	if err := json.NewDecoder(bytes.NewReader(data[u2.SourceOffset:])).Decode(&node); err != nil || node.ID != "u-2" {
		t.Fatalf("source offset %d does not point at node u-2: %v %+v", u2.SourceOffset, err, node)
	}
	if want := 1 + bytes.Count(data[:bytes.Index(data, []byte(`"u-2": {`))], []byte("\n")); u2.SourceLine != want {
		t.Fatalf("source line: got %d want %d", u2.SourceLine, want)
	}
	if u2.SourceArtifact == "" || u2.SessionID != "conv-gpt-0001" || u2.Product != ServiceChatGPT || u2.Vendor != "openai" {
		t.Fatalf("identity: %+v", u2)
	}

	// Epoch conversion keeps the original value.
	u1 := byPointer(res, conv, "/0/mapping/u-1/message")
	if len(u1) == 0 {
		t.Fatal("no u-1 events")
	}
	want := time.Unix(1788084010, 250000000).UTC().Format(time.RFC3339Nano)
	if u1[0].Timestamp != want || u1[0].TimestampSrc != "provider_export:create_time=1788084010.25" {
		t.Fatalf("timestamp: %q / %q (want %q)", u1[0].Timestamp, u1[0].TimestampSrc, want)
	}
	var sawAttachment bool
	for _, ev := range u1 {
		if ev.Result == resultAttachment && strings.Contains(ev.Summary, "diagram.png") && strings.Contains(ev.Summary, "file-Img001") {
			sawAttachment = true
		}
	}
	if !sawAttachment {
		t.Fatalf("attachment not listed: %+v", u1)
	}

	// Code interpreter: RECORDED tool call, never endpoint-correlatable.
	tc := one(t, res, conv, "/0/mapping/a-2/message")
	if tc.EventType != schema.EventToolCall || tc.Tool != "python" || tc.Corroboration != schema.StateObserved {
		t.Fatalf("tool call: %+v", tc)
	}
	if tc.Command != "" || tc.File != "" || tc.NetworkDest != "" || tc.Action != actionProvider {
		t.Fatalf("provider-side tool call must not carry endpoint fields: %+v", tc)
	}
	tr := one(t, res, conv, "/0/mapping/t-1/message")
	if tr.EventType != schema.EventToolResult || tr.Tool != "python" || tr.Summary != "200" {
		t.Fatalf("tool result: %+v", tr)
	}
	if b := one(t, res, conv, "/1/mapping/b/message"); b.Tool != "browser" {
		t.Fatalf("browsing call: %+v", b)
	}

	// Split file, metadata files.
	if len(byPointer(res, "conversations-001.json", "/0/mapping/n1/message")) != 1 {
		t.Fatal("split conversations file not parsed")
	}
	fb := one(t, res, "message_feedback.json", "/0")
	if fb.SessionID != "conv-gpt-0001" || !strings.Contains(fb.Summary, "thumbsUp") || fb.Timestamp != "2026-08-30T10:05:00Z" {
		t.Fatalf("feedback: %+v", fb)
	}
	if sh := one(t, res, "shared_conversations.json", "/0"); !strings.Contains(sh.Summary, "share-77") {
		t.Fatalf("shared: %+v", sh)
	}
	for _, ev := range res.Events {
		if ev.SourcePath == "chat.html" {
			t.Fatal("chat.html must be sealed, not parsed")
		}
		if ev.EventType == schema.EventToolCall && ev.Corroboration == schema.StateCorroborated {
			t.Fatal("export tool call promoted to CONFIRMED")
		}
	}
	var sawSession, sawUser bool
	for _, e := range res.Entities {
		if e.EntityID == "session:conv-gpt-0001" && e.Label == "Deploy script help" && e.Attributes["evidence_class"] == "provider_export" {
			sawSession = true
		}
		if e.Kind == "user" && e.Attributes["email"] == "analyst.subject@example.com" {
			sawUser = true
		}
	}
	if !sawSession || !sawUser {
		t.Fatalf("entities: session=%v user=%v %+v", sawSession, sawUser, res.Entities)
	}
}

func TestClaudeExport(t *testing.T) {
	res, _ := parseFixture(t, "claude")
	if g := gaps(res); len(g) != 0 {
		t.Fatalf("unexpected trace gaps: %+v", g)
	}
	const conv = "conversations.json"
	head := one(t, res, conv, "/0")
	if head.Timestamp != "2026-08-30T07:00:00Z" || !strings.Contains(head.TimestampSrc, "+02:00") {
		t.Fatalf("offset timestamp not normalized to UTC: %q %q", head.Timestamp, head.TimestampSrc)
	}
	use := one(t, res, conv, "/0/chat_messages/1/content/1")
	if use.EventType != schema.EventToolCall || use.Tool != "repl" || use.ToolCallID != "toolu_01" || use.Corroboration != schema.StateObserved || use.Command != "" {
		t.Fatalf("tool_use: %+v", use)
	}
	if use.Timestamp != "2026-08-30T07:00:03Z" {
		t.Fatalf("block start timestamp: %q", use.Timestamp)
	}
	r := one(t, res, conv, "/0/chat_messages/1/content/2")
	if r.EventType != schema.EventToolResult || r.ToolCallID != "toolu_01" || r.Summary != "2" {
		t.Fatalf("tool_result: %+v", r)
	}
	if th := one(t, res, conv, "/0/chat_messages/1/content/0"); !strings.HasPrefix(th.Summary, "[reasoning]") || th.Corroboration != schema.StateReported {
		t.Fatalf("thinking: %+v", th)
	}
	var attachments int
	for _, ev := range byPointer(res, conv, "/0/chat_messages/0") {
		if ev.Result == resultAttachment {
			attachments++
		}
	}
	if attachments != 2 {
		t.Fatalf("attachments listed: %d", attachments)
	}
	if p := one(t, res, conv, "/1/chat_messages/0"); p.EventType != schema.EventHumanPrompt || p.Corroboration != schema.StateRequested {
		t.Fatalf("text-only prompt: %+v", p)
	}
	if pr := byPointer(res, "projects.json", "/0/docs/0"); len(pr) != 1 || !strings.Contains(pr[0].Summary, "runbook.md") {
		t.Fatalf("project doc: %+v", pr)
	}
	if acct := one(t, res, "users.json", "/0"); !strings.Contains(acct.Summary, "subject@example.com") {
		t.Fatalf("account: %+v", acct)
	}
}

func TestDeepSeekExport(t *testing.T) {
	res, _ := parseFixture(t, "deepseek")
	if g := gaps(res); len(g) != 0 {
		t.Fatalf("unexpected trace gaps: %+v", g)
	}
	req := one(t, res, "conversations.json", "/0/mapping/1/message/fragments/0")
	if req.EventType != schema.EventHumanPrompt || req.Result != resultActive || req.Timestamp != "2026-09-01T10:00:01Z" {
		t.Fatalf("request: %+v", req)
	}
	// No current_node: both sides of the fork are unresolved, not guessed.
	for _, ptr := range []string{"/0/mapping/2/message/fragments/2", "/0/mapping/3/message/fragments/0"} {
		if ev := one(t, res, "conversations.json", ptr); ev.Result != resultUnresolved || ev.EventType != schema.EventModelResponse {
			t.Fatalf("%s: %+v", ptr, ev)
		}
	}
	s := one(t, res, "conversations.json", "/0/mapping/2/message/fragments/1")
	if s.EventType != schema.EventToolCall || s.Tool != "search" || !strings.Contains(s.Summary, "example.org/ssh") {
		t.Fatalf("search: %+v", s)
	}
	if s.Model != "deepseek-reasoner" || s.Product != ServiceDeepSeek {
		t.Fatalf("model/product: %+v", s)
	}
}

func TestGeminiTakeout(t *testing.T) {
	res, _ := parseFixture(t, "gemini")
	const path = "Takeout/My Activity/Gemini Apps/MyActivity.json"
	evs := byPointer(res, path, "/0")
	var prompt, attach bool
	for _, ev := range evs {
		if ev.EventType == schema.EventHumanPrompt && strings.HasPrefix(ev.Summary, "Draft an email") && ev.Timestamp == "2026-09-02T08:30:00.25Z" {
			prompt = true
		}
		if ev.Result == resultAttachment && strings.Contains(ev.Summary, "outage-report.pdf") {
			attach = true
		}
	}
	reply := one(t, res, path, "/0/safeHtmlItem/0/html")
	if !prompt || !attach || reply.EventType != schema.EventModelResponse || !strings.Contains(reply.Summary, "Outage & next steps") {
		t.Fatalf("gemini: prompt=%v attach=%v reply=%+v", prompt, attach, reply)
	}
	if m := one(t, res, path, "/1"); m.EventType != schema.EventSessionMeta {
		t.Fatalf("non-prompt activity: %+v", m)
	}

	html, _ := parseFixture(t, "gemini-html")
	g := gaps(html)
	if len(g) != 1 || g[0].Result != resultUnsup || !strings.Contains(g[0].Summary, "HTML") {
		t.Fatalf("HTML-only Takeout must be one UNSUPPORTED gap: %+v", g)
	}
}

func TestMalformedExport(t *testing.T) {
	res, _ := parseFixture(t, "malformed")
	if len(byPointer(res, "", "/0/mapping/b/message")) != 1 {
		t.Fatal("conversation before the truncation must survive")
	}
	g := gaps(res)
	if len(g) != 1 || g[0].Result != resultUnparsed || !strings.Contains(g[0].Summary, "truncated") || g[0].SourceJSONPath != "/1" {
		t.Fatalf("truncation gap: %+v", g)
	}
}

func TestUnknownSchemaIsUnsupported(t *testing.T) {
	res, _ := parseFixture(t, "unknown")
	if len(res.Events) != 1 {
		t.Fatalf("want exactly one event, got %d: %+v", len(res.Events), res.Events)
	}
	ev := res.Events[0]
	if ev.EventType != schema.EventTraceGap || ev.Result != resultUnsup ||
		!strings.Contains(ev.Summary, "conversations.json") || !strings.Contains(ev.Summary, "mapping") || !strings.Contains(ev.Summary, "thread_id") {
		t.Fatalf("unsupported gap: %+v", ev)
	}
}

func TestCycleAndDanglingNodes(t *testing.T) {
	dir := t.TempDir()
	doc := `[{"title":"loop","create_time":1,"current_node":"a","id":"c1","mapping":{
		"a":{"id":"a","parent":"b","children":["b"],"message":{"id":"a","author":{"role":"user"},"content":{"content_type":"text","parts":["x"]}}},
		"b":{"id":"b","parent":"a","children":["a"],"message":{"id":"b","author":{"role":"assistant"},"content":{"content_type":"text","parts":["y"]}}},
		"r":{"id":"r","parent":null,"children":["missing"],"message":null}}}]`
	if err := os.WriteFile(filepath.Join(dir, "conversations.json"), []byte(doc), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg, _ := sealTree(t, dir, PlanAll)
	res, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	g := gaps(res)
	if len(g) != 1 || !strings.Contains(g[0].Summary, "2 mapping node(s) unreachable") {
		t.Fatalf("cycle must be reported, not followed: %+v", g)
	}
}

func TestSniff(t *testing.T) {
	cases := []struct {
		name, path, head string
		ok               bool
		want             string
	}{
		{"chatgpt", "x/data.json", `[{"title":"t","create_time":1,"mapping":{"a":{"message":{"author":{"role":"user"}}}}}]`, true, "chatgpt/conversations/mapping-tree"},
		{"chatgpt cut head", "x/blob.bin", `[{"title":"t","create_time":1,"mapping":{"a":{"id":"a","message":{"author":{"ro`, true, "chatgpt/conversations/mapping-tree"},
		{"deepseek", "conversations.json", `[{"id":"1","inserted_at":"x","mapping":{"r":{"message":{"fragments":[]}}}}]`, true, "deepseek/conversations/mapping-fragments"},
		{"claude blocks", "a.json", `[{"uuid":"u","name":"n","chat_messages":[{"uuid":"m","content":[]}]}]`, true, "claude-ai/conversations/content-blocks"},
		{"claude text", "a.json", `[{"uuid":"u","chat_messages":[{"uuid":"m","text":"x"}]}]`, true, "claude-ai/conversations/text-only"},
		{"gemini", "MyActivity.json", `[{"header":"Gemini Apps","title":"Prompted x","time":"t","products":["Gemini Apps"]}]`, true, "gemini-apps/activity/takeout-json"},
		{"takeout search is not gemini", "Search/MyActivity.json", `[{"header":"Search","title":"Searched for x","time":"t","products":["Search"]}]`, false, ""},
		{"user.json", "user.json", `{"id":"u","email":"e","chatgpt_plus_user":false}`, true, "chatgpt/account/user-object"},
		{"random json", "package.json", `{"name":"x","version":"1"}`, false, ""},
		{"random array", "data.json", `[1,2,3]`, false, ""},
		{"empty known", "conversations.json", ``, true, "unknown/unsupported"},
		{"binary known", "conversations.json", "\x00\x01PK", true, "unknown/unsupported"},
		{"image", "photo.png", "\x89PNG\r\n", false, ""},
	}
	for _, c := range cases {
		d, ok := Sniff([]byte(c.head), c.path)
		if ok != c.ok || (ok && d.String() != c.want) {
			t.Errorf("%s: got %v %q, want %v %q", c.name, ok, d.String(), c.ok, c.want)
		}
	}
}

func TestUFDRLayout(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("report.xml", `<?xml version="1.0" encoding="utf-8"?><project id="1" name="Case" xmlns="http://pa.cellebrite.com/report/2.0"><decodedData/></project>`)
	write("files/Document/notes.txt", "notes")
	data, _ := os.ReadFile(filepath.Join("testdata", "claude", "conversations.json"))
	write("files/Document/export/conversations.json", string(data))
	pkg, pl := sealTree(t, root, PlanRecognized) // UFDR forces the whole tree
	if !pl.UFDR || pl.UFDRReport != "report.xml" || pl.Recognized != 1 {
		t.Fatalf("plan: %+v", pl)
	}
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	rules := map[string]string{}
	for _, a := range man.Current() {
		rules[a.LogicalPath] = a.CollectorRule + "|" + a.ArtifactType + "|" + a.Product
	}
	want := map[string]string{
		"report.xml":                               "ufdr.report|ufdr_report|ufdr",
		"files/Document/notes.txt":                 "ufdr.file|ufdr_file|ufdr",
		"files/Document/export/conversations.json": "aiexport.conversations|agent_session|claude-ai",
	}
	for k, v := range want {
		if rules[k] != v {
			t.Errorf("%s: got %q want %q", k, rules[k], v)
		}
	}
	res, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(byPointer(res, "files/Document/export/conversations.json", "/0/chat_messages/1/content/1")) != 1 {
		t.Fatal("AI export inside a UFDR must be parsed")
	}

	// A report.xml that is not Cellebrite's is not a UFDR.
	other := t.TempDir()
	_ = os.WriteFile(filepath.Join(other, "report.xml"), []byte(`<report><project/></report>`), 0o644)
	if pl, _ := PlanTree(other, PlanRecognized, nil); pl.Found() {
		t.Fatalf("non-UFDR report.xml recognized: %+v", pl)
	}
}

func TestOverlayCacheReplay(t *testing.T) {
	pkg, _ := sealTree(t, stage(t, "chatgpt"), PlanAll)
	full, err := ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	// A streamed parse produces the same events in the same order.
	var streamed []schema.Event
	res, err := StreamPackage(pkg, func(ev schema.Event) { streamed = append(streamed, ev) })
	if err != nil {
		t.Fatal(err)
	}
	if len(streamed) != len(full.Events) || len(res.Entities) != len(full.Entities) {
		t.Fatalf("stream %d/%d events, %d/%d entities", len(streamed), len(full.Events), len(res.Entities), len(full.Entities))
	}
	for i := range streamed {
		if streamed[i] != full.Events[i] {
			t.Fatalf("event %d differs", i)
		}
	}
}
