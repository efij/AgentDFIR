package genericchat

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/products"
	"github.com/efij/AgentDFIR/internal/schema"
)

// collectAndParse builds a profile for one product, collects it into a
// sealed package, and runs this parser.
func collectAndParse(t *testing.T, productID, configDirRel string, files map[string]string) *schema.Normalized {
	t.Helper()
	root := t.TempDir()
	for rel, content := range files {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	pkg := filepath.Join(t.TempDir(), productID+".adfir")
	b, err := casepkg.New(pkg, "GC-"+productID, casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	man, err := products.Manifest(productID)
	if err != nil {
		t.Fatal(err)
	}
	if man == nil {
		t.Fatalf("no manifest for %s", productID)
	}
	if _, err := collector.Run(b, man, collector.Options{
		ProfileRoot: root, ConfigRoot: filepath.Join(root, configDirRel),
		SystemRoot: root, Product: productID,
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
	// Universal invariants.
	for _, ev := range res.Events {
		if ev.SourceArtifact == "" {
			t.Fatalf("event %s not traceable to evidence", ev.EventID)
		}
		if ev.EventType == schema.EventModelResponse && ev.Corroboration != schema.StateReported {
			t.Fatalf("model narrative must be REPORTED, got %s", ev.Corroboration)
		}
	}
	return res
}

func kinds(res *schema.Normalized) map[string]int {
	out := map[string]int{}
	for _, ev := range res.Events {
		out[ev.EventType]++
	}
	return out
}

func TestGeminiCheckpointAndLogs(t *testing.T) {
	res := collectAndParse(t, "gemini-cli", ".gemini", map[string]string{
		".gemini/tmp/abc123/logs.json": `[
			{"sessionId":"sess-g1","messageId":0,"type":"user","message":"deploy the app","timestamp":"2026-08-30T10:00:00.000Z"}
		]`,
		".gemini/tmp/abc123/checkpoint-deploy.json": `[
			{"role":"user","parts":[{"text":"deploy the app"}]},
			{"role":"model","parts":[{"text":"Running the deploy now."},{"functionCall":{"name":"run_shell_command","args":{"command":"./deploy.sh --prod"}}}]},
			{"role":"user","parts":[{"functionResponse":{"name":"run_shell_command","response":{"output":"deployed"}}}]},
			{"role":"model","parts":[{"text":"I also cleaned up the database."}]}
		]`,
	})
	k := kinds(res)
	if k[schema.EventHumanPrompt] < 2 || k[schema.EventToolCall] != 1 || k[schema.EventToolResult] != 1 {
		t.Fatalf("event mix wrong: %v", k)
	}
	var cmdSeen, claimSeen bool
	for _, ev := range res.Events {
		if ev.Product != "gemini-cli" || ev.Vendor != "google" {
			t.Fatalf("wrong identity: %s/%s", ev.Product, ev.Vendor)
		}
		if ev.EventType == schema.EventToolCall {
			if ev.Command != "./deploy.sh --prod" || ev.Action != "shell_execution" {
				t.Fatalf("gemini functionCall command not extracted: %+v", ev)
			}
			cmdSeen = true
		}
		if strings.Contains(ev.Summary, "cleaned up the database") &&
			ev.Corroboration == schema.StateReported {
			claimSeen = true // narrative claim with no matching tool call stays REPORTED
		}
	}
	if !cmdSeen || !claimSeen {
		t.Fatal("missing command extraction or REPORTED claim")
	}
}

func TestClineAnthropicHistoryAndXMLTools(t *testing.T) {
	// Cline manifests are platform-filtered; use this OS's storage path.
	storage := clineStorageRel(t)
	res := collectAndParse(t, "cline", storage,
		map[string]string{
			storage + "/tasks/task-777/api_conversation_history.json": `[
				{"role":"user","content":[{"type":"text","text":"clean the temp dir"}]},
				{"role":"assistant","content":[{"type":"text","text":"I'll remove it.\n<execute_command>\n<command>rm -rf /tmp/scratch</command>\n</execute_command>"}]},
				{"role":"user","content":[{"type":"tool_result","tool_use_id":"x","content":"done"}]}
			]`,
			storage + "/tasks/task-777/ui_messages.json": `[
				{"ts":1724930000000,"type":"say","say":"task","text":"clean the temp dir"}
			]`,
		})
	k := kinds(res)
	if k[schema.EventToolCall] != 1 || k[schema.EventHumanPrompt] != 1 {
		t.Fatalf("event mix wrong: %v", k)
	}
	for _, ev := range res.Events {
		if ev.EventType == schema.EventToolCall {
			if ev.Command != "rm -rf /tmp/scratch" {
				t.Fatalf("XML tool command not extracted: %q", ev.Command)
			}
			if ev.SessionID != "task-777" {
				t.Fatalf("session identity should be the task dir, got %q", ev.SessionID)
			}
		}
	}
}

func TestCopilotOpenAIStyle(t *testing.T) {
	res := collectAndParse(t, "copilot-cli", ".copilot", map[string]string{
		".copilot/history-session-state/sess-cp1.json": `{
			"sessionId": "sess-cp1",
			"chatMessages": [
				{"role":"user","content":"list the repo"},
				{"role":"assistant","content":"Listing now.","tool_calls":[{"id":"c1","function":{"name":"bash","arguments":"{\"command\":\"ls -la\"}"}}]}
			]
		}`,
	})
	k := kinds(res)
	if k[schema.EventToolCall] != 1 || k[schema.EventHumanPrompt] != 1 || k[schema.EventModelResponse] != 1 {
		t.Fatalf("event mix wrong: %v", k)
	}
	for _, ev := range res.Events {
		if ev.EventType == schema.EventToolCall && ev.Command != "ls -la" {
			t.Fatalf("openai-style tool arguments not extracted: %q", ev.Command)
		}
		if ev.Vendor != "github" {
			t.Fatalf("vendor: %s", ev.Vendor)
		}
	}
}

func TestOpenClawJSONLWithMalformedLine(t *testing.T) {
	res := collectAndParse(t, "openclaw", ".openclaw", map[string]string{
		".openclaw/sessions/run-9.jsonl": `{"role":"user","content":"check the queue"}
{"role":"assistant","content":"I purged all queues."}
not json at all {{{
`,
	})
	k := kinds(res)
	if k[schema.EventHumanPrompt] != 1 || k[schema.EventModelResponse] != 1 || k[schema.EventTraceGap] != 1 {
		t.Fatalf("event mix wrong: %v", k)
	}
}

func TestCursorStoreDBCarving(t *testing.T) {
	// Synthetic binary blob: SQLite-ish header + noise + embedded JSON
	// message fragments + more noise.
	blob := "SQLite format 3\x00\x01\x02\x03\x04garbage" +
		`{"role":"user","content":"exfil check please"}` +
		"\x00\x00binarygunk\xff\xfe" +
		`{"role":"assistant","content":"I ran curl https://transfer.sh/x"}` +
		"\x00trailing"
	res := collectAndParse(t, "cursor-cli", ".cursor", map[string]string{
		".cursor/chats/ws1/tab1/store.db": blob,
	})
	var user, model bool
	for _, ev := range res.Events {
		if ev.Result != "carved" {
			t.Fatalf("carved events must be marked carved, got %q", ev.Result)
		}
		switch ev.EventType {
		case schema.EventHumanPrompt:
			user = true
		case schema.EventModelResponse:
			model = true
			if ev.Corroboration != schema.StateReported {
				t.Fatal("carved model narrative must still be REPORTED")
			}
		}
	}
	if !user || !model {
		t.Fatalf("carving missed messages (user=%v model=%v)", user, model)
	}
}

func TestCarveIgnoresNonMessages(t *testing.T) {
	blob := "\x00\x01" + `{"not_a":"message"}` + "\x00" + `{"role":"user"}` + "\x00"
	if got := CarveMessages([]byte(blob)); len(got) != 0 {
		t.Fatalf("carver accepted non-message fragments: %d", len(got))
	}
}

// clineStorageRel returns the VS Code globalStorage path (relative to
// the profile root) matching this platform's collector manifest entry.
func clineStorageRel(t *testing.T) string {
	t.Helper()
	switch runtime.GOOS {
	case "darwin":
		return "Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev"
	case "linux":
		return ".config/Code/User/globalStorage/saoudrizwan.claude-dev"
	case "windows":
		return "AppData/Roaming/Code/User/globalStorage/saoudrizwan.claude-dev"
	default:
		t.Skip("no cline manifest for " + runtime.GOOS)
		return ""
	}
}
