package genericchat

import (
	"runtime"
	"testing"

	"github.com/efij/AgentDFIR/internal/schema"
)

func TestOpenCodeStorage(t *testing.T) {
	res := collectAndParse(t, "opencode", ".config/opencode", map[string]string{
		// One message file (assistant) + one tool part file + one text part.
		".local/share/opencode/storage/message/ses_1/msg_1.json": `{"id":"msg_1","sessionID":"ses_1","role":"assistant","time":{"created":1724930000000}}`,
		".local/share/opencode/storage/part/msg_1/prt_1.json":    `{"id":"prt_1","messageID":"msg_1","sessionID":"ses_1","type":"tool","tool":"bash","state":{"status":"completed","input":{"command":"rm -rf build/"}}}`,
		".local/share/opencode/storage/part/msg_1/prt_2.json":    `{"id":"prt_2","messageID":"msg_1","sessionID":"ses_1","type":"text","text":"I removed the build directory."}`,
	})
	var toolCmd, sess bool
	for _, ev := range res.Events {
		if ev.Product != "opencode" || ev.Vendor != "sst" {
			t.Fatalf("identity: %s/%s", ev.Product, ev.Vendor)
		}
		if ev.SessionID == "ses_1" {
			sess = true
		}
		if ev.EventType == schema.EventToolCall && ev.Tool == "bash" {
			if ev.Command != "rm -rf build/" {
				t.Fatalf("opencode tool input not extracted: %q", ev.Command)
			}
			toolCmd = true
		}
	}
	if !toolCmd || !sess {
		t.Fatalf("opencode parse incomplete (tool=%v session=%v)", toolCmd, sess)
	}
}

func TestCopilotChatVSCode(t *testing.T) {
	storage := vscodeWorkspaceRel(t)
	res := collectAndParse(t, "copilot-chat-vscode", storage, map[string]string{
		storage + "/abc123hash/chatSessions/uuid-1.json": `{
			"requesterUsername": "dev",
			"requests": [
				{"message":{"text":"delete the logs"},
				 "response":[{"value":"I will delete them now."}],
				 "timestamp": 1724930000000}
			]
		}`,
	})
	k := kinds(res)
	if k[schema.EventHumanPrompt] != 1 || k[schema.EventModelResponse] != 1 {
		t.Fatalf("event mix wrong: %v", k)
	}
	for _, ev := range res.Events {
		if ev.Product != "copilot-chat-vscode" {
			t.Fatalf("product: %s", ev.Product)
		}
		if ev.EventType == schema.EventModelResponse && ev.Corroboration != schema.StateReported {
			t.Fatal("copilot chat response must be REPORTED")
		}
	}
}

func TestAiderMarkdownHistory(t *testing.T) {
	// Aider evidence is repo-local; collect with the profile root = repo.
	res := collectAndParse(t, "aider", "", map[string]string{
		".aider.chat.history.md": "# aider chat started at 2026-08-30 10:00:00\n" +
			"\n" +
			"#### please remove the old migrations\n" +
			"\n" +
			"I'll delete them and update the index.\n" +
			"\n" +
			"#### now run the tests\n",
		".aider.input.history": "# 2026-08-30 10:05:00.000000\n+run the deploy\n",
	})
	var userSeen, modelSeen, inputSeen bool
	for _, ev := range res.Events {
		if ev.Product != "aider" {
			t.Fatalf("product: %s", ev.Product)
		}
		switch {
		case ev.EventType == schema.EventHumanPrompt && ev.SourcePath == ".aider.chat.history.md":
			userSeen = true
		case ev.EventType == schema.EventModelResponse:
			modelSeen = true
			if ev.Corroboration != schema.StateReported {
				t.Fatal("aider assistant narrative must be REPORTED")
			}
		case ev.EventType == schema.EventHumanPrompt && ev.SourcePath == ".aider.input.history":
			inputSeen = true
			if ev.Summary != "run the deploy" {
				t.Fatalf("aider input not parsed: %q", ev.Summary)
			}
		}
	}
	if !userSeen || !modelSeen || !inputSeen {
		t.Fatalf("aider parse incomplete (user=%v model=%v input=%v)", userSeen, modelSeen, inputSeen)
	}
}

func TestWarpSQLiteCarving(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("warp linux/darwin manifests only in fixture")
	}
	blob := "SQLite format 3\x00" + "noise\x01\x02" +
		`{"role":"user","content":"summarize the incident"}` +
		"\x00\xff" +
		`{"role":"assistant","content":"Here is the summary."}` + "\x00"
	rel := "Library/Application Support/dev.warp.Warp-Stable/warp.sqlite"
	cfgRel := "Library/Application Support/dev.warp.Warp-Stable"
	if runtime.GOOS == "linux" {
		rel = ".local/state/warp-terminal/warp.sqlite"
		cfgRel = ".local/state/warp-terminal"
	}
	res := collectAndParse(t, "warp", cfgRel, map[string]string{rel: blob})
	var user, model bool
	for _, ev := range res.Events {
		if ev.Result != "carved" {
			t.Fatalf("warp events must be carved, got %q", ev.Result)
		}
		if ev.EventType == schema.EventHumanPrompt {
			user = true
		}
		if ev.EventType == schema.EventModelResponse {
			model = true
		}
	}
	if !user || !model {
		t.Fatalf("warp carving incomplete (user=%v model=%v)", user, model)
	}
}

func vscodeWorkspaceRel(t *testing.T) string {
	t.Helper()
	switch runtime.GOOS {
	case "darwin":
		return "Library/Application Support/Code/User/workspaceStorage"
	case "linux":
		return ".config/Code/User/workspaceStorage"
	case "windows":
		return "AppData/Roaming/Code/User/workspaceStorage"
	default:
		t.Skip("no vscode manifest for " + runtime.GOOS)
		return ""
	}
}
