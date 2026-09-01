package correlate

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/internal/schema"
)

func TestShellHistoryUpgradesToCorroborated(t *testing.T) {
	hist := filepath.Join(t.TempDir(), ".zsh_history")
	os.WriteFile(hist, []byte(": 1724930000:0;curl https://example.com/data\nls -la\n"), 0o644)

	events := []schema.Event{
		{ // agent claims + tool call for curl -> OBSERVED, should upgrade
			EventType: schema.EventToolCall, Action: "shell_execution",
			Command: "curl https://example.com/data", Corroboration: schema.StateObserved,
		},
		{ // a command NOT in history stays OBSERVED
			EventType: schema.EventToolCall, Action: "shell_execution",
			Command: "rm -rf /tmp/scratch", Corroboration: schema.StateObserved,
		},
		{ // pure narrative stays REPORTED (never touched)
			EventType: schema.EventModelResponse, Corroboration: schema.StateReported,
			Summary: "I ran curl https://example.com/data",
		},
	}

	res, err := Apply(events, &ShellHistoryAdapter{Path: hist})
	if err != nil {
		t.Fatal(err)
	}
	if res.Corroborated != 1 {
		t.Fatalf("expected 1 corroboration, got %d", res.Corroborated)
	}
	if events[0].Corroboration != schema.StateCorroborated {
		t.Fatalf("curl tool call not upgraded: %s", events[0].Corroboration)
	}
	if events[1].Corroboration != schema.StateObserved {
		t.Fatal("uncorroborated command must stay OBSERVED")
	}
	if events[2].Corroboration != schema.StateReported {
		t.Fatal("model narrative must never be upgraded by correlation")
	}
}

func TestNoEndpointEvidenceLeavesStatesUnchanged(t *testing.T) {
	events := []schema.Event{{
		EventType: schema.EventToolCall, Command: "ls", Corroboration: schema.StateObserved,
	}}
	// Adapter over a missing file: error recorded, nothing upgraded.
	res, err := Apply(events, &ShellHistoryAdapter{Path: "/nonexistent/history"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Corroborated != 0 || events[0].Corroboration != schema.StateObserved {
		t.Fatal("absence of endpoint evidence must not change corroboration")
	}
}
