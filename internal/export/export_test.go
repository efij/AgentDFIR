package export

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/internal/schema"
)

func TestSTIXBundleValidShape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.json")
	findings := []schema.Finding{{
		RuleID: "ORPHAN_AGENT", Severity: "HIGH", Title: "t", Description: "d",
		Status: schema.StateObserved, MitreATTACK: "T1485",
	}}
	if err := WriteSTIX(findings, "C-1", path); err != nil {
		t.Fatal(err)
	}
	var bundle struct {
		Type    string `json:"type"`
		ID      string `json:"id"`
		Objects []map[string]any
	}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if bundle.Type != "bundle" || len(bundle.Objects) != 1 {
		t.Fatalf("bad bundle: %+v", bundle)
	}
	if bundle.Objects[0]["spec_version"] != "2.1" {
		t.Fatal("missing spec_version 2.1")
	}
	// Deterministic IDs across re-export.
	path2 := filepath.Join(t.TempDir(), "b2.json")
	if err := WriteSTIX(findings, "C-1", path2); err != nil {
		t.Fatal(err)
	}
	data2, _ := os.ReadFile(path2)
	var b2 struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(data2, &b2)
	if b2.ID != bundle.ID {
		t.Fatal("bundle IDs not deterministic")
	}
}

func TestSTIXEmptyFindingsIsValid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := WriteSTIX(nil, "C-2", path); err != nil {
		t.Fatal(err)
	}
	var bundle map[string]any
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &bundle); err != nil {
		t.Fatal(err)
	}
	if _, ok := bundle["objects"].([]any); !ok {
		t.Fatal("objects must be an array (even when empty), not null")
	}
}

func TestOTelMapping(t *testing.T) {
	path := filepath.Join(t.TempDir(), "o.json")
	events := []schema.Event{{
		EventID: "e1", EventType: schema.EventToolCall, Tool: "Bash",
		Vendor: "anthropic", AgentID: "a1", SessionID: "s1", Model: "m",
		Corroboration: schema.StateObserved, Timestamp: "2026-08-30T10:00:00Z",
	}}
	if err := WriteOTel(events, path); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(path)
	s := string(data)
	for _, want := range []string{
		"gen_ai.agent.id", "gen_ai.operation.name", "execute_tool",
		"gen_ai.request.model", "agentdfir.corroboration_state",
	} {
		if !contains(s, want) {
			t.Fatalf("OTel output missing %q", want)
		}
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
