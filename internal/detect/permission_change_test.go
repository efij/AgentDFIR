package detect

import (
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/parsers/claudejsonl"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// The parser emits a permission_change event at the line where the mode
// changed, carrying the new mode. The escalation rule must still report
// the switch once, not once for the change event and again for the line.
func TestPermissionChangeEventDoesNotDoubleFire(t *testing.T) {
	var events []schema.Event
	live := claudejsonl.NewLive("h", func(ev schema.Event) { events = append(events, ev) })
	for i, l := range []string{
		`{"type":"user","sessionId":"s","permissionMode":"default","timestamp":"2026-10-01T10:00:00Z","message":{"role":"user","content":"go"}}`,
		`{"type":"user","sessionId":"s","permissionMode":"bypassPermissions","timestamp":"2026-10-01T10:00:01Z","message":{"role":"user","content":"go on"}}`,
		`{"type":"user","sessionId":"s","permissionMode":"bypassPermissions","timestamp":"2026-10-01T10:00:02Z","message":{"role":"user","content":"more"}}`,
		`{"type":"user","sessionId":"s","permissionMode":"default","timestamp":"2026-10-01T10:00:03Z","message":{"role":"user","content":"back"}}`,
	} {
		live.Line("t.jsonl", []byte(l), int64(i*100), i+1)
	}
	changes := 0
	for _, e := range events {
		if e.EventType == schema.EventPermissionChange {
			changes++
		}
	}
	if changes != 2 {
		t.Fatalf("%d permission_change events, want 2", changes)
	}
	var esc []schema.Finding
	for _, f := range permissionModeEscalation(newEventIndex(events)) {
		if f.RuleID == "AGENT_TOOL_PERMISSION_ESCALATION" {
			esc = append(esc, f)
		}
	}
	if len(esc) != 1 {
		t.Fatalf("%d escalation findings, want 1: %+v", len(esc), esc)
	}
}
