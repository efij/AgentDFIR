package provenance

import (
	"fmt"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// attributeFile used to compare every collected instruction file against
// every write: 5,698 files x 3,291 writes on one machine, each comparison
// normalizing both paths again — 72 s. Writes are now indexed by the last
// path element, which any two paths that pathsMatch must share. The index
// has to return exactly the writes a brute-force pathsMatch would, in the
// same order.
func TestWriteIndexMatchesBruteForce(t *testing.T) {
	paths := []string{
		"/Users/dev/.claude/CLAUDE.md", ".claude/CLAUDE.md", "CLAUDE.md", "claude.md",
		`C:\Users\dev\.claude\CLAUDE.md`, "/Users/dev/repo/CLAUDE.md", "repo/CLAUDE.md",
		"/Users/dev/.claude/settings.json", ".claude/settings.json", "settings.json",
		"/etc/CLAUDE.md/", "AGENTS.md", "/Users/dev/AGENTS.md", "", "/", "md",
		"/Users/dev/.claude/agents/x.md", "agents/x.md", "x.md", "/other/x.md",
	}
	var writes []Write
	for i, p := range paths {
		writes = append(writes, mk(writeEvent(fmt.Sprintf("t%d", i)), p, "c"))
	}
	idx := newWriteIndex(writes)
	for _, target := range paths {
		var want []int
		for i, w := range writes {
			if pathsMatch(w.Path, target) {
				want = append(want, i)
			}
		}
		got := idx.matching(target)
		if len(got) != len(want) {
			t.Errorf("%q: %d writes, want %d", target, len(got), len(want))
			continue
		}
		for k := range want {
			if got[k].Event.ToolCallID != writes[want[k]].Event.ToolCallID {
				t.Errorf("%q: match %d is %s, want %s", target, k, got[k].Event.ToolCallID, writes[want[k]].Event.ToolCallID)
			}
		}
	}
}

func writeEvent(id string) schema.Event {
	return schema.Event{EventType: schema.EventToolCall, ToolCallID: id, Tool: "Write"}
}
