package segment

import (
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// A parser hands addEntity a map it goes on to merge into. If the recorder
// keeps that reference, what it recorded changes after the fact — and what
// ends up persisted describes a segment as having contributed attributes
// that came from artifacts read later.
func TestRecorderDoesNotAliasTheCallersAttributes(t *testing.T) {
	live := map[string]string{"sidechain": "true"}
	var r Recorder
	r.Entity(schema.Entity{EntityID: "agent:a", Kind: "agent", Attributes: live})

	live["later"] = "from another artifact"
	if got := r.Entities[0].Attributes; len(got) != 1 || got["sidechain"] != "true" {
		t.Fatalf("recorded entity changed after it was recorded: %v", got)
	}
}

// An empty map is not the same thing as no map: the parsers merge by
// writing into whatever they already hold, so replaying a nil where a map
// was would be a panic rather than a divergence.
func TestRecorderKeepsAnEmptyMapDistinctFromNoMap(t *testing.T) {
	var r Recorder
	r.Entity(schema.Entity{EntityID: "agent:a", Attributes: map[string]string{}})
	r.Entity(schema.Entity{EntityID: "agent:b"})
	if r.Entities[0].Attributes == nil {
		t.Fatal("an empty attribute map was recorded as nil")
	}
	if r.Entities[1].Attributes != nil {
		t.Fatal("a nil attribute map was recorded as empty")
	}
}

// The de-dup rule: an identical repeat is dropped because every parser's
// addEntity is idempotent on one, and anything that differs is kept in
// order because the merge order decides the result.
func TestRecorderDropsIdenticalRepeatsAndKeepsChanges(t *testing.T) {
	var r Recorder
	plain := schema.Entity{EntityID: "agent:a", Kind: "agent", Label: "a", Attributes: map[string]string{}}
	side := schema.Entity{EntityID: "agent:a", Kind: "agent", Label: "a", Attributes: map[string]string{"sidechain": "true"}}
	r.Entity(plain)
	r.Entity(plain)
	r.Entity(side)
	r.Entity(side)
	r.Entity(plain)
	if len(r.Entities) != 3 {
		t.Fatalf("recorded %d call(s), want 3: %+v", len(r.Entities), r.Entities)
	}
	if len(r.Entities[0].Attributes) != 0 || r.Entities[1].Attributes["sidechain"] != "true" ||
		len(r.Entities[2].Attributes) != 0 {
		t.Fatalf("the order the attributes were contributed in was not preserved: %+v", r.Entities)
	}
}

// Relationships are de-duplicated the way addRel itself does it, on the
// whole edge. Collapsing two types between the same pair would drop an
// edge a full parse keeps.
func TestRecorderDedupsRelationshipsOnTheWholeEdge(t *testing.T) {
	var r Recorder
	r.Rel(schema.Relationship{From: "agent:a", To: "tool:Bash", Type: "invoked"})
	r.Rel(schema.Relationship{From: "agent:a", To: "tool:Bash", Type: "invoked"})
	r.Rel(schema.Relationship{From: "agent:a", To: "tool:Bash", Type: "blocked_by"})
	r.Rel(schema.Relationship{From: "agent:a", To: "session:s", Type: "invoked"})
	if len(r.Relationships) != 3 {
		t.Fatalf("recorded %d edge(s), want 3: %+v", len(r.Relationships), r.Relationships)
	}
}

// The mirror image: what a replay hands the parser must not be the cache's
// own map either, or the next artifact's merge writes back into the
// segment that is about to be persisted.
func TestCloneEntitiesReturnsIndependentMaps(t *testing.T) {
	cached := []schema.Entity{
		{EntityID: "agent:a", Attributes: map[string]string{"sidechain": "true"}},
		{EntityID: "agent:b"},
	}
	out := CloneEntities(cached)
	if len(out) != 2 {
		t.Fatalf("cloned %d of 2", len(out))
	}
	out[0].Attributes["added"] = "by a later artifact"
	if _, ok := cached[0].Attributes["added"]; ok {
		t.Fatal("a merge into the replayed entity reached the cached one")
	}
	if out[1].Attributes != nil {
		t.Fatal("a nil attribute map was cloned into an empty one")
	}
	if CloneEntities(nil) != nil {
		t.Fatal("cloning nothing should stay nothing")
	}
}

func TestRebaseRenumbersEventAndID(t *testing.T) {
	ev := schema.Event{Sequence: 4, EventID: "evt-x-000004"}
	Rebase(&ev, "evt-x-%06d", 7)
	if ev.Sequence != 11 || ev.EventID != "evt-x-000011" {
		t.Fatalf("rebased to %d/%s", ev.Sequence, ev.EventID)
	}
	Rebase(&ev, "evt-x-%06d", 0)
	if ev.Sequence != 11 || ev.EventID != "evt-x-000011" {
		t.Fatalf("a zero delta changed the event: %d/%s", ev.Sequence, ev.EventID)
	}
}

// derived_from carries event ids, so it has to move with them. A reference
// the format does not explain is left alone rather than corrupted: losing
// the link is recoverable, pointing it at an unrelated event is not.
func TestRebaseRefsRenumbersAndLeavesUnknownFormsAlone(t *testing.T) {
	got := RebaseRefs([]string{"evt-000004", "evt-000000", "sha256:abcdef", ""}, "evt-%06d", 3)
	want := []string{"evt-000007", "evt-000003", "sha256:abcdef", ""}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("ref %d: got %q, want %q", i, got[i], want[i])
		}
	}
	if RebaseRefs([]string{"evt-000004"}, "evt-%06d", 0)[0] != "evt-000004" {
		t.Fatal("a zero delta renumbered a reference")
	}
}
