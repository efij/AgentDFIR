// Package segment is the contract between a product parser and the
// incremental events overlay. It lets a parser hand one artifact's worth
// of normalized output to a cache, and skip an artifact the cache has
// already normalized in an earlier round.
//
// Why it exists: collection has been incremental since v1.5.0 — a second
// `agentdfir run` against the same machine re-read 10 files and carried
// 8,269 forward. Analysis was not. Any new round invalidated the whole
// overlay, and on a real two-round package that meant 7 minutes 27
// seconds to re-parse 206,896 events out of artifacts that had not
// changed a byte.
//
// The reason it could not simply be skipped is that a parser carries
// state across artifacts: one monotonic sequence counter that names every
// event, one entity map merged over the whole package, and one
// relationship list de-duplicated over the whole package. Parse a subset
// and all three are wrong — which would silently corrupt the entity graph
// and the agent lineage the detection rules are built on.
//
// The contract here solves that by making a parser's per-artifact
// contribution replayable rather than re-derivable:
//
//   - Events are named from a sequence counter, so a cached artifact's
//     events can be rebased onto whatever counter value the artifact now
//     starts at (see Rebase).
//   - Entities and relationships are recorded as the *calls* the parser
//     made while reading the artifact, not as a merged result. Replaying
//     those calls through the parser's own addEntity/addRel gives exactly
//     the graph a full parse would have built, because both merges are
//     order-sensitive in the same way and idempotent on repeats.
//
// Nothing here decides what is cacheable; that is the cache's business.
package segment

import (
	"fmt"
	"strconv"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// Replay is one artifact's cached contribution to a parse. Events have
// already been written to the overlay by the cache; the parser only has
// to advance its sequence counter by Events and feed Entities and
// Relationships through its own merge, in this order.
type Replay struct {
	Events        int
	Entities      []schema.Entity
	Relationships []schema.Relationship
}

// Cache is a parser's view of the overlay. A parser calls Begin before
// each artifact it would read and End after each one it actually read.
//
// Begin returning a nil Replay means "no usable cache entry, parse it".
// Begin returning a non-nil Replay means the cache has already emitted
// that artifact's events and the parser must not open the artifact.
type Cache interface {
	Begin(art casepkg.ArtifactRecord, base int) (*Replay, error)
	End(art casepkg.ArtifactRecord, base, count int, ents []schema.Entity, rels []schema.Relationship) error
}

// Recorder collects one artifact's entity and relationship calls while it
// is being parsed fresh.
//
// It de-duplicates the way the parsers themselves do, because a transcript
// calls addEntity for the same session and agent on every single line and
// storing all of those would make the cache larger than the evidence. The
// two rules are chosen so replay cannot change the outcome:
//
//   - An entity call identical to the last call for that entity id is
//     dropped. Every parser's addEntity is idempotent on an identical
//     repeat, so dropping it is invisible. A call that differs (a new
//     attribute, say) is kept, in order, because the claude parser merges
//     attributes and the merge order decides the result.
//   - A relationship call is kept only if no earlier call in this artifact
//     had the same (from, to, type). That is addRel's own rule, so the
//     dropped ones would have been discarded anyway — whether the edge was
//     first seen in this artifact or in an earlier one.
type Recorder struct {
	Entities      []schema.Entity
	Relationships []schema.Relationship

	lastEnt map[string]schema.Entity
	seenRel map[string]bool
}

// Entity records one addEntity call.
//
// The attribute map is copied, not referenced. A parser merges attributes
// by writing into the map already held in its entity table, and that is
// the same map the caller just handed here — so a recorded call that kept
// the reference would keep changing after it was recorded, and end up
// persisted holding attributes contributed by later artifacts. Replaying
// it into a package those later artifacts are no longer part of would then
// reinstate them out of nothing.
func (r *Recorder) Entity(e schema.Entity) {
	if r.lastEnt == nil {
		r.lastEnt = map[string]schema.Entity{}
	}
	if e.Attributes != nil {
		// Copied even when empty: a parser that was handed a map merges
		// into it later, and replaying a nil where it expects a map would
		// panic on the first merge rather than diverge quietly.
		attrs := make(map[string]string, len(e.Attributes))
		for k, v := range e.Attributes {
			attrs[k] = v
		}
		e.Attributes = attrs
	}
	if prev, ok := r.lastEnt[e.EntityID]; ok && sameEntity(prev, e) {
		return
	}
	r.lastEnt[e.EntityID] = e
	r.Entities = append(r.Entities, e)
}

// Rel records one addRel call.
func (r *Recorder) Rel(rel schema.Relationship) {
	if r.seenRel == nil {
		r.seenRel = map[string]bool{}
	}
	key := rel.From + "\x00" + rel.To + "\x00" + rel.Type
	if r.seenRel[key] {
		return
	}
	r.seenRel[key] = true
	r.Relationships = append(r.Relationships, rel)
}

func sameEntity(a, b schema.Entity) bool {
	if a.EntityID != b.EntityID || a.Kind != b.Kind || a.Label != b.Label || a.Product != b.Product {
		return false
	}
	if len(a.Attributes) != len(b.Attributes) {
		return false
	}
	for k, v := range a.Attributes {
		if w, ok := b.Attributes[k]; !ok || w != v {
			return false
		}
	}
	return true
}

// CloneEntities copies a cached artifact's entity calls before they are
// replayed.
//
// The reason is the same one Entity copies for, in the other direction. A
// parser that already holds an entity merges new attributes by writing
// into the map it holds, and after a replay that map is the cache's own —
// so the next artifact's merge would write back into the cached segment,
// and the state file written at the end of the round would describe that
// segment as having contributed attributes it never saw. One round later
// the segment replays them into a package whose evidence no longer
// supports them.
func CloneEntities(ents []schema.Entity) []schema.Entity {
	if len(ents) == 0 {
		return nil
	}
	out := make([]schema.Entity, len(ents))
	copy(out, ents)
	for i := range out {
		if out[i].Attributes == nil {
			continue
		}
		attrs := make(map[string]string, len(out[i].Attributes))
		for k, v := range out[i].Attributes {
			attrs[k] = v
		}
		out[i].Attributes = attrs
	}
	return out
}

// Rebase moves a cached event from the sequence number it was written at
// to the one it now has. An artifact that grew, or one collected before it
// in an earlier round, shifts every following artifact's numbering, so a
// segment is only reusable if its contents can be renumbered.
//
// Event ids are the sequence number rendered with a per-parser prefix
// ("evt-", "evt-x-", "evt-g-"), so renumbering regenerates the id from the
// format the cache was told to use.
func Rebase(ev *schema.Event, idFormat string, delta int) {
	if delta == 0 {
		return
	}
	ev.Sequence += delta
	ev.EventID = fmt.Sprintf(idFormat, ev.Sequence)
}

// RebaseRefs renumbers event ids embedded in derived data (a
// relationship's derived_from). The ids are a fixed prefix followed by the
// decimal sequence number, so the trailing digit run is the number; a
// reference that does not end in digits is left alone rather than
// corrupted.
func RebaseRefs(refs []string, idFormat string, delta int) []string {
	if delta == 0 || len(refs) == 0 {
		return refs
	}
	out := make([]string, len(refs))
	for i, id := range refs {
		out[i] = rebaseID(id, idFormat, delta)
	}
	return out
}

func rebaseID(id, idFormat string, delta int) string {
	cut := len(id)
	for cut > 0 && id[cut-1] >= '0' && id[cut-1] <= '9' {
		cut--
	}
	if cut == len(id) {
		return id
	}
	n, err := strconv.Atoi(id[cut:])
	if err != nil {
		return id
	}
	return fmt.Sprintf(idFormat, n+delta)
}
