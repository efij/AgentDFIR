// Package normalize runs every registered parser over a sealed package
// and merges their output into one schema.Normalized result. Adding a
// product parser means adding one entry to the registry — nothing in
// the analysis pipeline changes.
package normalize

import (
	"github.com/efij/AgentDFIR/internal/netdest"
	"github.com/efij/AgentDFIR/internal/parsers/claudejsonl"
	"github.com/efij/AgentDFIR/internal/parsers/codexjsonl"
	"github.com/efij/AgentDFIR/internal/parsers/genericchat"
	"github.com/efij/AgentDFIR/internal/schema"
)

// registry lists all product parsers (accumulating). Order is deterministic.
var registry = []func(pkgDir string) (*schema.Normalized, error){
	claudejsonl.ParsePackage,
	codexjsonl.ParsePackage,
	genericchat.ParsePackage,
}

// streamRegistry lists the sink-aware parser entrypoints, in the same
// order, so events are emitted without ever building a full slice.
var streamRegistry = []func(pkgDir string, sink func(schema.Event)) (*schema.Normalized, error){
	claudejsonl.StreamPackage,
	codexjsonl.StreamPackage,
	genericchat.StreamPackage,
}

// StreamResult carries the bounded (non-event) part of normalization
// plus the event count, when events were streamed to a sink instead of
// retained in memory.
type StreamResult struct {
	Entities      []schema.Entity
	Relationships []schema.Relationship
	EventCount    int
}

// ParseStream runs all parsers and calls sink for every normalized event
// as it is produced, retaining only entities/relationships in memory.
// This bounds analysis memory by entity/relationship count rather than
// event count. Enrichment (network_destination) is applied per event.
func ParseStream(pkgDir string, sink func(schema.Event) error) (*StreamResult, error) {
	merged := &schema.Normalized{}
	seenEnt := map[string]bool{}
	out := &StreamResult{}
	var sinkErr error
	for _, parse := range streamRegistry {
		res, err := parse(pkgDir, func(ev schema.Event) {
			if sinkErr != nil {
				return
			}
			enrichEvent(&ev)
			if e := sink(ev); e != nil {
				sinkErr = e
				return
			}
			out.EventCount++
		})
		if err != nil {
			return nil, err
		}
		if sinkErr != nil {
			return nil, sinkErr
		}
		for _, e := range res.Entities {
			if !seenEnt[e.EntityID] {
				seenEnt[e.EntityID] = true
				merged.Entities = append(merged.Entities, e)
			}
		}
		merged.Relationships = append(merged.Relationships, res.Relationships...)
	}
	out.Entities = merged.Entities
	out.Relationships = merged.Relationships
	return out, nil
}

// ParsePackage runs all parsers and merges results. Artifacts no parser
// claims remain preserved-but-unparsed evidence (never dropped).
func ParsePackage(pkgDir string) (*schema.Normalized, error) {
	merged := &schema.Normalized{}
	seenEnt := map[string]bool{}
	for _, parse := range registry {
		res, err := parse(pkgDir)
		if err != nil {
			return nil, err
		}
		merged.Events = append(merged.Events, res.Events...)
		for _, e := range res.Entities {
			if !seenEnt[e.EntityID] {
				seenEnt[e.EntityID] = true
				merged.Entities = append(merged.Entities, e)
			}
		}
		merged.Relationships = append(merged.Relationships, res.Relationships...)
	}
	enrich(merged)
	return merged, nil
}

// enrich derives cross-product fields from normalized content: network
// destinations referenced by agent-invoked commands (first destination
// on the event; all are available to rules via netdest.Extract).
func enrich(n *schema.Normalized) {
	for i := range n.Events {
		enrichEvent(&n.Events[i])
	}
}

func enrichEvent(ev *schema.Event) {
	if ev.EventType == schema.EventToolCall && ev.Command != "" && ev.NetworkDest == "" {
		if dests := netdest.Extract(ev.Command); len(dests) > 0 {
			ev.NetworkDest = dests[0]
		}
	}
}
