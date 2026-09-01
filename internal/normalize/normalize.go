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

// registry lists all product parsers. Order is deterministic.
var registry = []func(pkgDir string) (*schema.Normalized, error){
	claudejsonl.ParsePackage,
	codexjsonl.ParsePackage,
	genericchat.ParsePackage,
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
		ev := &n.Events[i]
		if ev.EventType == schema.EventToolCall && ev.Command != "" && ev.NetworkDest == "" {
			if dests := netdest.Extract(ev.Command); len(dests) > 0 {
				ev.NetworkDest = dests[0]
			}
		}
	}
}
