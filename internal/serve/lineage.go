package serve

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strconv"

	"github.com/efij/AgentDFIR/v3/internal/analysis"
	"github.com/efij/AgentDFIR/v3/internal/chain"
	"github.com/efij/AgentDFIR/v3/internal/lineage"
	"github.com/efij/AgentDFIR/v3/internal/overlay"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// The lineage panel draws a finding's or a session's graph in the browser,
// so it is bounded far below the CLI's defaults: a few hundred boxes is
// what a screen can show, and the graph says when it was cut.
const (
	panelMaxNodes = 240
	panelMaxEdges = 600
)

// ---- /api/lineage ----

// apiLineage answers ?finding=<index> (the explorer's numbering, as in
// /api/findings) or ?session=<id> with that scope's graph, built by the
// lineage package's own scoping (the same code `agentdfir lineage
// --finding/--session` runs), and with no parameter the whole-case graph
// analysis stored in normalized/lineage.json. Selectors are matched
// against the case, never used as paths.
func (s *Server) apiLineage(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	finding, session := q.Get("finding"), q.Get("session")
	switch {
	case finding != "" && session != "":
		http.Error(w, "finding and session are exclusive", http.StatusBadRequest)
		return
	case finding == "" && session == "":
		g := s.storedLineage()
		if g == nil {
			s.missing(w, "This case has no lineage graph (normalized/lineage.json). It was analyzed by an older version, or the derived files were removed.")
			return
		}
		writeJSON(w, map[string]any{"available": true, "graph": sanitizeGraph(g)})
		return
	}
	key := "s\x00" + session
	if finding != "" {
		n, err := strconv.Atoi(finding)
		if err != nil || n < 0 || n >= len(s.findings) || strconv.Itoa(n) != finding {
			http.Error(w, "no such finding", http.StatusNotFound)
			return
		}
		key = "f\x00" + finding
	} else if !s.hasSession(session) {
		http.Error(w, "no such session", http.StatusNotFound)
		return
	}
	s.lmu.Lock()
	g, ok := s.lcache[key]
	s.lmu.Unlock()
	if !ok {
		var err error
		g, err = s.buildLineage(finding, session)
		if err != nil {
			writeJSON(w, map[string]any{"available": true, "graph": nil, "reason": sanitize.Terminal(err.Error())})
			return
		}
		g = sanitizeGraph(g)
		s.lmu.Lock()
		if s.lcache == nil || len(s.lcache) >= 32 {
			s.lcache = map[string]*lineage.Graph{}
		}
		s.lcache[key] = g
		s.lmu.Unlock()
	}
	writeJSON(w, map[string]any{"available": true, "graph": g})
}

// buildLineage reads only the events the scope can reach: the session's,
// or for a finding the sessions its cited events belong to (a subagent's
// records, its spawn record and the human prompt above it are in the same
// session). Everything else about the graph — which events a finding
// cites, the ancestry walk, the cut, the bounds — is lineage.Build.
func (s *Server) buildLineage(finding, session string) (*lineage.Graph, error) {
	sessions := map[string]bool{}
	if session != "" {
		sessions[session] = true
	} else {
		n, _ := strconv.Atoi(finding)
		f := s.findings[n]
		if f.SessionID != "" {
			sessions[f.SessionID] = true
		}
		ids := map[string]bool{}
		for _, ref := range f.EvidenceRefs {
			if id := chain.EventForRef(s.byRef, ref); id != "" {
				ids[id] = true
			}
		}
		for _, st := range f.ChainSteps {
			ids[st.EventID] = true
		}
		for id := range ids {
			if i, ok := s.idx.Lookup(id); ok {
				if sid := s.idx.At(i).SessionID; sid != "" {
					sessions[sid] = true
				}
			}
		}
	}
	events := make([]schema.Event, 0)
	for i, n := 0, s.idx.Len(); i < n; i++ {
		if !sessions[s.idx.At(i).SessionID] {
			continue
		}
		if ev, err := s.idx.Event(i); err == nil {
			events = append(events, ev)
		}
	}
	corr, _ := s.correlation()
	in := analysis.LineageInput(s.pkg, events, s.findings, corr)
	return lineage.Build(in, lineage.Options{SessionID: session, Finding: finding, MaxNodes: panelMaxNodes, MaxEdges: panelMaxEdges})
}

// storedLineage reads normalized/lineage.json, or nil.
func (s *Server) storedLineage() *lineage.Graph {
	data, err := overlay.ReadFile(filepath.Join(s.pkg, "normalized", analysis.LineageFile))
	if err != nil {
		return nil
	}
	var g lineage.Graph
	if json.Unmarshal(data, &g) != nil || g.Schema != lineage.Schema {
		return nil
	}
	// The stored graph is the whole case at the CLI's bounds; the page
	// draws at most the panel's, and says so.
	if len(g.Nodes) > panelMaxNodes || len(g.Edges) > panelMaxEdges {
		keep := map[string]bool{}
		if len(g.Nodes) > panelMaxNodes {
			g.Omitted.Nodes += len(g.Nodes) - panelMaxNodes
			g.Nodes = g.Nodes[:panelMaxNodes]
		}
		for _, n := range g.Nodes {
			keep[n.ID] = true
		}
		edges := g.Edges[:0]
		for _, e := range g.Edges {
			if keep[e.From] && keep[e.To] && len(edges) < panelMaxEdges {
				edges = append(edges, e)
			} else {
				g.Omitted.Edges++
			}
		}
		g.Edges = edges
		g.Truncated = true
		g.Notes = append(g.Notes, "the explorer draws at most "+strconv.Itoa(panelMaxNodes)+" boxes; open a finding or a conversation for its own graph, or run agentdfir lineage")
	}
	return &g
}

// hasSession reports whether any event carries the session id.
func (s *Server) hasSession(id string) bool {
	if id == "" {
		return false
	}
	for i, n := 0, s.idx.Len(); i < n; i++ {
		if s.idx.At(i).SessionID == id {
			return true
		}
	}
	return false
}

// sanitizeGraph neutralizes terminal and invisible payloads in every
// evidence-derived string of a graph (labels, attributes, bases, notes,
// paths). Credential masking was already applied by the lineage package.
func sanitizeGraph(g *lineage.Graph) *lineage.Graph {
	if g == nil {
		return nil
	}
	refs := func(rs []lineage.Ref) []lineage.Ref {
		for i := range rs {
			rs[i].Path = sanitize.Terminal(rs[i].Path)
			rs[i].External = sanitize.Terminal(rs[i].External)
			rs[i].EventID = sanitize.Terminal(rs[i].EventID)
			rs[i].ArtifactID = sanitize.Terminal(rs[i].ArtifactID)
		}
		return rs
	}
	for i := range g.Nodes {
		n := &g.Nodes[i]
		n.ID, n.Label = sanitize.Terminal(n.ID), sanitize.Terminal(n.Label)
		for k, v := range n.Attrs {
			n.Attrs[k] = sanitize.Terminal(v)
		}
		n.Refs = refs(n.Refs)
	}
	for i := range g.Edges {
		e := &g.Edges[i]
		e.From, e.To = sanitize.Terminal(e.From), sanitize.Terminal(e.To)
		e.Basis, e.Note, e.Relation = sanitize.Terminal(e.Basis), sanitize.Terminal(e.Note), sanitize.Terminal(e.Relation)
		e.Refs = refs(e.Refs)
	}
	g.Notes = sanitizeAll(g.Notes)
	g.Scope.SessionID = sanitize.Terminal(g.Scope.SessionID)
	g.Scope.Findings = sanitizeAll(g.Scope.Findings)
	g.CaseID = sanitize.Terminal(g.CaseID)
	return g
}
