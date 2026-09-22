// Package serve hosts a local-only, read-only case explorer for one .adfir
// package: agent tree, timeline with density scrubber, evidence pane with
// the raw transcript line, findings, topology, and the MCP / provenance /
// corroboration results when present.
//
// Security posture: binds 127.0.0.1 only; no external resources (CSP
// self-only, like the HTML report); Host header must be loopback (DNS
// rebinding); every evidence string is sanitized before it leaves the
// process and rendered with textContent on the client; nothing is ever
// written to the package.
package serve

import (
	"bufio"
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/efij/AgentDFIR/v2/internal/analysis"
	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/chain"
	"github.com/efij/AgentDFIR/v2/internal/index"
	"github.com/efij/AgentDFIR/v2/internal/notes"
	"github.com/efij/AgentDFIR/v2/internal/overlay"
	"github.com/efij/AgentDFIR/v2/internal/report"
	"github.com/efij/AgentDFIR/v2/internal/sanitize"
	"github.com/efij/AgentDFIR/v2/internal/schema"
	"github.com/efij/AgentDFIR/v2/internal/seal"
	"github.com/efij/AgentDFIR/v2/internal/verify"
	"github.com/efij/AgentDFIR/v2/internal/version"
)

//go:embed ui.html
var uiHTML []byte

// Options configures the server.
type Options struct {
	Port int // 0 = ephemeral
	// MaxEvents is accepted and ignored. The explorer used to hold every
	// event in memory and cap the case at 500,000 of them; a real package
	// is 206,896 events and hundreds of MB of RSS, and on anything past the
	// cap the tail of the case was simply absent from the UI. Events now
	// live on disk behind an offset index, so there is nothing to bound.
	MaxEvents int
}

// Server holds the loaded case.
type Server struct {
	pkg      string
	man      *casepkg.Manifest
	arts     []casepkg.ArtifactRecord // the case as it now stands (newest round per source)
	store    *casepkg.Store
	info     *casepkg.CaseInfo
	verify   *casepkg.VerifyResult
	sig      string
	idx      *index.Index // the whole overlay, by offset; full events read on demand
	findings []schema.Finding
	entities []schema.Entity
	rels     []schema.Relationship
	byRef    map[string]string   // evidence reference → event id
	flagged  map[string][]string // event id → rule ids citing it
	notes    *notes.Store
	mu       sync.RWMutex

	// Timeline queries that carry free text have to read the candidate
	// events back off disk, so the last few result sets are kept: the UI
	// pages through one screen at a time and re-scanning the case for every
	// page would undo the point of the index.
	qmu   sync.Mutex
	qhits map[string][]int
}

// Load reads (normalizing if needed) everything the UI serves.
func Load(pkg string, opts Options) (*Server, error) {
	man, err := report.ReadManifest(pkg)
	if err != nil {
		return nil, err
	}
	s := &Server{pkg: pkg, man: man, arts: man.Current(), store: casepkg.NewStore(pkg, man)}
	s.info, _ = report.ReadCaseInfo(pkg)
	// Quick verification: the seal over the small sealed files, both hash
	// chains end to end, the manifest cross-check and every blob's
	// presence. Re-hashing gigabytes of evidence on every open would make
	// the explorer unusable on a real case; `agentdfir verify` still runs
	// the full check, and the UI offers it explicitly.
	s.verify, _ = casepkg.VerifyQuick(pkg)
	if sr, err := seal.Verify(pkg, ""); err != nil {
		s.sig = "error: " + err.Error()
	} else if !sr.Present {
		s.sig = "unsigned"
	} else if sr.Valid {
		s.sig = "VALID (" + sr.PublicKey[:min(16, len(sr.PublicKey))] + "…)"
	} else {
		s.sig = "INVALID — " + sr.Reason
	}

	// Analysis is never "not run yet": compute it when missing or stale.
	if _, err := analysis.Ensure(pkg, os.Stdout); err != nil {
		return nil, err
	}
	// Entities and relationships are read whole, so they come through the
	// compressed overlay. Events do not: the index addresses them by byte
	// offset, which is why events.jsonl stays uncompressed.
	s.entities = overlay.ReadJSONL[schema.Entity](filepath.Join(pkg, "normalized", "entities.jsonl"))
	s.rels = overlay.ReadJSONL[schema.Relationship](filepath.Join(pkg, "normalized", "relationships.jsonl"))
	// The event index: offsets plus the compact summary every list and
	// filter runs on. analysis.Run leaves one behind; a package from an
	// older version, or one whose index was deleted (it is derived, so
	// deleting it is allowed), gets one built here.
	x, err := index.Open(pkg)
	if err != nil {
		return nil, err
	}
	s.idx = x
	s.qhits = map[string][]int{}
	s.findings = analysis.LoadFindings(pkg)
	// The evidence-reference lookup, built from the index instead of from a
	// slice of events, so nothing has to be resident to resolve a finding
	// to the event it cites.
	s.byRef = make(map[string]string, x.Len()*2)
	for i, n := 0, x.Len(); i < n; i++ {
		e := x.At(i)
		chain.AddRefs(s.byRef, e.SourcePath, e.SourceLine, e.SourceOffset, e.EventID)
	}
	s.flagged = map[string][]string{}
	for _, f := range s.findings {
		seen := map[string]bool{}
		for _, ref := range f.EvidenceRefs {
			if id := chain.EventForRef(s.byRef, ref); id != "" && !seen[id] {
				seen[id] = true
				s.flagged[id] = append(s.flagged[id], f.RuleID)
			}
		}
		for _, st := range f.ChainSteps {
			if !seen[st.EventID] {
				seen[st.EventID] = true
				s.flagged[st.EventID] = append(s.flagged[st.EventID], f.RuleID)
			}
		}
	}
	s.notes = notes.Open(pkg)
	return s, nil
}

// Close releases what Load opened. The index keeps normalized/events.jsonl
// open for the whole life of the server — that is the point of it, events
// are read back by byte offset on demand — so a caller that finishes with a
// Server has to say so.
//
// It matters beyond tidiness on Windows, where a file with an open handle
// cannot be unlinked: a leaked index makes the case directory itself
// undeletable. That is the same defect casepkg.Builder.Close was written to
// fix, in a different package.
func (s *Server) Close() error {
	if s.idx == nil {
		return nil
	}
	err := s.idx.Close()
	s.idx = nil
	return err
}

// ListenAndServe binds loopback and serves until the listener fails.
// The returned URL is printed by the caller.
func (s *Server) Listen(port int) (net.Listener, string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return nil, "", err
	}
	return ln, "http://" + ln.Addr().String() + "/", nil
}

// Handler builds the HTTP mux.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.ui)
	mux.HandleFunc("/api/case", s.apiCase)
	mux.HandleFunc("/api/verify", s.apiVerify)
	mux.HandleFunc("/api/groups", s.apiGroups)
	mux.HandleFunc("/api/events", s.apiEvents)
	mux.HandleFunc("/api/event/", s.apiEvent)
	mux.HandleFunc("/api/raw", s.apiRaw)
	mux.HandleFunc("/api/findings", s.apiFindings)
	mux.HandleFunc("/api/graph", s.apiGraph)
	mux.HandleFunc("/api/buckets", s.apiBuckets)
	mux.HandleFunc("/api/extras", s.apiExtras)
	mux.HandleFunc("/api/sessions", s.apiSessions)
	mux.HandleFunc("/api/chain", s.apiChain)
	mux.HandleFunc("/api/search", s.apiSearch)
	mux.HandleFunc("/api/notes", s.apiNotes)
	return guard(mux)
}

// guard enforces loopback Host (DNS-rebinding defence), read-only methods
// and a strict CSP.
func guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host != "127.0.0.1" && host != "localhost" && host != "::1" && host != "[::1]" {
			http.Error(w, "forbidden host", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			// The one write: analyst notes, which live outside the sealed zone.
			// Same-origin only (no cross-site form or fetch can carry the header),
			// so a page in another tab cannot forge case-file entries.
			if r.Method != http.MethodPost || r.URL.Path != "/api/notes" || r.Header.Get("X-AgentDFIR-Notes") != "1" ||
				(r.Header.Get("Sec-Fetch-Site") != "" && r.Header.Get("Sec-Fetch-Site") != "same-origin") ||
				!originIsLoopback(r.Header.Get("Origin")) {
				http.Error(w, "read-only", http.StatusMethodNotAllowed)
				return
			}
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

// originIsLoopback accepts a missing Origin (same-origin fetch in most
// browsers sends it, but not all) or one that names the loopback host.
func originIsLoopback(o string) bool {
	if o == "" {
		return true
	}
	o = strings.TrimPrefix(o, "http://")
	if h, _, err := net.SplitHostPort(o); err == nil {
		o = h
	}
	return o == "127.0.0.1" || o == "localhost" || o == "::1" || o == "[::1]"
}

func (s *Server) ui(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(uiHTML)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	_ = enc.Encode(v)
}

// ---- /api/case ----

func (s *Server) apiCase(w http.ResponseWriter, r *http.Request) {
	types := map[string]int{}
	states := map[string]int{}
	sessions := map[string]bool{}
	agents := map[string]bool{}
	var first, last string
	for i, n := 0, s.idx.Len(); i < n; i++ {
		e := s.idx.At(i)
		types[e.EventType]++
		states[e.Corroboration]++
		if e.SessionID != "" {
			sessions[e.SessionID] = true
		}
		if e.AgentID != "" {
			agents[e.AgentID] = true
		}
		if e.Timestamp != "" {
			if first == "" || e.Timestamp < first {
				first = e.Timestamp
			}
			if e.Timestamp > last {
				last = e.Timestamp
			}
		}
	}
	sev := map[string]int{}
	chains := 0
	for _, f := range s.findings {
		sev[f.Severity]++
		if len(f.ChainSteps) > 0 {
			chains++
		}
	}
	nst, _ := s.notes.Load()
	out := map[string]any{
		"chains":    chains,
		"notes":     map[string]any{"records": nst.Records, "verdicts": len(nst.Verdicts), "pins": len(nst.Pins), "chain_ok": nst.ChainOK},
		"version":   version.Version,
		"package":   filepath.Base(s.pkg),
		"manifest":  s.man,
		"case":      s.info,
		"verify":    s.verify,
		"signature": s.sig,
		"events":    s.idx.Len(),
		// Kept in the shape the UI reads, and now always false: the index
		// covers the whole overlay, so there is no tail to hide.
		"truncated": false,
		"sessions":  len(sessions),
		"agents":    len(agents),
		"artifacts": len(s.arts),
		"findings":  len(s.findings),
		"severity":  sev,
		"types":     types,
		"states":    states,
		"first":     first,
		"last":      last,
	}
	// Strip potentially long arrays we don't need client-side.
	out["manifest"] = map[string]any{"case_id": s.man.CaseID, "host": s.man.Host, "os": s.man.OS, "arch": s.man.Arch,
		"created_utc": s.man.CreatedUTC, "collector_version": s.man.CollectorVersion, "adfir_version": s.man.ADFIRVersion}
	writeJSON(w, out)
}

// ---- /api/events ----

func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	offset, _ := strconv.Atoi(q.Get("offset"))
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 500 {
		limit = 200
	}
	matched := s.match(filter{
		session: q.Get("session"), agent: q.Get("agent"), typ: q.Get("type"), state: q.Get("state"),
		text: strings.ToLower(q.Get("q")), from: q.Get("from"), to: q.Get("to"),
	})
	total := len(matched)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	items := make([]map[string]any, 0, end-offset)
	for _, i := range matched[offset:end] {
		ev, err := s.idx.Event(i)
		if err != nil {
			continue
		}
		items = append(items, rowOf(ev))
	}
	writeJSON(w, map[string]any{"total": total, "offset": offset, "items": items})
}

// filter is one timeline query.
type filter struct{ session, agent, typ, state, text, from, to string }

func (f filter) key() string {
	return strings.Join([]string{f.session, f.agent, f.typ, f.state, f.text, f.from, f.to}, "\x00")
}

// match returns the positions of the events a query selects, in overlay
// order. Everything but the free-text term is answered from the index
// summaries and touches no disk at all; a text term is matched against the
// same six fields as before, which means reading those candidates back —
// so the result is cached against the query, because the UI asks for it
// once per page of 200.
func (s *Server) match(f filter) []int {
	key := f.key()
	if f.text != "" {
		s.qmu.Lock()
		hits, ok := s.qhits[key]
		s.qmu.Unlock()
		if ok {
			return hits
		}
	}
	x := s.idx
	var matched []int
	var buf []byte
	for i, n := 0, x.Len(); i < n; i++ {
		e := x.At(i)
		if f.session != "" && e.SessionID != f.session {
			continue
		}
		if f.agent != "" && e.AgentID != f.agent {
			continue
		}
		if f.typ != "" && e.EventType != f.typ {
			continue
		}
		if f.state != "" && e.Corroboration != f.state {
			continue
		}
		if f.from != "" && e.Timestamp < f.from {
			continue
		}
		if f.to != "" && e.Timestamp > f.to {
			continue
		}
		if f.text != "" {
			b, err := x.Line(i, buf)
			if err != nil {
				continue
			}
			buf = b
			var ev schema.Event
			if json.Unmarshal(b, &ev) != nil {
				continue
			}
			if !strings.Contains(strings.ToLower(ev.Command+" "+ev.Summary+" "+ev.Tool+" "+ev.File+" "+ev.NetworkDest+" "+ev.MCPServer), f.text) {
				continue
			}
		}
		matched = append(matched, i)
	}
	if f.text != "" {
		s.qmu.Lock()
		if len(s.qhits) >= 8 { // the analyst is on a new question; the old lists are dead weight
			s.qhits = map[string][]int{}
		}
		s.qhits[key] = matched
		s.qmu.Unlock()
	}
	return matched
}

// rowOf is the compact, sanitized timeline row.
func rowOf(e schema.Event) map[string]any {
	what := e.Summary
	switch {
	case e.Command != "":
		what = e.Command
	case e.File != "":
		what = e.File
	}
	return map[string]any{
		"id": e.EventID, "ts": e.Timestamp, "type": e.EventType, "actor": e.ActorType, "session": e.SessionID,
		"agent": e.AgentID, "parent": e.ParentAgentID, "tool": sanitize.Terminal(e.Tool), "mcp": sanitize.Terminal(e.MCPServer),
		"what": sanitize.Terminal(trimTo(what, 240)), "state": e.Corroboration, "state_label": schema.Label(e.Corroboration),
		"dest": sanitize.Terminal(e.NetworkDest),
		"path": sanitize.Terminal(e.SourcePath), "line": e.SourceLine, "artifact": e.SourceArtifact, "offset": e.SourceOffset,
		"product": e.Product,
	}
}

// ---- /api/event/{id} ----

func (s *Server) apiEvent(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/event/")
	i, ok := s.idx.Lookup(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	e, err := s.idx.Event(i)
	if err != nil {
		http.Error(w, "event unreadable", http.StatusInternalServerError)
		return
	}
	// Sanitize free-text fields before they leave.
	e.Summary = sanitize.Terminal(e.Summary)
	e.Command = sanitize.Terminal(e.Command)
	e.File = sanitize.Terminal(e.File)
	e.Result = sanitize.Terminal(e.Result)
	e.SourcePath = sanitize.Terminal(e.SourcePath)
	writeJSON(w, e)
}

// ---- /api/raw ----

// apiRaw returns the exact transcript line an event points at (bounded,
// sanitized) so the analyst sees the evidence, not a summary.
func (s *Server) apiRaw(w http.ResponseWriter, r *http.Request) {
	art := r.URL.Query().Get("artifact")
	off, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	if art == "" || strings.ContainsAny(art, "/\\.") {
		http.Error(w, "bad artifact", http.StatusBadRequest)
		return
	}
	found := false
	for _, a := range s.arts {
		if a.ArtifactID == art {
			found = true
			break
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	f, err := s.store.OpenAt(art, off)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	rd := bufio.NewReaderSize(f, 1<<20)
	line, _ := rd.ReadString('\n')
	if len(line) > 256<<10 {
		line = line[:256<<10] + "… [truncated]"
	}
	pretty := line
	var anyJSON any
	if json.Unmarshal([]byte(strings.TrimSpace(line)), &anyJSON) == nil {
		if b, err := json.MarshalIndent(anyJSON, "", "  "); err == nil {
			pretty = string(b)
		}
	}
	writeJSON(w, map[string]any{"artifact": art, "offset": off, "raw": sanitize.Terminal(line), "pretty": sanitize.Terminal(pretty)})
}

// ---- /api/findings ----

func (s *Server) apiFindings(w http.ResponseWriter, r *http.Request) {
	out := make([]map[string]any, 0, len(s.findings))
	for i, f := range s.findings {
		out = append(out, s.findingRow(i, f))
	}
	// Worst first, and within a severity the finding most likely to be
	// real first: an analyst reading top-down sees CRITICAL/HIGH confidence
	// HIGH before the same severity at confidence LOW.
	sort.SliceStable(out, func(i, j int) bool {
		si, sj := sevRank(out[i]["severity"].(string)), sevRank(out[j]["severity"].(string))
		if si != sj {
			return si > sj
		}
		return confRank(out[i]["confidence"].(string)) > confRank(out[j]["confidence"].(string))
	})
	writeJSON(w, out)
}

// confRank orders confidence levels; unknown/empty sorts last.
func confRank(c string) int {
	switch c {
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

// findingRow is the sanitized finding the UI lists; chain findings carry
// their steps so the list can show "3 steps" and the tree can open instantly.
func (s *Server) findingRow(i int, f schema.Finding) map[string]any {
	evID := ""
	for _, ref := range f.EvidenceRefs {
		if evID = chain.EventForRef(s.byRef, ref); evID != "" {
			break
		}
	}
	if evID == "" && len(f.ChainSteps) > 0 {
		evID = f.ChainSteps[len(f.ChainSteps)-1].EventID
	}
	row := map[string]any{
		"index": i, "rule_id": f.RuleID, "severity": f.Severity, "title": sanitize.Terminal(f.Title),
		"description": sanitize.Terminal(f.Description), "session": f.SessionID, "agent": f.AgentID, "parent": f.ParentAgentID,
		"status": f.Status, "endpoint": f.Endpoint,
		"status_label": schema.Label(f.Status), "endpoint_label": schema.Label(f.Endpoint),
		"confidence": f.Confidence, "confidence_reasons": f.Reasons, "class": f.Class, "timestamp": f.Timestamp,
		"mitre_attack": f.MitreATTACK, "mitre_atlas": f.MitreATLAS,
		"evidence": sanitizeAll(f.EvidenceRefs), "related": sanitizeAll(f.Related), "false_positive": sanitize.Terminal(f.FalsePositive),
		"event_id": evID, "key": notes.FindingKey(f.RuleID, f.EvidenceRefs), "chain": len(f.ChainSteps) > 0,
	}
	if len(f.ChainSteps) > 0 {
		steps := make([]map[string]any, 0, len(f.ChainSteps))
		for _, st := range f.ChainSteps {
			steps = append(steps, map[string]any{"step": sanitize.Terminal(st.Step), "event_id": st.EventID, "ts": st.Timestamp, "agent": st.AgentID, "summary": sanitize.Terminal(st.Summary)})
		}
		row["steps"] = steps
	}
	return row
}

// ---- /api/graph ----

func (s *Server) apiGraph(w http.ResponseWriter, r *http.Request) {
	type node struct {
		ID, Kind, Label, Product string
		Session                  string
		Events                   int
		Orphan, Subagent         bool
	}
	nodes := map[string]*node{}
	edges := map[string]map[string]string{} // from -> to -> type
	addEdge := func(a, b, t string) {
		if edges[a] == nil {
			edges[a] = map[string]string{}
		}
		edges[a][b] = t
	}
	spawned := map[string]bool{}
	for i, n := 0, s.idx.Len(); i < n; i++ {
		e := s.idx.At(i)
		if e.SessionID != "" {
			if nodes["session:"+e.SessionID] == nil {
				nodes["session:"+e.SessionID] = &node{ID: "session:" + e.SessionID, Kind: "session", Label: e.SessionID, Product: e.Product, Session: e.SessionID}
			}
			nodes["session:"+e.SessionID].Events++
		}
		if e.AgentID != "" {
			id := "agent:" + e.AgentID
			if nodes[id] == nil {
				nodes[id] = &node{ID: id, Kind: "agent", Label: e.AgentID, Product: e.Product, Session: e.SessionID, Subagent: !strings.HasPrefix(e.AgentID, "main:")}
			}
			nodes[id].Events++
			addEdge("session:"+e.SessionID, id, "belongs_to")
			if e.ParentAgentID != "" && e.ParentAgentID != "UNKNOWN" {
				addEdge("agent:"+e.ParentAgentID, id, "spawned")
			}
		}
		if e.EventType == schema.EventAgentSpawn && e.TaskID != "" {
			spawned[e.TaskID] = true
			addEdge("agent:"+e.AgentID, "agent:"+e.TaskID, "spawned")
		}
	}
	for _, f := range s.findings {
		if f.RuleID == "ORPHAN_AGENT" && f.AgentID != "" {
			if n := nodes["agent:"+f.AgentID]; n != nil {
				n.Orphan = true
			}
		}
	}
	var nl []*node
	for _, n := range nodes {
		n.Label = sanitize.Terminal(n.Label)
		nl = append(nl, n)
	}
	sort.Slice(nl, func(i, j int) bool { return nl[i].ID < nl[j].ID })
	var el []map[string]string
	for a, m := range edges {
		for b, t := range m {
			if nodes[a] != nil && nodes[b] != nil {
				el = append(el, map[string]string{"from": a, "to": b, "type": t})
			}
		}
	}
	sort.Slice(el, func(i, j int) bool { return el[i]["from"]+el[i]["to"] < el[j]["from"]+el[j]["to"] })
	writeJSON(w, map[string]any{"nodes": nl, "edges": el})
}

// ---- /api/buckets ----

func (s *Server) apiBuckets(w http.ResponseWriter, r *http.Request) {
	buckets := map[string]int{}
	for i, n := 0, s.idx.Len(); i < n; i++ {
		e := s.idx.At(i)
		if len(e.Timestamp) >= 16 {
			buckets[e.Timestamp[:16]]++ // minute resolution
		}
	}
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		out = append(out, map[string]any{"t": k, "n": buckets[k]})
	}
	writeJSON(w, out)
}

// ---- /api/extras ----

func (s *Server) apiExtras(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{}
	for name, file := range map[string]string{"mcp": "mcp-audit.json", "enrich": "corroboration.json", "provenance": "provenance.json"} {
		data, err := overlay.ReadFile(filepath.Join(s.pkg, "detections", file))
		if err != nil {
			continue
		}
		var v any
		if json.Unmarshal(data, &v) == nil {
			out[name] = sanitizeJSON(v)
		}
	}
	writeJSON(w, out)
}

// sanitizeJSON walks arbitrary JSON and neutralizes terminal/invisible
// payloads in every string.
func sanitizeJSON(v any) any {
	switch t := v.(type) {
	case string:
		return sanitize.Terminal(t)
	case []any:
		for i := range t {
			t[i] = sanitizeJSON(t[i])
		}
		return t
	case map[string]any:
		for k, val := range t {
			t[k] = sanitizeJSON(val)
		}
		return t
	}
	return v
}

// ---- helpers ----

func sanitizeAll(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = sanitize.Terminal(s)
	}
	return out
}

func sevRank(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	case "INFO":
		return 1
	}
	return 0
}

func trimTo(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Serve runs the HTTP server on ln until it stops; idle timeouts keep a
// forgotten instance from holding sockets.
func (s *Server) Serve(ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	return srv.Serve(ln)
}

// Describe prints a one-line summary for the console.
func (s *Server) Describe() string {
	return fmt.Sprintf("%d events, %d findings, %d artifacts", s.idx.Len(), len(s.findings), len(s.arts))
}

// ---- /api/verify ----

// apiVerify re-runs verification on demand. Loading the case uses the
// quick depth so the explorer opens immediately; this is the explicit
// full check, re-hashing every stored blob and every chunked artifact's
// concatenation. It reads the package and writes nothing.
func (s *Server) apiVerify(w http.ResponseWriter, r *http.Request) {
	res, err := casepkg.Verify(s.pkg)
	if err != nil {
		http.Error(w, sanitize.Terminal(err.Error()), http.StatusInternalServerError)
		return
	}
	s.mu.Lock()
	s.verify = res
	s.mu.Unlock()
	writeJSON(w, res)
}

// ---- /api/groups ----

// apiGroups returns findings collapsed by rule and session. A real machine
// produced 592 HIGH and CRITICAL findings that were 85 groups; a flat list
// of the former is not something anyone reads.
func (s *Server) apiGroups(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	findings := s.findings
	s.mu.RUnlock()
	groups := verify.GroupBy(findings)
	out := make([]map[string]any, 0, len(groups))
	for _, g := range groups {
		members := make([]string, 0, len(g.Members))
		for _, m := range g.Members {
			members = append(members, sanitize.Terminal(m))
		}
		out = append(out, map[string]any{
			"rule_id": g.RuleID, "session_id": g.SessionID, "title": sanitize.Terminal(g.Title),
			"severity": g.Severity, "confidence": g.Confidence, "count": g.Count,
			"first_seen": g.First, "last_seen": g.Last, "members": members, "class": g.Class,
		})
	}
	writeJSON(w, map[string]any{"groups": out, "findings": len(findings)})
}
