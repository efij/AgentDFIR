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
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/efij/AgentDFIR/internal/analysis"
	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/report"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/seal"
	"github.com/efij/AgentDFIR/internal/version"
)

//go:embed ui.html
var uiHTML []byte

// Options configures the server.
type Options struct {
	Port      int // 0 = ephemeral
	MaxEvents int // bound on events held in memory (default 500000)
}

// Server holds the loaded case.
type Server struct {
	pkg       string
	man       *casepkg.Manifest
	info      *casepkg.CaseInfo
	verify    *casepkg.VerifyResult
	sig       string
	events    []schema.Event
	byID      map[string]int
	findings  []schema.Finding
	entities  []schema.Entity
	rels      []schema.Relationship
	truncated bool
	mu        sync.RWMutex
}

// Load reads (normalizing if needed) everything the UI serves.
func Load(pkg string, opts Options) (*Server, error) {
	if opts.MaxEvents <= 0 {
		opts.MaxEvents = 500000
	}
	man, err := report.ReadManifest(pkg)
	if err != nil {
		return nil, err
	}
	s := &Server{pkg: pkg, man: man, byID: map[string]int{}}
	s.info, _ = report.ReadCaseInfo(pkg)
	s.verify, _ = casepkg.Verify(pkg)
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
	evPath := filepath.Join(pkg, "normalized", "events.jsonl")
	s.entities = readJSONL[schema.Entity](filepath.Join(pkg, "normalized", "entities.jsonl"))
	s.rels = readJSONL[schema.Relationship](filepath.Join(pkg, "normalized", "relationships.jsonl"))
	f, err := os.Open(evPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		if len(s.events) >= opts.MaxEvents {
			s.truncated = true
			break
		}
		var ev schema.Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil {
			s.byID[ev.EventID] = len(s.events)
			s.events = append(s.events, ev)
		}
	}
	s.findings = analysis.LoadFindings(pkg)
	return s, nil
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
	mux.HandleFunc("/api/events", s.apiEvents)
	mux.HandleFunc("/api/event/", s.apiEvent)
	mux.HandleFunc("/api/raw", s.apiRaw)
	mux.HandleFunc("/api/findings", s.apiFindings)
	mux.HandleFunc("/api/graph", s.apiGraph)
	mux.HandleFunc("/api/buckets", s.apiBuckets)
	mux.HandleFunc("/api/extras", s.apiExtras)
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
			http.Error(w, "read-only", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src data:; connect-src 'self'; base-uri 'none'; form-action 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
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
	for _, e := range s.events {
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
	for _, f := range s.findings {
		sev[f.Severity]++
	}
	out := map[string]any{
		"version":   version.Version,
		"package":   filepath.Base(s.pkg),
		"manifest":  s.man,
		"case":      s.info,
		"verify":    s.verify,
		"signature": s.sig,
		"events":    len(s.events),
		"truncated": s.truncated,
		"sessions":  len(sessions),
		"agents":    len(agents),
		"artifacts": len(s.man.Artifacts),
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
	session, agent, typ, state := q.Get("session"), q.Get("agent"), q.Get("type"), q.Get("state")
	text := strings.ToLower(q.Get("q"))
	from, to := q.Get("from"), q.Get("to")
	var matched []int
	for i, e := range s.events {
		if session != "" && e.SessionID != session {
			continue
		}
		if agent != "" && e.AgentID != agent {
			continue
		}
		if typ != "" && e.EventType != typ {
			continue
		}
		if state != "" && e.Corroboration != state {
			continue
		}
		if from != "" && e.Timestamp < from {
			continue
		}
		if to != "" && e.Timestamp > to {
			continue
		}
		if text != "" && !strings.Contains(strings.ToLower(e.Command+" "+e.Summary+" "+e.Tool+" "+e.File+" "+e.NetworkDest+" "+e.MCPServer), text) {
			continue
		}
		matched = append(matched, i)
	}
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
		items = append(items, rowOf(s.events[i]))
	}
	writeJSON(w, map[string]any{"total": total, "offset": offset, "items": items})
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
		"what": sanitize.Terminal(trimTo(what, 240)), "state": e.Corroboration, "dest": sanitize.Terminal(e.NetworkDest),
		"path": sanitize.Terminal(e.SourcePath), "line": e.SourceLine, "artifact": e.SourceArtifact, "offset": e.SourceOffset,
		"product": e.Product,
	}
}

// ---- /api/event/{id} ----

func (s *Server) apiEvent(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/event/")
	i, ok := s.byID[id]
	if !ok {
		http.NotFound(w, r)
		return
	}
	e := s.events[i]
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
	for _, a := range s.man.Artifacts {
		if a.ArtifactID == art {
			found = true
			break
		}
	}
	if !found {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(filepath.Join(s.pkg, "raw", art))
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	if off > 0 {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			http.Error(w, "seek", http.StatusBadRequest)
			return
		}
	}
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
		evID := ""
		if len(f.EvidenceRefs) > 0 {
			evID = s.eventForRef(f.EvidenceRefs[0])
		}
		out = append(out, map[string]any{
			"index": i, "rule_id": f.RuleID, "severity": f.Severity, "title": sanitize.Terminal(f.Title),
			"description": sanitize.Terminal(f.Description), "session": f.SessionID, "agent": f.AgentID, "parent": f.ParentAgentID,
			"status": f.Status, "endpoint": f.Endpoint, "mitre_attack": f.MitreATTACK, "mitre_atlas": f.MitreATLAS,
			"evidence": sanitizeAll(f.EvidenceRefs), "related": sanitizeAll(f.Related), "false_positive": sanitize.Terminal(f.FalsePositive),
			"event_id": evID,
		})
	}
	sort.SliceStable(out, func(i, j int) bool {
		return sevRank(out[i]["severity"].(string)) > sevRank(out[j]["severity"].(string))
	})
	writeJSON(w, out)
}

// eventForRef resolves "path:line (artifact …)" to an event id.
func (s *Server) eventForRef(ref string) string {
	i := strings.Index(ref, " (artifact ")
	if i < 0 {
		return ""
	}
	pl := ref[:i]
	c := strings.LastIndex(pl, ":")
	if c < 0 {
		return ""
	}
	line, err := strconv.Atoi(pl[c+1:])
	if err != nil {
		return ""
	}
	path := pl[:c]
	for _, e := range s.events {
		if e.SourceLine == line && e.SourcePath == path {
			return e.EventID
		}
	}
	return ""
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
	for _, e := range s.events {
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
	for _, e := range s.events {
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
	for name, file := range map[string]string{"mcp": "mcp-audit.json", "corroboration": "corroboration.json", "provenance": "provenance.json"} {
		data, err := os.ReadFile(filepath.Join(s.pkg, "detections", file))
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

func readJSONL[T any](path string) []T {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var v T
		if json.Unmarshal(sc.Bytes(), &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

// Serve runs the HTTP server on ln until it stops; idle timeouts keep a
// forgotten instance from holding sockets.
func (s *Server) Serve(ln net.Listener) error {
	srv := &http.Server{Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second}
	return srv.Serve(ln)
}

// Describe prints a one-line summary for the console.
func (s *Server) Describe() string {
	return fmt.Sprintf("%d events, %d findings, %d artifacts", len(s.events), len(s.findings), len(s.man.Artifacts))
}
