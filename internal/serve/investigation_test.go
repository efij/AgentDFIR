package serve

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/corpus"
	"github.com/efij/AgentDFIR/v4/internal/correlate"
	"github.com/efij/AgentDFIR/v4/internal/crosscase"
	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/lineage"
	"github.com/efij/AgentDFIR/v4/internal/overlay"
)

func loadSrv(t *testing.T, pkg string) (*Server, *httptest.Server) {
	t.Helper()
	s, err := Load(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(func() { srv.Close(); s.Close() })
	return s, srv
}

func getJSON(t *testing.T, srv *httptest.Server, path string) (int, map[string]any) {
	t.Helper()
	resp, body := get(t, srv, path, "")
	var v map[string]any
	_ = json.Unmarshal(body, &v)
	return resp.StatusCode, v
}

// removeOverlay deletes an overlay file in either of its stored forms, the
// way an old package (or an operator pruning derived data) leaves it.
func removeOverlay(t *testing.T, p string) {
	t.Helper()
	for _, f := range []string{p, p + ".gz"} {
		if err := os.Remove(f); err != nil && !os.IsNotExist(err) {
			t.Fatal(err)
		}
	}
}

// TestCoverageRoute: the stored report is served sanitized with its
// references resolved; a package without it, or with a report in another
// format, answers "not available" with the regenerate command, never 5xx.
func TestCoverageRoute(t *testing.T) {
	pkg := buildPkg(t)
	_, srv := loadSrv(t, pkg)
	code, v := getJSON(t, srv, "/api/coverage")
	if code != 200 || v["available"] != true {
		t.Fatalf("coverage: %d %v", code, v)
	}
	rep := v["report"].(map[string]any)
	if rep["schema"] != "agentdfir.coverage/1" || rep["items"] == nil {
		t.Fatalf("report: %v", rep)
	}

	cov := filepath.Join(pkg, "normalized", analysis.CoverageFile)
	// Another schema: UNSUPPORTED, not parsed.
	if err := overlay.WriteJSON(cov, map[string]any{"schema": "agentdfir.coverage/9", "items": []any{}}); err != nil {
		t.Fatal(err)
	}
	_, v = getJSON(t, srv, "/api/coverage")
	if v["available"] != false || !strings.Contains(v["reason"].(string), "UNSUPPORTED") {
		t.Fatalf("other schema: %v", v)
	}
	// Old package: no file at all.
	removeOverlay(t, cov)
	code, v = getJSON(t, srv, "/api/coverage")
	if code != 200 || v["available"] != false || !strings.Contains(v["regenerate"].(string), "agentdfir analyze") {
		t.Fatalf("missing coverage: %d %v", code, v)
	}
}

// TestCoverageRefsResolveSafely: references in the report resolve to the
// case's own events and artifacts; a reference naming an artifact the case
// does not have, or carrying a path, resolves to nothing.
func TestCoverageRefsResolveSafely(t *testing.T) {
	pkg := buildPkg(t)
	s, srv := loadSrv(t, pkg)
	ev := s.idx.At(1)
	art := ""
	if e, err := s.idx.Event(1); err == nil {
		art = e.SourceArtifact
	}
	good := fmt.Sprintf("%s:%d (artifact %s, offset %d)", ev.SourcePath, ev.SourceLine, art[:12], ev.SourceOffset)
	bad := "../../etc/passwd:1 (artifact deadbeefdead, offset 0)"
	esc := "x\x1b[31m:1 (artifact " + art[:12] + ", offset 0)"
	rep := map[string]any{"schema": "agentdfir.coverage/1", "items": []any{
		map[string]any{"status": "unknown", "category": "transcript", "text": "t\x1b[2Jx", "evidence_refs": []any{good, bad, esc}}}}
	if err := overlay.WriteJSON(filepath.Join(pkg, "normalized", analysis.CoverageFile), rep); err != nil {
		t.Fatal(err)
	}
	_, body := get(t, srv, "/api/coverage", "")
	if strings.Contains(string(body), `\u001b`) {
		t.Fatal("control characters reached the page")
	}
	var v struct {
		Refs map[string]map[string]any
	}
	_ = json.Unmarshal(body, &v)
	if loc := v.Refs[good]; loc == nil || loc["event_id"] != ev.EventID || loc["artifact"] != art {
		t.Fatalf("good ref: %v", v.Refs)
	}
	if v.Refs[bad] != nil {
		t.Fatalf("unknown artifact resolved: %v", v.Refs[bad])
	}
}

// TestLineageRoute covers the scopes, the selector validation (nothing in a
// selector is ever a path), the panel bounds and the missing overlay.
func TestLineageRoute(t *testing.T) {
	pkg := buildPkg(t)
	s, srv := loadSrv(t, pkg)

	code, v := getJSON(t, srv, "/api/lineage")
	if code != 200 || v["available"] != true || v["graph"] == nil {
		t.Fatalf("whole case: %d %v", code, v)
	}
	// A finding that cites a tool call: the graph holds it and its agent.
	fi := -1
	for i, f := range s.findings {
		if f.RuleID == "DESTRUCTIVE_COMMAND" {
			fi = i
		}
	}
	if fi < 0 {
		t.Fatal("fixture has no DESTRUCTIVE_COMMAND finding")
	}
	code, v = getJSON(t, srv, fmt.Sprintf("/api/lineage?finding=%d", fi))
	g, _ := v["graph"].(map[string]any)
	if code != 200 || g == nil {
		t.Fatalf("finding scope: %d %v", code, v)
	}
	kinds := map[string]bool{}
	for _, n := range g["nodes"].([]any) {
		kinds[n.(map[string]any)["kind"].(string)] = true
	}
	if !kinds["tool_call"] || !kinds["agent"] {
		t.Fatalf("finding graph kinds: %v", kinds)
	}
	if sc := g["scope"].(map[string]any); sc["finding"] != fmt.Sprint(fi) {
		t.Fatalf("scope: %v", sc)
	}
	code, v = getJSON(t, srv, "/api/lineage?session=s1")
	if code != 200 || v["graph"] == nil {
		t.Fatalf("session scope: %d %v", code, v)
	}
	for _, q := range []string{"finding=999", "finding=-1", "finding=01", "finding=1e2", "finding=" + url.QueryEscape("../../etc/passwd"),
		"session=" + url.QueryEscape("../../etc/passwd"), "session=" + url.QueryEscape("s1/../s1"), "session=nope"} {
		if resp, _ := get(t, srv, "/api/lineage?"+q, ""); resp.StatusCode != 404 {
			t.Errorf("%s: %d, want 404", q, resp.StatusCode)
		}
	}
	if resp, _ := get(t, srv, "/api/lineage?finding=0&session=s1", ""); resp.StatusCode != 400 {
		t.Errorf("both scopes: %d", resp.StatusCode)
	}

	// A stored whole-case graph larger than the panel is cut and says so,
	// and no edge points at a node the page does not have.
	big := &lineage.Graph{Schema: lineage.Schema}
	for i := 0; i < 500; i++ {
		big.Nodes = append(big.Nodes, lineage.Node{ID: fmt.Sprintf("file:/f%03d", i), Kind: "file", Label: fmt.Sprintf("/f%03d\x1b[31m", i)})
		if i > 0 {
			big.Edges = append(big.Edges, lineage.Edge{From: fmt.Sprintf("file:/f%03d", i-1), To: fmt.Sprintf("file:/f%03d", i), Relation: "touched"})
		}
	}
	lf := filepath.Join(pkg, "normalized", analysis.LineageFile)
	if err := overlay.WriteJSON(lf, big); err != nil {
		t.Fatal(err)
	}
	_, body := get(t, srv, "/api/lineage", "")
	var out struct {
		Graph lineage.Graph
	}
	_ = json.Unmarshal(body, &out)
	if len(out.Graph.Nodes) > panelMaxNodes || !out.Graph.Truncated || out.Graph.Omitted.Nodes != 500-panelMaxNodes {
		t.Fatalf("bound: %d nodes, truncated=%v omitted=%+v", len(out.Graph.Nodes), out.Graph.Truncated, out.Graph.Omitted)
	}
	have := map[string]bool{}
	for _, n := range out.Graph.Nodes {
		have[n.ID] = true
		if strings.Contains(n.Label, "\x1b") {
			t.Fatal("label not sanitized")
		}
	}
	for _, e := range out.Graph.Edges {
		if !have[e.From] || !have[e.To] {
			t.Fatalf("dangling edge %v", e)
		}
	}
	removeOverlay(t, lf)
	if _, v = getJSON(t, srv, "/api/lineage"); v["available"] != false || v["regenerate"] == nil {
		t.Fatalf("missing lineage: %v", v)
	}
	// Scoped graphs are built on demand and do not need the stored file.
	if code, v = getJSON(t, srv, "/api/lineage?session=s1"); code != 200 || v["graph"] == nil {
		t.Fatalf("session scope without the stored graph: %d %v", code, v)
	}
}

// TestWitnessRoute: no imported records → a plain answer; a paired event
// shows the agent's record next to the sanitized independent record; an
// unknown event id is a 404.
func TestWitnessRoute(t *testing.T) {
	pkg := buildPkg(t)
	_, srv := loadSrv(t, pkg)
	if _, v := getJSON(t, srv, "/api/witness"); v["available"] != false {
		t.Fatalf("no correlation: %v", v)
	}
	if resp, _ := get(t, srv, "/api/witness?event="+url.QueryEscape("../../x"), ""); resp.StatusCode != 404 {
		t.Fatalf("unknown event: %d", resp.StatusCode)
	}

	pkg2 := buildPkg(t)
	s2, err := Load(pkg2, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	var call string
	for i := 0; i < s2.idx.Len(); i++ {
		if e := s2.idx.At(i); e.EventType == "tool_call" {
			call = e.EventID
			break
		}
	}
	rec := endpoint.Record{Time: time.Date(2026, 8, 30, 10, 0, 6, 0, time.UTC), Kind: "process", PID: 42, Exe: "/bin/rm", Cmdline: "rm -rf build/\x1b]0;owned\x07", Source: "auditd", Ref: "audit.log:7"}
	s2.corr.once.Do(func() {
		s2.corr.res = &correlate.EndpointResult{Matches: []correlate.Match{{EventID: call, Witness: "endpoint", Score: 100, Basis: "same command line", Confidence: "HIGH", WindowMS: 3000, DeltaMS: 1000, Record: rec,
			Related: []correlate.RelatedRecord{{Basis: "endpoint pid", Record: endpoint.Record{Kind: "network", PID: 42, DestHost: "evil.example‮", Source: "auditd", Ref: "audit.log:8"}}}}}}
		s2.corr.byEvent = map[string][]int{call: {0}}
	})
	srv2 := httptest.NewServer(s2.Handler())
	defer srv2.Close()
	resp, body := get(t, srv2, "/api/witness?event="+url.QueryEscape(call), "")
	if resp.StatusCode != 200 || strings.Contains(string(body), `\u001b`) || strings.Contains(string(body), `‮`) || strings.Contains(string(body), "‮") {
		t.Fatalf("witness: %d %s", resp.StatusCode, body)
	}
	var w struct {
		Agent   map[string]any
		Matches []struct {
			Basis, Confidence string
			Record            map[string]any
			Related           []map[string]any
		}
	}
	_ = json.Unmarshal(body, &w)
	if w.Agent["id"] != call || len(w.Matches) != 1 || w.Matches[0].Confidence != "HIGH" || w.Matches[0].Record["pid"] != float64(42) || len(w.Matches[0].Related) != 1 {
		t.Fatalf("witness body: %+v", w)
	}
	_, v := getJSON(t, srv2, "/api/witness")
	if v["available"] != true || len(v["items"].([]any)) != 1 {
		t.Fatalf("witness list: %v", v)
	}
}

// TestConversationRoutes reads a synthetic provider export and synthetic
// browser history: sessions get the evidence's own names (never a raw
// web:… id), the evidence class, and branch markers.
func TestConversationRoutes(t *testing.T) {
	// An agent-only case has none, and says how to collect them.
	_, srv := loadSrv(t, buildPkg(t))
	if _, v := getJSON(t, srv, "/api/conversations"); v["available"] != false || v["howto"] == nil {
		t.Fatalf("agent-only case: %v", v)
	}
	if resp, _ := get(t, srv, "/api/conversation?session=s1", ""); resp.StatusCode != 404 {
		t.Fatalf("agent session listed as a conversation: %d", resp.StatusCode)
	}

	cases, err := corpus.Load(filepath.Join("..", "corpus", "testdata"))
	if err != nil {
		t.Fatal(err)
	}
	build := func(name string) string {
		for _, c := range cases {
			if c.Name == name {
				pkg := filepath.Join(t.TempDir(), name+".adfir")
				if err := corpus.BuildPackage(c, pkg, "CONV", "t"); err != nil {
					t.Fatal(err)
				}
				return pkg
			}
		}
		t.Fatalf("corpus case %s missing", name)
		return ""
	}

	_, srv = loadSrv(t, build("ai-export-ordinary-chats"))
	_, v := getJSON(t, srv, "/api/conversations")
	if v["available"] != true {
		t.Fatalf("export: %v", v)
	}
	branched := ""
	for _, it := range v["items"].([]any) {
		c := it.(map[string]any)
		if c["class"] == "provider_export" && c["named"] != true && c["prompts"].(float64) > 0 {
			t.Errorf("export conversation without its title: %v", c)
		}
		if c["branches"].(float64) > 0 {
			branched = c["id"].(string)
		}
	}
	if branched == "" {
		t.Fatal("no conversation reports its alternate branch")
	}
	_, v = getJSON(t, srv, "/api/conversation?session="+url.QueryEscape(branched))
	alt := 0
	for _, m := range v["messages"].([]any) {
		if m.(map[string]any)["branch"] == "alternate" {
			alt++
		}
	}
	if alt == 0 {
		t.Fatalf("no message marked as another branch: %v", v)
	}
	if resp, _ := get(t, srv, "/api/conversation?session="+url.QueryEscape("../"+branched), ""); resp.StatusCode != 404 {
		t.Fatalf("traversal-shaped session: %d", resp.StatusCode)
	}

	_, srv = loadSrv(t, build("browser-ai-share-link"))
	_, v = getJSON(t, srv, "/api/conversations")
	web := 0
	for _, it := range v["items"].([]any) {
		c := it.(map[string]any)
		if c["class"] != "browser-history" {
			t.Errorf("browser session with class %v", c["class"])
		}
		if strings.HasPrefix(c["id"].(string), "web:chatgpt:") {
			web++
			if l := c["label"].(string); l == "" || strings.HasPrefix(l, "web:") {
				t.Errorf("browser session shown by its id: %v", c)
			}
		}
	}
	if web == 0 {
		t.Fatal("no ChatGPT browser session")
	}
	// The Activity list names it too (/api/sessions label).
	_, body := get(t, srv, "/api/sessions", "")
	if !strings.Contains(string(body), `"label":"ChatGPT`) {
		t.Fatalf("/api/sessions has no readable label: %.400s", body)
	}
}

// TestExtensionsRoute: served when analysis wrote it, bounded, sanitized;
// missing on an old package.
func TestExtensionsRoute(t *testing.T) {
	pkg := buildPkg(t)
	_, srv := loadSrv(t, pkg)
	p := filepath.Join(pkg, "detections", "extensions.json")
	var exts []any
	for i := 0; i < 2100; i++ {
		exts = append(exts, map[string]any{"id": fmt.Sprintf("pub.ext%d​", i), "editor": "vscode"})
	}
	if err := overlay.WriteJSON(p, map[string]any{"inventory": map[string]any{"extensions": exts}, "findings": []any{}}); err != nil {
		t.Fatal(err)
	}
	_, body := get(t, srv, "/api/extensions", "")
	var v struct {
		Available bool
		Data      struct {
			Inventory map[string]any
		}
	}
	_ = json.Unmarshal(body, &v)
	if !v.Available || len(v.Data.Inventory["extensions"].([]any)) != 2000 || v.Data.Inventory["extensions_omitted"] != float64(100) {
		t.Fatalf("extensions: %.300s", body)
	}
	if strings.Contains(string(body), "​") || strings.Contains(string(body), `​`) {
		t.Fatal("zero-width character reached the page")
	}
	removeOverlay(t, p)
	if _, m := getJSON(t, srv, "/api/extensions"); m["available"] != false || m["regenerate"] == nil {
		t.Fatalf("missing: %v", m)
	}
}

// TestCompareRoute: without --compare the view says how; a refused second
// case shows the refusal; a compared one serves the sanitized report.
func TestCompareRoute(t *testing.T) {
	pkg := buildPkg(t)
	s, srv := loadSrv(t, pkg)
	if _, v := getJSON(t, srv, "/api/compare"); v["available"] != false || !strings.Contains(v["howto"].(string), "--compare") {
		t.Fatalf("no compare: %v", v)
	}
	refuse := func([]string, crosscase.Options) (*crosscase.Report, error) {
		return nil, &crosscase.RefusedError{Problems: []string{"C2 (b): seal does not verify\x1b[31m"}}
	}
	if err := s.setCompare("b", refuse, crosscase.Options{}); err == nil {
		t.Fatal("refusal not returned")
	}
	_, v := getJSON(t, srv, "/api/compare")
	if v["available"] != false || len(v["problems"].([]any)) != 1 || strings.Contains(fmt.Sprint(v["problems"]), "\x1b") {
		t.Fatalf("refused: %v", v)
	}
	other := buildPkg(t)
	if _, err := Load(other, Options{}); err != nil { // analyze it, as `serve` does for its own case
		t.Fatal(err)
	}
	ok := func(p []string, o crosscase.Options) (*crosscase.Report, error) {
		o.Verify = func(string) crosscase.Integrity { return crosscase.Integrity{Result: "VERIFIED", Signature: "none"} }
		return crosscase.Run(p, o)
	}
	if err := s.setCompare(other, ok, crosscase.Options{}); err != nil {
		var re *crosscase.RefusedError
		if errors.As(err, &re) {
			t.Fatalf("compare refused: %v", re.Problems)
		}
		t.Fatal(err)
	}
	_, v = getJSON(t, srv, "/api/compare")
	rep, _ := v["report"].(map[string]any)
	if v["available"] != true || rep == nil || len(rep["cases"].([]any)) != 2 || len(rep["shared"].([]any)) == 0 {
		t.Fatalf("compare: %v", v)
	}
}
