package serve

import (
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/correlate"
	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/proof"
	"github.com/efij/AgentDFIR/v5/internal/reconstruct"
	"github.com/efij/AgentDFIR/v5/internal/supplychain"
)

// hostile is evidence text built to break a page or a terminal: markup, an
// ANSI escape, an OSC title sequence and a right-to-left override.
const hostile = "<script>alert(1)</script><img src=x onerror=alert(2)>\x1b[2J\x1b]0;owned\x07‮exe.txt"

// assertClean: the body carries no control character, no bidi override
// and no raw markup (the JSON encoder escapes < and >, and the page renders
// text with textContent).
func assertClean(t *testing.T, what string, body []byte) {
	t.Helper()
	b := string(body)
	for _, bad := range []string{`\u001b`, `\u0007`, "\x1b", "‮", `‮`, "<script>", "<img"} {
		if strings.Contains(b, bad) {
			t.Fatalf("%s: %q reached the page: %.400s", what, bad, b)
		}
	}
}

// TestProofRoute: the proof report is computed on request from the case's
// own overlay, every action carries its claim, chain, assurance and
// limitations, and without telemetry the health is "none" with the note
// that nothing can be confirmed by the operating system.
func TestProofRoute(t *testing.T) {
	pkg := buildPkg(t)
	_, srv := loadSrv(t, pkg)
	code, v := getJSON(t, srv, "/api/proof")
	if code != 200 || v["available"] != true {
		t.Fatalf("proof: %d %v", code, v)
	}
	rep := v["report"].(map[string]any)
	if rep["schema"] != proof.Schema {
		t.Fatalf("schema: %v", rep["schema"])
	}
	acts, _ := rep["actions"].([]any)
	if len(acts) != 2 {
		t.Fatalf("want the 2 tool calls, got %d", len(acts))
	}
	for _, a := range acts {
		a := a.(map[string]any)
		for _, k := range []string{"claim", "chain", "confidence", "evidence_state", "limitations"} {
			if _, ok := a[k]; !ok {
				t.Fatalf("action lacks %s: %v", k, a)
			}
		}
		if c := a["confidence"]; c != "inferred" {
			t.Fatalf("no telemetry, yet confidence %v", c)
		}
	}
	tel := rep["telemetry"].(map[string]any)
	if tel["imported"] != false || !strings.Contains(tel["note"].(string), "no endpoint telemetry") {
		t.Fatalf("telemetry: %v", tel)
	}
	if hl := v["health"].(map[string]any); hl["verdict"] != "none" {
		t.Fatalf("health: %v", hl)
	}
	if !strings.Contains(v["cli"].(string), "agentdfir proof ") {
		t.Fatalf("cli: %v", v["cli"])
	}
	// A session the case does not have: said so, not a 5xx, and no
	// "re-run the analysis" advice that would not help.
	code, v = getJSON(t, srv, "/api/proof?session=nope")
	if code != 200 || v["available"] != false || !strings.Contains(v["reason"].(string), "nope") || v["regenerate"] != nil {
		t.Fatalf("unknown session: %d %v", code, v)
	}
}

// TestProofRouteHostileTelemetry: collection-health and coverage values in
// the correlation overlay are attacker-reachable (a crafted telemetry file
// name, a drop detail); they reach the page sanitized.
func TestProofRouteHostileTelemetry(t *testing.T) {
	pkg := buildPkg(t)
	_, srv := loadSrv(t, pkg)
	at := time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC)
	res := correlate.EndpointResult{Records: 3, WindowMS: 3000,
		Health: []endpoint.SourceHealth{
			{File: "audit-" + hostile + ".log", Records: 2, First: at, Last: at.Add(time.Minute), Verdict: endpoint.HealthPartial, Gaps: 1,
				Drops: []endpoint.DropSignal{{Signal: "lost-events", Detail: hostile, Count: 4}}},
			{File: "dns.log", Records: 1, Verdict: endpoint.HealthUnknown},
		},
		KindCoverage: []correlate.KindCoverage{{Host: hostile, Kind: "process", CountsAsCoverage: true, Records: 2, Start: at, End: at.Add(time.Minute), Health: endpoint.HealthPartial}},
	}
	cp := filepath.Join(pkg, "detections", "corroboration.json")
	removeOverlay(t, cp)
	if err := overlay.WriteJSON(cp, map[string]any{"summary": res}); err != nil {
		t.Fatal(err)
	}
	resp, body := get(t, srv, "/api/proof", "")
	if resp.StatusCode != 200 {
		t.Fatalf("proof: %d", resp.StatusCode)
	}
	assertClean(t, "proof", body)
	var v struct {
		Available bool
		Health    struct{ Verdict string }
		Report    struct {
			Telemetry struct {
				Imported bool
				Sources  []map[string]any
				Coverage []map[string]any
			}
		}
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatal(err)
	}
	if !v.Available || !v.Report.Telemetry.Imported || len(v.Report.Telemetry.Sources) != 2 || len(v.Report.Telemetry.Coverage) != 1 || v.Health.Verdict != endpoint.HealthPartial {
		t.Fatalf("telemetry: %+v", v)
	}
	if !strings.Contains(v.Report.Telemetry.Sources[0]["file"].(string), "alert(1)") {
		t.Fatalf("the file name was dropped instead of neutralized: %v", v.Report.Telemetry.Sources[0]["file"])
	}
}

// TestHealthRoute: the badge is the worst verdict across sources with the
// count of each; a verdict this version does not know counts as UNKNOWN,
// never HEALTHY; no telemetry answers "none" with the reason.
func TestHealthRoute(t *testing.T) {
	pkg := buildPkg(t)
	_, srv := loadSrv(t, pkg)
	code, v := getJSON(t, srv, "/api/health")
	if code != 200 || v["available"] != false || v["verdict"] != "none" || v["reason"] == nil {
		t.Fatalf("no telemetry: %d %v", code, v)
	}

	s2, err := Load(buildPkg(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.corr.once.Do(func() {
		s2.corr.res = &correlate.EndpointResult{Records: 9, Health: []endpoint.SourceHealth{
			{File: "a.evtx", Verdict: endpoint.HealthHealthy},
			{File: "b.json", Verdict: "BOGUS"},
			{File: hostile, Verdict: endpoint.HealthPartial, Gaps: 2, Note: hostile},
		}}
		s2.corr.byEvent = map[string][]int{}
	})
	srv2 := httptest.NewServer(s2.Handler())
	defer srv2.Close()
	resp, body := get(t, srv2, "/api/health", "")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	assertClean(t, "health", body)
	var h struct {
		Available bool
		Verdict   string
		Counts    map[string]int
		Sources   []map[string]any
	}
	_ = json.Unmarshal(body, &h)
	if !h.Available || h.Verdict != endpoint.HealthPartial || h.Counts[endpoint.HealthUnknown] != 1 || h.Counts[endpoint.HealthHealthy] != 1 || h.Counts["BOGUS"] != 0 {
		t.Fatalf("badge: %+v", h)
	}
	if h.Sources[0]["verdict"] != endpoint.HealthPartial || h.Sources[0]["gaps"] != float64(2) {
		t.Fatalf("worst source not first: %v", h.Sources)
	}
	if got := healthSummary([]endpoint.SourceHealth{{Verdict: endpoint.HealthHealthy}, {Verdict: endpoint.HealthUnknown}})["verdict"]; got != endpoint.HealthUnknown {
		t.Fatalf("UNKNOWN must outrank HEALTHY: %v", got)
	}
}

// TestSupplyChainRoute: the stored report is served with verified and
// inferred relationships apart; hostile component names are neutralized;
// another schema is UNSUPPORTED; a missing file answers with the command.
func TestSupplyChainRoute(t *testing.T) {
	pkg := buildPkg(t)
	_, srv := loadSrv(t, pkg)
	scp := filepath.Join(pkg, "normalized", supplychain.File)
	// What analysis wrote for this case, if anything, is served as is.
	if _, v := getJSON(t, srv, "/api/supplychain"); v["available"] == true {
		if v["report"].(map[string]any)["schema"] != supplychain.Schema {
			t.Fatalf("analysis report: %v", v)
		}
	}
	rep := supplychain.Report{Schema: supplychain.Schema, CaseID: "SRV", Window: "10m0s",
		Components: []supplychain.Component{{ID: "skill:x", Kind: supplychain.KindSkill, Name: hostile, Origin: supplychain.Origin{Type: "local", Trust: "unknown", Basis: hostile}}},
		Drift:      []supplychain.Drift{},
		Relations: supplychain.Relations{
			Verified: []supplychain.Relation{{From: "skill:x", To: "tool:1", Type: "invoked", Class: supplychain.Verified, Basis: "transcript names it"}},
			Inferred: []supplychain.Relation{{From: "skill:x", To: "tool:2", Type: "followed_by", Class: supplychain.Inferred, Basis: "within " + hostile}},
		},
		Timeline:    []supplychain.TimelineEntry{{Time: "2026-08-30T10:00:00Z", TimeSource: "log_record", Kind: "invocation", Component: "skill:x", Text: hostile}},
		Unsupported: []string{}, Notes: []string{}}
	removeOverlay(t, scp)
	if err := overlay.WriteJSON(scp, rep); err != nil {
		t.Fatal(err)
	}
	resp, body := get(t, srv, "/api/supplychain", "")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	assertClean(t, "supplychain", body)
	var v struct {
		Available bool
		Report    struct {
			Components []map[string]any
			Relations  struct{ Verified, Inferred []map[string]any }
			Timeline   []map[string]any
		}
	}
	_ = json.Unmarshal(body, &v)
	if !v.Available || len(v.Report.Components) != 1 || len(v.Report.Relations.Verified) != 1 || len(v.Report.Relations.Inferred) != 1 || len(v.Report.Timeline) != 1 {
		t.Fatalf("supplychain: %+v", v)
	}
	if v.Report.Relations.Verified[0]["class"] != "verified" || v.Report.Relations.Inferred[0]["class"] != "inferred" {
		t.Fatalf("classes mixed: %+v", v.Report.Relations)
	}

	if err := overlay.WriteJSON(scp, map[string]any{"schema": "agentdfir.supplychain/9"}); err != nil {
		t.Fatal(err)
	}
	if _, v := getJSON(t, srv, "/api/supplychain"); v["available"] != false || !strings.Contains(v["reason"].(string), "UNSUPPORTED") {
		t.Fatalf("other schema: %v", v)
	}
	removeOverlay(t, scp)
	code, m := getJSON(t, srv, "/api/supplychain")
	if code != 200 || m["available"] != false || !strings.Contains(m["regenerate"].(string), "agentdfir analyze") {
		t.Fatalf("missing: %d %v", code, m)
	}
}

// TestReconstructRoute: without normalized/reconstruct.json the answer is
// the exact command; with one written by the real reconstruction it is
// served whole; hostile timeline text is neutralized; another schema is
// UNSUPPORTED.
func TestReconstructRoute(t *testing.T) {
	pkg := buildPkg(t)
	_, srv := loadSrv(t, pkg)
	code, v := getJSON(t, srv, "/api/reconstruct")
	if code != 200 || v["available"] != false || v["regenerate"] != "agentdfir reconstruct "+pkg {
		t.Fatalf("missing: %d %v", code, v)
	}

	rep, err := reconstruct.Run([]string{pkg}, reconstruct.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := reconstruct.WriteOverlay(pkg, rep); err != nil {
		t.Fatal(err)
	}
	_, v = getJSON(t, srv, "/api/reconstruct")
	r, _ := v["report"].(map[string]any)
	if v["available"] != true || r["schema"] != reconstruct.Schema {
		t.Fatalf("real reconstruction: %v", v)
	}
	for _, k := range []string{"timeline", "delegations", "handoffs", "stages", "missing_evidence"} {
		if _, ok := r[k]; !ok {
			t.Fatalf("reconstruction lacks %s", k)
		}
	}
	if len(r["timeline"].([]any)) == 0 {
		t.Fatal("empty timeline for a case with events")
	}

	rep.Timeline = append(rep.Timeline, reconstruct.Entry{Seq: 999, Case: "C1", Kind: "tool_call", Summary: hostile, Ref: hostile})
	rep.Missing = append(rep.Missing, reconstruct.Missing{Scope: "case", Target: hostile, Status: "unknown", Category: "x", Text: hostile, Source: "reconstruct"})
	if err := reconstruct.WriteOverlay(pkg, rep); err != nil {
		t.Fatal(err)
	}
	_, body := get(t, srv, "/api/reconstruct", "")
	assertClean(t, "reconstruct", body)

	if err := overlay.WriteJSON(filepath.Join(pkg, "normalized", reconstruct.OverlayFile), map[string]any{"schema": "agentdfir.reconstruct/9"}); err != nil {
		t.Fatal(err)
	}
	if _, v := getJSON(t, srv, "/api/reconstruct"); v["available"] != false || !strings.Contains(v["reason"].(string), "UNSUPPORTED") || v["regenerate"] == nil {
		t.Fatalf("other schema: %v", v)
	}
}

// TestV45ViewsReachable: the Proof, Supply chain and Reconstruct views are
// in the navigation and the palette with their renderers and routes, the
// collection-health badge opens the proof view's health section, and the
// Coverage view shows per-kind coverage and collection health.
func TestV45ViewsReachable(t *testing.T) {
	ui := string(uiHTML)
	for _, want := range []string{
		`data-m="proof"`, `data-m="supplychain"`, `data-m="reconstruct"`,
		`['proof','Proof',`, `['supplychain','Supply chain',`, `['reconstruct','Reconstruct',`,
		"if(moreTab==='proof') return renderProof(box);", "if(moreTab==='supplychain') return renderSupplyChain(box);", "if(moreTab==='reconstruct') return renderReconstruct(box);",
		"api('/api/proof')", "api('/api/health')", "api('/api/supplychain')", "api('/api/reconstruct')",
		`id="healthb"`, "$('#healthb').addEventListener('click',openProofHealth);", "loadHealthBadge();", "'proof-health'", "title:'Collection health'",
		"healthSection(sw.collection_health,sw.kind_coverage,", "'Telemetry coverage & health'",
		"' Verified relationships'", "' Inferred relationships'",
		"'Evidence chain'", "Human → Agent → Tool → Process → File/Network → Outcome",
		"notInCase(box,'No proof report',d)", "notInCase(box,'No supply-chain report',d)", "'No reconstruction in this case'",
	} {
		if !strings.Contains(ui, want) {
			t.Errorf("ui.html lost %q", want)
		}
	}
}

// TestNewViewsRedactSecrets: a token-shaped value in supply-chain drift
// (a settings change that added an environment variable), in a
// reconstruction and in collection health never leaves the process raw.
func TestNewViewsRedactSecrets(t *testing.T) {
	const gh = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"
	const aws = "AKIA" + "IOSFODNN7EXAMPLE"
	pkg := buildPkg(t)
	_, srv := loadSrv(t, pkg)
	rep := supplychain.Report{Schema: supplychain.Schema, CaseID: "SRV", Window: "10m0s",
		Components: []supplychain.Component{},
		Drift: []supplychain.Drift{{Kind: "settings_changed", Component: "settings:x", Subject: "env",
			From: supplychain.Snapshot{Label: "round 1"}, To: supplychain.Snapshot{Label: "round 2"},
			Added: []string{"GITHUB_TOKEN=" + gh}, Removed: []string{"AWS_ACCESS_KEY_ID=" + aws}, Changed: []string{"token " + gh},
			Expansion: []string{"Bash(curl -H 'Authorization: token " + gh + "')"}, Class: supplychain.Verified, Basis: gh}},
		Relations:   supplychain.Relations{Verified: []supplychain.Relation{}, Inferred: []supplychain.Relation{}},
		Unsupported: []string{"unsupported " + gh}, Notes: []string{aws}}
	scp := filepath.Join(pkg, "normalized", supplychain.File)
	removeOverlay(t, scp)
	if err := overlay.WriteJSON(scp, rep); err != nil {
		t.Fatal(err)
	}
	_, body := get(t, srv, "/api/supplychain", "")
	if strings.Contains(string(body), gh) || strings.Contains(string(body), aws) {
		t.Fatalf("secret reached the page: %s", body)
	}
	if !strings.Contains(string(body), "[REDACTED:secret:") || !strings.Contains(string(body), "GITHUB_TOKEN=") {
		t.Fatalf("drift lost instead of masked: %s", body)
	}

	rr, err := reconstruct.Run([]string{pkg}, reconstruct.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rr.Timeline = append(rr.Timeline, reconstruct.Entry{Seq: 999, Case: "C1", Kind: "tool_call", Summary: "export GITHUB_TOKEN=" + gh})
	rr.Notes = append(rr.Notes, aws)
	if err := reconstruct.WriteOverlay(pkg, rr); err != nil {
		t.Fatal(err)
	}
	_, body = get(t, srv, "/api/reconstruct", "")
	if strings.Contains(string(body), gh) || strings.Contains(string(body), aws) {
		t.Fatalf("secret reached the page: %.400s", body)
	}

	s2, err := Load(buildPkg(t), Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.corr.once.Do(func() {
		s2.corr.res = &correlate.EndpointResult{Records: 1, Health: []endpoint.SourceHealth{{File: gh + ".log", Verdict: endpoint.HealthPartial, Note: aws}}}
		s2.corr.byEvent = map[string][]int{}
	})
	srv2 := httptest.NewServer(s2.Handler())
	defer srv2.Close()
	_, body = get(t, srv2, "/api/health", "")
	if strings.Contains(string(body), gh) || strings.Contains(string(body), aws) {
		t.Fatalf("secret reached the badge: %s", body)
	}
}
