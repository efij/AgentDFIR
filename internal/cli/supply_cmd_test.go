package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/collector"
	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/products"
	"github.com/efij/AgentDFIR/v5/internal/supplychain"
)

// twoRoundPackage collects round1 and then round2 of a fixture home into
// one case, the way a repeat `run` adds a round.
func twoRoundPackage(t *testing.T, fixture string) string {
	t.Helper()
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	man, err := products.ManifestAllPlatforms("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	// One home path for both rounds, as on a real machine: the second round
	// replaces the first round's files in place.
	root := filepath.Join(t.TempDir(), "home")
	for i, r := range []string{"round1", "round2"} {
		if err := os.RemoveAll(root); err != nil {
			t.Fatal(err)
		}
		if err := os.CopyFS(root, os.DirFS(filepath.Join("..", "supplychain", "testdata", fixture, r))); err != nil {
			t.Fatal(err)
		}
		var b *casepkg.Builder
		if i == 0 {
			b, err = casepkg.New(pkg, "SUPPLY-"+fixture, casepkg.CaseInfo{OperatorOSUser: "tester"})
		} else {
			b, err = casepkg.Reopen(pkg, casepkg.CaseInfo{OperatorOSUser: "tester"})
		}
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
	}
	return pkg
}

func supplyReport(t *testing.T, pkg string, args ...string) *supplychain.Report {
	t.Helper()
	code, out := capture(t, append([]string{"supply-chain", pkg, "--json"}, args...)...)
	if code != 0 {
		t.Fatalf("supply-chain exit %d:\n%s", code, out)
	}
	var rep supplychain.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out)
	}
	return &rep
}

func rules(rep *supplychain.Report) map[string]int {
	m := map[string]int{}
	for _, f := range rep.Findings {
		m[f.RuleID]++
	}
	return m
}

// untrusted repository → modified skill → MCP invocation → behaviour
// change → executed command, across two rounds.
func TestSupplyChainExampleChain(t *testing.T) {
	t.Setenv("AGENTDFIR_HOME", t.TempDir())
	pkg := twoRoundPackage(t, "chain")
	rep := supplyReport(t, pkg)
	if !overlay.Exists(filepath.Join(pkg, "normalized", supplychain.File)) {
		t.Fatal("analysis did not write normalized/supplychain.json")
	}
	byID := map[string]supplychain.Component{}
	for _, c := range rep.Components {
		byID[c.ID] = c
	}
	plugin := byID["plugin:claude-code:deploy-kit@evil-tools"]
	if plugin.Origin.Trust != "third_party" || plugin.Origin.GitRemote != "attacker/agent-tools" || plugin.Origin.GitCommit == "" {
		t.Errorf("plugin origin: %+v", plugin.Origin)
	}
	if plugin.FirstSeen == nil || plugin.FirstSeen.Source != supplychain.TimeInstall {
		t.Errorf("plugin first seen: %+v", plugin.FirstSeen)
	}
	var skill supplychain.Component
	for _, c := range rep.Components {
		if c.Kind == supplychain.KindSkill && c.Name == "deploy-kit:release" {
			skill = c
		}
	}
	if skill.ID == "" || skill.Parent != plugin.ID || !skill.Origin.Untrusted() {
		t.Fatalf("skill: %+v", skill)
	}
	if len(skill.History) < 2 || skill.History[0].SHA256 == skill.History[1].SHA256 {
		t.Errorf("skill hash history across rounds: %+v", skill.History)
	}
	if skill.Invocations != 2 || len(skill.Sessions) != 2 {
		t.Errorf("skill invocations: %d in %v", skill.Invocations, skill.Sessions)
	}
	kinds := map[string]bool{}
	expansion := false
	for _, d := range rep.Drift {
		kinds[d.Kind] = true
		if d.Kind == "mcp_tool_definition" && d.From.Source == "round" && len(d.Expansion) > 0 {
			expansion = strings.Contains(strings.Join(d.Expansion, "|"), "new tool write_file") &&
				strings.Contains(strings.Join(d.Expansion, "|"), "new filesystem path argument /") &&
				strings.Contains(strings.Join(d.Expansion, "|"), "new env key GITHUB_TOKEN")
		}
	}
	if !expansion || !kinds["agent_settings"] {
		t.Errorf("drift: %+v", rep.Drift)
	}
	// Verified: skill invocation (logged), hook execution (identical
	// command), MCP call. Inferred: the command after the skill.
	has := func(rs []supplychain.Relation, typ, from string) bool {
		for _, r := range rs {
			if r.Type == typ && (from == "" || r.From == from) {
				return true
			}
		}
		return false
	}
	if !has(rep.Relations.Verified, "invoked", skill.ID) || !has(rep.Relations.Verified, "hook_executed", "") || !has(rep.Relations.Verified, "installed_from", plugin.ID) {
		t.Errorf("verified relations: %+v", rep.Relations.Verified)
	}
	if !has(rep.Relations.Inferred, "followed_by", "") {
		t.Errorf("inferred relations: %+v", rep.Relations.Inferred)
	}
	for _, r := range rep.Relations.Verified {
		if r.Type == "followed_by" {
			t.Errorf("temporal link promoted to verified: %+v", r)
		}
	}
	got := rules(rep)
	for _, want := range []string{"SUPPLY_MCP_TOOL_DRIFT_EXPANSION", "SUPPLY_UNTRUSTED_COMPONENT_BEFORE_HIGH"} {
		if got[want] == 0 {
			t.Errorf("missing %s; findings %v", want, got)
		}
	}
	// The findings reach the case's findings.json too.
	data, _ := overlay.ReadFile(filepath.Join(pkg, "detections", "findings.json"))
	if !strings.Contains(string(data), "SUPPLY_UNTRUSTED_COMPONENT_BEFORE_HIGH") {
		t.Error("supply-chain findings not in findings.json")
	}

	// Text: sections kept apart, chronological timeline.
	code, out := capture(t, "supply-chain", pkg)
	if code != 0 || !strings.Contains(out, "VERIFIED RELATIONSHIPS") || !strings.Contains(out, "INFERRED RELATIONSHIPS") || !strings.Contains(out, "TIMELINE") {
		t.Fatalf("text exit %d:\n%s", code, out)
	}
	// --since, --out.
	outFile := filepath.Join(t.TempDir(), "sc.json")
	if code, _ := capture(t, "supply-chain", pkg, "--json", "--since", "2026-09-22", "--out", outFile); code != 0 {
		t.Fatalf("--out exit %d", code)
	}
	b, err := os.ReadFile(outFile)
	if err != nil || !strings.Contains(string(b), `"since": "2026-09-22T00:00:00Z"`) {
		t.Errorf("--out file: %v %.200s", err, b)
	}
	if code, _ := capture(t, "supply-chain", pkg, "--since", "yesterday"); code != 2 {
		t.Errorf("bad --since exit %d", code)
	}
	// Cross-case: the same case's twin shares every hash.
	twin := twoRoundPackage(t, "chain")
	if code, out := capture(t, "analyze", twin); code != 0 && code != 3 {
		t.Fatalf("analyze twin %d:\n%s", code, out)
	}
	rep2 := supplyReport(t, pkg, "--peer", twin)
	cross := false
	for _, r := range rep2.Reuse {
		if len(r.Cases) > 0 && r.Class == supplychain.Verified {
			cross = true
		}
	}
	if !cross {
		t.Errorf("no cross-case reuse: %+v", rep2.Reuse)
	}
}

// The same home collected twice: no drift, no supply-chain finding.
func TestSupplyChainBenignBaseline(t *testing.T) {
	t.Setenv("AGENTDFIR_HOME", t.TempDir())
	pkg := twoRoundPackage(t, "benign")
	rep := supplyReport(t, pkg)
	if len(rep.Drift) != 0 {
		t.Errorf("drift on an unchanged home: %+v", rep.Drift)
	}
	if len(rep.Findings) != 0 {
		t.Errorf("findings on an unchanged home: %+v", rep.Findings)
	}
	if len(rep.Components) == 0 {
		t.Error("no components")
	}
	// An MCP baseline from the same state shows no drift either; a
	// malformed baseline is refused.
	bad := filepath.Join(t.TempDir(), "b.json")
	os.WriteFile(bad, []byte(`{"x":1}`), 0o600)
	if code, _ := capture(t, "supply-chain", pkg, "--baseline", bad); code != 2 {
		t.Errorf("unsupported baseline exit %d", code)
	}
}
