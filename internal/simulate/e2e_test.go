package simulate_test

import (
	"path/filepath"
	"sort"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/analysis"
	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/collector"
	"github.com/efij/AgentDFIR/v3/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v3/internal/products"
	"github.com/efij/AgentDFIR/v3/internal/reposcan"
	"github.com/efij/AgentDFIR/v3/internal/simulate"
)

// TestScenariosEndToEnd runs every scenario through the real pipeline —
// write the profile, collect it into a sealed package (Claude Code and
// host shell), analyze — and requires the rules each scenario claims.
func TestScenariosEndToEnd(t *testing.T) {
	for _, sc := range simulate.Catalog {
		sc := sc
		t.Run(sc.ID, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "home")
			if err := sc.Run(root); err != nil {
				t.Fatal(err)
			}
			abs, _ := filepath.Abs(root)
			pkg := filepath.Join(t.TempDir(), "case.adfir")
			b, err := casepkg.New(pkg, "SIM-"+sc.ID, casepkg.CaseInfo{OperatorOSUser: "sim"})
			if err != nil {
				t.Fatal(err)
			}
			for _, prod := range []string{"claude-code", "host-shell"} {
				man, err := products.ManifestAllPlatforms(prod)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := collector.Run(b, man, collector.Options{ProfileRoot: abs, ConfigRoot: filepath.Join(abs, ".claude"), SystemRoot: abs, Product: prod}); err != nil {
					t.Fatal(err)
				}
			}
			if err := b.Seal(); err != nil {
				t.Fatal(err)
			}
			b.Close()
			res, err := analysis.Run(pkg, analysis.Options{})
			if err != nil {
				t.Fatal(err)
			}
			got := map[string]string{}
			for _, f := range res.Findings {
				got[f.RuleID] = f.Severity
			}
			var missing []string
			for _, id := range sc.Expect {
				if _, ok := got[id]; !ok {
					missing = append(missing, id)
				}
			}
			if len(missing) > 0 {
				var have []string
				for id := range got {
					have = append(have, id)
				}
				sort.Strings(have)
				t.Errorf("missing %v; got %v", missing, have)
			}
			if man, err := casepkg.ReadManifest(pkg); err != nil || !analysis.IsSimulated(man) {
				t.Errorf("simulated marker not collected")
			}
			for _, f := range res.Findings {
				if f.RuleID == "KNOWN_INCIDENT_IOC" && len(f.Title) > 0 && f.Title[:11] != "[SIMULATED]" {
					t.Errorf("IOC finding in a simulated case not labelled: %s", f.Title)
				}
			}
		})
	}
}

// TestRugpullAgainstBaseline: the rug-pull scenario's approved state,
// snapshotted as a baseline, must show the command and tool-definition
// change.
func TestRugpullAgainstBaseline(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	if err := simulate.MCPoisonRugpull(root); err != nil {
		t.Fatal(err)
	}
	bp := filepath.Join(t.TempDir(), "b.json")
	if err := mcpaudit.WriteBaseline(mcpaudit.ScanProfile(filepath.Join(root, simulate.BaselineProfile)), bp); err != nil {
		t.Fatal(err)
	}
	b, err := mcpaudit.LoadBaseline(bp)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range mcpaudit.Compare(mcpaudit.ScanProfile(root), b) {
		got[f.RuleID] = true
	}
	for _, id := range []string{"MCP_SERVER_CHANGED", "MCP_TOOL_DEFINITION_CHANGED"} {
		if !got[id] {
			t.Errorf("missing %s; got %v", id, got)
		}
	}
}

// TestKeyvRepoCaughtBeforeOpen: scan-repo on the keyv scenario's working
// repository flags the committed hook and task as critical.
func TestKeyvRepoCaughtBeforeOpen(t *testing.T) {
	root := filepath.Join(t.TempDir(), "home")
	if err := simulate.KeyvHook(root); err != nil {
		t.Fatal(err)
	}
	r, err := reposcan.Scan(filepath.Join(root, "work", "app"), reposcan.Options{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, f := range r.Findings {
		if got[f.RuleID] != "CRITICAL" {
			got[f.RuleID] = f.Severity
		}
	}
	if got["REPO_AGENT_HOOK_AUTORUN"] != "CRITICAL" || got["REPO_VSCODE_AUTORUN_TASK"] != "CRITICAL" {
		t.Errorf("keyv repo: %v", got)
	}
}
