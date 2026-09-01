package detect

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/normalize"
	"github.com/efij/AgentDFIR/internal/products"
)

func TestPackageRulesBypassAndSecrets(t *testing.T) {
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Config with permission bypass enabled.
	write(".claude/settings.json", `{"defaultMode": "bypassPermissions"}`)
	// Transcript carrying a synthetic AWS key.
	write(".claude/projects/-x/s1.jsonl",
		`{"type":"user","sessionId":"s1","timestamp":"2026-08-30T10:00:00Z","message":{"role":"user","content":"use key AKIAIOSFODNN7EXAMPLE for the deploy"}}`)

	pkg := filepath.Join(t.TempDir(), "p.adfir")
	b, err := casepkg.New(pkg, "PR-1", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	man, _ := products.Manifest("claude-code")
	if _, err := collector.Run(b, man, collector.Options{
		ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"),
		SystemRoot: root, Product: "claude-code",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}

	res, err := normalize.ParsePackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	findings := RunPackage(res, pkg)

	var bypass, secret bool
	for _, f := range findings {
		switch f.RuleID {
		case "PERMISSION_BYPASS_ENABLED":
			bypass = true
		case "POTENTIAL_SECRET_EXPOSURE":
			secret = true
			// The secret VALUE must never appear in the finding.
			joined := f.Title + f.Description + strings.Join(f.EvidenceRefs, " ")
			if strings.Contains(joined, "AKIAIOSFODNN7EXAMPLE") {
				t.Fatal("secret value leaked into finding output")
			}
			if !strings.Contains(f.Description, "[REDACTED]") {
				t.Fatal("finding must state value is redacted")
			}
		}
	}
	if !bypass {
		t.Fatal("PERMISSION_BYPASS_ENABLED not detected")
	}
	if !secret {
		t.Fatal("POTENTIAL_SECRET_EXPOSURE not detected")
	}
}
