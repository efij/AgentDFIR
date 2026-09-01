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

// A 20 MB transcript with a secret only at the very end must still be
// detected — the earlier whole-blob read skipped anything over 16 MB.
func TestStreamingScanFindsSecretPastOldLimit(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".claude", "projects", "-big")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	filler := `{"type":"assistant","sessionId":"s","timestamp":"2026-08-30T10:00:00Z","message":{"role":"assistant","content":[{"type":"text","text":"` + strings.Repeat("x", 900) + `"}]}}` + "\n"
	for b.Len() < 20<<20 {
		b.WriteString(filler)
	}
	b.WriteString(`{"type":"user","sessionId":"s","timestamp":"2026-08-30T10:00:01Z","message":{"role":"user","content":"key AKIAIOSFODNN7EXAMPLE"}}` + "\n")
	if err := os.WriteFile(filepath.Join(dir, "big.jsonl"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "big.adfir")
	bld, _ := casepkg.New(pkg, "SCAN", casepkg.CaseInfo{OperatorOSUser: "t"})
	man, _ := products.Manifest("claude-code")
	if _, err := collector.Run(bld, man, collector.Options{
		ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"),
		SystemRoot: root, Product: "claude-code",
	}); err != nil {
		t.Fatal(err)
	}
	if err := bld.Seal(); err != nil {
		t.Fatal(err)
	}
	res, _ := normalize.ParsePackage(pkg)
	f := RunAll(res, pkg, Options{})
	for _, x := range f {
		if x.RuleID == "POTENTIAL_SECRET_EXPOSURE" {
			return
		}
	}
	t.Fatal("secret past the old 16MB limit was not detected (streaming scan regression)")
}
