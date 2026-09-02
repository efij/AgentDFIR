package collector

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/products"
)

// A KAPE-style Windows tree and a Linux home, analyzed on whatever OS runs
// the test: discovery is by config presence and manifests apply for all
// platforms.
func TestDiscoverProfilesAndImportCollect(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"C/Users/alice/.claude/settings.json":                     `{"permissions":{}}`,
		"C/Users/alice/.claude/projects/p1/s1.jsonl":              `{"type":"user","uuid":"u1","sessionId":"s1","timestamp":"2026-08-30T10:00:00Z","message":{"role":"user","content":"hi"}}` + "\n",
		"C/Users/alice/.codex/config.toml":                        `model = "x"`,
		"C/Users/bob/.gemini/settings.json":                       `{}`,
		"C/Users/bob/.gemini/tmp/abc/logs.json":                   `[{"sessionId":"g1","type":"user","message":"hello","timestamp":"2026-08-30T10:00:00Z"}]`,
		"C/Users/bob/Documents/notes.txt":                         "not an agent",
		"C/Windows/System32/config/SAM":                           "x",
		"uploads/client-1/home/carol/.aider.chat.history.md":      "# aider chat started at 2026-08-30 10:00:00\n\n#### hi\n",
		"C/Users/alice/.claude/projects/p1/nested/.claude/x.json": `{}`, // nested .claude must not become a second profile
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	prods, err := products.All()
	if err != nil {
		t.Fatal(err)
	}
	profiles := DiscoverProfiles(root, prods, 12)
	if len(profiles) != 3 {
		t.Fatalf("expected 3 profiles, got %d: %+v", len(profiles), profiles)
	}
	byUser := map[string]Profile{}
	for _, p := range profiles {
		byUser[p.User] = p
	}
	if got := byUser["alice"].Products; len(got) != 2 || got[0] != "claude-code" || got[1] != "codex-cli" {
		t.Fatalf("alice products: %v", got)
	}
	if got := byUser["bob"].Products; len(got) != 1 || got[0] != "gemini-cli" {
		t.Fatalf("bob products: %v", got)
	}
	if got := byUser["carol"].Products; len(got) != 1 || got[0] != "aider" {
		t.Fatalf("carol products: %v", got)
	}

	// Collect every product for every profile into one package.
	pkg := filepath.Join(t.TempDir(), "imp.adfir")
	b, err := casepkg.New(pkg, "IMP", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	users := map[string]bool{}
	for _, pr := range profiles {
		for _, pid := range pr.Products {
			man, err := products.ManifestAllPlatforms(pid)
			if err != nil || man == nil {
				t.Fatalf("manifest %s: %v", pid, err)
			}
			prod, _ := products.ByID(pid)
			cfg := pr.Path
			if len(prod.ConfigDirs) > 0 {
				cfg = filepath.Join(pr.Path, filepath.FromSlash(prod.ConfigDirs[0]))
			}
			st, err := Run(b, man, Options{ProfileRoot: pr.Path, ConfigRoot: cfg, SystemRoot: root, User: pr.User, Product: pid})
			if err != nil {
				t.Fatal(err)
			}
			total += st.Acquired
			if st.Acquired > 0 {
				users[pr.User] = true
			}
		}
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	if total < 5 {
		t.Fatalf("expected at least 5 artifacts across users, got %d", total)
	}
	if !users["alice"] || !users["bob"] || !users["carol"] {
		t.Fatalf("not every user contributed artifacts: %v", users)
	}
	res, err := casepkg.Verify(pkg)
	if err != nil || len(res.Problems) != 0 {
		t.Fatalf("verify: %v %v", err, res)
	}
}
