package collector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/products"
)

// fixtureProfile builds a synthetic Claude Code profile with the traps a
// hostile host would plant: a symlink pointing outside the config tree
// and an oversized file.
func fixtureProfile(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	claude := filepath.Join(root, ".claude")
	proj := filepath.Join(claude, "projects", "-Users-victim-repo")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(".claude.json", `{"mcpServers":{}}`)
	write(".claude/settings.json", `{"permissions":{}}`)
	write(".claude/history.jsonl", `{"display":"hello"}`)
	write(".claude/projects/-Users-victim-repo/session-1.jsonl",
		`{"type":"user","message":"do things"}`+"\n"+`{"type":"assistant"}`)
	write(".claude/projects/-Users-victim-repo/session-2.jsonl",
		`{"type":"user","message":"subagent run"}`)

	// Trap 1: symlink escaping the profile — must be recorded, never followed.
	secret := filepath.Join(root, "outside-secret.txt")
	write("outside-secret.txt", "PRIVATE KEY MATERIAL")
	_ = secret
	if err := os.Symlink(secret, filepath.Join(proj, "planted-link.jsonl")); err != nil {
		t.Skipf("symlink not supported: %v", err)
	}

	// Trap 2: oversized file (bound in test set to 1KiB).
	write(".claude/projects/-Users-victim-repo/huge.jsonl", strings.Repeat("A", 4096))
	return root
}

func runCollection(t *testing.T, root string) (string, *Stats) {
	t.Helper()
	man, err := products.Manifest("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := casepkg.New(pkg, "TEST-COLLECT", casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	st, err := Run(b, man, Options{
		ProfileRoot:  root,
		ConfigRoot:   filepath.Join(root, ".claude"),
		SystemRoot:   root,
		Product:      "claude-code",
		MaxFileBytes: 1024,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return pkg, st
}

func TestCollectClaudeFixture(t *testing.T) {
	root := fixtureProfile(t)
	pkg, st := runCollection(t, root)

	// 6 regular files under bound: .claude.json, settings, history, 2 sessions... huge.jsonl is over bound.
	if st.Acquired != 5 {
		t.Fatalf("acquired = %d, want 5", st.Acquired)
	}
	if st.Symlinks != 1 {
		t.Fatalf("symlinks recorded = %d, want 1", st.Symlinks)
	}
	if st.Skipped != 1 {
		t.Fatalf("skipped = %d, want 1 (bound exceeded)", st.Skipped)
	}

	res, err := casepkg.Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Problems) != 0 {
		t.Fatalf("verify problems: %v", res.Problems)
	}

	man, err := os.ReadFile(filepath.Join(pkg, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(man)
	if !strings.Contains(s, casepkg.StatusSymlink) {
		t.Error("symlink not recorded in manifest")
	}
	if !strings.Contains(s, casepkg.StatusSkippedBound) {
		t.Error("bound-exceeded file not recorded in manifest")
	}
	if strings.Contains(s, "PRIVATE KEY MATERIAL") {
		t.Error("symlink target content leaked into manifest")
	}

	// The symlink target's CONTENT must not have been acquired.
	entries, _ := os.ReadDir(filepath.Join(pkg, "raw"))
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(pkg, "raw", e.Name()))
		if strings.Contains(string(data), "PRIVATE KEY MATERIAL") {
			t.Fatal("collector followed a symlink out of the profile — evidence contains outside content")
		}
	}
}

func TestOfflinePathModeUsesProvidedRoot(t *testing.T) {
	root := fixtureProfile(t)
	pkg, st := runCollection(t, root)
	if st.Acquired == 0 {
		t.Fatal("offline collection acquired nothing")
	}
	man, _ := os.ReadFile(filepath.Join(pkg, "manifest.json"))
	if !strings.Contains(string(man), ".claude/projects/-Users-victim-repo/session-1.jsonl") {
		t.Error("logical_path not root-relative")
	}
}
