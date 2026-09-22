package products

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Kiro (dev.kiro.desktop) is a VS Code fork whose agent surface is its
// instruction, MCP and extension state rather than a transcript store, so
// the manifest must route those files to the categories the rules read.
func TestKiroIsAKnownProductWithACollector(t *testing.T) {
	p, err := ByID("kiro")
	if err != nil {
		t.Fatalf("ByID(kiro): %v", err)
	}
	if p.Name != "Kiro" || len(p.ConfigDirs) != 1 || p.ConfigDirs[0] != ".kiro" || !contains(p.Binaries, "kiro") {
		t.Fatalf("unexpected product definition: %+v", *p)
	}
	m, err := ManifestAllPlatforms("kiro")
	if err != nil || m == nil {
		t.Fatalf("ManifestAllPlatforms(kiro) = %v, %v; want a manifest", m, err)
	}
	want := map[string]string{
		"kiro.steering":    "agent_instructions",
		"kiro.mcp":         "product_config",
		"kiro.skills":      "agent_definitions",
		"kiro.powers":      "agent_definitions",
		"kiro.auth":        "credentials",
		"kiro.state_macos": "agent_session",
	}
	got := map[string]string{}
	for _, e := range m.Entries {
		got[e.ID] = e.Category
		for _, pth := range e.Paths {
			if !strings.HasPrefix(pth, "${PROFILE_ROOT}") && !strings.HasPrefix(pth, "${CONFIG_ROOT}") && !strings.HasPrefix(pth, "${SYSTEM_ROOT}") {
				t.Errorf("%s: path %q has no root token", e.ID, pth)
			}
		}
	}
	for id, cat := range want {
		if got[id] != cat {
			t.Errorf("entry %s category = %q, want %q", id, got[id], cat)
		}
	}
}

func TestKiroManifestIsFilteredToTheRunningOS(t *testing.T) {
	m, err := Manifest("kiro")
	if err != nil || m == nil {
		t.Fatalf("Manifest(kiro) = %v, %v", m, err)
	}
	for _, e := range m.Entries {
		if len(e.Platforms) > 0 && !contains(e.Platforms, runtime.GOOS) {
			t.Errorf("entry %s for %v survived the %s filter", e.ID, e.Platforms, runtime.GOOS)
		}
	}
}

// A profile with only ~/.kiro/settings/mcp.json and no binary on PATH is
// still a Kiro install: detection is presence-based and never executes.
func TestKiroDetectedFromConfigDirAlone(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".kiro", "settings"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".kiro", "settings", "mcp.json"), []byte(`{"mcpServers":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", home) // nothing executable here
	dets, err := DetectAll(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dets {
		if d.Product.ID != "kiro" {
			continue
		}
		if !d.Detected || len(d.ConfigPaths) != 1 || d.BinaryPath != "" {
			t.Fatalf("kiro detection = %+v; want Detected via config dir only", d)
		}
		return
	}
	t.Fatal("kiro missing from DetectAll")
}

// Claude Cowork is the desktop app's agent mode. It has no binary of its
// own to hash (it is the Claude.app Electron bundle) and no dotfile: it is
// detected by its session store under the app's support directory, and its
// manifest must route the audit log, the in-VM transcripts and the
// per-session sidecars to agent_session so the Claude parser reads them.
func TestCoworkIsAKnownProductWithACollector(t *testing.T) {
	p, err := ByID("claude-cowork")
	if err != nil {
		t.Fatalf("ByID(claude-cowork): %v", err)
	}
	if p.Name != "Claude Cowork" || len(p.Binaries) != 0 || len(p.ConfigDirs) < 3 {
		t.Fatalf("product = %+v", p)
	}
	m, err := ManifestAllPlatforms("claude-cowork")
	if err != nil || m == nil {
		t.Fatalf("ManifestAllPlatforms(claude-cowork) = %v, %v; want a manifest", m, err)
	}
	want := map[string]string{
		"cowork.sessions_macos":            "agent_session",
		"cowork.audit_macos":               "agent_session",
		"cowork.audit_key_macos":           "credentials",
		"cowork.session_meta_macos":        "agent_session",
		"cowork.session_credentials_macos": "credentials",
		"cowork.desktop_sessions_macos":    "agent_session",
		"cowork.desktop_config_macos":      "product_config",
		"cowork.plugins_macos":             "agent_definitions",
		"cowork.logs_macos":                "debug_logs",
		"cowork.sessions_linux":            "agent_session",
		"cowork.sessions_windows":          "agent_session",
	}
	got := map[string]string{}
	for _, e := range m.Entries {
		got[e.ID] = e.Category
		if len(e.Platforms) != 1 {
			t.Errorf("%s: every Cowork entry is platform-specific; got platforms %v", e.ID, e.Platforms)
		}
		for _, path := range e.Paths {
			if !strings.HasPrefix(path, "${PROFILE_ROOT}/") {
				t.Errorf("%s: path %q must be profile-relative (no CONFIG_ROOT: the product has three roots)", e.ID, path)
			}
		}
	}
	for id, cat := range want {
		if got[id] != cat {
			t.Errorf("entry %s category = %q; want %q", id, got[id], cat)
		}
	}
}

func TestCoworkDetectedFromSessionStoreAlone(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "Library", "Application Support", "Claude", "local-agent-mode-sessions", "acct", "org")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	dets, err := DetectAll(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dets {
		if d.Product.ID != "claude-cowork" {
			continue
		}
		if !d.Detected || len(d.ConfigPaths) != 1 || d.BinaryPath != "" {
			t.Fatalf("cowork detection = %+v; want Detected via the session store only", d)
		}
		return
	}
	t.Fatal("claude-cowork missing from DetectAll")
}

// The Codex desktop app moved the transcript into SQLite beside the rollout
// files. The manifest has to collect the stores and their write-ahead logs
// together, or the parser reads a checkpoint-stale database.
func TestCodexManifestCollectsTheSQLiteStoresWithTheirWAL(t *testing.T) {
	m, err := ManifestAllPlatforms("codex-cli")
	if err != nil || m == nil {
		t.Fatalf("Manifest(codex-cli) = %v, %v", m, err)
	}
	byID := map[string]ManifestEntry{}
	for _, e := range m.Entries {
		byID[e.ID] = e
	}
	for id, cat := range map[string]string{
		"codex.state_db": "agent_session", "codex.thread_history_db": "agent_session",
		"codex.logs_db": "debug_logs", "codex.session_index": "agent_session",
		"codex.app_state": "product_state", "codex.plugins": "agent_definitions",
		"codex.browser": "agent_session", "codex.desktop_app_macos": "product_state",
		"codex.chatgpt_app_macos": "agent_session",
	} {
		e, ok := byID[id]
		if !ok || e.Category != cat {
			t.Errorf("entry %s = %+v; want category %s", id, e, cat)
		}
	}
	for _, id := range []string{"codex.state_db", "codex.thread_history_db", "codex.logs_db"} {
		var db, wal bool
		for _, p := range byID[id].Paths {
			db = db || strings.HasSuffix(p, ".sqlite")
			wal = wal || strings.HasSuffix(p, ".sqlite-wal")
		}
		if !db || !wal {
			t.Errorf("%s paths %v: want both the database and its -wal", id, byID[id].Paths)
		}
	}
	for _, p := range byID["codex.computer_use"].Paths {
		if strings.HasSuffix(p, "/**") {
			t.Errorf("codex.computer_use %q would collect the bundled .app; only its config belongs in evidence", p)
		}
	}
}
