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
