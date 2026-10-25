package products

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Browser history is broad personal data. It must never be picked up by
// detection, `run` or `--import` on its own: it is absent from All() and
// reachable only by name.
func TestBrowserIsOptInOnly(t *testing.T) {
	all, err := All()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range all {
		if p.ID == "browser" {
			t.Fatal("browser must not be in All(): it would be collected by default")
		}
	}
	if !IsOptIn("browser") || IsOptIn("claude-code") {
		t.Fatal("IsOptIn wrong")
	}
	p, err := ByID("browser")
	if err != nil || p.ID != "browser" || len(p.ConfigDirs) == 0 {
		t.Fatalf("ByID(browser) = %+v, %v", p, err)
	}
	m, err := ManifestAllPlatforms("browser")
	if err != nil || m == nil {
		t.Fatalf("ManifestAllPlatforms(browser) = %v, %v", m, err)
	}
	seen := map[string]bool{}
	for _, e := range m.Entries {
		if e.Category != "browser_history" {
			t.Errorf("%s: category %q, want browser_history (never agent_session: transcript rules must not scan a whole history DB)", e.ID, e.Category)
		}
		if !strings.HasPrefix(e.ID, "browser.") || !strings.Contains(e.ID, "_") {
			t.Errorf("%s: rule id must be browser.<name>_<platform>", e.ID)
		}
		seen[e.ID[len("browser."):strings.LastIndex(e.ID, "_")]] = true
		for _, pth := range e.Paths {
			if !strings.HasPrefix(pth, "${PROFILE_ROOT}/") {
				t.Errorf("%s: path %q has no profile root", e.ID, pth)
			}
		}
	}
	for _, b := range []string{"chrome", "edge", "brave", "arc", "vivaldi", "opera", "chromium", "firefox", "safari"} {
		if !seen[b] {
			t.Errorf("no collector entry for %s", b)
		}
	}
	if dets, _ := DetectAll(t.TempDir()); len(dets) != len(all) {
		t.Fatalf("DetectAll probed %d products, want %d (opt-in products are not probed)", len(dets), len(all))
	}
}

func TestPackCannotShadowAnOptInProduct(t *testing.T) {
	defer ResetRegistered()
	err := Register(Product{ID: "browser", Name: "x"}, CollectorManifest{Product: "browser"})
	if err == nil {
		t.Fatal("a pack registered the opt-in browser product")
	}
}

func TestContinueAndWindsurfAreKnownProducts(t *testing.T) {
	want := map[string]map[string]string{
		"continue": {
			"continue.config":   "product_config",
			"continue.sessions": "agent_session",
			"continue.rules":    "agent_instructions",
			"continue.mcp":      "product_config",
			"continue.env":      "credentials",
		},
		"windsurf": {
			"windsurf.mcp":         "product_config",
			"windsurf.rules":       "agent_instructions",
			"windsurf.memories":    "agent_session",
			"windsurf.cascade":     "agent_session",
			"windsurf.workflows":   "agent_instructions",
			"windsurf.state_macos": "product_state",
		},
	}
	for id, entries := range want {
		if _, err := ByID(id); err != nil {
			t.Fatal(err)
		}
		m, err := ManifestAllPlatforms(id)
		if err != nil || m == nil {
			t.Fatalf("%s: manifest %v, %v", id, m, err)
		}
		got := map[string]string{}
		for _, e := range m.Entries {
			got[e.ID] = e.Category
		}
		for e, cat := range entries {
			if got[e] != cat {
				t.Errorf("%s: %s category = %q, want %q", id, e, got[e], cat)
			}
		}
	}
}

func TestWindsurfDetectedFromCodeiumDir(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".codeium", "windsurf"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", home)
	dets, err := DetectAll(home)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range dets {
		if d.Product.ID == "windsurf" && d.Detected {
			return
		}
	}
	t.Fatal("windsurf not detected from ~/.codeium/windsurf")
}
