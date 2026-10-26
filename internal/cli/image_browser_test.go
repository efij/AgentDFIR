package cli

import (
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/diskimage"
)

// Opt-in products (browser history) are part of image and import
// discovery only with --include-browser.
func TestDiscoveryProductsOptIn(t *testing.T) {
	has := func(opt bool) bool {
		prods, err := discoveryProducts(opt)
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range prods {
			if p.ID == browserProductID {
				return true
			}
		}
		return false
	}
	if has(false) || !has(true) {
		t.Fatalf("browser in discovery: without flag %v, with flag %v", has(false), has(true))
	}

	// On a filesystem holding an agent profile with Chrome history, the
	// history file is an extraction candidate only with the flag.
	fsys := fstest.MapFS{
		"Users/alice/.claude/settings.json":                                     {Data: []byte(`{}`)},
		"Users/alice/.claude/projects/p/s.jsonl":                                {Data: []byte("{}\n")},
		"Users/alice/Library/Application Support/Google/Chrome/Default/History": {Data: []byte("SQLite format 3\x00")},
	}
	cands := func(opt bool) []string {
		prods, _ := discoveryProducts(opt)
		return diskimage.FindCandidates(fsys, prods, diskimage.DefaultLimits()).Files
	}
	hasHistory := func(files []string) bool {
		for _, f := range files {
			if strings.HasSuffix(f, "/Default/History") {
				return true
			}
		}
		return false
	}
	if hasHistory(cands(false)) {
		t.Fatalf("history extracted without --include-browser: %v", cands(false))
	}
	if !hasHistory(cands(true)) {
		t.Fatalf("history not extracted with --include-browser: %v", cands(true))
	}
}

// collect --image accepts --include-browser like --import: the case
// records the opt-in, and the image (which holds no browser) still
// yields its agent evidence.
func TestCollectImageIncludeBrowser(t *testing.T) {
	dir := t.TempDir()
	img := imageFixture(t, dir, "disk.E01")
	pkg := filepath.Join(dir, "case.adfir")
	if code := Main([]string{"collect", "--image", img, "--include-browser", "--skip-image-verify", "--out", pkg, "--no-sign"}); code != 0 {
		t.Fatalf("collect --image --include-browser exit %d", code)
	}
	info, err := casepkg.ReadCaseInfo(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if info.Notes["browser_history"] == "" || info.Notes["mode"] != "image" {
		t.Fatalf("notes: %v", info.Notes)
	}
	// Without the flag nothing says browser history was requested.
	pkg2 := filepath.Join(dir, "case2.adfir")
	if code := Main([]string{"collect", "--image", img, "--skip-image-verify", "--out", pkg2, "--no-sign"}); code != 0 {
		t.Fatalf("collect --image exit %d", code)
	}
	if info, _ := casepkg.ReadCaseInfo(pkg2); info.Notes["browser_history"] != "" {
		t.Fatalf("browser note without the flag: %v", info.Notes)
	}
}
