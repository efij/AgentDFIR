package cli

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/simulate"
)

// chromeProfileDir is where Chrome keeps its default profile on the OS the
// test runs on (current-user and --path collection use that OS's paths).
func chromeProfileDir() string {
	switch runtime.GOOS {
	case "darwin":
		return "Library/Application Support/Google/Chrome/Default"
	case "windows":
		return "AppData/Local/Google/Chrome/User Data/Default"
	}
	return ".config/google-chrome/Default"
}

func plantHistory(t *testing.T, profile, rel string) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "parsers", "browser", "testdata", "chrome_History"))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(profile, filepath.FromSlash(rel))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "History"), b, 0o644); err != nil {
		t.Fatal(err)
	}
}

// browserArtifacts counts acquired browser-history artifacts in a package.
func browserArtifacts(t *testing.T, pkg string) (int, map[string]string) {
	t.Helper()
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, a := range man.Current() {
		if a.ArtifactType == "browser_history" && a.Status == casepkg.StatusOK {
			n++
		}
	}
	info, err := casepkg.ReadCaseInfo(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return n, info.Notes
}

func TestCollectBrowserHistoryIsOptIn(t *testing.T) {
	home := t.TempDir()
	if err := simulate.OrphanAgent(home); err != nil {
		t.Fatal(err)
	}
	plantHistory(t, home, chromeProfileDir())

	plain := filepath.Join(t.TempDir(), "plain.adfir")
	if code := Main([]string{"collect", "--product", "claude", "--path", home, "--out", plain, "--no-sign"}); code != 0 {
		t.Fatalf("collect exit %d", code)
	}
	if n, notes := browserArtifacts(t, plain); n != 0 || notes["browser_history"] != "" {
		t.Fatalf("browser history collected without --include-browser (%d artifacts)", n)
	}

	opted := filepath.Join(t.TempDir(), "opted.adfir")
	if code := Main([]string{"collect", "--product", "claude", "--path", home, "--include-browser", "--out", opted, "--no-sign"}); code != 0 {
		t.Fatalf("collect --include-browser exit %d", code)
	}
	n, notes := browserArtifacts(t, opted)
	if n != 1 || notes["browser_history"] == "" {
		t.Fatalf("--include-browser: %d artifacts, notes %v", n, notes)
	}

	only := filepath.Join(t.TempDir(), "only.adfir")
	if code := Main([]string{"collect", "--product", "browser", "--path", home, "--out", only, "--no-sign"}); code != 0 {
		t.Fatalf("collect --product browser exit %d", code)
	}
	if n, _ := browserArtifacts(t, only); n != 1 {
		t.Fatalf("--product browser: %d artifacts", n)
	}
}

func TestImportFindsBrowserOnlyProfilesOnlyWhenAsked(t *testing.T) {
	tree := t.TempDir()
	bob := filepath.Join(tree, "C", "Users", "bob")
	if err := simulate.OrphanAgent(bob); err != nil {
		t.Fatal(err)
	}
	// alice has no AI agent, only a Linux Chrome profile.
	plantHistory(t, filepath.Join(tree, "C", "Users", "alice"), ".config/google-chrome/Default")

	plain := filepath.Join(t.TempDir(), "plain.adfir")
	if code := Main([]string{"collect", "--import", tree, "--out", plain, "--no-sign"}); code != 0 {
		t.Fatalf("import exit %d", code)
	}
	if n, _ := browserArtifacts(t, plain); n != 0 {
		t.Fatalf("import collected %d history DBs without --include-browser", n)
	}
	opted := filepath.Join(t.TempDir(), "opted.adfir")
	if code := Main([]string{"collect", "--import", tree, "--include-browser", "--out", opted, "--no-sign"}); code != 0 {
		t.Fatalf("import --include-browser exit %d", code)
	}
	n, notes := browserArtifacts(t, opted)
	if n != 1 || notes["browser_history"] == "" || notes["profiles"] != "2" {
		t.Fatalf("import --include-browser: %d artifacts, notes %v", n, notes)
	}
}

func TestRunIncludeBrowserReachesTheFindings(t *testing.T) {
	home := t.TempDir()
	if err := simulate.OrphanAgent(home); err != nil {
		t.Fatal(err)
	}
	plantHistory(t, home, chromeProfileDir())
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	out := filepath.Join(t.TempDir(), "case.adfir")
	if code := Main([]string{"run", "--no-serve", "--include-browser", "--out", out, "--case-id", "RUN-BROWSER"}); code != 0 && code != 3 {
		t.Fatalf("run exit %d", code)
	}
	if n, notes := browserArtifacts(t, out); n != 1 || notes["browser_history"] == "" {
		t.Fatalf("run --include-browser: %d artifacts, notes %v", n, notes)
	}
	share := 0
	for _, f := range analysis.LoadFindings(out) {
		if f.RuleID == "AI_WEB_SHARE_LINK_VISITED" {
			share++
		}
	}
	if share != 1 {
		t.Fatalf("AI_WEB_SHARE_LINK_VISITED fired %d times, want 1", share)
	}
}
