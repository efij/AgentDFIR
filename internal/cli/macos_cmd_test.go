package cli

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/casepkg"
)

func TestCollectMacOSHostIsOptInAndAnalyzed(t *testing.T) {
	home := t.TempDir()
	sess := filepath.Join(home, ".claude", "projects", "-Users-user-proj")
	if err := os.MkdirAll(sess, 0o755); err != nil {
		t.Fatal(err)
	}
	transcript := `{"type": "user", "uuid": "u1", "sessionId": "m1", "timestamp": "2026-10-20T09:00:01Z", "cwd": "/Users/user/proj", "message": {"role": "user", "content": "run the tests"}}
{"type": "assistant", "uuid": "a1", "sessionId": "m1", "timestamp": "2026-10-20T09:00:10Z", "cwd": "/Users/user/proj", "parentUuid": "u1", "message": {"role": "assistant", "content": [{"type": "text", "text": "done"}]}}
`
	if err := os.WriteFile(filepath.Join(sess, "m1.jsonl"), []byte(transcript), 0o644); err != nil {
		t.Fatal(err)
	}
	tcc, err := os.ReadFile(filepath.Join("..", "macoshost", "testdata", "TCC.db"))
	if err != nil {
		t.Fatal(err)
	}
	tccDir := filepath.Join(home, "Library", "Application Support", "com.apple.TCC")
	if err := os.MkdirAll(tccDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(tccDir, "TCC.db"), tcc, 0o644); err != nil {
		t.Fatal(err)
	}

	count := func(pkg string) int {
		man, err := casepkg.ReadManifest(pkg)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, a := range man.Current() {
			if a.Product == "macos-host" && a.Status == casepkg.StatusOK {
				n++
			}
		}
		return n
	}
	plain := filepath.Join(t.TempDir(), "plain.adfir")
	if code := Main([]string{"collect", "--product", "claude", "--path", home, "--out", plain, "--no-sign"}); code != 0 {
		t.Fatalf("collect exit %d", code)
	}
	if n := count(plain); n != 0 {
		t.Fatalf("macOS host state collected without --include-macos-host (%d)", n)
	}
	opted := filepath.Join(t.TempDir(), "opted.adfir")
	if code := Main([]string{"collect", "--product", "claude", "--path", home, "--include-macos-host", "--out", opted, "--no-sign"}); code != 0 {
		t.Fatalf("collect --include-macos-host exit %d", code)
	}
	if n := count(opted); n < 2 { // TCC.db + keychain listing
		t.Fatalf("opted-in collection took %d macos-host artifacts", n)
	}
	res, err := analysis.Run(opted, analysis.Options{})
	if err != nil {
		t.Fatal(err)
	}
	hits := 0
	for _, f := range res.Findings {
		if f.RuleID == "MACOS_TCC_MODIFIED_BY_AGENT" {
			hits++
			if f.Severity != "MEDIUM" {
				t.Fatalf("time-overlap TCC finding must be MEDIUM: %+v", f)
			}
		}
	}
	if hits != 1 {
		t.Fatalf("TCC row inside the session: %d findings", hits)
	}
}
