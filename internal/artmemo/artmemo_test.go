package artmemo

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/store"
)

func withKey(t *testing.T) {
	t.Helper()
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(store.EnvHome, home)
	if _, err := store.MachineKey(); err != nil {
		t.Fatal(err)
	}
}

var art = casepkg.ArtifactRecord{ArtifactID: "abc", LogicalPath: "t.jsonl", ArtifactType: "agent_session", Status: casepkg.StatusOK}

func TestRoundTripAndScope(t *testing.T) {
	withKey(t)
	pkg := t.TempDir()
	m := Open[[]string](pkg, "x", "rules-v1")
	m.Put(art, []string{"finding"})
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	again := Open[[]string](pkg, "x", "rules-v1")
	if v, ok := again.Get(art); !ok || len(v) != 1 || v[0] != "finding" {
		t.Fatalf("remembered result not served: %v %v", v, ok)
	}
	// Other rules: nothing carries over.
	if _, ok := Open[[]string](pkg, "x", "rules-v2").Get(art); ok {
		t.Fatal("result served under a different rule set")
	}
	// A different artifact record (same bytes, other path): not the same key.
	other := art
	other.LogicalPath = "u.jsonl"
	if _, ok := again.Get(other); ok {
		t.Fatal("result served for a different record")
	}
}

// An edited memo fails its MAC and is ignored: a re-scan, never a hidden
// finding.
func TestTamperedMemoIsIgnored(t *testing.T) {
	withKey(t)
	pkg := t.TempDir()
	m := Open[[]string](pkg, "x", "s")
	m.Put(art, []string{"finding"})
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(pkg, "detections", "memo", "x.json.gz")
	data, _ := os.ReadFile(p)
	data[len(data)-1] ^= 0xff
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := Open[[]string](pkg, "x", "s").Get(art); ok {
		t.Fatal("a memo that fails its MAC was served")
	}
}

// Without a machine key nothing is remembered or served.
func TestNoKeyNoMemo(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	t.Setenv(store.EnvHome, home)
	pkg := t.TempDir()
	m := Open[[]string](pkg, "x", "s")
	if m.Enabled() {
		t.Fatal("memo enabled without a key")
	}
	m.Put(art, []string{"f"})
	if err := m.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(pkg, "detections", "memo")); err == nil {
		t.Fatal("memo written without a key")
	}
}
