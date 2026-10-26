package macoshost

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/collector"
	"github.com/efij/AgentDFIR/v4/internal/products"
)

func put(t *testing.T, root, rel, src string, data []byte) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if src != "" {
		var err error
		if data, err = os.ReadFile(filepath.Join("testdata", src)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(p, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

// collect builds a package from a fake host root the way
// `collect --include-macos-host` does.
func collect(t *testing.T, root string) (*casepkg.Manifest, *casepkg.Store) {
	t.Helper()
	pkg := filepath.Join(t.TempDir(), "c.adfir")
	b, err := casepkg.New(pkg, "C", casepkg.CaseInfo{})
	if err != nil {
		t.Fatal(err)
	}
	man, err := products.ManifestAllPlatforms(Product)
	if err != nil || man == nil {
		t.Fatalf("manifest: %v", err)
	}
	if _, err := collector.Run(b, man, collector.Options{ProfileRoot: root, ConfigRoot: root, SystemRoot: root, Product: Product}); err != nil {
		t.Fatal(err)
	}
	if err := CollectKeychainIndex(b, root, root, "h", "u"); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	m, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	return m, casepkg.NewStore(pkg, m)
}

func TestReadHostState(t *testing.T) {
	root := t.TempDir()
	put(t, root, "Library/LaunchAgents/com.example.agent.plist", "com.example.agent.plist", nil)
	put(t, root, "Library/LaunchDaemons/com.example.binary.plist", "com.example.binary.plist", nil)
	put(t, root, "Library/Application Support/com.apple.TCC/TCC.db", "TCC.db", nil)
	put(t, root, "private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v13.btm", "", []byte("bplist00 opaque"))
	put(t, root, "Library/Keychains/login.keychain-db", "", []byte("SECRET-MUST-NOT-BE-READ"))
	put(t, root, "Library/Keychains/ABCD-1234/keychain-2.db", "", []byte("SECRET-MUST-NOT-BE-READ"))

	man, store := collect(t, root)
	for _, a := range man.Current() {
		if a.ArtifactID != "" {
			data, _ := store.ReadAll(a.ArtifactID, 1<<20)
			if strings.Contains(string(data), "SECRET-MUST-NOT-BE-READ") {
				t.Fatalf("keychain content sealed in %s", a.LogicalPath)
			}
		}
	}
	st := Read(man, store)
	var agent, bin *LaunchItem
	for i := range st.Launchd {
		switch {
		case strings.HasSuffix(st.Launchd[i].Path, "com.example.agent.plist"):
			agent = &st.Launchd[i]
		case strings.HasSuffix(st.Launchd[i].Path, "com.example.binary.plist"):
			bin = &st.Launchd[i]
		}
	}
	if agent == nil || agent.Status != "parsed" || agent.Label != "com.example.agent" || len(agent.Args) != 2 || !agent.RunAtLoad || !agent.KeepAlive {
		t.Fatalf("xml plist: %+v", agent)
	}
	if bin == nil || bin.Status != "UNSUPPORTED" {
		t.Fatalf("binary plist: %+v", bin)
	}
	if len(st.TCCRows) != 3 {
		t.Fatalf("tcc rows: %+v", st.TCCRows)
	}
	r := st.TCCRows[len(st.TCCRows)-1]
	if r.Resource != "kTCCServiceSystemPolicyAllFiles" || r.Exe != "com.updater.agent" || r.Source != "tcc-db" ||
		r.Time.Format("2006-01-02T15:04:05Z") != "2026-10-20T09:00:05Z" || !strings.Contains(r.Message, "auth_value=2") {
		t.Fatalf("tcc row: %+v", r)
	}
	if len(st.Keychains) != 3 { // login.keychain-db, ABCD-1234/, ABCD-1234/keychain-2.db
		t.Fatalf("keychain listing: %+v", st.Keychains)
	}
	un := strings.Join(st.Unsupported, "\n")
	if !strings.Contains(un, "Background Task Management store") || !strings.Contains(un, "binary property list") {
		t.Fatalf("unsupported: %v", st.Unsupported)
	}
	if !strings.Contains(st.Summary(), "3 TCC access row(s)") {
		t.Fatal(st.Summary())
	}
}

func TestPermissionDeniedIsARecordedSkip(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads everything")
	}
	if runtime.GOOS == "windows" {
		t.Skip("chmod 0 does not deny reads on Windows")
	}
	root := t.TempDir()
	put(t, root, "Library/Application Support/com.apple.TCC/TCC.db", "TCC.db", nil)
	p := filepath.Join(root, "Library/Application Support/com.apple.TCC/TCC.db")
	if err := os.Chmod(p, 0); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(p, 0o644)
	man, store := collect(t, root)
	st := Read(man, store)
	if len(st.Skipped) != 1 || !strings.Contains(st.Skipped[0], casepkg.StatusAccessDenied) {
		t.Fatalf("skipped: %v", st.Skipped)
	}
}

func TestMalformedPlistAndTCC(t *testing.T) {
	var it LaunchItem
	parsePlistInto([]byte("<plist><dict><key>Label</key><string>x"), &it)
	if it.Status != "malformed" {
		t.Fatalf("truncated plist: %+v", it)
	}
	parsePlistInto([]byte(strings.Repeat("<array>", 100)), &it)
	if it.Status != "malformed" {
		t.Fatalf("deep plist: %+v", it)
	}
	root := t.TempDir()
	put(t, root, "Library/Application Support/com.apple.TCC/TCC.db", "", []byte("not sqlite at all"))
	man, store := collect(t, root)
	if st := Read(man, store); !strings.Contains(strings.Join(st.Unsupported, " "), "not a readable SQLite database") {
		t.Fatalf("corrupt TCC.db: %v", st.Unsupported)
	}
}

func FuzzPlist(f *testing.F) {
	data, _ := os.ReadFile("testdata/com.example.agent.plist")
	f.Add(data)
	f.Fuzz(func(t *testing.T, b []byte) {
		var it LaunchItem
		parsePlistInto(b, &it)
	})
}
