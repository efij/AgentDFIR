package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/products"
)

// collectInto runs a collection over root with the given options and
// returns the sealed package path.
func collectInto(t *testing.T, root string, opts Options) (string, *Stats) {
	t.Helper()
	man, err := products.Manifest("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := casepkg.New(pkg, "TEST-PAR", casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	opts.ProfileRoot = root
	opts.ConfigRoot = filepath.Join(root, ".claude")
	opts.SystemRoot = root
	opts.Product = "claude-code"
	st, err := Run(b, man, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	return pkg, st
}

// manifestShape reduces a package to what must not vary between runs.
func manifestShape(t *testing.T, pkg string) []string {
	t.Helper()
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(man.Artifacts))
	for _, a := range man.Artifacts {
		out = append(out, fmt.Sprintf("%s|%s|%s|%d", a.LogicalPath, a.Status, a.ArtifactID, a.Size))
	}
	return out
}

// TestParallelCollectionIsDeterministic is the property that makes a
// worker pool acceptable in a forensic tool: what gets collected, and the
// order it is recorded in, must not depend on how the workers interleaved.
func TestParallelCollectionIsDeterministic(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(root, ".claude", "projects", "-repo")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 60; i++ {
		content := strings.Repeat(fmt.Sprintf(`{"i":%d,"pad":"xxxxxxxxxxxxxxxx"}`+"\n", i), 40)
		if err := os.WriteFile(filepath.Join(proj, fmt.Sprintf("s%02d.jsonl", i)), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, ".claude.json"), []byte(`{"mcpServers":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	serialPkg, serialStats := collectInto(t, root, Options{Jobs: 1})
	parallelPkg, parallelStats := collectInto(t, root, Options{Jobs: 8})

	serial, parallel := manifestShape(t, serialPkg), manifestShape(t, parallelPkg)
	if len(serial) != len(parallel) {
		t.Fatalf("record count differs: serial %d, parallel %d", len(serial), len(parallel))
	}
	for i := range serial {
		if serial[i] != parallel[i] {
			t.Fatalf("record %d differs between a serial and a parallel run:\n  serial:   %s\n  parallel: %s", i, serial[i], parallel[i])
		}
	}
	if serialStats.Acquired != parallelStats.Acquired || serialStats.TotalBytes != parallelStats.TotalBytes {
		t.Fatalf("stats differ: serial %+v, parallel %+v", *serialStats, *parallelStats)
	}
	if res, err := casepkg.Verify(parallelPkg); err != nil || len(res.Problems) != 0 {
		t.Fatalf("parallel package does not verify: %v %v", err, res.Problems)
	}
}

// TestTotalBoundIsDeterministicUnderParallelism: which files a package
// bound excludes must be decided in discovery order, not by whichever
// worker got there first.
func TestTotalBoundIsDeterministicUnderParallelism(t *testing.T) {
	root := t.TempDir()
	proj := filepath.Join(root, ".claude", "projects", "-repo")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 40; i++ {
		if err := os.WriteFile(filepath.Join(proj, fmt.Sprintf("s%02d.jsonl", i)),
			[]byte(strings.Repeat("A", 4096)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A bound that cuts the set in the middle.
	opts := Options{MaxTotalBytes: 20 * 4096}
	a, _ := collectInto(t, root, opts)
	opts.Jobs = 8
	b, _ := collectInto(t, root, opts)
	sa, sb := manifestShape(t, a), manifestShape(t, b)
	if len(sa) != len(sb) {
		t.Fatalf("record count differs under a bound: %d vs %d", len(sa), len(sb))
	}
	for i := range sa {
		if sa[i] != sb[i] {
			t.Fatalf("bound excluded different files across runs at %d:\n  %s\n  %s", i, sa[i], sb[i])
		}
	}
}

// TestExcludedSubtreeIsRecordedNotDropped: skipping vendored dependencies
// saves hundreds of megabytes, but evidence that was never collected
// cannot be examined later — so the exclusion has to be visible.
func TestExcludedSubtreeIsRecordedNotDropped(t *testing.T) {
	root := t.TempDir()
	plugins := filepath.Join(root, ".claude", "plugins", "somepack")
	nm := filepath.Join(plugins, "node_modules", "dep")
	if err := os.MkdirAll(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugins, "plugin.json"), []byte(`{"name":"p"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nm, "index.js"), []byte(strings.Repeat("x", 5000)), 0o644); err != nil {
		t.Fatal(err)
	}

	pkg, _ := collectInto(t, root, Options{})
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var excluded, collectedDep bool
	for _, a := range man.Artifacts {
		if a.Status == casepkg.StatusSkippedPolicy && strings.Contains(a.LogicalPath, "node_modules") {
			excluded = true
			if !strings.Contains(a.Error, "1 file(s)") {
				t.Errorf("policy record does not say what was left out: %q", a.Error)
			}
		}
		if strings.Contains(a.LogicalPath, "node_modules/dep/index.js") && a.Status == casepkg.StatusOK {
			collectedDep = true
		}
	}
	if !excluded {
		t.Error("excluded subtree left no manifest record — the exclusion is invisible to an analyst")
	}
	if collectedDep {
		t.Error("node_modules content collected despite the default policy")
	}

	// --full-plugins must bring it back.
	pkg2, _ := collectInto(t, root, Options{FullContent: true})
	man2, err := casepkg.ReadManifest(pkg2)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range man2.Artifacts {
		if strings.Contains(a.LogicalPath, "node_modules/dep/index.js") && a.Status == casepkg.StatusOK {
			found = true
		}
	}
	if !found {
		t.Error("--full-plugins did not collect the excluded subtree")
	}
}

// TestSecondRoundCarriesForwardUnchangedFiles exercises the collector end
// to end: a repeat collection must not re-read what it already holds.
func TestSecondRoundCarriesForwardUnchangedFiles(t *testing.T) {
	root := fixtureProfile(t)
	man, err := products.Manifest("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	opts := Options{
		ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"), SystemRoot: root,
		Product: "claude-code", MaxFileBytes: 1024,
	}
	b, err := casepkg.New(pkg, "TEST-ROUND1", casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	first, err := Run(b, man, opts)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	if first.Acquired == 0 {
		t.Fatal("first round acquired nothing")
	}

	b2, err := casepkg.Reopen(pkg, casepkg.CaseInfo{OperatorOSUser: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := Run(b2, man, opts)
	if err != nil {
		t.Fatal(err)
	}
	roundStats := b2.Stats()
	if err := b2.Seal(); err != nil {
		t.Fatal(err)
	}
	if second.Carried != first.Acquired {
		t.Fatalf("carried forward %d of %d unchanged artifacts", second.Carried, first.Acquired)
	}
	if second.Acquired != 0 {
		t.Fatalf("re-read %d unchanged files on the second round", second.Acquired)
	}
	if roundStats.StoredBytes != 0 {
		t.Fatalf("second round wrote %d bytes for evidence it already held", roundStats.StoredBytes)
	}
	if res, err := casepkg.Verify(pkg); err != nil || len(res.Problems) != 0 {
		t.Fatalf("package does not verify after two rounds: %v %v", err, res.Problems)
	}
}
