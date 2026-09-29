package analysis

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/detect"
	"github.com/efij/AgentDFIR/v3/internal/fingerprint"
	"github.com/efij/AgentDFIR/v3/internal/normalize"
	"github.com/efij/AgentDFIR/v3/internal/overlay"
	"github.com/efij/AgentDFIR/v3/internal/rulepack"
	"github.com/efij/AgentDFIR/v3/internal/store"
)

// analyzedCase is a two-transcript-product case analyzed once.
func analyzedCase(t *testing.T) (pkg, root string, first *Result) {
	t.Helper()
	root = t.TempDir()
	writeProfile(t, root, 1)
	pkg = filepath.Join(t.TempDir(), "d.adfir")
	b, err := casepkg.New(pkg, "DELTA", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	collectRound(t, b, root)
	first, err = Run(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	return pkg, root, first
}

// A round in which nothing changed leaves the stored results current: no
// rebuild, no re-analysis. And a new release of the binary that did not
// change any parsing or analysis code does not invalidate them either —
// the release number is not part of the key any more.
func TestNothingChangedMeansNothingRecomputed(t *testing.T) {
	pkg, root, _ := analyzedCase(t)
	b, err := casepkg.Reopen(pkg, casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	collectRound(t, b, root) // same files: every one carried forward
	if ok, why := Current(pkg, Options{}); !ok {
		t.Fatalf("unchanged round made results stale: %s", why)
	}
	// Rewrite analysis.json's version as if an older release (with the
	// same code) had produced it.
	p := filepath.Join(pkg, "detections", "analysis.json")
	var m map[string]any
	data, _ := overlay.ReadFile(p)
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	m["agentdfir_version"] = "0.0.1"
	if err := overlay.WriteJSON(p, m); err != nil {
		t.Fatal(err)
	}
	if ok, why := Current(pkg, Options{}); !ok {
		t.Fatalf("a release number alone invalidated results: %s", why)
	}
	// Different analysis code must invalidate them.
	m["analysis_fingerprint"] = "0000"
	if err := overlay.WriteJSON(p, m); err != nil {
		t.Fatal(err)
	}
	if ok, _ := Current(pkg, Options{}); ok {
		t.Fatal("results from different analysis code were treated as current")
	}
	if m["parse_fingerprint"] != fingerprint.Parse() {
		t.Fatal("analysis.json does not record the parse fingerprint")
	}
}

// Options that change what analysis finds make earlier results unusable.
func TestDifferentOptionsAreNotCurrent(t *testing.T) {
	pkg, _, _ := analyzedCase(t)
	if ok, why := Current(pkg, Options{}); !ok {
		t.Fatalf("fresh analysis not current: %s", why)
	}
	if ok, _ := Current(pkg, Options{Honeytokens: []string{"canary-123"}}); ok {
		t.Fatal("results computed without a honeytoken reused for a run with one")
	}
}

// Someone deletes an event from the overlay. The overlay no longer
// hashes to what AgentDFIR last wrote, so it is rebuilt from the sealed
// evidence and the event is back.
func TestEditedEventsAreRebuiltFromEvidence(t *testing.T) {
	pkg, _, first := analyzedCase(t)
	evPath := filepath.Join(pkg, "normalized", "events.jsonl")
	data, err := os.ReadFile(evPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.SplitAfter(string(data), "\n")
	if err := os.WriteFile(evPath, []byte(strings.Join(lines[1:], "")), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := normalize.Status(pkg); st.Current {
		t.Fatal("an overlay with an event removed was reported current")
	}
	again, err := Run(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !again.Renormalized || again.Events != first.Events {
		t.Fatalf("rebuilt=%t events=%d, want a rebuild back to %d", again.Renormalized, again.Events, first.Events)
	}
}

// Someone edits a cached segment. The next round that rebuilds the
// overlay replays it, the hash does not match, and the whole overlay is
// rebuilt from the sealed evidence — identical to a full re-parse.
func TestEditedSegmentIsRejected(t *testing.T) {
	pkg, root, _ := analyzedCase(t)
	segs, _ := filepath.Glob(filepath.Join(pkg, "normalized", "events", "*", "*.jsonl.gz"))
	if len(segs) == 0 {
		t.Fatal("no cached segments")
	}
	for _, sp := range segs {
		rewriteGz(t, sp, func(b []byte) []byte { return bytes.Replace(b, []byte("curl"), []byte("true"), 1) })
	}
	writeProfile(t, root, 2) // new evidence, so the overlay is rebuilt
	b, err := casepkg.Reopen(pkg, casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	collectRound(t, b, root)
	inc, err := Run(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, n := range inc.StageNotes {
		if strings.Contains(n, "cache rejected") {
			found = true
		}
	}
	if !found {
		t.Fatalf("edited segments were not reported: %v", inc.StageNotes)
	}
	clone := copyPkg(t, pkg)
	if _, err := Run(clone, Options{Renormalize: true}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(pkg, "normalized", "events.jsonl")) != readFile(t, filepath.Join(clone, "normalized", "events.jsonl")) {
		t.Fatal("overlay after rejecting the edited cache differs from a full parse")
	}
}

// With a machine key, the overlay state is authenticated: an edited
// state.json is not trusted.
func TestStateIsAuthenticatedWithTheMachineKey(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(store.EnvHome, home)
	if _, err := store.MachineKey(); err != nil {
		t.Fatal(err)
	}
	pkg, _, _ := analyzedCase(t)
	if _, err := os.Stat(filepath.Join(pkg, "normalized", "state.mac")); err != nil {
		t.Fatalf("no MAC written with a machine key present: %v", err)
	}
	if st := normalize.Status(pkg); !st.Current {
		t.Fatalf("authenticated overlay not current: %s", st.Reason)
	}
	sp := filepath.Join(pkg, "normalized", "state.json")
	data, _ := os.ReadFile(sp)
	if err := os.WriteFile(sp, bytes.Replace(data, []byte(`"events": `), []byte(`"events":  `), 1), 0o600); err != nil {
		t.Fatal(err)
	}
	if st := normalize.Status(pkg); st.Current {
		t.Fatal("state.json edited without the key was trusted")
	}
}

func rewriteGz(t *testing.T, path string, edit func([]byte) []byte) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	zr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := io.ReadAll(zr)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write(edit(plain))
	zw.Close()
	_ = os.Chmod(path, 0o600)
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Retiring artifacts from the scan set rebuilds the overlay incrementally,
// and the result is what a full parse of the reduced set produces.
func TestRetirementIsIncrementalAndEquivalent(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, 1)
	nm := filepath.Join(root, ".claude", "projects", "p", "node_modules")
	if err := os.MkdirAll(nm, 0o755); err != nil {
		t.Fatal(err)
	}
	writeTranscript(t, filepath.Join(nm, "vendored.jsonl"), claudeLines("sv", 0, 3))
	pkg := filepath.Join(t.TempDir(), "r.adfir")
	b, err := casepkg.New(pkg, "RET", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	// An older collector took the node_modules transcript.
	src := filepath.Join(nm, "vendored.jsonl")
	if err := b.IngestFile(src, casepkg.ArtifactRecord{SourcePath: src, LogicalPath: ".claude/projects/p/node_modules/vendored.jsonl",
		Product: "claude-code", ArtifactType: "transcript", CollectorRule: "claude.sessions"}); err != nil {
		t.Fatal(err)
	}
	collectRound(t, b, root)
	before, err := Run(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	inc, err := Run(pkg, Options{RetireExcluded: true})
	if err != nil {
		t.Fatal(err)
	}
	if inc.Events >= before.Events {
		t.Fatalf("events %d → %d: the retired transcript was never in the overlay; the test proves nothing", before.Events, inc.Events)
	}
	if inc.Reparsed != 0 {
		t.Fatalf("retiring re-parsed %d artifact(s); the rest are unchanged", inc.Reparsed)
	}
	clone := copyPkg(t, pkg)
	if _, err := Run(clone, Options{Renormalize: true}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"events.jsonl", "entities.jsonl", "relationships.jsonl"} {
		if readFile(t, filepath.Join(pkg, "normalized", name)) != readFile(t, filepath.Join(clone, "normalized", name)) {
			t.Fatalf("%s after incremental retirement differs from a full parse", name)
		}
	}
	if ok, why := Current(pkg, Options{RetireExcluded: true}); !ok {
		t.Fatalf("after retiring once, results not current: %s", why)
	}
}

// With a machine key, the content scans remember each artifact's result:
// a second analysis reads no unchanged artifact again, and what it finds
// is exactly what a scan of everything finds.
func TestContentScansAreRememberedPerArtifact(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(store.EnvHome, home)
	if _, err := store.MachineKey(); err != nil {
		t.Fatal(err)
	}
	pkg, root, _ := analyzedCase(t)
	writeProfile(t, root, 2) // some transcripts grow, one is new
	b, err := casepkg.Reopen(pkg, casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	collectRound(t, b, root)
	clone := copyPkg(t, pkg)
	inc, err := Run(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if detect.ContentMemoHits == 0 || rulepack.ArtifactMemoHits == 0 {
		t.Fatalf("no artifact served from the memo (content %d, rule packs %d)", detect.ContentMemoHits, rulepack.ArtifactMemoHits)
	}
	// The same round analyzed with no memo at all.
	if err := os.RemoveAll(filepath.Join(clone, "detections", "memo")); err != nil {
		t.Fatal(err)
	}
	full, err := Run(clone, Options{Renormalize: true})
	if err != nil {
		t.Fatal(err)
	}
	got, want := canonicalFindings(t, inc.Findings), canonicalFindings(t, full.Findings)
	if len(got) != len(want) {
		t.Fatalf("findings with memo %d, without %d", len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("finding %d differs:\n memo:    %s\n no memo: %s", i, got[i], want[i])
		}
	}
}
