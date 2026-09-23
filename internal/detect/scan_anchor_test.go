package detect

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
)

// scanFixtureStore ingests one blob and returns a store plus its artifact id.
func scanFixtureStore(t *testing.T, data []byte) (*casepkg.Store, string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "s.jsonl")
	if err := os.WriteFile(src, data, 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(t.TempDir(), "p.adfir")
	b, err := casepkg.New(pkg, "SCAN-A", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.IngestFile(src, casepkg.ArtifactRecord{SourcePath: src, LogicalPath: "s.jsonl", Product: "claude-code", ArtifactType: "agent_session"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	cur := man.Current()
	if len(cur) != 1 {
		t.Fatalf("want 1 artifact, got %d", len(cur))
	}
	return casepkg.NewStore(pkg, man), cur[0].ArtifactID
}

// referenceScan is the plain definition the streaming scan must agree
// with: every pattern's non-overlapping matches over the whole blob.
func referenceScan(data []byte) (first map[string]int64, counts map[string]int) {
	first, counts = map[string]int64{}, map[string]int{}
	for _, p := range secretPatterns {
		for _, loc := range p.re.FindAllIndex(data, -1) {
			counts[p.name]++
			if _, ok := first[p.name]; !ok {
				first[p.name] = int64(loc[0])
			}
		}
	}
	return
}

// The secret scan is prefiltered on each pattern's literal anchor. That
// must not change what it finds: counts and first offsets have to equal
// a whole-blob FindAllIndex, including a secret at offset 0, one glued to
// a word character (not a match), adjacent secrets, a secret that both
// the Anthropic and OpenAI patterns claim, and one straddling a chunk
// boundary.
func TestAnchoredSecretScanMatchesReference(t *testing.T) {
	aws := "AKIAIOSFODNN7EXAMPLE"
	ghp := "ghp_" + strings.Repeat("a", 36)
	ant := "sk-ant-" + strings.Repeat("b", 30)
	jwt := "eyJ" + strings.Repeat("c", 12) + "." + strings.Repeat("d", 12) + "." + strings.Repeat("e", 12)
	var b bytes.Buffer
	b.WriteString(aws)                         // offset 0: leading \b with no preceding byte
	b.WriteString(" x" + aws)                  // glued to a word char: no match
	b.WriteString(" " + ghp + " " + ghp + " ") // adjacent
	b.WriteString(ant + "\n")                  // ANTHROPIC and OPENAI both match here
	b.WriteString(jwt + "\n")
	for b.Len() < scanChunk-10 {
		b.WriteString(strings.Repeat("z", 1000) + "\n")
	}
	b.WriteString(aws) // straddles the first chunk boundary
	b.WriteString("\n" + strings.Repeat("y", 3000) + " " + ghp + "\n")
	data := b.Bytes()

	store, id := scanFixtureStore(t, data)
	hits, counts := scanRegex(blobReader{store, id}, secretPatterns)
	wantFirst, wantCounts := referenceScan(data)

	if len(wantCounts) == 0 {
		t.Fatal("fixture produced no reference matches")
	}
	gotFirst := map[string]int64{}
	for _, h := range hits {
		gotFirst[h.name] = h.offset
	}
	names := make([]string, 0, len(wantCounts))
	for n := range wantCounts {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if counts[n] != wantCounts[n] {
			t.Errorf("%s: count %d, want %d", n, counts[n], wantCounts[n])
		}
		if gotFirst[n] != wantFirst[n] {
			t.Errorf("%s: first offset %d, want %d", n, gotFirst[n], wantFirst[n])
		}
	}
	for n := range counts {
		if _, ok := wantCounts[n]; !ok {
			t.Errorf("%s: %d spurious match(es)", n, counts[n])
		}
	}
}

// Every secret pattern must carry a literal anchor that the pattern
// itself cannot match without; otherwise the prefilter would hide hits.
func TestSecretPatternsAnchorsAreRequired(t *testing.T) {
	for _, p := range secretPatterns {
		if p.lit == "" {
			t.Errorf("%s: no literal anchor", p.name)
			continue
		}
		if !strings.Contains(p.re.String(), p.lit) {
			t.Errorf("%s: anchor %q is not literally part of %q", p.name, p.lit, p.re.String())
		}
		// anchoredMatches assumes an anchor cannot occur at both offset
		// n and n+1, so a match found in the window starts at the anchor.
		if strings.HasPrefix(p.lit, p.lit[1:]) {
			t.Errorf("%s: anchor %q overlaps itself at shift one", p.name, p.lit)
		}
	}
}
