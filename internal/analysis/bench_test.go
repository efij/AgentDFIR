// Benchmarks for the incremental overlay. The pair that matters is
// BenchmarkNormalizeFull against BenchmarkNormalizeIncrementalNoChange:
// the second is the cost of a collection round that found nothing new,
// which is what an analyst re-running `agentdfir run` on a quiet machine
// pays. The Analyze pair shows how much of that reaches a whole analysis,
// which is far less, because detection, rule packs, provenance and chains
// still re-scan every event.

package analysis

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/normalize"
)

// benchPkg builds and analyzes a package of the given shape once, so a
// benchmark measures a re-analysis rather than a first one.
func benchPkg(b *testing.B, transcripts, calls int) string {
	root := b.TempDir()
	cdir := filepath.Join(root, ".claude", "projects", "p")
	xdir := filepath.Join(root, ".codex", "sessions")
	wt := func(p, s string) { writeTranscript(b, p, s) }
	wt(filepath.Join(root, ".claude", "settings.json"), `{"permissions":{"defaultMode":"bypassPermissions"}}`)
	for i := 0; i < transcripts; i++ {
		wt(filepath.Join(cdir, fmt.Sprintf("c%02d.jsonl", i)), claudeLines(fmt.Sprintf("s%02d", i), 0, calls))
		wt(filepath.Join(xdir, fmt.Sprintf("x%02d.jsonl", i)), codexLines(fmt.Sprintf("q%02d", i), 0, calls))
	}
	pkg := filepath.Join(b.TempDir(), "bench.adfir")
	bld, err := casepkg.New(pkg, "BN", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		b.Fatal(err)
	}
	collectAll(b, bld, root)
	if _, err := Run(pkg, Options{}); err != nil {
		b.Fatal(err)
	}
	return pkg
}

func BenchmarkNormalizeFull(b *testing.B) {
	pkg := benchPkg(b, 40, 400)
	dir := filepath.Join(pkg, "normalized")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := normalize.BuildOverlay(pkg, dir, normalize.OverlayOptions{Full: true}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNormalizeIncrementalNoChange(b *testing.B) {
	pkg := benchPkg(b, 40, 400)
	dir := filepath.Join(pkg, "normalized")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := normalize.BuildOverlay(pkg, dir, normalize.OverlayOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeFull(b *testing.B) {
	pkg := benchPkg(b, 40, 400)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Run(pkg, Options{Renormalize: true}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyzeIncremental(b *testing.B) {
	pkg := benchPkg(b, 40, 400)
	dir := filepath.Join(pkg, "normalized")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Force the normalize stage to run without forcing a re-parse,
		// which is the shape a new collection round produces.
		if _, err := normalize.BuildOverlay(pkg, dir, normalize.OverlayOptions{}); err != nil {
			b.Fatal(err)
		}
		if _, err := Run(pkg, Options{}); err != nil {
			b.Fatal(err)
		}
	}
}
