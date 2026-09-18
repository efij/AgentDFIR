package casepkg

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Benchmarks for the acquisition path. They exist so claims about size and
// speed are measured rather than asserted:
//
//	go test ./internal/casepkg -run XXX -bench . -benchmem
//
// BenchmarkIngest* report bytes/op against the same fixture with and
// without compression, so the storage saving is visible next to its CPU
// cost. BenchmarkSeal and BenchmarkVerify* separate the two verification
// depths, which is the difference between opening a case instantly and
// re-reading every blob.

// transcriptFixture writes n synthetic JSONL transcripts shaped like real
// agent sessions (highly repetitive, which is why they compress).
func transcriptFixture(tb testing.TB, n, linesPerFile int) []string {
	tb.Helper()
	dir := tb.TempDir()
	var paths []string
	for i := 0; i < n; i++ {
		var sb strings.Builder
		for l := 0; l < linesPerFile; l++ {
			fmt.Fprintf(&sb, `{"type":"assistant","uuid":"u%d-%d","sessionId":"s%d","timestamp":"2026-01-01T00:00:%02dZ","message":{"role":"assistant","content":[{"type":"tool_use","id":"t%d","name":"Bash","input":{"command":"ls -la /some/path"}}]}}`+"\n",
				i, l, i, l%60, l)
		}
		p := filepath.Join(dir, fmt.Sprintf("session-%03d.jsonl", i))
		if err := os.WriteFile(p, []byte(sb.String()), 0o644); err != nil {
			tb.Fatal(err)
		}
		paths = append(paths, p)
	}
	return paths
}

func ingestAll(tb testing.TB, pkg string, paths []string, noCodec bool) *Builder {
	tb.Helper()
	b, err := New(pkg, "BENCH", CaseInfo{OperatorOSUser: "bench"})
	if err != nil {
		tb.Fatal(err)
	}
	b.NoCodec = noCodec
	for _, p := range paths {
		if err := b.IngestFile(p, ArtifactRecord{
			SourcePath: p, LogicalPath: filepath.Base(p), Product: "claude-code",
		}); err != nil {
			tb.Fatal(err)
		}
	}
	return b
}

func dirBytes(tb testing.TB, dir string) int64 {
	tb.Helper()
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func benchIngest(b *testing.B, noCodec bool) {
	paths := transcriptFixture(b, 24, 400)
	var stored, plain int64
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pkg := filepath.Join(b.TempDir(), fmt.Sprintf("case-%d.adfir", i))
		bld := ingestAll(b, pkg, paths, noCodec)
		if err := bld.Seal(); err != nil {
			b.Fatal(err)
		}
		if i == 0 {
			b.StopTimer()
			stored = dirBytes(b, filepath.Join(pkg, "raw"))
			for _, p := range paths {
				if fi, err := os.Stat(p); err == nil {
					plain += fi.Size()
				}
			}
			b.StartTimer()
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(stored), "stored_bytes")
	if stored > 0 {
		b.ReportMetric(float64(plain)/float64(stored), "compression_x")
	}
}

// BenchmarkIngestCompressed is the shipped path.
func BenchmarkIngestCompressed(b *testing.B) { benchIngest(b, false) }

// BenchmarkIngestPlain is the same work storing plaintext, for comparison.
func BenchmarkIngestPlain(b *testing.B) { benchIngest(b, true) }

// BenchmarkSeal measures sealing on its own: it reuses hashes computed
// during ingest instead of re-reading every blob.
func BenchmarkSeal(b *testing.B) {
	paths := transcriptFixture(b, 24, 400)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pkg := filepath.Join(b.TempDir(), fmt.Sprintf("case-%d.adfir", i))
		bld := ingestAll(b, pkg, paths, false)
		b.StartTimer()
		if err := bld.Seal(); err != nil {
			b.Fatal(err)
		}
	}
}

func benchVerify(b *testing.B, full bool) {
	paths := transcriptFixture(b, 24, 400)
	pkg := filepath.Join(b.TempDir(), "case.adfir")
	bld := ingestAll(b, pkg, paths, false)
	if err := bld.Seal(); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		var err error
		if full {
			_, err = Verify(pkg)
		} else {
			_, err = VerifyQuick(pkg)
		}
		if err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkVerifyFull re-hashes every stored blob (`agentdfir verify`).
func BenchmarkVerifyFull(b *testing.B) { benchVerify(b, true) }

// BenchmarkVerifyQuick is what opening a case in the explorer costs.
func BenchmarkVerifyQuick(b *testing.B) { benchVerify(b, false) }

// BenchmarkSecondRoundUnchanged measures a repeat collection where nothing
// changed: the work should be manifest bookkeeping, not re-reading files.
func BenchmarkSecondRoundUnchanged(b *testing.B) {
	if !SupportsCarryForward() {
		b.Skip("carry-forward unavailable on this platform")
	}
	paths := transcriptFixture(b, 24, 400)
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pkg := filepath.Join(b.TempDir(), fmt.Sprintf("case-%d.adfir", i))
		bld := ingestAll(b, pkg, paths, false)
		if err := bld.Seal(); err != nil {
			b.Fatal(err)
		}
		b.StartTimer()

		r2, err := Reopen(pkg, CaseInfo{OperatorOSUser: "bench"})
		if err != nil {
			b.Fatal(err)
		}
		for _, p := range paths {
			info, err := os.Lstat(p)
			if err != nil {
				b.Fatal(err)
			}
			prev, ok := r2.Unchanged(p, info)
			if !ok {
				b.Fatal("unchanged file not recognized")
			}
			if err := r2.CarryForward(prev, ArtifactRecord{SourcePath: p, LogicalPath: filepath.Base(p)}); err != nil {
				b.Fatal(err)
			}
		}
		if err := r2.Seal(); err != nil {
			b.Fatal(err)
		}
		b.StopTimer()
		if got := r2.Stats().StoredBytes; got != 0 {
			b.Fatalf("second round wrote %d bytes for evidence it already held", got)
		}
		b.StartTimer()
	}
}
