package benchmark

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/corpus"
	"github.com/efij/AgentDFIR/v4/internal/overlay"
	"github.com/efij/AgentDFIR/v4/internal/repro"
)

// sealedCopy copies only the sealed zone of a package, so a second
// analysis starts from the evidence alone and shares no overlay state.
func sealedCopy(t *testing.T, src string) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), "copy.adfir")
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{"normalized", "detections", "index", "reports"} {
		if err := os.RemoveAll(filepath.Join(dst, d)); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

// TestAnalysisIsDeterministic is what makes a findings fingerprint worth
// recording: the same sealed evidence analyzed twice from scratch, by the
// same code with the same options, must give the same findings — the
// same fingerprint, the same findings.json bytes and the same action
// graph. Map iteration order differs from run to run in Go, so any stage
// that emits findings, evidence references or graph elements in map
// order shows up here.
func TestAnalysisIsDeterministic(t *testing.T) {
	work := t.TempDir()
	fx, _, err := loadFixtures(Options{}, work)
	if err != nil {
		t.Fatal(err)
	}
	if testing.Short() {
		fx = quickSample(fx)
	}
	for i, f := range fx {
		f := f
		t.Run(f.name, func(t *testing.T) {
			var pkg string
			name := fmt.Sprintf("det-%d", i)
			switch {
			case f.case_ != nil:
				pkg = filepath.Join(work, name+".adfir")
				if err := corpus.BuildPackage(*f.case_, pkg, "DET-"+name, "benchmark"); err != nil {
					t.Fatal(err)
				}
			default:
				profile := f.profile
				if f.write != nil {
					profile = filepath.Join(work, "profile-"+name)
					if err := f.write(profile); err != nil {
						t.Fatal(err)
					}
				}
				if pkg, err = collect(work, name, profile, f.prods); err != nil {
					t.Fatal(err)
				}
			}
			var fps []string
			var files, graphs [][]byte
			for run := 0; run < 2; run++ {
				p := sealedCopy(t, pkg)
				if _, err := analysis.Run(p, analysis.Options{}); err != nil {
					t.Fatal(err)
				}
				m, err := repro.Read(repro.Path(p))
				if err != nil {
					t.Fatal(err)
				}
				fps = append(fps, m.FindingsFingerprint)
				fdata, _ := overlay.ReadFile(filepath.Join(p, "detections", "findings.json"))
				gdata, _ := overlay.ReadFile(filepath.Join(p, "normalized", "lineage.json"))
				files, graphs = append(files, fdata), append(graphs, gdata)
				if got, _, err := repro.FingerprintJSON(fdata); err != nil || got != m.FindingsFingerprint {
					t.Fatalf("findings.json fingerprint %s, manifest %s (%v)", got, m.FindingsFingerprint, err)
				}
			}
			if fps[0] != fps[1] {
				t.Errorf("findings fingerprint differs between two analyses of the same evidence: %s vs %s", fps[0], fps[1])
			}
			if !bytes.Equal(files[0], files[1]) {
				t.Errorf("findings.json differs between two analyses of the same evidence (ordering or content)")
			}
			if !bytes.Equal(graphs[0], graphs[1]) {
				t.Errorf("lineage.json differs between two analyses of the same evidence")
			}
		})
	}
}
