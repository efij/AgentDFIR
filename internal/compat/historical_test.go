package compat

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/analysis"
	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/seal"
)

// TestHistoricalPackages extends the v1.0.0 guarantee to every release line
// since: v2.0.0 (append-only manifest), v2.7.0, v3.0.0 and v3.2.0 (signed
// rounds). Each package was written by that tag's own binary from the
// synthetic orphan-agent profile; the current binary must verify it, check
// its signature when it has one, and analyze it to the same verdict.
func TestHistoricalPackages(t *testing.T) {
	pkgs := Packages()
	if len(pkgs) < 5 {
		t.Fatalf("historical packages = %d, want v1.0.0 plus at least four tagged releases", len(pkgs))
	}
	for _, p := range pkgs {
		p := p
		t.Run(p.Version, func(t *testing.T) {
			dir, err := p.Extract(filepath.Join(t.TempDir(), "case.adfir"))
			if err != nil {
				t.Fatal(err)
			}
			res, err := casepkg.Verify(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(res.Problems) != 0 {
				t.Fatalf("%s package no longer verifies: %v", p.Version, res.Problems)
			}
			if res.ArtifactsOK == 0 {
				t.Fatalf("%s package: no artifacts", p.Version)
			}
			sig, err := seal.Verify(dir, "")
			if err != nil {
				t.Fatal(err)
			}
			if sig.Present && !sig.Valid {
				t.Fatalf("%s package: signature no longer verifies: %s", p.Version, sig.Reason)
			}
			ar, err := analysis.Run(dir, analysis.Options{})
			if err != nil {
				t.Fatalf("analyzing a %s package: %v", p.Version, err)
			}
			if ar.Events == 0 {
				t.Fatalf("%s package: no events", p.Version)
			}
			if p.Version == "v1.0.0" {
				return // a different profile; covered by compat_test.go
			}
			got := false
			for _, f := range ar.Findings {
				if f.RuleID == "ORPHAN_AGENT" {
					got = true
				}
			}
			if !got {
				t.Errorf("%s package: ORPHAN_AGENT no longer detected in the orphan-agent profile", p.Version)
			}
		})
	}
}

// TestHistoricalArchivesStaySmall: these ship inside the binary.
func TestHistoricalArchivesStaySmall(t *testing.T) {
	matches, _ := filepath.Glob("testdata/*.tar.gz")
	for _, m := range matches {
		st, err := os.Stat(m)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() > 1<<20 {
			t.Errorf("%s is %d bytes; keep historical packages under 1 MiB", m, st.Size())
		}
	}
}
