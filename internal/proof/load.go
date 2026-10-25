package proof

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"path/filepath"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/lineage"
	"github.com/efij/AgentDFIR/v4/internal/overlay"
	"github.com/efij/AgentDFIR/v4/internal/version"
)

// derivedFiles are the overlay files the report is read from, relative
// to the package.
var derivedFiles = []struct{ path, note string }{
	{"normalized/events.jsonl", "normalized events with the evidence states analysis set"},
	{"detections/corroboration.json", "correlation summary: matches, per-kind coverage, collection health, coverage decisions"},
}

// Load builds the report for an analyzed package.
func Load(pkg string, o Options) (*Report, error) {
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		return nil, err
	}
	events := analysis.LoadEvents(pkg)
	findings := analysis.LoadFindings(pkg)
	corr := analysis.LoadCorrelation(pkg)
	g, err := lineage.Build(analysis.LineageInput(pkg, events, findings, corr), lineage.Options{SessionID: o.SessionID})
	if err != nil {
		return nil, err
	}
	in := Input{CaseID: man.CaseID, ToolVersion: version.Version, Events: events, Correlation: corr, Graph: g, Manifest: man}
	for _, d := range derivedFiles {
		if sum, ok := overlayHash(filepath.Join(pkg, filepath.FromSlash(d.path))); ok {
			in.Derived = append(in.Derived, DerivedFile{Path: d.path, SHA256: sum, Note: d.note})
		}
	}
	return Build(in, o), nil
}

// overlayHash hashes an overlay file's content, streaming (the events
// overlay can be hundreds of megabytes) and decompressed.
func overlayHash(p string) (string, bool) {
	rc, err := overlay.Open(p)
	if err != nil {
		return "", false
	}
	defer rc.Close()
	h := sha256.New()
	if _, err := io.Copy(h, rc); err != nil {
		return "", false
	}
	return hex.EncodeToString(h.Sum(nil)), true
}
