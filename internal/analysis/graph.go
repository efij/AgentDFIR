package analysis

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/efij/AgentDFIR/v3/internal/accounts"
	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/correlate"
	"github.com/efij/AgentDFIR/v3/internal/gaps"
	"github.com/efij/AgentDFIR/v3/internal/lineage"
	"github.com/efij/AgentDFIR/v3/internal/overlay"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/witness"
)

// Overlay files of the investigation layer, under normalized/. Both are
// derived data like the rest of the overlay: regenerable, outside the seal.
const (
	CoverageFile = "coverage.json"
	LineageFile  = "lineage.json"
)

// LoadCorrelation reads the endpoint correlation summary analysis stored,
// or nil when the case has none.
func LoadCorrelation(pkg string) *correlate.EndpointResult {
	data, err := overlay.ReadFile(filepath.Join(pkg, "detections", "corroboration.json"))
	if err != nil {
		return nil
	}
	var v struct {
		Summary *correlate.EndpointResult `json:"summary"`
	}
	if json.Unmarshal(data, &v) != nil {
		return nil
	}
	return v.Summary
}

// GapsInput assembles what coverage is computed from. events and
// findings may be passed in by a caller that already holds them; nil
// loads them from the overlay.
func GapsInput(pkg string, events []schema.Event, findings []schema.Finding, corr *correlate.EndpointResult) gaps.Input {
	if events == nil {
		events = LoadEvents(pkg)
	}
	if findings == nil {
		findings = LoadFindings(pkg)
	}
	in := gaps.Input{Events: events, Findings: findings, Correlation: corr}
	if man, err := casepkg.ReadManifest(pkg); err == nil {
		in.Manifest, in.CaseID, in.Host = man, man.CaseID, man.Host
	}
	if ci, err := casepkg.ReadCaseInfo(pkg); err == nil {
		in.CaseInfo = ci
		if in.CaseID == "" {
			in.CaseID = ci.CaseID
		}
	}
	if w, err := witness.Load(pkg); err == nil {
		in.Witness = w
	}
	return in
}

// LineageInput assembles what the lineage graph is built from, with the
// account of every transcript resolved from the login files in the case.
func LineageInput(pkg string, events []schema.Event, findings []schema.Finding, corr *correlate.EndpointResult) lineage.Input {
	if events == nil {
		events = LoadEvents(pkg)
	}
	if findings == nil {
		findings = LoadFindings(pkg)
	}
	in := lineage.Input{Events: events, Findings: findings, Correlation: corr}
	if man, err := casepkg.ReadManifest(pkg); err == nil {
		in.CaseID = man.CaseID
		accts, uuids := accounts.Identities(casepkg.NewStore(pkg, man), man.Current())
		in.Account = func(logical, product string) *accounts.Account {
			return accounts.Resolve(accts, uuids, logical, product)
		}
	}
	return in
}

// investigationOverlay writes normalized/coverage.json and
// normalized/lineage.json from the finished analysis. It is the one stage
// that may not fail the analysis: what it reports is about the evidence,
// not part of it, so any error — including a panic on input nobody
// anticipated — becomes a stage note and the findings stand.
func investigationOverlay(pkg string, events []schema.Event, findings []schema.Finding, corr *correlate.EndpointResult) (notes []string) {
	defer func() {
		if r := recover(); r != nil {
			notes = append(notes, fmt.Sprintf("investigation overlay stopped: %v", r))
		}
	}()
	dir := filepath.Join(pkg, "normalized")
	cov := gaps.Build(GapsInput(pkg, events, findings, corr), gaps.Options{})
	if err := overlay.WriteJSON(filepath.Join(dir, CoverageFile), cov); err != nil {
		notes = append(notes, "coverage report not written: "+err.Error())
	}
	g, err := lineage.Build(LineageInput(pkg, events, findings, corr), lineage.Options{})
	if err != nil {
		return append(notes, "lineage graph not built: "+err.Error())
	}
	if err := overlay.WriteJSON(filepath.Join(dir, LineageFile), g); err != nil {
		notes = append(notes, "lineage graph not written: "+err.Error())
	}
	return notes
}

// LoadCoverage reads normalized/coverage.json, or nil when it is missing
// or unreadable.
func LoadCoverage(pkg string) *gaps.Report {
	data, err := overlay.ReadFile(filepath.Join(pkg, "normalized", CoverageFile))
	if err != nil {
		return nil
	}
	var r gaps.Report
	if json.Unmarshal(data, &r) != nil || r.Schema != gaps.Schema {
		return nil
	}
	return &r
}

// StaleReason says why a package's stored analysis is missing or was not
// produced by this binary's analysis code from the evidence it holds now,
// or "" when it is current. Commands that read results across cases
// refuse stale ones rather than compare results from different code.
func StaleReason(pkg string) string { return staleReason(pkg) }
