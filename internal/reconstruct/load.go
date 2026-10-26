package reconstruct

import (
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/analysis"
	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/crosscase"
	"github.com/efij/AgentDFIR/v5/internal/gaps"
	"github.com/efij/AgentDFIR/v5/internal/lineage"
	"github.com/efij/AgentDFIR/v5/internal/overlay"
)

// Run loads, verifies and reconstructs the packages.
func Run(pkgs []string, o Options) (*Report, error) {
	in, err := LoadInput(pkgs, o)
	if err != nil {
		return nil, err
	}
	return Build(*in, o), nil
}

// LoadInput reads every package's stored analysis. The rules are
// crosscase's: each package must be analyzed by this binary's analysis
// code and its seal must verify (unless AllowUnverified, which marks the
// report). With two or more packages the shared items come from
// crosscase.Run, which applies the same checks.
func LoadInput(pkgs []string, o Options) (*Input, error) {
	if len(pkgs) == 0 {
		return nil, errors.New("need at least one package")
	}
	if o.Verify == nil {
		o.Verify = crosscase.VerifyPackage
	}
	in := &Input{}
	integrity := map[string]string{}
	if len(pkgs) >= 2 {
		rep, err := crosscase.Run(pkgs, crosscase.Options{AllowUnverified: o.AllowUnverified, IncludeCommon: o.IncludeCommon, Verify: o.Verify})
		if err != nil {
			return nil, err
		}
		in.Cross = rep
		in.Notes = append(in.Notes, rep.Notes...)
		for _, c := range rep.Cases {
			integrity[c.Label] = c.Integrity.Result
		}
	} else {
		label := "C1"
		if why := analysis.StaleReason(pkgs[0]); why != "" {
			return nil, &crosscase.RefusedError{Problems: []string{fmt.Sprintf("%s (%s): analysis is not current (%s). Run: agentdfir analyze %s", label, pkgs[0], why, pkgs[0])}}
		}
		integ := o.Verify(pkgs[0])
		if integ.Result != "VERIFIED" && !o.AllowUnverified {
			return nil, &crosscase.RefusedError{Problems: []string{fmt.Sprintf("%s (%s): seal does not verify (%s). Pass --allow-unverified to reconstruct it anyway; every result is then marked.",
				label, pkgs[0], strings.Join(integ.Problems, "; "))}}
		}
		integrity[label] = integ.Result
	}
	for i, p := range pkgs {
		label := fmt.Sprintf("C%d", i+1)
		ci, err := LoadCase(label, p)
		if err != nil {
			return nil, &crosscase.RefusedError{Problems: []string{fmt.Sprintf("%s (%s): %v", label, p, err)}}
		}
		ci.Integrity = integrity[label]
		in.Cases = append(in.Cases, *ci)
	}
	return in, nil
}

// LoadCase reads one analyzed package. It does not verify the seal; the
// caller does (LoadInput).
func LoadCase(label, pkg string) (*CaseInput, error) {
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		return nil, err
	}
	ci := &CaseInput{Label: label, Path: pkg, CaseID: man.CaseID, Host: man.Host, OS: man.OS}
	users := map[string]bool{}
	for _, a := range man.Current() {
		if a.User != "" {
			users[a.User] = true
		}
	}
	for u := range users {
		ci.OSUsers = append(ci.OSUsers, u)
	}
	sort.Strings(ci.OSUsers)
	ci.Events = analysis.LoadEvents(pkg)
	ci.Findings = analysis.LoadFindings(pkg)
	ci.Correlation = analysis.LoadCorrelation(pkg)
	ci.Coverage = analysis.LoadCoverage(pkg)
	if ci.Coverage == nil {
		ci.Coverage = gaps.Build(analysis.GapsInput(pkg, ci.Events, ci.Findings, ci.Correlation), gaps.Options{})
	}
	ci.Lineage = storedLineage(pkg)
	if ci.Lineage == nil {
		g, err := lineage.Build(analysis.LineageInput(pkg, ci.Events, ci.Findings, ci.Correlation), lineage.Options{})
		if err == nil {
			ci.Lineage = g
		}
	}
	return ci, nil
}

func storedLineage(pkg string) *lineage.Graph {
	data, err := overlay.ReadFile(filepath.Join(pkg, "normalized", analysis.LineageFile))
	if err != nil {
		return nil
	}
	var g lineage.Graph
	if json.Unmarshal(data, &g) != nil || g.Schema != lineage.Schema {
		return nil
	}
	return &g
}

// WriteOverlay stores the report as normalized/reconstruct.json in a
// package: derived data like coverage.json and lineage.json, outside the
// seal, replaced by the next reconstruction that includes the package.
func WriteOverlay(pkg string, r *Report) error {
	return overlay.WriteJSON(filepath.Join(pkg, "normalized", OverlayFile), r)
}

// LoadOverlay reads normalized/reconstruct.json, or nil.
func LoadOverlay(pkg string) *Report {
	data, err := overlay.ReadFile(filepath.Join(pkg, "normalized", OverlayFile))
	if err != nil {
		return nil
	}
	var r Report
	if json.Unmarshal(data, &r) != nil || r.Schema != Schema {
		return nil
	}
	return &r
}
