// Package benchmark makes AgentDFIR's forensic accuracy measurable by
// someone who does not trust its authors.
//
// Every number it reports comes from running the real pipeline — collect
// into a sealed package, verify, normalize, analyze — over labeled
// synthetic evidence, and comparing what came out with what the label
// says should have:
//
//	detection    the labeled corpus (internal/corpus) plus every simulate
//	             scenario: per-rule true/false positives and misses, rules
//	             that fired on benign fixtures, rules nothing tests
//	evidence     the evidence-state contract: nothing CONFIRMED without a
//	             second-witness record, model narrative stays CLAIMED,
//	             DISPROVED only on endpoint evidence
//	provenance   every event and finding points at a sealed artifact and
//	             a line that exists in it
//	integrity    a sealed package mutated one way at a time; verify must
//	             catch every mutation
//	compat       packages written by released binaries still verify and
//	             analyze
//	robustness   truncated, rewritten, clock-skewed and corrupted inputs:
//	             no crash, the right gap findings, no unsupported promotion
//	performance  analyze time and peak heap on a generated large case,
//	             against a recorded baseline (a warning, never a failure)
//
// and the cross-platform suites, each with its own PASS / FAIL / SKIP
// (suites.go): acquisition (every disk-image fixture), per-OS
// corroboration (Windows, macOS, Linux telemetry and the incomplete-
// telemetry contract), forensic interop (UFDR, AXIOM, Plaso, Autopsy),
// detection quality per platform, and evidence integrity (mutations,
// historical packages, the independent Python verifier).
//
// The results are SYNTHETIC. The fixtures are written to reproduce real
// shapes, but a score on them says how the tool behaves on those shapes
// and nothing about its accuracy on real evidence.
package benchmark

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"

	"github.com/efij/AgentDFIR/v5/internal/analysis"
	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/collector"
	"github.com/efij/AgentDFIR/v5/internal/corpus"
	"github.com/efij/AgentDFIR/v5/internal/products"
	"github.com/efij/AgentDFIR/v5/internal/schema"
	"github.com/efij/AgentDFIR/v5/internal/version"
)

// Label heads every report, in every format.
const Label = "SYNTHETIC benchmark — measured on labeled synthetic fixtures; not evidence of real-world accuracy"

// IndependentNote qualifies every precision and recall figure.
const IndependentNote = "Precision and recall here are measured on the synthetic corpus, whose labels were written next to the rules. Metrics on an independent corpus are reported separately; none are published yet."

// Options controls one run.
type Options struct {
	// Quick runs the fast subset `go test` uses: a sample of the corpus
	// and scenarios, every integrity mutation, no performance case.
	Quick bool
	// CorpusDir is a labeled corpus directory (benign/ and attack/); empty
	// uses the corpus embedded in the binary.
	CorpusDir string
	// SkipPerf leaves the performance case out.
	SkipPerf bool
	// PerfSessions sizes the generated performance case (default 400
	// sessions of 60 tool calls each).
	PerfSessions int
	// Baseline is compared against the measured performance; nil uses
	// the baseline embedded from testdata/perf-baseline.json.
	Baseline *PerfNumbers
	// Work is a scratch directory; empty creates and removes a temporary one.
	Work string
	// Log receives one progress line per section; nil is silent.
	Log io.Writer
	// RepoRoot is a source checkout holding the disk-image, telemetry and
	// interop fixtures and the Python verifier; empty searches from the
	// working directory. Without one those suites are skipped, with the
	// reason in the report.
	RepoRoot string
	// PythonVerifier runs tools/adfir-verify from a checkout found by
	// searching from the working directory. Without it (or RepoRoot) the
	// script, which executes, is never run: the directory may be anyone's.
	PythonVerifier bool
}

// Report is everything one run measured.
type Report struct {
	Label       string       `json:"label"`
	Version     string       `json:"agentdfir_version"`
	Quick       bool         `json:"quick_subset"`
	Detection   Detection    `json:"detection"`
	Evidence    Evidence     `json:"evidence_states"`
	Provenance  Provenance   `json:"provenance"`
	Integrity   Integrity    `json:"integrity"`
	Compat      Compat       `json:"compatibility"`
	Robustness  Robustness   `json:"robustness"`
	Performance *Performance `json:"performance,omitempty"`
	// The cross-platform suites, each with its own verdict in Suites.
	Suites       []Suite            `json:"suites,omitempty"`
	Acquisition  *Acquisition       `json:"acquisition,omitempty"`
	Platforms    *Platforms         `json:"platform_corroboration,omitempty"`
	Interop      *Interop           `json:"forensic_interop,omitempty"`
	IntegritySet *EvidenceIntegrity `json:"evidence_integrity,omitempty"`
	// V5 holds the checks of the v5 suites (v5.go).
	V5 *V5 `json:"v5,omitempty"`
	// Failures are hard checks that did not hold. Empty means the run
	// passed. Warnings never fail a run.
	Failures []string `json:"failures"`
	Warnings []string `json:"warnings"`

	// newPackages are packages this run built, handed to the independent
	// verifier by the evidence-integrity suite.
	newPackages []string
	// fixtures are the labeled detection fixtures, fired the rules each
	// one that ran produced, and mitreSeen the MITRE references of every
	// finding the detection section produced (rule → "ATLAS ATT&CK").
	fixtures  []fixture
	fired     map[string]map[string]int
	mitreSeen map[string]string
}

// Passed reports whether every hard check held.
func (r *Report) Passed() bool { return len(r.Failures) == 0 }

func (r *Report) fail(format string, a ...any) {
	r.Failures = append(r.Failures, fmt.Sprintf(format, a...))
}

// Run executes the benchmark.
func Run(o Options) (*Report, error) {
	work := o.Work
	if work == "" {
		dir, err := os.MkdirTemp("", "agentdfir-benchmark-")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		work = dir
	}
	r := &Report{Label: Label, Version: version.Version, Quick: o.Quick, Failures: []string{}, Warnings: []string{}}
	logf := func(format string, a ...any) {
		if o.Log != nil {
			fmt.Fprintf(o.Log, format+"\n", a...)
		}
	}
	prov := newProvenanceChecker()

	logf("detection: corpus + simulate scenarios")
	if err := runDetection(r, o, filepath.Join(work, "detection"), prov); err != nil {
		return nil, fmt.Errorf("detection: %w", err)
	}
	logf("evidence states: second-witness scenarios")
	if err := runEvidence(r, filepath.Join(work, "evidence"), prov); err != nil {
		return nil, fmt.Errorf("evidence states: %w", err)
	}
	logf("integrity: mutation suite")
	if err := runIntegrity(r, filepath.Join(work, "integrity")); err != nil {
		return nil, fmt.Errorf("integrity: %w", err)
	}
	logf("compatibility: historical packages")
	runCompat(r, filepath.Join(work, "compat"))
	logf("robustness: hostile inputs")
	if err := runRobustness(r, o, filepath.Join(work, "robustness"), prov); err != nil {
		return nil, fmt.Errorf("robustness: %w", err)
	}
	runSuites(r, o, work, prov)
	r.Provenance = prov.result()
	if n := r.Provenance.Dangling(); n > 0 {
		r.fail("provenance: %d dangling reference(s)", n)
	}
	if !o.Quick && !o.SkipPerf {
		logf("performance: generated large case")
		if err := runPerf(r, o, filepath.Join(work, "perf")); err != nil {
			return nil, fmt.Errorf("performance: %w", err)
		}
	}
	sort.Strings(r.Warnings)
	return r, nil
}

// analyzed is one profile after the real pipeline ran over it.
type analyzed struct {
	pkg      string
	result   *analysis.Result
	events   []schema.Event
	findings []schema.Finding
}

// collectAndAnalyze collects profile (a fake home directory) for the given
// products into a sealed package under work and analyzes it. A panic
// anywhere in the pipeline is returned as an error, not propagated: the
// robustness section counts crashes instead of dying on the first one.
func collectAndAnalyze(work, name, profile string, prods []string, ao analysis.Options) (a *analyzed, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = &crashError{fmt.Sprintf("panic: %v\n%s", p, debug.Stack())}
		}
	}()
	pkg, err := collect(work, name, profile, prods)
	if err != nil {
		return nil, err
	}
	res, err := analysis.Run(pkg, ao)
	if err != nil {
		return nil, err
	}
	return &analyzed{pkg: pkg, result: res, events: analysis.LoadEvents(pkg), findings: res.Findings}, nil
}

// buildAndAnalyze builds a corpus case through corpus.BuildPackage and
// analyzes it, with the same crash handling as collectAndAnalyze.
func buildAndAnalyze(work, name string, c corpus.Case, ao analysis.Options) (a *analyzed, err error) {
	defer func() {
		if p := recover(); p != nil {
			err = &crashError{fmt.Sprintf("panic: %v\n%s", p, debug.Stack())}
		}
	}()
	pkg := filepath.Join(work, name+".adfir")
	if err := corpus.BuildPackage(c, pkg, "BENCH-"+name, "benchmark"); err != nil {
		return nil, err
	}
	if len(c.Endpoint) > 0 {
		ao.EndpointLogs = c.EndpointLogs()
	}
	if c.Gateway != "" {
		ao.GatewayLog = c.GatewayLog()
	}
	res, err := analysis.Run(pkg, ao)
	if err != nil {
		return nil, err
	}
	return &analyzed{pkg: pkg, result: res, events: analysis.LoadEvents(pkg), findings: res.Findings}, nil
}

// collect acquires profile for prods into a sealed package and returns it.
func collect(work, name, profile string, prods []string) (string, error) {
	abs, err := filepath.Abs(profile)
	if err != nil {
		return "", err
	}
	pkg := filepath.Join(work, name+".adfir")
	b, err := casepkg.New(pkg, "BENCH-"+name, casepkg.CaseInfo{OperatorOSUser: "benchmark"})
	if err != nil {
		return "", err
	}
	defer b.Close()
	for _, prod := range prods {
		man, err := products.ManifestAllPlatforms(prod)
		if err != nil {
			return "", err
		}
		cfg := abs
		if p, err := products.ByID(prod); err == nil && len(p.ConfigDirs) > 0 {
			cfg = filepath.Join(abs, p.ConfigDirs[0])
		}
		if _, err := collector.Run(b, man, collector.Options{ProfileRoot: abs, ConfigRoot: cfg, SystemRoot: abs, Product: prod}); err != nil {
			return "", err
		}
	}
	return pkg, b.Seal()
}

// crashError marks a recovered panic.
type crashError struct{ msg string }

func (e *crashError) Error() string { return e.msg }

func isCrash(err error) bool {
	var c *crashError
	return errors.As(err, &c)
}

func ratio(num, den int) *float64 {
	if den == 0 {
		return nil
	}
	v := float64(num) / float64(den)
	return &v
}
