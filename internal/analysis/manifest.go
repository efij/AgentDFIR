package analysis

import (
	"runtime"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/fingerprint"
	"github.com/efij/AgentDFIR/v5/internal/repro"
	"github.com/efij/AgentDFIR/v5/internal/rulepack"
	"github.com/efij/AgentDFIR/v5/internal/schema"
	"github.com/efij/AgentDFIR/v5/internal/version"
)

// BuildManifest describes one finished analysis for
// detections/analysis-manifest.json (see package repro): the binary and
// code, the rule set, the evidence, the options and the findings
// fingerprint. reused is the number of endpoint-correlation findings the
// run carried forward, with the event states, from an earlier run instead
// of computing them (-1 when it reused none); overlayReused says the
// normalized events, with the evidence states earlier runs wrote into
// them, were reused rather than rebuilt from the sealed zone.
func BuildManifest(pkg string, o Options, packs []rulepack.PackSource, findings []schema.Finding, inputsDigest string, reused int, overlayReused bool, at time.Time) *repro.Manifest {
	if o.SpawnThreshold <= 0 {
		o.SpawnThreshold = 10
	}
	m := &repro.Manifest{
		Schema: repro.ManifestSchema, Spec: repro.Spec,
		Tool: repro.Tool{Name: "agentdfir", Version: version.Version, GoVersion: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH,
			AnalysisFingerprint: fingerprint.Analysis(), ParseFingerprint: fingerprint.Parse()},
		RuleSet: repro.RuleSet{BuiltinFingerprint: fingerprint.Analysis(), BuiltinPacks: !o.NoBuiltinPacks, Packs: []repro.Pack{},
			RulesDir: o.RulesDir, RulesDirFiles: repro.RulesDirFiles(o.RulesDir)},
		Input:       repro.SealInput(pkg),
		AnalyzedUTC: at.UTC().Format(time.RFC3339),
	}
	for _, p := range packs {
		m.RuleSet.Packs = append(m.RuleSet.Packs, repro.Pack{Pack: p.Pack, Version: p.Version, Rules: p.Rules, Origin: p.Origin, SHA256: p.SHA256})
	}
	m.Input.InputsDigest = inputsDigest
	if man, err := casepkg.ReadManifest(pkg); err == nil {
		m.Input.CaseID, m.Input.ADFIRVersion, m.Input.Artifacts = man.CaseID, man.ADFIRVersion, len(man.Current())
	}
	m.Options = ManifestOptions(o)
	if reused >= 0 {
		m.Options.ReusedCorrelation, m.Options.ReusedCorrelationFindings = true, reused
		m.Notes = append(m.Notes, "endpoint-correlation results (findings and event states) were carried forward from an earlier analysis; a reproduction from the sealed evidence cannot include them")
	}
	m.Options.OverlayReused = overlayReused
	rt := repro.RoundTrip(findings)
	m.Findings = repro.FindingsSummary{Count: len(rt), File: repro.FindingsFile, Algorithm: repro.FindingsAlgorithm, Fields: repro.FingerprintFields}
	m.FindingsFingerprint = repro.Fingerprint(rt)
	return m
}

// ManifestOptions records the options that change findings, naming every
// input file by its content.
func ManifestOptions(o Options) repro.Options {
	if o.SpawnThreshold <= 0 {
		o.SpawnThreshold = 10
	}
	ro := repro.Options{
		EndpointLogs: repro.HashFiles(o.EndpointLogs), EndpointFormat: string(o.EndpointFormat), WindowMS: o.Window.Milliseconds(),
		ShellHistory: repro.HashOptional(o.ShellHistory), GatewayLog: repro.HashOptional(o.GatewayLog), GatewayMap: repro.HashOptional(o.GatewayMap),
		GatewayServers: o.GatewayServers, NoBuiltinPacks: o.NoBuiltinPacks, SpawnThreshold: o.SpawnThreshold,
		KnownDests: o.KnownDests, IOCFiles: repro.HashFiles(o.IOCFiles), RetireExcluded: o.RetireExcluded,
	}
	ro.Honeytokens = repro.HoneytokenCount(o.Honeytokens)
	return ro
}
