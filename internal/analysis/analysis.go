// Package analysis is the one place a package gets analyzed. It runs the
// stages in the right order — normalize (only when needed), endpoint
// correlation, detections, rule packs, MCP audit, provenance — and writes
// one consistent set of results under <pkg>/detections/. Every command
// that shows or exports results (analyze/triage, serve, investigate,
// report) goes through here, so nothing is ever "not run yet" and later
// stages never clobber earlier ones.
package analysis

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/chain"
	"github.com/efij/AgentDFIR/v3/internal/correlate"
	"github.com/efij/AgentDFIR/v3/internal/detect"
	"github.com/efij/AgentDFIR/v3/internal/endpoint"
	"github.com/efij/AgentDFIR/v3/internal/fingerprint"
	"github.com/efij/AgentDFIR/v3/internal/index"
	"github.com/efij/AgentDFIR/v3/internal/ioc"
	"github.com/efij/AgentDFIR/v3/internal/journal"
	"github.com/efij/AgentDFIR/v3/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v3/internal/normalize"
	"github.com/efij/AgentDFIR/v3/internal/overlay"
	"github.com/efij/AgentDFIR/v3/internal/provenance"
	"github.com/efij/AgentDFIR/v3/internal/rulepack"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/verify"
	"github.com/efij/AgentDFIR/v3/internal/version"
	"github.com/efij/AgentDFIR/v3/internal/witness"
)

// Options are the optional inputs an analyst may add.
type Options struct {
	EndpointLogs   []string // auditd / Sysmon XML / JSONL-CSV exports (second witness)
	EndpointFormat endpoint.Format
	Window         time.Duration
	ShellHistory   string
	GatewayLog     string
	GatewayMap     string
	GatewayServers []string
	RulesDir       string
	NoBuiltinPacks bool // skip the packs embedded in the binary (built-in Go rules only)
	Honeytokens    []string
	SpawnThreshold int
	KnownDests     []string
	IOCFiles       []string  // extra incident IOC feeds (agentdfir pack, STIX 2.1, MISP)
	Renormalize    bool      // force re-parse even if the overlay is current
	RetireExcluded bool      // drop records the current collection policy would not have collected (node_modules, .git objects) from the scan set
	Log            io.Writer // progress lines; nil = silent
	// Stage is called as each stage begins, for a caller that wants to show
	// which one is running. Deliberately no time estimate: stage costs
	// differ by an order of magnitude and a guessed ETA is worse than none.
	Stage func(n, total int, name string)
}

// Result summarizes one run.
type Result struct {
	Events       int
	Entities     int
	Renormalized bool
	// Reused and Reparsed are source artifacts served from the overlay's
	// per-artifact segments versus read again, on the rounds where the
	// overlay had to be rebuilt.
	Reused      int
	Reparsed    int
	Findings    []schema.Finding
	Correlation *correlate.EndpointResult
	MCPServers  int
	Provenance  int // instruction files attributed
	Chains      int // attack-chain findings
	Packs       []rulepack.PackSource
	Witness     *witness.Result
	Groups      int
	StageNotes  []string
}

// stages are announced in the order Run executes them.
const analysisStages = 7

func (o *Options) stage(n int, name string) {
	if o.Stage != nil {
		o.Stage(n, analysisStages, name)
	}
}

func (o *Options) logf(format string, a ...any) {
	if o.Log != nil {
		fmt.Fprintf(o.Log, format+"\n", a...)
	}
}

// Stale reports whether results need (re)computing: no overlay, no
// findings, or the package was sealed after the overlay was written.
func Stale(pkg string) bool { return staleReason(pkg) != "" }

// staleReason says why results must be recomputed, or "" when they are
// current.
//
// Results are current when they were computed by this binary's analysis
// code, on the overlay the package holds now, from the evidence the
// package holds now. None of that is the release number: a release that
// changes no parser and no rule used to throw away every case's results,
// and three releases in a day meant three full re-analyses of an unchanged
// machine. Results computed by different analysis code are still
// recomputed — on a real case the difference was once 66 HIGH findings.
func staleReason(pkg string) string {
	st := normalize.Status(pkg)
	if !st.Current {
		return st.Reason
	}
	if !overlay.Exists(filepath.Join(pkg, "detections", "findings.json")) {
		return "no findings"
	}
	meta, err := readMeta(pkg)
	if err != nil {
		return "no analysis metadata"
	}
	switch {
	case meta.AnalysisFingerprint == "":
		if meta.Version != "" {
			return "analysis was produced by agentdfir " + meta.Version
		}
		return "analysis metadata carries no fingerprint"
	case meta.AnalysisFingerprint != fingerprint.Analysis():
		return "analysis code changed since agentdfir " + meta.Version + " produced these results"
	case meta.OverlayBuild != st.BuildID:
		return "the overlay was rebuilt since the last analysis"
	}
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		return "unreadable manifest"
	}
	if meta.InputsDigest != analysisInputs(man) {
		return "evidence changed since the last analysis"
	}
	return ""
}

// meta is the part of analysis.json staleness reads.
type meta struct {
	Events              int    `json:"events"`
	Version             string `json:"agentdfir_version"`
	AnalysisFingerprint string `json:"analysis_fingerprint"`
	OverlayBuild        string `json:"overlay_build"`
	InputsDigest        string `json:"inputs_digest"`
	OptionsDigest       string `json:"options_digest"`
}

func readMeta(pkg string) (*meta, error) {
	data, err := overlay.ReadFile(filepath.Join(pkg, "detections", "analysis.json"))
	if err != nil {
		return nil, err
	}
	var m meta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// analysisInputs identifies everything in the sealed zone analysis reads:
// every current record, including the ones no parser reads (the host
// witness, MCP configs read by the audit), by content address.
func analysisInputs(man *casepkg.Manifest) string {
	var keys []string
	for _, a := range man.Current() {
		keys = append(keys, a.Status+"\x00"+a.LogicalPath+"\x00"+a.SourcePath+"\x00"+a.ArtifactID+"\x00"+a.Product)
	}
	sort.Strings(keys)
	h := sha256.New()
	for _, k := range keys {
		h.Write([]byte(k))
		h.Write([]byte{'\n'})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// optionsDigest identifies the analyst-supplied inputs that change what a
// default analysis would find. A caller deciding whether earlier results
// can stand compares it along with staleness.
func (o Options) optionsDigest() string {
	h := sha256.New()
	fmt.Fprintf(h, "rules=%s\x00nopacks=%t\x00spawn=%d\x00", o.RulesDir, o.NoBuiltinPacks, o.SpawnThreshold)
	for _, l := range [][]string{o.EndpointLogs, o.Honeytokens, o.KnownDests, o.IOCFiles, o.GatewayServers} {
		fmt.Fprintf(h, "%q\x00", l)
	}
	fmt.Fprintf(h, "%s\x00%s\x00%s\x00%s\x00%s", o.ShellHistory, o.GatewayLog, o.GatewayMap, o.EndpointFormat, o.Window)
	return hex.EncodeToString(h.Sum(nil))
}

// Current reports whether the package's stored results are the ones Run
// with these options would produce now, and why not when they are not.
// A caller that gets true can use them instead of re-running.
func Current(pkg string, o Options) (bool, string) {
	if o.Renormalize {
		return false, "re-parse requested"
	}
	if why := staleReason(pkg); why != "" {
		return false, why
	}
	if o.SpawnThreshold <= 0 {
		o.SpawnThreshold = 10
	}
	o.Log, o.Stage = nil, nil
	m, err := readMeta(pkg)
	if err != nil || m.OptionsDigest != o.optionsDigest() {
		return false, "analysis options differ from the last analysis"
	}
	if o.RetireExcluded {
		if man, err := casepkg.ReadManifest(pkg); err == nil && man.RetireExcluded() > 0 {
			return false, "artifacts to retire from the scan set"
		}
	}
	return true, ""
}

// Ensure runs a default analysis only when results are missing or stale,
// and says why, so the analyst knows the numbers they were about to read
// were not the running version's.
func Ensure(pkg string, log io.Writer) (*Result, error) {
	why := staleReason(pkg)
	if why == "" {
		return nil, nil
	}
	if log != nil {
		fmt.Fprintf(log, "Re-running analysis with agentdfir %s: %s.\n", version.Version, why)
	}
	return Run(pkg, Options{Log: log})
}

// Run executes every stage and persists results.
func Run(pkg string, o Options) (*Result, error) {
	if o.SpawnThreshold <= 0 {
		o.SpawnThreshold = 10
	}
	res := &Result{}
	dir := filepath.Join(pkg, "normalized")
	var inputsDigest string
	detDir := filepath.Join(pkg, "detections")
	for _, d := range []string{dir, detDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}

	if o.RetireExcluded {
		// Records an older collector took from trees the policy now skips
		// stay as evidence but leave the scan set. On a real case this was
		// 5,752 plugin files (640 MB) from a v1.0.0 round, and the only
		// HIGH unicode finding was a .pptx among them.
		if man, err := casepkg.ReadManifest(pkg); err == nil {
			if n := man.RetireExcluded(); n > 0 {
				if err := casepkg.WriteRetired(pkg, man); err != nil {
					return nil, fmt.Errorf("retire excluded artifacts: %w", err)
				}
				res.StageNotes = append(res.StageNotes, fmt.Sprintf("%d artifacts under node_modules/.git objects retired from the scan set (evidence kept)", n))
				// No full re-parse: retiring changes the overlay's inputs,
				// so the incremental rebuild drops exactly those segments.
			}
		}
	}
	if man, err := casepkg.ReadManifest(pkg); err == nil {
		inputsDigest = analysisInputs(man)
	}
	o.stage(1, "normalize")
	// ---- 1. normalize (streaming) — only when the overlay is missing/stale.
	evPath := filepath.Join(dir, "events.jsonl")
	ovStatus := normalize.Status(pkg)
	needNorm := o.Renormalize || !ovStatus.Current
	prevMeta, _ := readMeta(pkg)
	var entities []schema.Entity
	if needNorm {
		// The overlay is segmented per source artifact, so a new collection
		// round only re-parses the transcripts whose content address
		// changed; the rest are copied back out of their segments. On a
		// real two-round package the old behaviour was 7 minutes 27 seconds
		// to re-parse 206,896 events out of artifacts that had not changed.
		//
		// events.jsonl itself stays uncompressed: internal/index records a
		// byte offset per event so the explorer can open one without
		// holding all of them, and a gzip stream cannot be seeked.
		sr, err := normalize.Refresh(pkg, normalize.OverlayOptions{Full: o.Renormalize})
		if err != nil {
			return nil, err
		}
		if sr.CacheRejected != "" {
			res.StageNotes = append(res.StageNotes, "overlay cache rejected, rebuilt from the sealed evidence: "+sr.CacheRejected)
		}
		entities, res.Events, res.Renormalized = sr.Entities, sr.EventCount, true
		res.Reused, res.Reparsed = sr.Reused, sr.Reparsed
		o.logf("Normalized: %d events, %d entities, %d relationships (%d artifact(s) parsed, %d reused from the overlay)",
			sr.EventCount, len(sr.Entities), len(sr.Relationships), sr.Reparsed, sr.Reused)
	} else {
		// A package analyzed by an earlier binary carries the overlay as
		// plaintext, and the reuse path below never rewrites it — so without
		// this the 178 MB would sit there until someone re-collected or
		// forced a re-parse. Migrate it once, here, where the files are about
		// to be read anyway.
		var reclaimed int64
		for _, name := range []string{"entities.jsonl", "relationships.jsonl"} {
			n, err := overlay.Compress(filepath.Join(dir, name))
			if err != nil {
				return nil, err
			}
			reclaimed += n
		}
		entities = overlay.ReadJSONL[schema.Entity](filepath.Join(dir, "entities.jsonl"))
		res.Events = overlay.CountLines(evPath)
		// Built since the last analysis (acquisition refreshes it before
		// asking the host about the agent's claims): new evidence, so
		// results computed on the previous build do not carry over.
		if prevMeta == nil || prevMeta.OverlayBuild != ovStatus.BuildID {
			res.Renormalized = true
		}
		o.logf("Normalized: reusing overlay (%d events); corroboration states preserved", res.Events)
		// Not a StageNote: those are printed as "note:" on stderr and mean a
		// stage was skipped or degraded. Reclaiming disk is neither.
		if reclaimed > 0 {
			o.logf("Normalized: overlay recompressed, %d bytes reclaimed", reclaimed)
		}
	}
	res.Entities = len(entities)

	o.stage(2, "second witness")
	var findings []schema.Finding
	// The events are decoded once and shared by every stage below. Each
	// stage used to read the whole overlay again — seven decodes of every
	// event per analysis, 323 MB each on a real machine. The stages that
	// annotate events (host witness, endpoint and shell corroboration)
	// change this one copy, and it is written back once, before the
	// detections that stream the file read it.
	var events []schema.Event
	loaded, dirty := false, false
	allEvents := func() []schema.Event {
		if !loaded {
			events, loaded = LoadEvents(pkg), true
		}
		return events
	}
	// Host witness recorded during acquisition. This is the only source
	// that is always available: it needs no EDR, no auditd, no Sysmon, and
	// it is why a finding can now say CONFIRMED instead of only RECORDED.
	if wrec, wErr := witness.Load(pkg); wErr == nil {
		wres, wf := witness.Apply(allEvents(), wrec)
		if wres.Checked > 0 {
			dirty = true
			findings = append(findings, wf...)
			res.Witness = &wres
			o.logf("Host witness: %d claimed write(s) checked — %d CONFIRMED, %d DISPROVED, %d no longer present",
				wres.Checked, wres.Confirmed, wres.Disproved, wres.Absent)
		}
	}
	// ---- 2. second witness (runs BEFORE detection so findings carry the states).
	if len(o.EndpointLogs) > 0 || o.ShellHistory != "" {
		events := allEvents()
		dirty = true
		if o.ShellHistory != "" {
			if cres, err := correlate.Apply(events, &correlate.ShellHistoryAdapter{Path: o.ShellHistory}); err == nil && cres.Corroborated > 0 {
				o.logf("Shell history: %d tool call(s) corroborated", cres.Corroborated)
			}
		}
		if len(o.EndpointLogs) > 0 {
			var records []endpoint.Record
			for _, p := range o.EndpointLogs {
				lr, err := endpoint.Load(p, o.EndpointFormat)
				if err != nil {
					return nil, fmt.Errorf("endpoint log %s: %w", p, err)
				}
				o.logf("Endpoint log %s: %s, %d records (%d skipped)", filepath.Base(p), lr.Format, len(lr.Records), lr.Skipped)
				records = append(records, lr.Records...)
			}
			cres, cf := correlate.Endpoint(events, records, correlate.EndpointOptions{Window: o.Window, KnownDests: o.KnownDests})
			res.Correlation = cres
			findings = append(findings, cf...)
			_ = overlay.WriteJSON(filepath.Join(detDir, "corroboration.json"), struct {
				Summary  *correlate.EndpointResult `json:"summary"`
				Findings []schema.Finding          `json:"findings"`
			}{cres, cf})
			o.logf("Endpoint correlation: %d checked — %d CORROBORATED, %d CONTRADICTED, %d outside coverage; %d unlogged agent records",
				cres.ToolCalls, cres.Corroborated, cres.Contradicted, cres.OutsideCover, cres.Unlogged)
			if cres.CloudRecords > 0 {
				o.logf("Cloud audit correlation: %d cloud command(s) checked — %d CORROBORATED (%d refused by the cloud); %d destructive burst(s)",
					cres.CloudCommands, cres.CloudCorroborated, cres.CloudRefused, cres.CloudBursts)
			}
		}
	}
	if dirty {
		if err := overlay.WriteJSONLPlain(evPath, len(events), func(i int) any { return events[i] }); err != nil {
			return nil, err
		}
		if err := normalize.RecordEvents(pkg); err != nil {
			return nil, err
		}
	}

	// Earlier second-witness results stay part of the case as long as the
	// overlay they were computed on is still in use; a re-parse invalidates them.
	corrPath := filepath.Join(detDir, "corroboration.json")
	if len(o.EndpointLogs) == 0 {
		if res.Renormalized {
			_ = overlay.Remove(corrPath)
		} else if data, err := overlay.ReadFile(corrPath); err == nil {
			var prev struct {
				Summary  *correlate.EndpointResult `json:"summary"`
				Findings []schema.Finding          `json:"findings"`
			}
			if json.Unmarshal(data, &prev) == nil {
				res.Correlation = prev.Summary
				findings = append(findings, prev.Findings...)
				o.logf("Endpoint correlation: reusing earlier results (%d finding(s))", len(prev.Findings))
			}
		}
	}

	o.stage(3, "detections")
	// ---- 3. detections (streaming over the overlay).
	det, err := detect.RunStream(pkg, entities, detect.Options{Honeytokens: o.Honeytokens, SpawnThreshold: o.SpawnThreshold, KnownDestinations: o.KnownDests})
	if err != nil {
		return nil, err
	}
	findings = append(findings, det...)
	// Transcripts against the monitor journal, when one was collected.
	if man, err := casepkg.ReadManifest(pkg); err == nil {
		jf := journal.Check(man, casepkg.NewStore(pkg, man))
		findings = append(findings, jf...)
		if len(jf) > 0 {
			o.logf("Monitor journal: %d finding(s)", len(jf))
		}
	}

	o.stage(4, "rule packs")
	// ---- 4. declarative rule packs.
	//
	// The packs shipped with the binary run by default. They used to load
	// only from --rules, which nothing set, so on an installed copy the
	// whole declarative rule set was inert.
	var packs []rulepack.Pack
	var packSrcs []rulepack.PackSource
	if !o.NoBuiltinPacks {
		ep, es, err := rulepack.Embedded()
		if err != nil {
			return nil, fmt.Errorf("embedded rule packs: %w", err)
		}
		packs, packSrcs = ep, es
	}
	if o.RulesDir != "" {
		extraPacks, err := rulepack.LoadDir(o.RulesDir)
		if err != nil {
			return nil, fmt.Errorf("rule packs: %w", err)
		}
		for _, ep := range extraPacks {
			packSrcs = append(packSrcs, rulepack.PackSource{
				Pack: ep.Pack, Version: ep.Version, Rules: len(ep.Rules), Origin: o.RulesDir,
			})
		}
		packs = append(packs, extraPacks...)
	}
	if len(packs) > 0 {
		var dropped []string
		packs, dropped = rulepack.Dedupe(packs)
		for _, d := range dropped {
			res.StageNotes = append(res.StageNotes, "duplicate rule id: "+d)
		}
		extra, err := rulepack.Apply(packs, &schema.Normalized{Events: allEvents()}, pkg)
		if err != nil {
			return nil, fmt.Errorf("rule packs: %w", err)
		}
		findings = append(findings, extra...)
		n := 0
		for _, p := range packs {
			n += len(p.Rules)
		}
		o.logf("Rule packs: %d pack(s), %d rule(s), %d finding(s)", len(packs), n, len(extra))
	}
	res.Packs = packSrcs

	o.stage(5, "MCP audit")
	// ---- 5. MCP supply-chain audit (+ gateway corroboration).
	inv, mcpExtra, err := mcpaudit.ScanPackage(pkg)
	if err == nil {
		mf := append(mcpExtra, mcpaudit.Evaluate(inv)...)
		var gw *mcpaudit.GatewaySummary
		if o.GatewayLog != "" {
			m := mcpaudit.DefaultGatewayMap
			if o.GatewayMap != "" {
				if data, err := os.ReadFile(o.GatewayMap); err == nil {
					_ = json.Unmarshal(data, &m)
				}
			}
			recs, unparsed, err := mcpaudit.LoadGatewayLog(o.GatewayLog, m)
			if err != nil {
				return nil, fmt.Errorf("gateway log: %w", err)
			}
			sum, gf := mcpaudit.CorrelateGateway(allEvents(), recs, o.GatewayServers, 3)
			sum.Unparsed = unparsed
			gw = &sum
			mf = append(mf, gf...)
		}
		res.MCPServers = len(inv.Servers)
		findings = append(findings, mf...)
		_ = overlay.WriteJSON(filepath.Join(detDir, "mcp-audit.json"), struct {
			Inventory *mcpaudit.Inventory      `json:"inventory"`
			Findings  []schema.Finding         `json:"findings"`
			Gateway   *mcpaudit.GatewaySummary `json:"gateway,omitempty"`
		}{inv, mf, gw})
		o.logf("MCP audit: %d server(s) in %d config(s), %d finding(s)", len(inv.Servers), len(inv.Configs), len(mf))
	} else {
		res.StageNotes = append(res.StageNotes, "mcp audit skipped: "+err.Error())
	}
	// Known-incident indicators (the embedded packs, plus --iocs feeds):
	// commands, tool output, configs, shell history, MCP packages and file
	// hashes. Raw transcript bytes and lockfiles on disk are `agentdfir
	// hunt`'s job; this keeps analyze at one read per small artifact.
	if hf, notes, err := HuntCase(pkg, inv, HuntOptions{IOCFiles: o.IOCFiles}); err == nil {
		findings = append(findings, ioc.Findings(hf)...)
		res.StageNotes = append(res.StageNotes, notes...)
		_ = overlay.WriteJSON(filepath.Join(detDir, "hunt.json"), hf)
		hits := 0
		for _, v := range hf {
			if len(v.Hits) > 0 {
				hits++
			}
		}
		o.logf("Incident IOCs: %d incident(s) checked, %d with indicators present", len(hf), hits)
	} else {
		res.StageNotes = append(res.StageNotes, "incident IOC check skipped: "+err.Error())
	}

	o.stage(6, "provenance")
	// ---- 6. instruction & memory provenance.
	if prov, err := provenance.Run(pkg, allEvents(), ""); err == nil {
		res.Provenance = len(prov.Files)
		findings = append(findings, prov.Findings...)
		_ = overlay.WriteJSON(filepath.Join(detDir, "provenance.json"), prov)
		o.logf("Provenance: %d instruction file(s) attributed, %d write(s) to uncollected instruction paths, %d finding(s)", len(prov.Files), len(prov.OtherWrite), len(prov.Findings))
	} else {
		res.StageNotes = append(res.StageNotes, "provenance skipped: "+err.Error())
	}

	o.stage(7, "attack chains")
	// ---- 7. attack chains: toxic combinations across the findings above.
	chains := append([]chain.Chain(nil), chain.Builtin...)
	if o.RulesDir != "" { //nolint:dupl // embedded chain packs are not shipped yet
		extra, err := chain.LoadDir(o.RulesDir)
		if err != nil {
			return nil, fmt.Errorf("chain packs: %w", err)
		}
		chains = append(chains, extra...)
	}
	cf := chain.Run(allEvents(), findings, chains)
	res.Chains = len(cf)
	findings = append(findings, cf...)
	o.logf("Attack chains: %d chain(s) evaluated, %d matched", len(chains), len(cf))

	// ---- 8. confidence, then one findings file, severity-sorted.
	//
	// Confidence is computed last, over the finished set, so a verifier can
	// see the enrichment states the earlier stages produced.
	findings = verify.Apply(findings, allEvents())
	findings = dedupe(findings)
	sortBySeverity(findings)
	res.Findings = findings
	_ = overlay.WriteJSON(filepath.Join(detDir, "findings.json"), findings)
	// Grouped by rule and session, which is how an analyst reads them: on a
	// real machine 592 HIGH and CRITICAL findings were 85 groups.
	groups := verify.GroupBy(findings)
	res.Groups = len(groups)
	_ = overlay.WriteJSON(filepath.Join(detDir, "groups.json"), groups)
	_ = overlay.WriteJSON(filepath.Join(detDir, "analysis.json"), map[string]any{
		"analyzed_utc": time.Now().UTC().Format(time.RFC3339), "events": res.Events, "renormalized": res.Renormalized,
		"artifacts_parsed": res.Reparsed, "artifacts_reused": res.Reused,
		"findings": len(findings), "endpoint_logs": o.EndpointLogs, "gateway_log": o.GatewayLog, "rules_dir": o.RulesDir,
		"honeytokens": len(o.Honeytokens), "chains": res.Chains, "notes": res.StageNotes,
		// Which rule set decided this, by name, version and content hash —
		// so the question stays answerable after the binary is replaced.
		"rule_packs": packSrcs, "agentdfir_version": version.Version,
		// What decides whether these results can be reused: the code that
		// produced them, the overlay build and evidence they were computed
		// on, and the analyst's options (see staleReason and Current).
		"analysis_fingerprint": fingerprint.Analysis(), "parse_fingerprint": fingerprint.Parse(),
		"overlay_build": normalize.Status(pkg).BuildID, "inputs_digest": inputsDigest,
		"options_digest": o.optionsDigest(),
	})
	// The explorer's offset index over the finished overlay, built here so
	// opening a case is instant instead of re-parsing hundreds of MB of
	// JSON. It is derived data: it sits in <pkg>/index/, outside the sealed
	// zone and outside SHA256SUMS, and anything that can go wrong writing
	// it (a read-only evidence share, a full disk) costs nothing, because
	// serve rebuilds a missing index by itself.
	if err := index.Refresh(pkg); err != nil {
		res.StageNotes = append(res.StageNotes, "event index skipped: "+err.Error())
	}
	return res, nil
}

// LoadEvents reads the overlay into memory (for stages that need it).
func LoadEvents(pkg string) []schema.Event {
	return overlay.ReadJSONL[schema.Event](filepath.Join(pkg, "normalized", "events.jsonl"))
}

// LoadEntities reads the overlay entities.
func LoadEntities(pkg string) []schema.Entity {
	return overlay.ReadJSONL[schema.Entity](filepath.Join(pkg, "normalized", "entities.jsonl"))
}

// PreviousEvents is how many events the last analysis of the package
// covered (0 when there was none). Progress uses it to size the analysis
// before it starts.
func PreviousEvents(pkg string) int {
	if m, err := readMeta(pkg); err == nil {
		return m.Events
	}
	return 0
}

// LoadFindings reads the persisted findings.
func LoadFindings(pkg string) []schema.Finding {
	var out []schema.Finding
	if data, err := overlay.ReadFile(filepath.Join(pkg, "detections", "findings.json")); err == nil {
		_ = json.Unmarshal(data, &out)
	}
	return out
}

func dedupe(f []schema.Finding) []schema.Finding {
	seen := map[string]bool{}
	var out []schema.Finding
	for _, x := range f {
		key := x.RuleID + "|" + x.SessionID + "|" + x.AgentID + "|" + strings.Join(x.EvidenceRefs, "|") + "|" + x.Title
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, x)
	}
	return out
}

var sevRank = map[string]int{"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2, "INFO": 1}

func sortBySeverity(f []schema.Finding) {
	for i := 1; i < len(f); i++ {
		for j := i; j > 0 && sevRank[f[j].Severity] > sevRank[f[j-1].Severity]; j-- {
			f[j], f[j-1] = f[j-1], f[j]
		}
	}
}
