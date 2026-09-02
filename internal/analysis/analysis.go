// Package analysis is the one place a package gets analyzed. It runs the
// stages in the right order — normalize (only when needed), endpoint
// correlation, detections, rule packs, MCP audit, provenance — and writes
// one consistent set of results under <pkg>/detections/. Every command
// that shows or exports results (analyze/triage, serve, investigate,
// report) goes through here, so nothing is ever "not run yet" and later
// stages never clobber earlier ones.
package analysis

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/correlate"
	"github.com/efij/AgentDFIR/internal/detect"
	"github.com/efij/AgentDFIR/internal/endpoint"
	"github.com/efij/AgentDFIR/internal/mcpaudit"
	"github.com/efij/AgentDFIR/internal/normalize"
	"github.com/efij/AgentDFIR/internal/provenance"
	"github.com/efij/AgentDFIR/internal/rulepack"
	"github.com/efij/AgentDFIR/internal/schema"
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
	Honeytokens    []string
	SpawnThreshold int
	KnownDests     []string
	Renormalize    bool      // force re-parse even if the overlay is current
	Log            io.Writer // progress lines; nil = silent
}

// Result summarizes one run.
type Result struct {
	Events       int
	Entities     int
	Renormalized bool
	Findings     []schema.Finding
	Correlation  *correlate.EndpointResult
	MCPServers   int
	Provenance   int // instruction files attributed
	StageNotes   []string
}

func (o *Options) logf(format string, a ...any) {
	if o.Log != nil {
		fmt.Fprintf(o.Log, format+"\n", a...)
	}
}

// Stale reports whether results need (re)computing: no overlay, no
// findings, or the package was sealed after the overlay was written.
func Stale(pkg string) bool {
	ev, err := os.Stat(filepath.Join(pkg, "normalized", "events.jsonl"))
	if err != nil {
		return true
	}
	if _, err := os.Stat(filepath.Join(pkg, "detections", "findings.json")); err != nil {
		return true
	}
	if man, err := os.Stat(filepath.Join(pkg, "manifest.json")); err == nil && man.ModTime().After(ev.ModTime()) {
		return true
	}
	return false
}

// Ensure runs a default analysis only when results are missing or stale.
func Ensure(pkg string, log io.Writer) (*Result, error) {
	if !Stale(pkg) {
		return nil, nil
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
	detDir := filepath.Join(pkg, "detections")
	for _, d := range []string{dir, detDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}

	// ---- 1. normalize (streaming) — only when the overlay is missing/stale.
	evPath := filepath.Join(dir, "events.jsonl")
	needNorm := o.Renormalize
	if fi, err := os.Stat(evPath); err != nil {
		needNorm = true
	} else if man, err := os.Stat(filepath.Join(pkg, "manifest.json")); err == nil && man.ModTime().After(fi.ModTime()) {
		needNorm = true
	}
	var entities []schema.Entity
	if needNorm {
		f, err := os.OpenFile(evPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, err
		}
		enc := json.NewEncoder(f)
		sr, err := normalize.ParseStream(pkg, func(ev schema.Event) error { return enc.Encode(ev) })
		if err != nil {
			f.Close()
			return nil, err
		}
		f.Close()
		if err := writeJSONL(filepath.Join(dir, "entities.jsonl"), len(sr.Entities), func(i int) any { return sr.Entities[i] }); err != nil {
			return nil, err
		}
		if err := writeJSONL(filepath.Join(dir, "relationships.jsonl"), len(sr.Relationships), func(i int) any { return sr.Relationships[i] }); err != nil {
			return nil, err
		}
		entities, res.Events, res.Renormalized = sr.Entities, sr.EventCount, true
		o.logf("Normalized: %d events, %d entities, %d relationships", sr.EventCount, len(sr.Entities), len(sr.Relationships))
	} else {
		entities = readJSONL[schema.Entity](filepath.Join(dir, "entities.jsonl"))
		res.Events = countLines(evPath)
		o.logf("Normalized: reusing overlay (%d events); corroboration states preserved", res.Events)
	}
	res.Entities = len(entities)

	// ---- 2. second witness (runs BEFORE detection so findings carry the states).
	var findings []schema.Finding
	if len(o.EndpointLogs) > 0 || o.ShellHistory != "" {
		events := LoadEvents(pkg)
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
			writeJSON(filepath.Join(detDir, "corroboration.json"), struct {
				Summary  *correlate.EndpointResult `json:"summary"`
				Findings []schema.Finding          `json:"findings"`
			}{cres, cf})
			o.logf("Endpoint correlation: %d checked — %d CORROBORATED, %d CONTRADICTED, %d outside coverage; %d unlogged agent records",
				cres.ToolCalls, cres.Corroborated, cres.Contradicted, cres.OutsideCover, cres.Unlogged)
		}
		if err := writeJSONL(evPath, len(events), func(i int) any { return events[i] }); err != nil {
			return nil, err
		}
	}

	// Earlier second-witness results stay part of the case as long as the
	// overlay they were computed on is still in use; a re-parse invalidates them.
	corrPath := filepath.Join(detDir, "corroboration.json")
	if len(o.EndpointLogs) == 0 {
		if res.Renormalized {
			_ = os.Remove(corrPath)
		} else if data, err := os.ReadFile(corrPath); err == nil {
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

	// ---- 3. detections (streaming over the overlay).
	det, err := detect.RunStream(pkg, entities, detect.Options{Honeytokens: o.Honeytokens, SpawnThreshold: o.SpawnThreshold, KnownDestinations: o.KnownDests})
	if err != nil {
		return nil, err
	}
	findings = append(findings, det...)

	// ---- 4. declarative rule packs.
	if o.RulesDir != "" {
		packs, err := rulepack.LoadDir(o.RulesDir)
		if err != nil {
			return nil, fmt.Errorf("rule packs: %w", err)
		}
		extra, err := rulepack.Apply(packs, &schema.Normalized{Events: LoadEvents(pkg)}, pkg)
		if err != nil {
			return nil, fmt.Errorf("rule packs: %w", err)
		}
		findings = append(findings, extra...)
		o.logf("Rule packs: %d pack(s), %d finding(s)", len(packs), len(extra))
	}

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
			sum, gf := mcpaudit.CorrelateGateway(LoadEvents(pkg), recs, o.GatewayServers, 3)
			sum.Unparsed = unparsed
			gw = &sum
			mf = append(mf, gf...)
		}
		res.MCPServers = len(inv.Servers)
		findings = append(findings, mf...)
		writeJSON(filepath.Join(detDir, "mcp-audit.json"), struct {
			Inventory *mcpaudit.Inventory      `json:"inventory"`
			Findings  []schema.Finding         `json:"findings"`
			Gateway   *mcpaudit.GatewaySummary `json:"gateway,omitempty"`
		}{inv, mf, gw})
		o.logf("MCP audit: %d server(s) in %d config(s), %d finding(s)", len(inv.Servers), len(inv.Configs), len(mf))
	} else {
		res.StageNotes = append(res.StageNotes, "mcp audit skipped: "+err.Error())
	}

	// ---- 6. instruction & memory provenance.
	if prov, err := provenance.Run(pkg, LoadEvents(pkg), ""); err == nil {
		res.Provenance = len(prov.Files)
		findings = append(findings, prov.Findings...)
		writeJSON(filepath.Join(detDir, "provenance.json"), prov)
		o.logf("Provenance: %d instruction file(s) attributed, %d write(s) to uncollected instruction paths, %d finding(s)", len(prov.Files), len(prov.OtherWrite), len(prov.Findings))
	} else {
		res.StageNotes = append(res.StageNotes, "provenance skipped: "+err.Error())
	}

	// ---- 7. one findings file, severity-sorted, de-duplicated.
	findings = dedupe(findings)
	sortBySeverity(findings)
	res.Findings = findings
	writeJSON(filepath.Join(detDir, "findings.json"), findings)
	writeJSON(filepath.Join(detDir, "analysis.json"), map[string]any{
		"analyzed_utc": time.Now().UTC().Format(time.RFC3339), "events": res.Events, "renormalized": res.Renormalized,
		"findings": len(findings), "endpoint_logs": o.EndpointLogs, "gateway_log": o.GatewayLog, "rules_dir": o.RulesDir,
		"honeytokens": len(o.Honeytokens), "notes": res.StageNotes,
	})
	return res, nil
}

// LoadEvents reads the overlay into memory (for stages that need it).
func LoadEvents(pkg string) []schema.Event {
	return readJSONL[schema.Event](filepath.Join(pkg, "normalized", "events.jsonl"))
}

// LoadEntities reads the overlay entities.
func LoadEntities(pkg string) []schema.Entity {
	return readJSONL[schema.Entity](filepath.Join(pkg, "normalized", "entities.jsonl"))
}

// LoadFindings reads the persisted findings.
func LoadFindings(pkg string) []schema.Finding {
	var out []schema.Finding
	if data, err := os.ReadFile(filepath.Join(pkg, "detections", "findings.json")); err == nil {
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

func writeJSON(path string, v any) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(path, append(data, '\n'), 0o600)
}

func writeJSONL(path string, n int, get func(int) any) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	for i := 0; i < n; i++ {
		if err := enc.Encode(get(i)); err != nil {
			f.Close()
			return err
		}
	}
	return f.Close()
}

func readJSONL[T any](path string) []T {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []T
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var v T
		if json.Unmarshal(sc.Bytes(), &v) == nil {
			out = append(out, v)
		}
	}
	return out
}

func countLines(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()
	n := 0
	buf := make([]byte, 256<<10)
	for {
		k, err := f.Read(buf)
		for i := 0; i < k; i++ {
			if buf[i] == '\n' {
				n++
			}
		}
		if err != nil {
			return n
		}
	}
}
