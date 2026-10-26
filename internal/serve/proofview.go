package serve

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"

	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/proof"
	"github.com/efij/AgentDFIR/v5/internal/reconstruct"
	"github.com/efij/AgentDFIR/v5/internal/redact"
	"github.com/efij/AgentDFIR/v5/internal/sanitize"
	"github.com/efij/AgentDFIR/v5/internal/supplychain"
)

// The v4.5 views: the action proof report (computed on request from the
// overlay, like `agentdfir proof`), the collection-health badge, the
// agent-environment supply chain (normalized/supplychain.json) and the
// multi-case reconstruction (normalized/reconstruct.json, written by
// `agentdfir reconstruct`). Every string is evidence-derived and goes
// through sanitizeJSON before it leaves the process; the page renders it
// as text.

// proofMaxActions bounds the actions the explorer lists. The CLI's bound
// is larger; the page says how many were left out and how to see them.
const proofMaxActions = 2000

// ---- /api/proof ----

// apiProof serves the proof report for the case, or for one session with
// ?session=. Building it reads the events overlay and the action graph, so
// the last few results are kept.
func (s *Server) apiProof(w http.ResponseWriter, r *http.Request) {
	sess := trimTo(r.URL.Query().Get("session"), 512)
	s.pmu.Lock()
	cached, ok := s.pcache[sess]
	s.pmu.Unlock()
	if !ok {
		rep, err := buildProof(s.pkg, sess)
		if err != nil {
			// Not a missing overlay (re-running analysis would not help):
			// an unknown session, or a case the report cannot be built for.
			writeJSON(w, map[string]any{"available": false, "reason": "The proof report could not be built: " + sanitize.Terminal(trimTo(err.Error(), 300))})
			return
		}
		data, err := json.Marshal(rep)
		if err != nil {
			s.missing(w, "The proof report could not be encoded.")
			return
		}
		var v map[string]any
		if json.Unmarshal(data, &v) != nil {
			s.missing(w, "The proof report could not be encoded.")
			return
		}
		cached = redactSecrets(map[string]any{"available": true, "report": boundLists(sanitizeJSON(v), proofMaxActions, 0),
			"health": healthSummary(rep.Telemetry.Sources), "cli": sanitize.Terminal("agentdfir proof " + s.pkg)}).(map[string]any)
		s.pmu.Lock()
		if s.pcache == nil || len(s.pcache) >= 8 {
			s.pcache = map[string]map[string]any{}
		}
		s.pcache[sess] = cached
		s.pmu.Unlock()
	}
	writeJSON(w, cached)
}

// buildProof runs proof.Load, turning a panic on input nobody anticipated
// into an error: the explorer answers "not available", it does not die.
func buildProof(pkg, sess string) (rep *proof.Report, err error) {
	defer func() {
		if p := recover(); p != nil {
			rep, err = nil, fmt.Errorf("internal error while building the report: %v", p)
		}
	}()
	return proof.Load(pkg, proof.Options{SessionID: sess, MaxActions: proofMaxActions})
}

// ---- /api/health ----

// Health verdicts, worst first. PARTIAL outranks UNKNOWN because it is a
// positive signal of loss (a sequence gap or a drop the source reported);
// UNKNOWN means completeness cannot be established either way. The badge
// lists the count of each, so neither hides the other.
var healthRank = map[string]int{endpoint.HealthPartial: 3, endpoint.HealthUnknown: 2, endpoint.HealthHealthy: 1}

// healthSummary is the badge: the worst verdict across sources, the count
// per verdict, and each source's verdict, gaps and drops. "none" when no
// telemetry was imported.
func healthSummary(src []endpoint.SourceHealth) map[string]any {
	worst := "none"
	counts := map[string]int{}
	rows := make([]map[string]any, 0, min(len(src), 200))
	for _, h := range src {
		v := h.Verdict
		if _, known := healthRank[v]; !known {
			// A verdict this version does not know is reported, never
			// promoted to HEALTHY.
			v = endpoint.HealthUnknown
		}
		counts[v]++
		if worst == "none" || healthRank[v] > healthRank[worst] {
			worst = v
		}
		if len(rows) < 200 {
			rows = append(rows, map[string]any{"file": sanitize.Terminal(trimTo(h.File, 300)), "verdict": v, "records": h.Records,
				"gaps": h.Gaps, "drops": len(h.Drops) + h.DropsOmitted, "note": sanitize.Terminal(trimTo(h.Note, 500))})
		}
	}
	sort.SliceStable(rows, func(a, b int) bool {
		return healthRank[rows[a]["verdict"].(string)] > healthRank[rows[b]["verdict"].(string)]
	})
	return map[string]any{"verdict": worst, "counts": counts, "sources": rows, "sources_total": len(src)}
}

// apiHealth is the header badge. It reads the correlation summary the
// server already holds, so it is cheap enough to ask on every page load.
func (s *Server) apiHealth(w http.ResponseWriter, r *http.Request) {
	corr, _ := s.correlation()
	var src []endpoint.SourceHealth
	if corr != nil {
		src = corr.Health
	}
	out := healthSummary(src)
	out["available"] = len(src) > 0
	switch {
	case corr == nil || (corr.Records == 0 && len(corr.Health) == 0):
		out["reason"] = "No independent telemetry was imported for this case, so collection health cannot be assessed."
	case len(src) == 0:
		out["reason"] = "This case was analyzed before collection-health reporting existed; re-run the analysis to assess it."
		out["regenerate"] = sanitize.Terminal(s.regenerate())
	}
	writeJSON(w, redactSecrets(out))
}

// ---- /api/supplychain ----

// apiSupplyChain serves normalized/supplychain.json: components, timeline,
// drift, and verified and inferred relationships kept apart as the
// document keeps them.
func (s *Server) apiSupplyChain(w http.ResponseWriter, r *http.Request) {
	data, err := overlay.ReadFile(filepath.Join(s.pkg, "normalized", supplychain.File))
	if err != nil {
		s.missing(w, "This case has no supply-chain report (normalized/supplychain.json). It was analyzed by an older version, or the derived files were removed.")
		return
	}
	var v map[string]any
	if json.Unmarshal(data, &v) != nil {
		s.missing(w, "The supply-chain report in this case could not be read.")
		return
	}
	if sch, _ := v["schema"].(string); sch != supplychain.Schema {
		s.missing(w, "The supply-chain report in this case uses a format this version does not read ("+sanitize.Terminal(trimTo(sch, 60))+"); UNSUPPORTED.")
		return
	}
	writeJSON(w, map[string]any{"available": true, "report": redactSecrets(boundLists(sanitizeJSON(v), 2000, 0)), "regenerate": sanitize.Terminal(s.regenerate())})
}

// ---- /api/reconstruct ----

// apiReconstruct serves normalized/reconstruct.json when `agentdfir
// reconstruct` has stored one in this case; otherwise the exact command
// that makes it.
func (s *Server) apiReconstruct(w http.ResponseWriter, r *http.Request) {
	cmd := sanitize.Terminal("agentdfir reconstruct " + s.pkg)
	none := func(reason string) {
		writeJSON(w, map[string]any{"available": false, "reason": reason, "regenerate": cmd})
	}
	data, err := overlay.ReadFile(filepath.Join(s.pkg, "normalized", reconstruct.OverlayFile))
	if err != nil {
		none("No reconstruction is stored in this case (normalized/reconstruct.json). Run the command below, with this case and any related ones, to build the merged timeline, delegation, hand-offs, attack stages and missing evidence.")
		return
	}
	var v map[string]any
	if json.Unmarshal(data, &v) != nil {
		none("The reconstruction stored in this case could not be read. Run the command below to rebuild it.")
		return
	}
	if sch, _ := v["schema"].(string); sch != reconstruct.Schema {
		none("The reconstruction in this case uses a format this version does not read (" + sanitize.Terminal(trimTo(sch, 60)) + "); UNSUPPORTED. Run the command below to rebuild it.")
		return
	}
	writeJSON(w, map[string]any{"available": true, "report": redactSecrets(boundLists(sanitizeJSON(v), 5000, 0)), "regenerate": cmd})
}

// redactSecrets masks credential-shaped values (the secret patterns of
// internal/redact, the same ones `--redact secrets` uses) in every string
// of a decoded value. These views carry configuration drift, hook
// commands and environment-bearing command lines, which can hold live
// tokens; the page masks them too, but the value never needs to leave the
// process. A Redactor is not safe for concurrent use, so each call builds
// its own.
func redactSecrets(v any) any {
	r, err := redact.Parse("secrets")
	if err != nil || r == nil {
		return v
	}
	var walk func(v any, depth int) any
	walk = func(v any, depth int) any {
		if depth > 64 {
			return nil
		}
		switch t := v.(type) {
		case string:
			return r.String(t, "")
		case []any:
			for i := range t {
				t[i] = walk(t[i], depth+1)
			}
		case []map[string]any:
			for i := range t {
				walk(t[i], depth+1)
			}
		case map[string]any:
			for k, val := range t {
				t[k] = walk(val, depth+1)
			}
		}
		return v
	}
	return walk(v, 0)
}
