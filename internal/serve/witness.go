package serve

import (
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/correlate"
	"github.com/efij/AgentDFIR/v3/internal/endpoint"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// ---- /api/witness ----

// apiWitness puts an agent's record next to the independent record that
// confirmed (or partly confirmed) it: the process, file, network, cloud,
// DNS, proxy or script record the correlate package paired with the tool
// call, with that pairing's basis, score and confidence, and the event's
// witness note. Without ?event= it lists the paired events (bounded), so
// the coverage view can say which actions have a second witness.
func (s *Server) apiWitness(w http.ResponseWriter, r *http.Request) {
	corr, byEvent := s.correlation()
	id := r.URL.Query().Get("event")
	if id == "" {
		if corr == nil {
			s.missing(w, "No independent records were imported for this case, so no action has a second witness. Import operating-system, DNS, proxy or cloud logs with: agentdfir analyze <case> --endpoint <log>.")
			return
		}
		const maxList = 500
		ids := make([]string, 0, len(byEvent))
		for e := range byEvent {
			ids = append(ids, e)
		}
		sort.Strings(ids)
		items := make([]map[string]any, 0, min(len(ids), maxList))
		for _, e := range ids {
			if len(items) >= maxList {
				break
			}
			i, ok := s.idx.Lookup(e)
			if !ok {
				continue
			}
			ev, err := s.idx.Event(i)
			if err != nil {
				continue
			}
			best := corr.Matches[byEvent[e][0]]
			row := rowOf(ev)
			row["witness"], row["basis"], row["confidence"] = sanitize.Terminal(best.Witness), sanitize.Terminal(best.Basis), best.Confidence
			items = append(items, row)
		}
		sort.SliceStable(items, func(a, b int) bool { return items[a]["ts"].(string) < items[b]["ts"].(string) })
		writeJSON(w, map[string]any{"available": true, "items": items, "total": len(ids), "truncated": len(ids) > maxList,
			"matches_omitted": corr.MatchesOmitted})
		return
	}
	i, ok := s.idx.Lookup(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	ev, err := s.idx.Event(i)
	if err != nil {
		http.Error(w, "event unreadable", http.StatusInternalServerError)
		return
	}
	agent := map[string]any{
		"id": ev.EventID, "ts": ev.Timestamp, "type": ev.EventType, "tool": sanitize.Terminal(ev.Tool),
		"command": sanitize.Terminal(trimTo(ev.Command, 2000)), "file": sanitize.Terminal(ev.File), "dest": sanitize.Terminal(ev.NetworkDest),
		"summary": sanitize.Terminal(trimTo(ev.Summary, 600)), "state": ev.Corroboration, "state_label": schema.Label(ev.Corroboration),
		"path": sanitize.Terminal(ev.SourcePath), "line": ev.SourceLine, "artifact": ev.SourceArtifact, "offset": ev.SourceOffset,
	}
	out := map[string]any{"available": corr != nil, "agent": agent, "witness_note": sanitize.Terminal(ev.WitnessNote), "matches": []any{}}
	if corr != nil {
		ms := make([]map[string]any, 0, len(byEvent[id]))
		for _, p := range byEvent[id] {
			ms = append(ms, matchRow(corr.Matches[p]))
		}
		out["matches"] = ms
		if corr.MatchesOmitted > 0 && len(ms) == 0 {
			out["note"] = "The case kept the first pairings only; this action may have one that was not stored."
		}
	}
	writeJSON(w, out)
}

// matchRow is one sanitized pairing, record and related records included.
func matchRow(m correlate.Match) map[string]any {
	rel := make([]map[string]any, 0, len(m.Related))
	for _, rr := range m.Related {
		rel = append(rel, map[string]any{"basis": sanitize.Terminal(rr.Basis), "record": recordRow(rr.Record)})
	}
	return map[string]any{
		"witness": sanitize.Terminal(m.Witness), "score": m.Score, "basis": sanitize.Terminal(m.Basis), "confidence": m.Confidence,
		"window_ms": m.WindowMS, "delta_ms": m.DeltaMS, "record": recordRow(m.Record), "related": rel,
	}
}

// recordRow is an endpoint record with every string sanitized and only the
// fields it has.
func recordRow(r endpoint.Record) map[string]any {
	out := map[string]any{"kind": sanitize.Terminal(r.Kind), "source": sanitize.Terminal(r.Source), "ref": sanitize.Terminal(r.Ref)}
	if !r.Time.IsZero() {
		out["time"] = r.Time.UTC().Format(time.RFC3339Nano)
	}
	set := func(k, v string) {
		if v = strings.TrimSpace(v); v != "" {
			out[k] = sanitize.Terminal(trimTo(v, 1000))
		}
	}
	set("exe", r.Exe)
	set("cmdline", r.Cmdline)
	set("parent_exe", r.ParentExe)
	set("user", r.User)
	set("dest_ip", r.DestIP)
	set("dest_host", r.DestHost)
	set("file_path", r.FilePath)
	set("file_op", r.FileOp)
	set("url", r.URL)
	set("answers", r.Answers)
	set("provider", r.Provider)
	set("operation", r.Operation)
	set("resource", r.Resource)
	set("source_ip", r.SourceIP)
	set("failed", r.Failed)
	if r.PID != 0 {
		out["pid"] = r.PID
	}
	if r.PPID != 0 {
		out["ppid"] = r.PPID
	}
	if r.DestPort != 0 {
		out["dest_port"] = r.DestPort
	}
	return out
}
