package correlate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// Corroborate-only witnesses from native Windows event logs: PowerShell
// script blocks (4104) and module logs (4103, Operation "module"), and
// process creations known only by image path (Security 4688 without
// command-line auditing). Neither is complete
// process telemetry, so neither contradicts a command or widens the
// coverage window. Matches are marked in WitnessNote with their basis
// ("script-block", "process-image") so they stay distinguishable from
// process-telemetry confirmations.

const (
	maxScriptBlock    = 64 << 10 // script-block text considered per record
	minScriptContains = 12       // shortest command accepted by containment
	scriptMinScore    = 90
)

// scriptPass matches commands not yet corroborated against PowerShell
// script blocks. Only an exact match (100) or the whole command inside
// the block at token boundaries (90) counts. A command the host pass
// already contradicted keeps that state; the matching block is noted
// next to it, because an in-process PowerShell host runs scripts without
// spawning a process.
func scriptPass(events []schema.Event, records []endpoint.Record, opts EndpointOptions, res *EndpointResult) {
	if len(records) == 0 {
		return
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].Time.Before(records[j].Time) })
	used := make([]bool, len(records))
	for i := range events {
		ev := &events[i]
		if ev.EventType != schema.EventToolCall || ev.Command == "" || ev.Corroboration == schema.StateCorroborated {
			continue
		}
		t, ok := parseEventTime(ev.Timestamp)
		if !ok {
			continue
		}
		best, bestScore := -1, 0
		forWindow(records, t, opts.Window, func(j int) {
			if used[j] {
				return
			}
			if s := scriptMatch(ev.FullCommand(), records[j].Cmdline); s >= scriptMinScore && s > bestScore {
				best, bestScore = j, s
			}
		})
		if best < 0 {
			continue
		}
		used[best] = true
		r := records[best]
		how := "exact"
		if bestScore < 100 {
			how = "whole command inside the block"
		}
		log := "PowerShell script block log"
		if r.Operation == "module" { // 4103: same strict matching, against the module log payload
			log = "PowerShell module log"
		}
		ev.WitnessNote = appendNote(ev.WitnessNote, fmt.Sprintf("script-block: %s, %s match (%s)", log, how, r.Ref))
		// The pairing is recorded even beside a contradiction: the block
		// exists, and the lineage edge carries the event's own state.
		if bestScore >= 100 {
			addMatchBasis(res, WitnessScript, ev, r, bestScore, "script block exact match (whitespace and case collapsed)", "HIGH", opts.Window, nil)
		} else {
			addMatchBasis(res, WitnessScript, ev, r, bestScore, "script block contains the whole command at token boundaries", "MEDIUM", opts.Window, nil)
		}
		if ev.Corroboration == schema.StateContradicted {
			ev.Summary = appendNote(ev.Summary, fmt.Sprintf("PowerShell script block log shows a matching script (%s)", r.Ref))
			continue
		}
		switch ev.Corroboration {
		case schema.StateObserved, schema.StateReported, schema.StateUnknown, schema.StatePartial:
			ev.Corroboration = schema.StateCorroborated
		}
		ev.Summary = appendNote(ev.Summary, fmt.Sprintf("corroborated by %s script-block (%s)", r.Source, r.Ref))
		res.ScriptCorroborated++
	}
}

// scriptMatch scores a command against a script block: 100 when equal
// (whitespace-collapsed, case-insensitive), 90 when the whole command
// occurs inside the block at token boundaries, else 0. The command may
// be wrapped as `powershell -Command <script>`; the inner script is
// tried too.
func scriptMatch(cmd, block string) int {
	if len(block) > maxScriptBlock {
		block = block[:maxScriptBlock]
	}
	b := strings.ToLower(normalizeCmd(block))
	if b == "" {
		return 0
	}
	best := 0
	for _, a := range scriptCandidates(cmd) {
		switch {
		case a == b:
			return 100
		case len(a) >= minScriptContains && strings.Contains(a, " ") && containsAtBoundary(b, a):
			best = 90
		}
	}
	return best
}

// scriptCandidates: the normalized command and, for an explicit
// `powershell|pwsh … -c|-Command <script>` wrapper, the inner script.
func scriptCandidates(cmd string) []string {
	a := strings.ToLower(normalizeCmd(cmd))
	if a == "" {
		return nil
	}
	out := []string{a}
	f := strings.Fields(a)
	if len(f) < 3 {
		return out
	}
	if n := exeName(f[0]); n != "powershell" && n != "pwsh" {
		return out
	}
	for i := 1; i < len(f)-1; i++ {
		switch f[i] {
		case "-c", "-command", "/c", "/command":
			inner := strings.Join(f[i+1:], " ")
			if len(inner) >= 2 && (inner[0] == '"' || inner[0] == '\'') && inner[len(inner)-1] == inner[0] {
				inner = inner[1 : len(inner)-1]
			}
			if inner = strings.TrimSpace(inner); inner != "" {
				out = append(out, inner)
			}
			return out
		}
	}
	return out
}

// containsAtBoundary reports whether a occurs in b with a token
// boundary (start/end, whitespace or a shell/script delimiter) on both
// sides.
func containsAtBoundary(b, a string) bool {
	for from := 0; from <= len(b)-len(a); {
		i := strings.Index(b[from:], a)
		if i < 0 {
			return false
		}
		i += from
		end := i + len(a)
		if (i == 0 || isTokenBoundary(b[i-1])) && (end == len(b) || isTokenBoundary(b[end])) {
			return true
		}
		from = i + 1
	}
	return false
}

func isTokenBoundary(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', ';', '|', '&', '(', ')', '{', '}', '"', '\'':
		return true
	}
	return false
}

// imagePass gives commands a partial confirmation from process
// creations known only by image path: the program a command (or one of
// its compound segments) starts must equal the record's image basename.
// It never upgrades past PARTIALLY_CORROBORATED and never contradicts.
func imagePass(events []schema.Event, records []endpoint.Record, opts EndpointOptions, res *EndpointResult) {
	if len(records) == 0 {
		return
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].Time.Before(records[j].Time) })
	used := make([]bool, len(records))
	for i := range events {
		ev := &events[i]
		if ev.EventType != schema.EventToolCall || ev.Command == "" ||
			ev.Corroboration == schema.StateCorroborated || ev.Corroboration == schema.StatePartial {
			continue
		}
		t, ok := parseEventTime(ev.Timestamp)
		if !ok {
			continue
		}
		progs := map[string]bool{}
		for _, seg := range splitCompound(normalizeCmd(ev.Command)) {
			if f := strings.Fields(seg); len(f) > 0 {
				progs[exeName(f[0])] = true
			}
		}
		best := -1
		forWindow(records, t, opts.Window, func(j int) {
			if best < 0 && !used[j] && records[j].Exe != "" && progs[exeName(records[j].Exe)] {
				best = j
			}
		})
		if best < 0 {
			continue
		}
		used[best] = true
		r := records[best]
		ev.WitnessNote = appendNote(ev.WitnessNote, fmt.Sprintf("process-image: %s started %s (program name only, no command line audited) (%s)", r.Source, baseName(r.Exe), r.Ref))
		addMatchBasis(res, WitnessProcessImage, ev, r, 50, "process image basename "+exeName(r.Exe)+" (no command line audited)", "LOW", opts.Window, nil)
		if ev.Corroboration == schema.StateContradicted {
			continue
		}
		switch ev.Corroboration {
		case schema.StateObserved, schema.StateReported, schema.StateUnknown:
			ev.Corroboration = schema.StatePartial
		}
		ev.Summary = appendNote(ev.Summary, fmt.Sprintf("partly corroborated by %s process-image: %s (%s)", r.Source, baseName(r.Exe), r.Ref))
		res.ImagePartial++
	}
}

// forWindow calls fn for each record index within ±w of t (records sorted by time).
func forWindow(records []endpoint.Record, t time.Time, w time.Duration, fn func(int)) {
	for j := lowerBound(records, t.Add(-w)); j < len(records) && !records[j].Time.After(t.Add(w)); j++ {
		fn(j)
	}
}
