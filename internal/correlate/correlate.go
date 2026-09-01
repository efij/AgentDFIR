// Package correlate raises agent-reported/observed activity to
// corroborated (or contradicted) by comparing it against independent
// endpoint evidence (plan §16). External evidence enters through the
// Adapter interface, so new sources (EDR exports, DNS logs, process
// telemetry, MCP-gateway logs) plug in without touching the core.
//
// Correlation NEVER invents evidence: an event is only upgraded when an
// adapter yields an independent observation that matches it. Absence of
// endpoint evidence leaves the state UNKNOWN, never CONTRADICTED.
package correlate

import (
	"strings"

	"github.com/efij/AgentDFIR/internal/schema"
)

// Observation is one independent endpoint fact from an external source.
type Observation struct {
	Source string // adapter name, e.g. "shell_history"
	Kind   string // "command" | "network" | "process" | "dns"
	Value  string // normalized value (e.g. the command line)
	Ref    string // evidence reference (file:line or export id)
}

// Adapter yields independent endpoint observations. Implementations must
// treat their input as hostile (bounded reads, no execution).
type Adapter interface {
	Name() string
	Observations() ([]Observation, error)
}

// Result summarizes a correlation pass.
type Result struct {
	Corroborated int
	Sources      []string
	Notes        []string
}

// Apply correlates events in place against all adapters. Tool-call events
// with a command are matched against endpoint "command" observations; a
// match upgrades OBSERVED -> CORROBORATED and records the corroborating
// source on the event summary (evidence-linked).
func Apply(events []schema.Event, adapters ...Adapter) (*Result, error) {
	res := &Result{}
	var obs []Observation
	for _, a := range adapters {
		o, err := a.Observations()
		if err != nil {
			res.Notes = append(res.Notes, a.Name()+": "+err.Error())
			continue
		}
		if len(o) > 0 {
			res.Sources = append(res.Sources, a.Name())
			obs = append(obs, o...)
		}
	}
	if len(obs) == 0 {
		return res, nil
	}

	for i := range events {
		ev := &events[i]
		if ev.EventType != schema.EventToolCall || ev.Command == "" {
			continue
		}
		if ev.Corroboration != schema.StateObserved {
			continue
		}
		for _, o := range obs {
			if o.Kind != "command" {
				continue
			}
			if commandsMatch(ev.Command, o.Value) {
				ev.Corroboration = schema.StateCorroborated
				ev.Summary = appendNote(ev.Summary,
					"corroborated by "+o.Source+" ("+o.Ref+")")
				res.Corroborated++
				break
			}
		}
	}
	return res, nil
}

// commandsMatch compares an agent-reported command to an endpoint-observed
// command line. Conservative: requires the agent command's core to be a
// substring of the endpoint command (or vice versa) after normalization,
// so shell wrappers (bash -lc "…") still match.
func commandsMatch(agentCmd, endpointCmd string) bool {
	a := normalizeCmd(agentCmd)
	b := normalizeCmd(endpointCmd)
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.Contains(b, a) || strings.Contains(a, b)
}

func normalizeCmd(s string) string {
	s = strings.TrimSpace(s)
	s = strings.Join(strings.Fields(s), " ") // collapse whitespace
	return s
}

func appendNote(summary, note string) string {
	if summary == "" {
		return note
	}
	return summary + " [" + note + "]"
}
