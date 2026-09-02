package detect

import (
	"fmt"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/schema"
)

// Live evaluates events one at a time as they are tailed from a running
// agent session (real-time detection). It reuses the streaming engine's
// per-event rules and bounded aggregates in a single pass, so what fires
// live is a subset of what `triage` finds afterwards: every per-event and
// sequence rule, honeytokens and injection phrases in live content, and
// spawn-explosion. Whole-package rules that need the complete transcript
// (orphan agents, session tampering, timestomping, content scans of raw
// artifacts) remain post-hoc.
type Live struct {
	agg      *streamAgg
	p2       *streamPass2
	opts     Options
	spawnHit map[string]bool
	seen     map[string]bool // dedupe key
}

// NewLive creates a live evaluator.
func NewLive(opts Options) *Live {
	if opts.SpawnThreshold <= 0 {
		opts.SpawnThreshold = 10
	}
	agg := &streamAgg{
		completed: map[string]time.Time{}, mcpServers: map[string]string{},
		artSessions: map[string]map[string]bool{}, artLatest: map[string]time.Time{},
		artSample: map[string]schema.Event{}, artBreaks: map[string]int{}, artRegress: map[string]int{},
		artLastTS: map[string]time.Time{}, spawnCount: map[string]int{}, spawnFirst: map[string]schema.Event{},
		spawnedAgents: map[string]bool{}, agentSession: map[string]string{}, agentRefs: map[string][]string{},
		agentSessID: map[string]string{}, agentSide: map[string]bool{},
	}
	return &Live{
		agg:  agg,
		p2:   &streamPass2{agg: agg, sidechain: map[string]bool{}, opts: opts, pendingExfil: map[string]schema.Event{}, seenDest: map[string]bool{}, resumeFlag: map[string]bool{}},
		opts: opts, spawnHit: map[string]bool{}, seen: map[string]bool{},
	}
}

// Eval ingests one event and returns the findings it triggers (may be none).
func (l *Live) Eval(ev schema.Event) []schema.Finding {
	l.agg.pass1(ev)
	before := len(l.p2.findings)
	l.p2.handle(ev)
	out := append([]schema.Finding(nil), l.p2.findings[before:]...)
	l.p2.findings = l.p2.findings[:0] // never accumulate across a long-running tail

	// Honeytokens in live content.
	for _, m := range l.opts.Honeytokens {
		m = strings.TrimSpace(m)
		if m == "" {
			continue
		}
		if strings.Contains(ev.Command, m) || strings.Contains(ev.File, m) || strings.Contains(ev.Summary, m) {
			out = append(out, schema.Finding{
				RuleID: "SECRET_ACCESS", Severity: "HIGH", Title: "Honeytoken Accessed by Agent",
				Description: "A planted canary marker appears in live agent activity (" + ev.EventType + "). Canaries have no legitimate use; this is a high-confidence signal.",
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown, MitreATTACK: "T1552",
				FalsePositive: "Only if the marker string was reused for something real.",
			})
			break
		}
	}
	// Injection phrases arriving in agent-facing content.
	if ev.EventType == schema.EventHumanPrompt || ev.EventType == schema.EventToolResult {
		if ph, ok := InjectionPhrase(ev.Summary); ok {
			out = append(out, schema.Finding{
				RuleID: "PROMPT_INJECTION_INDICATOR", Severity: "MEDIUM", Title: "Prompt Injection Indicator",
				Description: fmt.Sprintf("Instruction-override phrase %q arrived in live %s content. Indicator, not proof — watch the agent's next actions.", ph, ev.EventType),
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown, MitreATLAS: "AML.T0051",
				FalsePositive: "Security discussions and documentation contain these phrases.",
			})
		}
	}
	// Spawn explosion: once per session when the threshold is crossed.
	if ev.EventType == schema.EventAgentSpawn && l.agg.spawnCount[ev.SessionID] > l.opts.SpawnThreshold && !l.spawnHit[ev.SessionID] {
		l.spawnHit[ev.SessionID] = true
		out = append(out, schema.Finding{
			RuleID: "AGENT_SPAWN_EXPLOSION", Severity: "MEDIUM", Title: "Excessive Subagent Spawning",
			Description: fmt.Sprintf("Session %s has spawned %d subagents (threshold %d) and is still spawning.", ev.SessionID, l.agg.spawnCount[ev.SessionID], l.opts.SpawnThreshold),
			SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
			Status: ev.Corroboration, Endpoint: schema.StateUnknown,
			FalsePositive: "Large legitimate fan-out tasks; raise --spawn-threshold.",
		})
	}
	// Dedupe on (rule, first evidence ref).
	var uniq []schema.Finding
	for _, f := range out {
		key := f.RuleID + "|" + strings.Join(f.EvidenceRefs, "|")
		if l.seen[key] {
			continue
		}
		l.seen[key] = true
		uniq = append(uniq, f)
	}
	if len(l.seen) > 100000 { // bound memory over very long runs
		l.seen = map[string]bool{}
	}
	return uniq
}
