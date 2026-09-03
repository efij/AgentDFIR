// Package detect implements deterministic, rule-based detections over
// normalized events (plan §14). No LLM involvement — ever.
//
// Mapping discipline (plan §15): MITRE ATLAS/ATT&CK fields are set only
// where a valid technique exists; absence of a mapping is correct
// behavior, not a gap. Findings never escalate to conclusions like
// "compromise" or "exfiltration" — they state what the evidence shows.
package detect

import (
	"fmt"
	"strings"

	"github.com/efij/AgentDFIR/internal/schema"
)

// Run evaluates all rules and returns findings ordered by severity.
func Run(res *schema.Normalized) []schema.Finding {
	var findings []schema.Finding
	findings = append(findings, orphanAgents(res)...)
	findings = append(findings, crossAgentMessages(res)...)
	findings = append(findings, destructiveCommands(res)...)
	findings = append(findings, shellExecution(res)...)
	findings = append(findings, traceGaps(res)...)
	return sortBySeverity(findings)
}

func evidenceRef(ev schema.Event) string {
	return fmt.Sprintf("%s:%d (artifact %s, offset %d)",
		ev.SourcePath, ev.SourceLine, short(ev.SourceArtifact), ev.SourceOffset)
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// ORPHAN_AGENT — a subagent transcript exists but no observed spawn
// (Task tool call/result) links any parent to it.
func orphanAgents(res *schema.Normalized) []schema.Finding {
	spawned := res.SpawnEvidence()
	// Any Task tool_result that references an agent also counts as
	// spawn evidence (captured by the parser into SpawnEvidence).
	var out []schema.Finding
	for _, ent := range res.Entities {
		if ent.Kind != "agent" || ent.Attributes["sidechain"] != "true" {
			continue
		}
		agentID := strings.TrimPrefix(ent.EntityID, "agent:")
		if _, ok := spawned[agentID]; ok {
			continue
		}
		var refs []string
		var sessionID string
		for _, ev := range res.Events {
			if ev.AgentID == agentID {
				if len(refs) < 3 {
					refs = append(refs, evidenceRef(ev))
				}
				sessionID = ev.SessionID
			}
		}
		out = append(out, schema.Finding{
			RuleID:        "ORPHAN_AGENT",
			Severity:      "HIGH",
			Title:         "Unexpected Agent Activity",
			Description:   "Agent appeared without a verified parent invocation: no Task spawn event or spawn result links any parent agent to this transcript.",
			SessionID:     sessionID,
			AgentID:       agentID,
			ParentAgentID: "UNKNOWN",
			EvidenceRefs:  refs,
			Status:        schema.StateObserved,
			Endpoint:      schema.StateUnknown,
			FalsePositive: "Spawn evidence may live in a session not collected (partial acquisition) or in a format version this parser does not yet link.",
		})
	}
	return out
}

// CROSS_SESSION_MESSAGE / UNEXPECTED_AGENT_RESUME — inter-agent
// communication targeting an agent outside the sender's session.
func crossAgentMessages(res *schema.Normalized) []schema.Finding {
	// Map agents to their sessions.
	agentSession := map[string]string{}
	for _, ev := range res.Events {
		if ev.AgentID != "" && ev.SessionID != "" {
			agentSession[ev.AgentID] = ev.SessionID
		}
	}
	spawned := res.SpawnEvidence()
	var out []schema.Finding
	for _, ev := range res.Events {
		if ev.EventType != schema.EventToolCall || ev.Action != "inter_agent_message" {
			continue
		}
		target := strings.TrimPrefix(ev.Summary, "to=")
		targetSession, known := agentSession[target]
		cross := known && targetSession != ev.SessionID
		if !cross && known {
			continue // same-session messaging: normal
		}
		sev := "MEDIUM"
		desc := "Inter-agent message/resume interaction observed."
		if _, senderSpawned := spawned[ev.AgentID]; !senderSpawned && strings.Contains(ev.AgentID, ":") == false {
			// Sender is itself an unverified (orphan) agent: escalate.
			sev = "HIGH"
			desc = "Inter-agent message/resume initiated by an agent with no verified parent invocation."
		}
		related := fmt.Sprintf("SendMessage/resume interaction with agent %s", target)
		if known {
			related += fmt.Sprintf(" (session %s)", targetSession)
		}
		out = append(out, schema.Finding{
			RuleID:       "CROSS_SESSION_MESSAGE",
			Severity:     sev,
			Title:        "Cross-Agent Communication",
			Description:  desc,
			SessionID:    ev.SessionID,
			AgentID:      ev.AgentID,
			Related:      []string{related},
			EvidenceRefs: []string{evidenceRef(ev)},
			Status:       ev.Corroboration,
			Endpoint:     schema.StateUnknown,
		})
	}
	return out
}

// DESTRUCTIVE_COMMAND — shell commands with destructive patterns.
// Path context matters (plan §14 FP hygiene): recursive deletion inside
// a temp dir is noise; this rule reports the command and lets the
// analyst judge — it never auto-labels intent.
func destructiveCommands(res *schema.Normalized) []schema.Finding {
	patterns := []string{"rm -rf ", "rm -fr ", "mkfs", "dd if=", ":(){", "git push --force", "git push -f"}
	var out []schema.Finding
	for _, ev := range res.Events {
		if ev.EventType != schema.EventToolCall || ev.Command == "" {
			continue
		}
		lower := strings.ToLower(ev.Command)
		for _, pat := range patterns {
			if strings.Contains(lower, pat) {
				out = append(out, schema.Finding{
					RuleID:        "DESTRUCTIVE_COMMAND",
					Severity:      "MEDIUM",
					Title:         "Potentially Destructive Command",
					Description:   "Agent-invoked shell command matches a destructive pattern: " + pat,
					SessionID:     ev.SessionID,
					AgentID:       ev.AgentID,
					EvidenceRefs:  []string{evidenceRef(ev)},
					Status:        ev.Corroboration,
					Endpoint:      schema.StateUnknown,
					MitreATTACK:   "T1485",     // Data Destruction (candidate; analyst confirms)
					MitreATLAS:    "AML.T0101", // Data Destruction via AI Agent Tool Invocation
					FalsePositive: "Destructive patterns are common in legitimate development (cleanups, test scaffolding). Path context and repo scope decide.",
				})
				break
			}
		}
	}
	return out
}

// SHELL_EXECUTION — informational by default (fires on nearly every
// CLI-agent session; plan §14).
func shellExecution(res *schema.Normalized) []schema.Finding {
	count := 0
	var first schema.Event
	for _, ev := range res.Events {
		if ev.EventType == schema.EventToolCall && ev.Action == "shell_execution" {
			if count == 0 {
				first = ev
			}
			count++
		}
	}
	if count == 0 {
		return nil
	}
	return []schema.Finding{{
		RuleID:        "SHELL_EXECUTION",
		Severity:      "INFO",
		Title:         "Shell Execution Present",
		Description:   fmt.Sprintf("%d shell command(s) invoked via the Bash tool across the collected sessions.", count),
		EvidenceRefs:  []string{evidenceRef(first)},
		Status:        schema.StateObserved,
		Endpoint:      schema.StateUnknown,
		MitreATTACK:   "T1059",     // Command and Scripting Interpreter
		MitreATLAS:    "AML.T0050", // Command and Scripting Interpreter
		FalsePositive: "Expected in virtually every coding-agent session; informational context, not an indicator.",
	}}
}

// TRACE_GAP — malformed/truncated transcript regions. These downgrade
// trust in OBSERVED events from the affected artifact (plan §12).
func traceGaps(res *schema.Normalized) []schema.Finding {
	var out []schema.Finding
	for _, ev := range res.Events {
		if ev.EventType != schema.EventTraceGap {
			continue
		}
		out = append(out, schema.Finding{
			RuleID:       "TRACE_GAP",
			Severity:     "MEDIUM",
			Title:        "Transcript Integrity Gap",
			Description:  "Malformed or truncated region in a session transcript. OBSERVED events from this artifact carry reduced confidence; consider SESSION_TAMPERING review.",
			SessionID:    ev.SessionID,
			EvidenceRefs: []string{evidenceRef(ev)},
			Status:       schema.StateObserved,
			Endpoint:     schema.StateUnknown,
		})
	}
	return out
}

var sevRank = map[string]int{"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

func sortBySeverity(f []schema.Finding) []schema.Finding {
	// A finding's endpoint corroboration follows its events: when endpoint
	// correlation already raised (or contradicted) the underlying tool call,
	// the finding must say so instead of the static UNKNOWN.
	for i := range f {
		switch f[i].Status {
		case schema.StateCorroborated, schema.StatePartial, schema.StateContradicted:
			if f[i].Endpoint == "" || f[i].Endpoint == schema.StateUnknown {
				f[i].Endpoint = f[i].Status
			}
		}
	}
	// Stable insertion sort by severity rank (small n).
	for i := 1; i < len(f); i++ {
		for j := i; j > 0 && sevRank[f[j].Severity] < sevRank[f[j-1].Severity]; j-- {
			f[j], f[j-1] = f[j-1], f[j]
		}
	}
	return f
}
