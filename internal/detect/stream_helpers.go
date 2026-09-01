package detect

import (
	"fmt"
	"strings"

	"github.com/efij/AgentDFIR/internal/netdest"
	"github.com/efij/AgentDFIR/internal/schema"
)

// oneToolCallRules evaluates the stateless-and-per-session tool-call rules
// for a single event, updating per-session exfil state on p.
func oneToolCallRules(ev schema.Event, p *streamPass2) []schema.Finding {
	var out []schema.Finding

	// SENSITIVE_FILE_READ
	subj := ev.File
	if subj == "" {
		subj = ev.Command
	}
	if m, ok := containsSensitivePath(subj); ok {
		out = append(out, schema.Finding{
			RuleID: "SENSITIVE_FILE_READ", Severity: "MEDIUM", Title: "Sensitive Path Accessed by Agent",
			Description: fmt.Sprintf("Agent tool activity references a sensitive location (%s).", m),
			SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
			Status: ev.Corroboration, Endpoint: schema.StateUnknown, MitreATTACK: "T1552.001",
			FalsePositive: "Agents legitimately edit .env / SSH config on request; check the preceding prompt.",
		})
	}

	// AGENT_SELF_MODIFICATION
	if ev.Action == "write_file" || ev.Action == "edit_file" ||
		(ev.Action == "shell_execution" && lowerHas(subj, "echo", ">", "sed", "tee", "cp ", "mv ", "cat >", "python", "node")) {
		if selfCfgRe.MatchString(subj) {
			out = append(out, schema.Finding{
				RuleID: "AGENT_SELF_MODIFICATION", Severity: "HIGH", Title: "Agent Modified Its Own Configuration",
				Description: "Agent wrote to its own settings, hooks, instructions or MCP configuration. Self-modification can persist injected behavior across sessions.",
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown, MitreATTACK: "T1562.001",
				FalsePositive: "Users ask agents to configure themselves; check the prompt and diff against baseline.",
			})
		}
	}

	if ev.Command != "" {
		// git
		switch {
		case gitPushRe.MatchString(ev.Command):
			out = append(out, schema.Finding{
				RuleID: "AGENT_GENERATED_PUSH", Severity: "LOW", Title: "Agent Pushed to a Remote",
				Description: "Agent executed git push. Code left the host under agent control.",
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown,
				FalsePositive: "Routine when the user asked the agent to push.",
			})
		case gitCommitRe.MatchString(ev.Command):
			out = append(out, schema.Finding{
				RuleID: "AGENT_GENERATED_COMMIT", Severity: "INFO", Title: "Agent Created a Commit",
				Description: "Agent executed git commit — useful provenance for code-review and supply-chain questions.",
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown,
				FalsePositive: "Expected in coding-agent sessions; informational.",
			})
		}
		// LOG_DELETION
		if (deleteCmdRe.MatchString(ev.Command) && logTargetRe.MatchString(ev.Command)) || histClearRe.MatchString(ev.Command) {
			out = append(out, schema.Finding{
				RuleID: "LOG_DELETION", Severity: "HIGH", Title: "Agent Activity Logs Targeted for Deletion",
				Description: "Agent command deletes or clears agent transcripts, history or shell history — anti-forensic behavior.",
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown, MitreATTACK: "T1070.004",
				FalsePositive: "Users sometimes ask agents to free disk space; verify the request.",
			})
		}
		// network destinations
		for _, d := range netdest.Extract(ev.Command) {
			if netdest.IsCloudMetadata(d) {
				out = append(out, schema.Finding{
					RuleID: "UNEXPECTED_NETWORK_DESTINATION", Severity: "HIGH", Title: "Cloud Metadata Endpoint Contacted",
					Description: fmt.Sprintf("Agent command reaches the instance-metadata service (%s) — a credential-theft pivot in cloud workloads.", d),
					SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
					Status: ev.Corroboration, Endpoint: schema.StateUnknown, MitreATTACK: "T1552.005",
					FalsePositive: "Cloud-native tooling queries metadata legitimately on cloud hosts.",
				})
				continue
			}
			if netdest.IsAllowed(d, p.opts.KnownDestinations) || p.seenDest[d] {
				continue
			}
			p.seenDest[d] = true
			out = append(out, schema.Finding{
				RuleID: "UNEXPECTED_NETWORK_DESTINATION", Severity: "LOW", Title: "Network Destination Outside Allowlist",
				Description: fmt.Sprintf("Agent command contacts %s, not in the default development allowlist or org baseline.", d),
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown, MitreATTACK: "T1071",
				FalsePositive: "Internal registries and project APIs are common; add via baseline/--known-destinations.",
			})
		}
		// POTENTIAL_DATA_EXFILTRATION (per-session sequence)
		if precursor, ok := p.pendingExfil[ev.SessionID]; ok && netdest.IsUpload(ev.Command) {
			out = append(out, schema.Finding{
				RuleID: "POTENTIAL_DATA_EXFILTRATION", Severity: "HIGH", Title: "Sensitive Access Followed by Upload-Shaped Command",
				Description: "In the same session, sensitive data access/staging is followed by an upload-shaped command. Sequence is suggestive, not conclusive — confirm what was transmitted.",
				SessionID:   ev.SessionID, AgentID: ev.AgentID,
				Related:      []string{"precursor: " + ref(precursor)},
				EvidenceRefs: []string{ref(ev)},
				Status:       ev.Corroboration, Endpoint: schema.StateUnknown, MitreATTACK: "T1041",
				FalsePositive: "Deploy pipelines archive and upload artifacts; check destination and payload.",
			})
			delete(p.pendingExfil, ev.SessionID)
		} else if _, sok := p.pendingExfil[ev.SessionID]; !sok {
			if _, isSensitive := containsSensitivePath(subj); isSensitive || stagingRe.MatchString(ev.Command) {
				p.pendingExfil[ev.SessionID] = ev
			}
		}
	}
	return out
}

func mcpPoisonOne(ev schema.Event, server string) (schema.Finding, bool) {
	low := strings.ToLower(ev.Summary)
	for _, ph := range injectionPhrases {
		if strings.Contains(low, ph) {
			return schema.Finding{
				RuleID: "MCP_TOOL_POISONING", Severity: "HIGH", Title: "Instruction Content Returned by MCP Tool",
				Description: fmt.Sprintf("Result from MCP server %q contains instruction-override phrase %q. Tool results are model context — the tool-poisoning delivery path.", server, ph),
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown, MitreATLAS: "AML.T0053",
				FalsePositive: "Tools that legitimately return docs about prompt injection will match; inspect the full result.",
			}, true
		}
	}
	return schema.Finding{}, false
}

func nestedTaskFinding(ev schema.Event) schema.Finding {
	return schema.Finding{
		RuleID: "UNEXPECTED_TASK", Severity: "MEDIUM", Title: "Nested Subagent Spawn",
		Description: "A subagent spawned another subagent. Nested delegation widens the blast radius and is uncommon in normal sessions.",
		SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
		Status: ev.Corroboration, Endpoint: schema.StateUnknown,
		FalsePositive: "Some orchestration patterns intentionally nest agents; compare with the task description.",
	}
}

var destructivePatterns = []string{"rm -rf ", "rm -fr ", "mkfs", "dd if=", ":(){", "git push --force", "git push -f"}

func destructiveOne(ev schema.Event) (schema.Finding, bool) {
	if ev.Command == "" {
		return schema.Finding{}, false
	}
	low := strings.ToLower(ev.Command)
	for _, pat := range destructivePatterns {
		if strings.Contains(low, pat) {
			return schema.Finding{
				RuleID: "DESTRUCTIVE_COMMAND", Severity: "MEDIUM", Title: "Potentially Destructive Command",
				Description: "Agent-invoked shell command matches a destructive pattern: " + pat,
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown, MitreATTACK: "T1485",
				FalsePositive: "Destructive patterns are common in legitimate development; path context and repo scope decide.",
			}, true
		}
	}
	return schema.Finding{}, false
}

func traceGapOne(ev schema.Event) schema.Finding {
	return schema.Finding{
		RuleID: "TRACE_GAP", Severity: "MEDIUM", Title: "Transcript Integrity Gap",
		Description: "Malformed or truncated region in a session transcript. OBSERVED events from this artifact carry reduced confidence; consider SESSION_TAMPERING review.",
		SessionID:   ev.SessionID, EvidenceRefs: []string{ref(ev)},
		Status: schema.StateObserved, Endpoint: schema.StateUnknown,
	}
}

func crossMessageOne(ev schema.Event, agg *streamAgg) (schema.Finding, bool) {
	target := strings.TrimPrefix(ev.Summary, "to=")
	targetSession, known := agg.agentSession[target]
	cross := known && targetSession != ev.SessionID
	if !cross && known {
		return schema.Finding{}, false
	}
	sev, desc := "MEDIUM", "Inter-agent message/resume interaction observed."
	if _, senderSpawned := agg.spawnedAgents[ev.AgentID]; !senderSpawned && !strings.Contains(ev.AgentID, ":") {
		sev, desc = "HIGH", "Inter-agent message/resume initiated by an agent with no verified parent invocation."
	}
	related := fmt.Sprintf("SendMessage/resume interaction with agent %s", target)
	if known {
		related += fmt.Sprintf(" (session %s)", targetSession)
	}
	return schema.Finding{
		RuleID: "CROSS_SESSION_MESSAGE", Severity: sev, Title: "Cross-Agent Communication",
		Description: desc, SessionID: ev.SessionID, AgentID: ev.AgentID,
		Related: []string{related}, EvidenceRefs: []string{ref(ev)},
		Status: ev.Corroboration, Endpoint: schema.StateUnknown,
	}, true
}
