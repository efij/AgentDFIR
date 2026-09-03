// v0.5.0 behavioral and integrity rules — completes the plan §14 set.
// All deterministic over normalized events + manifest metadata.
package detect

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/netdest"
	"github.com/efij/AgentDFIR/internal/schema"
)

const defaultSpawnThreshold = 10

var (
	gitCommitRe = regexp.MustCompile(`\bgit\b(\s+-\S+)*\s+commit\b`)
	gitPushRe   = regexp.MustCompile(`\bgit\b(\s+-\S+)*\s+push\b`)
	stagingRe   = regexp.MustCompile(`\b(tar\s+-?c|zip\s+-r|7z\s+a|gzip|xz\s)\b`)
	deleteCmdRe = regexp.MustCompile(`(?i)\b(rm|shred|unlink|del|Remove-Item|rmdir)\b`)
	logTargetRe = regexp.MustCompile(`(?i)(\.claude/projects|\.claude/history|\.claude/logs|\.codex/sessions|\.codex/history|\.gemini/tmp|\.cursor/chats|history-session-state|\.aider\.(chat|input|llm)\.history|opencode/storage|warp\.sqlite|\.zsh_history|\.bash_history)`)
	histClearRe = regexp.MustCompile(`(?i)(history\s+-c|unset\s+HISTFILE|HISTSIZE=0|>\s*~?/?\.?\w*_history)`)
	selfCfgRe   = regexp.MustCompile(`(?i)(\.claude/(settings[^/]*\.json|hooks|agents|commands|skills|plugins)|CLAUDE\.md|\.mcp\.json|\.claude\.json|\.codex/config\.toml|\.gemini/settings\.json|GEMINI\.md|\.cursor/(rules|mcp\.json)|\.copilot/(config|mcp-config)\.json|opencode/opencode\.json|\.aider\.conf\.yml|managed-settings\.json)`)
)

// behavioralRules covers activity-shaped detections.
func behavioralRules(res *schema.Normalized, man *casepkg.Manifest, opts Options) []schema.Finding {
	var out []schema.Finding
	out = append(out, unexpectedAgentResume(res)...)
	out = append(out, unexpectedTask(res)...)
	out = append(out, mcpToolPoisoning(res)...)
	out = append(out, sensitiveFileRead(res)...)
	out = append(out, networkAndExfil(res, opts)...)
	out = append(out, gitActivity(res)...)
	out = append(out, spawnExplosion(res, opts)...)
	out = append(out, logDeletion(res)...)
	out = append(out, agentSelfModification(res)...)
	return out
}

// integrityRules covers evidence-integrity heuristics.
func integrityRules(res *schema.Normalized, man *casepkg.Manifest) []schema.Finding {
	var out []schema.Finding
	out = append(out, identityMismatch(res)...)
	out = append(out, sessionTampering(res)...)
	out = append(out, timestompIndicator(res, man)...)
	return out
}

func ref(ev schema.Event) string { return evidenceRef(ev) }

func parseTS(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// UNEXPECTED_AGENT_RESUME — a subagent has activity AFTER the parent
// recorded its completion (tool_result carrying the agent id).
func unexpectedAgentResume(res *schema.Normalized) []schema.Finding {
	completed := map[string]time.Time{}
	for _, ev := range res.Events {
		if ev.EventType == schema.EventToolResult && ev.TaskID != "" {
			if t, ok := parseTS(ev.Timestamp); ok {
				if cur, seen := completed[ev.TaskID]; !seen || t.After(cur) {
					completed[ev.TaskID] = t
				}
			}
		}
	}
	var out []schema.Finding
	flagged := map[string]bool{}
	for _, ev := range res.Events {
		done, ok := completed[ev.AgentID]
		if !ok || flagged[ev.AgentID] || ev.EventType == schema.EventToolResult {
			continue
		}
		t, ok := parseTS(ev.Timestamp)
		if !ok || !t.After(done.Add(60*time.Second)) {
			continue
		}
		flagged[ev.AgentID] = true
		out = append(out, schema.Finding{
			RuleID:        "UNEXPECTED_AGENT_RESUME",
			Severity:      "MEDIUM",
			Title:         "Agent Active After Recorded Completion",
			Description:   fmt.Sprintf("Agent %s has activity %s after its parent recorded completion at %s.", ev.AgentID, t.Format(time.RFC3339), done.Format(time.RFC3339)),
			SessionID:     ev.SessionID,
			AgentID:       ev.AgentID,
			EvidenceRefs:  []string{ref(ev)},
			Status:        ev.Corroboration,
			Endpoint:      schema.StateUnknown,
			FalsePositive: "Legitimate resumes happen when a user re-attaches to a prior task; check whether a human prompt precedes the activity.",
		})
	}
	return out
}

// UNEXPECTED_TASK — a subagent spawning further subagents.
func unexpectedTask(res *schema.Normalized) []schema.Finding {
	sidechain := map[string]bool{}
	for _, e := range res.Entities {
		if e.Kind == "agent" && e.Attributes["sidechain"] == "true" {
			sidechain[strings.TrimPrefix(e.EntityID, "agent:")] = true
		}
	}
	var out []schema.Finding
	for _, ev := range res.Events {
		if ev.EventType != schema.EventAgentSpawn || !sidechain[ev.AgentID] {
			continue
		}
		out = append(out, schema.Finding{
			RuleID:        "UNEXPECTED_TASK",
			Severity:      "MEDIUM",
			Title:         "Nested Subagent Spawn",
			Description:   "A subagent spawned another subagent. Nested delegation widens the blast radius and is uncommon in normal sessions.",
			SessionID:     ev.SessionID,
			AgentID:       ev.AgentID,
			EvidenceRefs:  []string{ref(ev)},
			Status:        ev.Corroboration,
			Endpoint:      schema.StateUnknown,
			FalsePositive: "Some orchestration patterns intentionally nest agents; compare with the task description.",
		})
	}
	return out
}

// MCP_TOOL_POISONING — injection phrases arriving via an MCP tool result.
func mcpToolPoisoning(res *schema.Normalized) []schema.Finding {
	mcpCalls := map[string]string{}
	for _, ev := range res.Events {
		if ev.EventType == schema.EventToolCall && ev.Action == "mcp_call" && ev.ToolCallID != "" {
			mcpCalls[ev.ToolCallID] = ev.MCPServer
		}
	}
	var out []schema.Finding
	for _, ev := range res.Events {
		if ev.EventType != schema.EventToolResult {
			continue
		}
		server, ok := mcpCalls[ev.ToolCallID]
		if !ok {
			continue
		}
		low := strings.ToLower(ev.Summary)
		for _, p := range injectionPhrases {
			if strings.Contains(low, p) {
				out = append(out, schema.Finding{
					RuleID:        "MCP_TOOL_POISONING",
					Severity:      "HIGH",
					Title:         "Instruction Content Returned by MCP Tool",
					Description:   fmt.Sprintf("Result from MCP server %q contains instruction-override phrase %q. Tool results are model context — this is the tool-poisoning delivery path.", server, p),
					SessionID:     ev.SessionID,
					AgentID:       ev.AgentID,
					EvidenceRefs:  []string{ref(ev)},
					Status:        ev.Corroboration,
					Endpoint:      schema.StateUnknown,
					MitreATLAS:    "AML.T0099", // AI Agent Tool Data Poisoning (instructions in tool results)
					FalsePositive: "Tools that legitimately return documentation about prompt injection will match; inspect the full result.",
				})
				break
			}
		}
	}
	return out
}

// SENSITIVE_FILE_READ — tool activity touching credential/config paths.
func sensitiveFileRead(res *schema.Normalized) []schema.Finding {
	var out []schema.Finding
	for _, ev := range res.Events {
		if ev.EventType != schema.EventToolCall {
			continue
		}
		subject := ev.File
		if subject == "" {
			subject = ev.Command
		}
		m, ok := containsSensitivePath(subject)
		if !ok {
			continue
		}
		out = append(out, schema.Finding{
			RuleID:        "SENSITIVE_FILE_READ",
			Severity:      "MEDIUM",
			Title:         "Sensitive Path Accessed by Agent",
			Description:   fmt.Sprintf("Agent tool activity references a sensitive location (%s).", m),
			SessionID:     ev.SessionID,
			AgentID:       ev.AgentID,
			EvidenceRefs:  []string{ref(ev)},
			Status:        ev.Corroboration,
			Endpoint:      schema.StateUnknown,
			MitreATTACK:   "T1552.001", // Credentials In Files
			MitreATLAS:    "AML.T0055", // Unsecured Credentials
			FalsePositive: "Agents legitimately edit .env files or SSH config on request; check the preceding human prompt.",
		})
	}
	return out
}

// networkAndExfil covers UNEXPECTED_NETWORK_DESTINATION and
// POTENTIAL_DATA_EXFILTRATION (sequence-aware, per session).
func networkAndExfil(res *schema.Normalized, opts Options) []schema.Finding {
	var out []schema.Finding
	seenDest := map[string]bool{}

	// Per-session ordering by sequence.
	bySession := map[string][]schema.Event{}
	for _, ev := range res.Events {
		bySession[ev.SessionID] = append(bySession[ev.SessionID], ev)
	}
	sessions := make([]string, 0, len(bySession))
	for s := range bySession {
		sessions = append(sessions, s)
	}
	sort.Strings(sessions)

	for _, s := range sessions {
		evs := bySession[s]
		sort.SliceStable(evs, func(i, j int) bool { return evs[i].Sequence < evs[j].Sequence })
		var sensitive *schema.Event
		for i := range evs {
			ev := evs[i]
			if ev.EventType != schema.EventToolCall {
				continue
			}
			// Track a "sensitive precursor": credential path read or staging.
			if sensitive == nil {
				if _, ok := containsSensitivePath(ev.File + " " + ev.Command); ok || stagingRe.MatchString(ev.Command) {
					sensitive = &evs[i]
				}
			}
			for _, d := range netdest.Extract(ev.Command) {
				if netdest.IsCloudMetadata(d) {
					out = append(out, schema.Finding{
						RuleID: "UNEXPECTED_NETWORK_DESTINATION", Severity: "HIGH",
						Title:       "Cloud Metadata Endpoint Contacted",
						Description: fmt.Sprintf("Agent command reaches the instance-metadata service (%s) — a credential-theft pivot in cloud workloads.", d),
						SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
						Status: ev.Corroboration, Endpoint: schema.StateUnknown,
						MitreATTACK:   "T1552.005", // Cloud Instance Metadata API
						MitreATLAS:    "AML.T0075", // Cloud Service Discovery
						FalsePositive: "Cloud-native tooling queries metadata legitimately on cloud hosts.",
					})
					continue
				}
				if netdest.IsAllowed(d, opts.KnownDestinations) || seenDest[d] {
					continue
				}
				seenDest[d] = true
				out = append(out, schema.Finding{
					RuleID: "UNEXPECTED_NETWORK_DESTINATION", Severity: "LOW",
					Title:       "Network Destination Outside Allowlist",
					Description: fmt.Sprintf("Agent command contacts %s, which is not in the default development allowlist or org baseline.", d),
					SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
					Status: ev.Corroboration, Endpoint: schema.StateUnknown,
					MitreATTACK:   "T1071", // Application Layer Protocol
					FalsePositive: "Internal registries and project-specific APIs are common; add them via baseline/--known-destinations.",
				})
			}
			if sensitive != nil && &evs[i] != sensitive && netdest.IsUpload(ev.Command) {
				out = append(out, schema.Finding{
					RuleID: "POTENTIAL_DATA_EXFILTRATION", Severity: "HIGH",
					Title:       "Sensitive Access Followed by Upload-Shaped Command",
					Description: "In the same session, sensitive data access/staging is followed by a command with upload semantics. Sequence is suggestive, not conclusive — confirm what was transmitted.",
					SessionID:   ev.SessionID, AgentID: ev.AgentID,
					Related:      []string{"precursor: " + ref(*sensitive)},
					EvidenceRefs: []string{ref(ev)},
					Status:       ev.Corroboration, Endpoint: schema.StateUnknown,
					MitreATTACK:   "T1041",     // Exfiltration Over C2/Web
					MitreATLAS:    "AML.T0086", // Exfiltration via AI Agent Tool Invocation
					FalsePositive: "Deploy pipelines legitimately archive and upload build artifacts; check destination and payload.",
				})
				sensitive = nil
			}
		}
	}
	return out
}

// gitActivity — AGENT_GENERATED_COMMIT / AGENT_GENERATED_PUSH.
func gitActivity(res *schema.Normalized) []schema.Finding {
	var out []schema.Finding
	for _, ev := range res.Events {
		if ev.EventType != schema.EventToolCall || ev.Command == "" {
			continue
		}
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
				Description: "Agent executed git commit. Useful provenance for code-review and supply-chain questions.",
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown,
				FalsePositive: "Expected in coding-agent sessions; informational.",
			})
		}
	}
	return out
}

// AGENT_SPAWN_EXPLOSION — many spawns in one session.
func spawnExplosion(res *schema.Normalized, opts Options) []schema.Finding {
	th := opts.SpawnThreshold
	if th <= 0 {
		th = defaultSpawnThreshold
	}
	count := map[string]int{}
	first := map[string]schema.Event{}
	for _, ev := range res.Events {
		if ev.EventType == schema.EventAgentSpawn {
			count[ev.SessionID]++
			if _, ok := first[ev.SessionID]; !ok {
				first[ev.SessionID] = ev
			}
		}
	}
	var out []schema.Finding
	for s, n := range count {
		if n <= th {
			continue
		}
		out = append(out, schema.Finding{
			RuleID: "AGENT_SPAWN_EXPLOSION", Severity: "MEDIUM", Title: "Excessive Subagent Spawning",
			Description: fmt.Sprintf("%d subagent spawns in one session (threshold %d). Runaway delegation loops amplify cost and blast radius.", n, th),
			SessionID:   s, AgentID: first[s].AgentID, EvidenceRefs: []string{ref(first[s])},
			Status: schema.StateObserved, Endpoint: schema.StateUnknown,
			MitreATLAS:    "AML.T0034.002", // Cost Harvesting: Agentic Resource Consumption
			FalsePositive: "Large fan-out tasks (e.g. per-file review) legitimately spawn many agents; tune with --spawn-threshold.",
		})
	}
	return out
}

// LOG_DELETION — commands removing agent transcripts/history.
func logDeletion(res *schema.Normalized) []schema.Finding {
	var out []schema.Finding
	for _, ev := range res.Events {
		if ev.EventType != schema.EventToolCall || ev.Command == "" {
			continue
		}
		if !(deleteCmdRe.MatchString(ev.Command) && logTargetRe.MatchString(ev.Command)) &&
			!histClearRe.MatchString(ev.Command) {
			continue
		}
		out = append(out, schema.Finding{
			RuleID: "LOG_DELETION", Severity: "HIGH", Title: "Agent Activity Logs Targeted for Deletion",
			Description: "Agent command deletes or clears agent transcripts, history or shell history — anti-forensic behavior.",
			SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
			Status: ev.Corroboration, Endpoint: schema.StateUnknown,
			MitreATTACK:   "T1070.004", // Indicator Removal: File Deletion
			FalsePositive: "Users sometimes ask agents to clean up disk space; verify the request.",
		})
	}
	return out
}

// AGENT_SELF_MODIFICATION — agent edits its own configuration.
func agentSelfModification(res *schema.Normalized) []schema.Finding {
	var out []schema.Finding
	for _, ev := range res.Events {
		if ev.EventType != schema.EventToolCall {
			continue
		}
		// Reads are fine; writes/edits/shell touching own config are the signal.
		isWrite := ev.Action == "write_file" || ev.Action == "edit_file" || ev.Action == "shell_execution"
		if !isWrite {
			continue
		}
		subject := ev.File
		if subject == "" {
			subject = ev.Command
		}
		if ev.Action == "shell_execution" && !lowerHas(subject, "echo", ">", "sed", "tee", "cp ", "mv ", "cat >", "python", "node") {
			continue
		}
		if !selfCfgRe.MatchString(subject) {
			continue
		}
		out = append(out, schema.Finding{
			RuleID: "AGENT_SELF_MODIFICATION", Severity: "HIGH", Title: "Agent Modified Its Own Configuration",
			Description: "Agent wrote to its own settings, hooks, instructions or MCP configuration. Self-modification can persist injected behavior across sessions.",
			SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
			Status: ev.Corroboration, Endpoint: schema.StateUnknown,
			MitreATTACK:   "T1562.001",
			MitreATLAS:    "AML.T0081", // Modify AI Agent Configuration
			FalsePositive: "Users ask agents to configure themselves (add MCP servers, hooks); check the preceding prompt and diff against baseline.",
		})
	}
	return out
}

// AGENT_IDENTITY_MISMATCH — one transcript artifact carries >1 sessionId.
func identityMismatch(res *schema.Normalized) []schema.Finding {
	sessions := map[string]map[string]bool{}
	sample := map[string]schema.Event{}
	for _, ev := range res.Events {
		if ev.SessionID == "" || ev.SourceArtifact == "" {
			continue
		}
		if sessions[ev.SourceArtifact] == nil {
			sessions[ev.SourceArtifact] = map[string]bool{}
			sample[ev.SourceArtifact] = ev
		}
		sessions[ev.SourceArtifact][ev.SessionID] = true
	}
	var out []schema.Finding
	for art, set := range sessions {
		if len(set) < 2 {
			continue
		}
		ids := make([]string, 0, len(set))
		for s := range set {
			ids = append(ids, s)
		}
		sort.Strings(ids)
		out = append(out, schema.Finding{
			RuleID: "AGENT_IDENTITY_MISMATCH", Severity: "HIGH", Title: "Transcript Carries Multiple Session Identities",
			Description:  fmt.Sprintf("Artifact %.12s contains records from %d different sessions (%s). Single-session files should not — indicates splicing or identity confusion.", art, len(set), strings.Join(ids, ", ")),
			EvidenceRefs: []string{ref(sample[art])},
			Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
			MitreATTACK:   "T1565.001", // Stored Data Manipulation
			FalsePositive: "Some products legitimately append resumed sessions with new IDs to the same file; confirm with product version.",
		})
	}
	return out
}

// SESSION_TAMPERING — chain breaks + backward timestamps per artifact.
func sessionTampering(res *schema.Normalized) []schema.Finding {
	type stats struct {
		chainBreaks int
		regressions int
		sample      schema.Event
		lastTS      time.Time
		hasLast     bool
	}
	per := map[string]*stats{}
	order := []string{}
	for _, ev := range res.Events {
		if ev.SourceArtifact == "" {
			continue
		}
		st, ok := per[ev.SourceArtifact]
		if !ok {
			st = &stats{sample: ev}
			per[ev.SourceArtifact] = st
			order = append(order, ev.SourceArtifact)
		}
		if ev.EventType == schema.EventSessionMeta && ev.Result == "chain_break" {
			st.chainBreaks++
		}
		if t, ok := parseTS(ev.Timestamp); ok {
			if st.hasLast && t.Before(st.lastTS.Add(-60*time.Second)) {
				st.regressions++
			}
			st.lastTS, st.hasLast = t, true
		}
	}
	var out []schema.Finding
	for _, art := range order {
		st := per[art]
		if st.chainBreaks == 0 && st.regressions == 0 {
			continue
		}
		sev := "MEDIUM"
		if st.chainBreaks > 0 {
			sev = "HIGH"
		}
		out = append(out, schema.Finding{
			RuleID: "SESSION_TAMPERING", Severity: sev, Title: "Transcript Integrity Anomalies",
			Description:  fmt.Sprintf("Artifact %.12s shows %d parent-chain break(s) and %d backward timestamp regression(s) (>60s). OBSERVED events from this artifact carry reduced confidence.", art, st.chainBreaks, st.regressions),
			SessionID:    st.sample.SessionID,
			EvidenceRefs: []string{ref(st.sample)},
			Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
			MitreATTACK:   "T1565.001",
			FalsePositive: "Clock adjustments and product bugs can regress timestamps; chain breaks are the stronger signal.",
		})
	}
	return out
}

// TIMESTOMP_INDICATOR — artifact mtime predates content it contains.
func timestompIndicator(res *schema.Normalized, man *casepkg.Manifest) []schema.Finding {
	latest := map[string]time.Time{}
	sample := map[string]schema.Event{}
	for _, ev := range res.Events {
		if t, ok := parseTS(ev.Timestamp); ok && ev.SourceArtifact != "" {
			if t.After(latest[ev.SourceArtifact]) {
				latest[ev.SourceArtifact] = t
				sample[ev.SourceArtifact] = ev
			}
		}
	}
	var out []schema.Finding
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK || !isType(a, "agent_session", "prompt_history") {
			continue
		}
		mt, ok := parseTS(a.ModTimeUTC)
		lt, ok2 := latest[a.ArtifactID]
		if !ok || !ok2 {
			continue
		}
		if mt.Before(lt.Add(-5 * time.Minute)) {
			out = append(out, schema.Finding{
				RuleID: "TIMESTOMP_INDICATOR", Severity: "MEDIUM", Title: "File Modified Before Content It Contains",
				Description:  fmt.Sprintf("%s has filesystem mtime %s but contains an event timestamped %s. A file cannot legitimately predate its own content — indicates timestamp manipulation or clock skew.", a.LogicalPath, mt.Format(time.RFC3339), lt.Format(time.RFC3339)),
				SessionID:    sample[a.ArtifactID].SessionID,
				EvidenceRefs: []string{ref(sample[a.ArtifactID])},
				Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
				MitreATTACK:   "T1070.006", // Timestomp
				FalsePositive: "Host clock skew or restoring files from backup produces the same pattern; correlate with case.json clock data.",
			})
		}
	}
	return out
}
