// Package catalog is the single machine-readable index of every built-in
// detection rule AgentDFIR can emit, with its MITRE ATT&CK / ATLAS mapping.
//
// The built-in rules live as Go code across internal/detect, internal/mcpaudit,
// internal/provenance and internal/correlate; this table mirrors them so that
// `agentdfir rules list`, docs/detection-coverage.md and SIEM integrations can
// enumerate coverage without executing an analysis. catalog_test.go fails the
// build when a RuleID literal appears in source without a catalog entry (or
// vice versa), so the table cannot silently drift from the code.
//
// Mapping discipline: ATT&CK/ATLAS fields are filled only where a valid
// technique exists; rules that describe evidence-quality problems (trace
// gaps, orphan agents) intentionally carry none.
package catalog

// Rule describes one built-in detection.
type Rule struct {
	ID          string `json:"id"`
	Package     string `json:"package"`      // Go package that emits it
	Surface     string `json:"surface"`      // transcript | command | config | mcp | provenance | endpoint
	MaxSeverity string `json:"max_severity"` // highest severity the rule emits
	Title       string `json:"title"`
	Summary     string `json:"summary"`
	MitreATTACK string `json:"mitre_attack,omitempty"`
	MitreATLAS  string `json:"mitre_atlas,omitempty"`
}

// Builtin lists every built-in rule. Keep sorted by package, then ID.
var Builtin = []Rule{
	// ---------------------------------------------------------------- detect
	{ID: "AGENT_CONTEXT_POISONING", Package: "detect", Surface: "config", MaxSeverity: "HIGH",
		Title: "Agent Context Poisoning Indicator", Summary: "Instruction-override phrase in standing agent instructions (CLAUDE.md, rules).",
		MitreATLAS: "AML.T0080.000"},
	{ID: "AGENT_GENERATED_COMMIT", Package: "detect", Surface: "command", MaxSeverity: "INFO",
		Title: "Agent Created a Commit", Summary: "Provenance marker: git commit executed by the agent."},
	{ID: "AGENT_GENERATED_PUSH", Package: "detect", Surface: "command", MaxSeverity: "LOW",
		Title: "Agent Pushed to a Remote", Summary: "git push executed by the agent; code left the host."},
	{ID: "AGENT_IDENTITY_MISMATCH", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Transcript Carries Multiple Session Identities", Summary: "One session file contains records from several sessions (splicing).",
		MitreATTACK: "T1565.001"},
	{ID: "AGENT_SELF_MODIFICATION", Package: "detect", Surface: "command", MaxSeverity: "HIGH",
		Title: "Agent Modified Its Own Configuration", Summary: "Write to the agent's own settings, hooks, instructions or MCP config.",
		MitreATTACK: "T1562.001", MitreATLAS: "AML.T0081"},
	{ID: "AGENT_SPAWN_EXPLOSION", Package: "detect", Surface: "transcript", MaxSeverity: "MEDIUM",
		Title: "Excessive Subagent Spawning", Summary: "Subagent spawns in one session exceed the threshold.",
		MitreATLAS: "AML.T0034.002"},
	{ID: "CROSS_SESSION_MESSAGE", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Cross-Agent Communication", Summary: "Message or resume interaction between agents/sessions."},
	{ID: "DESTRUCTIVE_COMMAND", Package: "detect", Surface: "command", MaxSeverity: "MEDIUM",
		Title: "Potentially Destructive Command", Summary: "rm -rf, mkfs, dd, fork bomb, force push.",
		MitreATTACK: "T1485", MitreATLAS: "AML.T0101"},
	{ID: "INVISIBLE_UNICODE_INSTRUCTION", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Invisible Unicode in Agent-Facing Content", Summary: "Unicode tag / bidi / zero-width characters smuggling instructions.",
		MitreATLAS: "AML.T0068"},
	{ID: "LOG_DELETION", Package: "detect", Surface: "command", MaxSeverity: "HIGH",
		Title: "Agent Activity Logs Targeted for Deletion", Summary: "Deletion of agent transcripts, history or shell history.",
		MitreATTACK: "T1070.004"},
	{ID: "MCP_TOOL_POISONING", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Instruction Content Returned by MCP Tool", Summary: "Instruction-override phrase inside an MCP tool result.",
		MitreATLAS: "AML.T0099"},
	{ID: "ORPHAN_AGENT", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Unexpected Agent Activity", Summary: "Agent transcript with no verified parent spawn."},
	{ID: "PERMISSION_BYPASS_ENABLED", Package: "detect", Surface: "config", MaxSeverity: "HIGH",
		Title: "Permission/Sandbox Controls Disabled", Summary: "Configuration disables permission prompting or sandboxing.",
		MitreATTACK: "T1562.001", MitreATLAS: "AML.T0081"},
	{ID: "PERMISSION_ESCALATION", Package: "detect", Surface: "config", MaxSeverity: "MEDIUM",
		Title: "Blanket Tool Permission Granted", Summary: "Wildcard allow rules remove per-command review.",
		MitreATTACK: "T1562.001", MitreATLAS: "AML.T0081"},
	{ID: "POTENTIAL_DATA_EXFILTRATION", Package: "detect", Surface: "command", MaxSeverity: "HIGH",
		Title: "Sensitive Access Followed by Upload-Shaped Command", Summary: "Per-session sequence: credential/staging access then upload.",
		MitreATTACK: "T1041", MitreATLAS: "AML.T0086"},
	{ID: "POTENTIAL_SECRET_EXPOSURE", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Credential Material in Agent Conversation", Summary: "API keys, tokens or private-key blocks inside a transcript.",
		MitreATTACK: "T1552", MitreATLAS: "AML.T0057"},
	{ID: "PROMPT_INJECTION_INDICATOR", Package: "detect", Surface: "transcript", MaxSeverity: "MEDIUM",
		Title: "Prompt Injection Indicator", Summary: "Instruction-override phrase in conversation or tool-result content.",
		MitreATLAS: "AML.T0051"},
	{ID: "SECRET_ACCESS", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Honeytoken Accessed by Agent", Summary: "Planted canary marker appears in agent activity.",
		MitreATTACK: "T1552", MitreATLAS: "AML.T0055"},
	{ID: "SENSITIVE_FILE_READ", Package: "detect", Surface: "command", MaxSeverity: "MEDIUM",
		Title: "Sensitive Path Accessed by Agent", Summary: "Tool activity touching credential/config paths.",
		MitreATTACK: "T1552.001", MitreATLAS: "AML.T0055"},
	{ID: "SESSION_TAMPERING", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Transcript Integrity Anomalies", Summary: "Parent-chain breaks and timestamp regressions in a session file.",
		MitreATTACK: "T1565.001"},
	{ID: "SHELL_EXECUTION", Package: "detect", Surface: "command", MaxSeverity: "INFO",
		Title: "Shell Execution Present", Summary: "Shell commands were invoked via a tool (context, not an indicator).",
		MitreATTACK: "T1059", MitreATLAS: "AML.T0050"},
	{ID: "TIMESTOMP_INDICATOR", Package: "detect", Surface: "transcript", MaxSeverity: "MEDIUM",
		Title: "File Modified Before Content It Contains", Summary: "Filesystem mtime predates an event timestamp inside the file.",
		MitreATTACK: "T1070.006"},
	{ID: "TOOL_POISONING_INDICATOR", Package: "detect", Surface: "config", MaxSeverity: "HIGH",
		Title: "Tool/Skill Definition Poisoning Indicator", Summary: "Instruction-override phrase in a tool, skill, agent or plugin definition.",
		MitreATLAS: "AML.T0110"},
	{ID: "TRACE_GAP", Package: "detect", Surface: "transcript", MaxSeverity: "MEDIUM",
		Title: "Transcript Integrity Gap", Summary: "Malformed or truncated transcript region; lowers trust in OBSERVED events."},
	{ID: "UNEXPECTED_AGENT_RESUME", Package: "detect", Surface: "transcript", MaxSeverity: "MEDIUM",
		Title: "Agent Active After Recorded Completion", Summary: "Activity after the agent's completion record."},
	{ID: "UNEXPECTED_NETWORK_DESTINATION", Package: "detect", Surface: "command", MaxSeverity: "HIGH",
		Title: "Network Destination Outside Allowlist / Cloud Metadata Contacted", Summary: "HIGH for the instance-metadata service (T1552.005); LOW for other non-allowlisted hosts (T1071).",
		MitreATTACK: "T1552.005", MitreATLAS: "AML.T0075"},
	{ID: "UNEXPECTED_TASK", Package: "detect", Surface: "transcript", MaxSeverity: "MEDIUM",
		Title: "Nested Subagent Spawn", Summary: "A subagent spawned another subagent."},

	// -------------------------------------------------------------- mcpaudit
	{ID: "INSECURE_MCP_TRANSPORT", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "HIGH",
		Title: "MCP Server Over Plaintext Transport", Summary: "http:// or ws:// MCP endpoint.",
		MitreATTACK: "T1557"},
	{ID: "MCP_ALL_PROJECT_SERVERS_TRUSTED", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "HIGH",
		Title: "All Project MCP Servers Auto-Trusted", Summary: "Any cloned repository can install servers without a prompt.",
		MitreATTACK: "T1195", MitreATLAS: "AML.T0010"},
	{ID: "MCP_GATEWAY_BACKEND_ERRORS", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "LOW",
		Title: "MCP Backend Failing Behind the Gateway", Summary: "Gateway log shows repeated backend errors for a server."},
	{ID: "MCP_GATEWAY_CONTRADICTED_CALL", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "HIGH",
		Title: "Transcript MCP Call Never Reached the Gateway", Summary: "Transcript claims an MCP call the gateway log does not contain (CONTRADICTED).",
		MitreATTACK: "T1562"},
	{ID: "MCP_GATEWAY_DENIED_CALL", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "MEDIUM",
		Title: "MCP Call Denied by Gateway Policy", Summary: "Gateway refused a tool call the agent attempted.",
		MitreATTACK: "T1548"},
	{ID: "MCP_GATEWAY_UNLOGGED_CALL", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "HIGH",
		Title: "Gateway Saw an MCP Call the Transcript Does Not Contain", Summary: "Tool call in the gateway log with no transcript counterpart.",
		MitreATTACK: "T1070"},
	{ID: "MCP_SERVER_CHANGED", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "HIGH",
		Title: "MCP Server Definition Changed Since Baseline", Summary: "Command, package or transport differs from the recorded baseline.",
		MitreATTACK: "T1195.002", MitreATLAS: "AML.T0010"},
	{ID: "MCP_AUTO_APPROVE", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "HIGH",
		Title: "MCP Tools Auto-Approved Without Human Confirmation", Summary: "Tools pre-approved; injected instructions can drive them unprompted.",
		MitreATTACK: "T1548", MitreATLAS: "AML.T0053"},
	{ID: "MCP_NAME_COLLISION", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "MEDIUM",
		Title: "Same MCP Server Name Resolves to Different Programs", Summary: "Shadowing of a user-level server by a project definition.",
		MitreATTACK: "T1036", MitreATLAS: "AML.T0053"},
	{ID: "MCP_PROJECT_SCOPED_SERVER", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "INFO",
		Title: "Project-Scoped MCP Server", Summary: "Server defined by a repository rather than the user.",
		MitreATTACK: "T1195"},
	{ID: "MCP_REMOTE_FETCH_COMMAND", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "CRITICAL",
		Title: "MCP Server Command Fetches and Executes Remote Code", Summary: "Launch command downloads and runs code (CRITICAL) or wraps a shell (MEDIUM).",
		MitreATTACK: "T1105", MitreATLAS: "AML.T0010"},
	{ID: "MCP_SECRET_IN_CONFIG", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "MEDIUM",
		Title: "Credential Material Inline in MCP Server Config", Summary: "Token or key embedded in server definition.",
		MitreATTACK: "T1552.001"},
	{ID: "MCP_SERVER_ADDED", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "MEDIUM",
		Title: "MCP Server Not in Baseline", Summary: "Server present now but absent from the recorded baseline.",
		MitreATTACK: "T1195.002", MitreATLAS: "AML.T0010"},
	{ID: "MCP_SERVER_REMOVED", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "LOW",
		Title: "Baseline MCP Server Missing", Summary: "Server in the baseline no longer configured."},
	{ID: "MCP_TOOL_DESCRIPTION_POISONING", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "CRITICAL",
		Title: "Instruction Payload in MCP Tool Description", Summary: "Instruction-override phrase in a tool description delivered to the model every session.",
		MitreATLAS: "AML.T0110"},
	{ID: "MCP_WILDCARD_TOOL_PERMISSION", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "MEDIUM",
		Title: "Wildcard Permission Grants MCP Tools Without Prompting", Summary: "mcp__server__* style allow pattern.",
		MitreATTACK: "T1548"},
	{ID: "UNPINNED_MCP_PACKAGE", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "HIGH",
		Title: "MCP Server Package Not Pinned", Summary: "npx/uvx package launched without an exact version.",
		MitreATTACK: "T1195.002", MitreATLAS: "AML.T0010"},

	// ------------------------------------------------------------ provenance
	{ID: "INSTRUCTION_FILE_WRITTEN_BY_AGENT", Package: "provenance", Surface: "provenance", MaxSeverity: "INFO",
		Title: "Agent Wrote to Its Own Instruction File", Summary: "Provenance marker for instruction-file writes."},
	{ID: "INSTRUCTION_FROM_TOOL_RESULT", Package: "provenance", Surface: "provenance", MaxSeverity: "HIGH",
		Title: "Instruction Line Originated From Tool Output", Summary: "A line of CLAUDE.md/rules/settings was written from web, file or MCP output rather than a human prompt.",
		MitreATTACK: "T1547", MitreATLAS: "AML.T0080.000"},
	{ID: "INSTRUCTION_INJECTION_PHRASE", Package: "provenance", Surface: "provenance", MaxSeverity: "HIGH",
		Title: "Instruction File Contains an Override Phrase", Summary: "Injection phrase written into a persistent instruction file.",
		MitreATLAS: "AML.T0051"},
	{ID: "INSTRUCTION_WRITTEN_BY_SUBAGENT", Package: "provenance", Surface: "provenance", MaxSeverity: "MEDIUM",
		Title: "Subagent Modified a Persistent Instruction File", Summary: "A delegated agent, not the primary, changed standing instructions.",
		MitreATTACK: "T1562.001"},

	// ------------------------------------------------------------- correlate
	{ID: "ENDPOINT_CONTRADICTED_COMMAND", Package: "correlate", Surface: "endpoint", MaxSeverity: "HIGH",
		Title: "Transcript Command Not Seen by the Operating System", Summary: "OS telemetry covered the window but shows no matching process (CONTRADICTED).",
		MitreATTACK: "T1070"},
	{ID: "UNLOGGED_AGENT_ACTIVITY", Package: "correlate", Surface: "endpoint", MaxSeverity: "MEDIUM",
		Title: "Process Spawned by the Agent Has No Transcript Entry", Summary: "Endpoint shows agent-lineage processes with no transcript counterpart.",
		MitreATTACK: "T1070"},
	{ID: "UNLOGGED_AGENT_NETWORK", Package: "correlate", Surface: "endpoint", MaxSeverity: "HIGH",
		Title: "Agent Process Connected to a Destination Not in the Transcript", Summary: "Endpoint network record from an agent process with no transcript evidence.",
		MitreATTACK: "T1071"},
}

// ByID returns the catalog entry for id.
func ByID(id string) (Rule, bool) {
	for _, r := range Builtin {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}
