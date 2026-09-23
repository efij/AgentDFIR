package chain

// Builtin chains ship with the binary. IDs are mirrored in internal/catalog
// (enforced by test) so `rules list` and the coverage matrix include them.
// Step predicates lean on existing findings where one exists, so a chain
// never re-implements a detection — it connects them.
// injectionPhrases mirrors the core of detect.InjectionPhrase for chains that
// must still work when the indicator finding was suppressed or truncated.
const injectionPhrases = `ignore (all )?(previous|prior|above) instructions|disregard (all )?(previous|prior) instructions|you must now|new system prompt|system note:|do not tell the user`

// selfConfigPaths are the agent's own instruction / configuration files.
const selfConfigPaths = `(^|/)(\.claude/(settings[^/]*\.json|hooks|agents|commands|skills|plugins)|CLAUDE\.md|AGENTS\.md|\.mcp\.json|\.claude\.json|\.codex/config\.toml|\.gemini/settings\.json|GEMINI\.md|\.cursor/(rules|mcp\.json)|\.cursorrules|\.copilot/(config|mcp-config)\.json|opencode/opencode\.json|\.aider\.conf\.yml)`

var Builtin = []Chain{
	{
		ID: "CHAIN_CONTEXT_POISON_TO_EXEC", Severity: "CRITICAL", Scope: "session", WindowMinutes: 120,
		Title:       "Untrusted Content Rewrote the Agent's Instructions, Then Code Ran",
		Description: "Instruction-override content arrived in a tool result, the agent then wrote to its own instruction or configuration files, and afterwards executed a shell command in the same session.",
		Steps: []Step{
			{Name: "injection in tool result", EventTypes: []string{"tool_result"}, FindingRules: []string{"PROMPT_INJECTION_INDICATOR", "MCP_TOOL_POISONING", "INVISIBLE_UNICODE_INSTRUCTION"},
				Or: []Step{{EventTypes: []string{"tool_result"}, TextRegex: injectionPhrases}}},
			{Name: "agent wrote its own instructions/config", FindingRules: []string{"AGENT_SELF_MODIFICATION", "INSTRUCTION_FILE_WRITTEN_BY_AGENT", "INSTRUCTION_FROM_TOOL_RESULT"},
				Or: []Step{{EventTypes: []string{"tool_call"}, FileRegex: selfConfigPaths}}},
			{Name: "shell command executed", EventTypes: []string{"tool_call"}, CommandRegex: `\S`},
		},
		MitreATLAS: "AML.T0080.000", MitreATTACK: "T1059",
		FalsePositive: "A developer knowingly pasting an instruction-like snippet into a file the agent then reads. Check who authored the tool result's source.",
	},
	{
		ID: "CHAIN_SECRET_TO_EXFIL", Severity: "CRITICAL", Scope: "session", WindowMinutes: 60,
		Title:       "Secret Material Accessed, Then Data Left the Host",
		Description: "The agent read credential material and, shortly after, ran an upload-shaped command or contacted a network destination.",
		Steps: []Step{
			{Name: "secret or credential file accessed", FindingRules: []string{"SECRET_ACCESS", "POTENTIAL_SECRET_EXPOSURE", "SENSITIVE_FILE_READ"}},
			// A network verb the shell actually runs — not a URL inside a
			// heredoc or a quoted string, and not an `nc -z` probe. Nine of
			// fifteen CRITICAL chains on a real machine had such a step.
			{Name: "upload or outbound connection", EventTypes: []string{"tool_call"}, Outbound: true},
		},
		MitreATLAS: "AML.T0086", MitreATTACK: "T1048",
		FalsePositive: "Legitimate deploys read a token and push. Confirm the destination against the allowlist (analyze --known-destinations).",
	},
	{
		ID: "CHAIN_ORPHAN_PERSISTENCE", Severity: "CRITICAL", Scope: "agent", WindowMinutes: 120,
		Title:       "Agent With No Verified Parent Changed Configuration, Then Acted",
		Description: "An agent that no spawn record explains modified agent configuration or instruction files and went on to execute tools.",
		Steps: []Step{
			{Name: "orphan agent appears", FindingRules: []string{"ORPHAN_AGENT"}},
			{Name: "orphan writes config/instructions", FindingRules: []string{"AGENT_SELF_MODIFICATION", "INSTRUCTION_FILE_WRITTEN_BY_AGENT", "INSTRUCTION_WRITTEN_BY_SUBAGENT"}},
			{Name: "orphan executes a tool", EventTypes: []string{"tool_call"}},
		},
		MitreATLAS: "AML.T0081", MitreATTACK: "T1562.001",
		FalsePositive: "Partial acquisition: the spawning session may simply not have been collected.",
	},
	{
		ID: "CHAIN_MCP_RESULT_TO_DESTRUCTIVE", Severity: "CRITICAL", Scope: "session", WindowMinutes: 60,
		Title:       "Poisoned MCP Tool Result Followed by a Destructive Command",
		Description: "An MCP tool returned instruction-override content and the agent then ran a destructive command in the same session.",
		Steps: []Step{
			{Name: "poisoned MCP tool result", EventTypes: []string{"tool_result"}, FindingRules: []string{"MCP_TOOL_POISONING", "TOOL_POISONING_INDICATOR", "PROMPT_INJECTION_INDICATOR"}},
			{Name: "destructive command", FindingRules: []string{"DESTRUCTIVE_COMMAND", "LOG_DELETION"}},
		},
		MitreATLAS: "AML.T0099", MitreATTACK: "T1485",
	},
	{
		ID: "CHAIN_INJECTION_TO_PUSH", Severity: "HIGH", Scope: "session", WindowMinutes: 180,
		Title:       "Injected Instructions Followed by Code Pushed to a Remote",
		Description: "Instruction-override content entered the session through a tool result and the agent later committed and pushed code: a supply-chain path.",
		Steps: []Step{
			{Name: "injection in tool result", EventTypes: []string{"tool_result"}, FindingRules: []string{"PROMPT_INJECTION_INDICATOR", "MCP_TOOL_POISONING", "INVISIBLE_UNICODE_INSTRUCTION"}},
			{Name: "commit created", FindingRules: []string{"AGENT_GENERATED_COMMIT"}},
			{Name: "pushed to remote", FindingRules: []string{"AGENT_GENERATED_PUSH"}},
		},
		MitreATLAS: "AML.T0010", MitreATTACK: "T1195.002",
		FalsePositive: "Review the diff of the pushed commit; the injection may not have influenced it.",
	},
	{
		ID: "CHAIN_DOWNLOAD_AND_EXECUTE", Severity: "MEDIUM", Scope: "session", WindowMinutes: 30,
		Title:       "Agent Downloaded Content, Then Executed It",
		Description: "A download command (curl/wget) was followed by execution of a script or binary in the same session.",
		Steps: []Step{
			{Name: "download", EventTypes: []string{"tool_call"}, CommandRegex: `(^|\s|;|&&|\|)(curl|wget)\s`},
			{Name: "execute", EventTypes: []string{"tool_call"}, CommandRegex: `(^|\s|;|&&|\|)(chmod\s+\+x|sh|bash|zsh|python3?|node|perl|ruby)\s`},
		},
		MitreATTACK:   "T1105",
		FalsePositive: "Package installers and build scripts do this legitimately. Check the download source.",
	},
	{
		ID: "CHAIN_ACTION_THEN_LOG_TAMPER", Severity: "CRITICAL", Scope: "session", WindowMinutes: 120,
		Title:       "Suspicious Action Followed by Deletion of Agent Logs",
		Description: "After a destructive or exfiltration-shaped action, the agent targeted its own transcripts or history for deletion: anti-forensics.",
		Steps: []Step{
			{Name: "destructive or exfil action", FindingRules: []string{"DESTRUCTIVE_COMMAND", "POTENTIAL_DATA_EXFILTRATION", "UNEXPECTED_NETWORK_DESTINATION", "CHAIN_SECRET_TO_EXFIL"}},
			{Name: "agent logs deleted", FindingRules: []string{"LOG_DELETION"}},
		},
		MitreATTACK: "T1070.004", MitreATLAS: "AML.T0101",
	},
	{
		ID: "CHAIN_SUBAGENT_CROSS_TALK_EXFIL", Severity: "HIGH", Scope: "session", WindowMinutes: 120,
		Title:       "Subagent Spawned, Talked Across Sessions, Then Data Left",
		Description: "A subagent was spawned, exchanged messages with an agent outside its session, and an outbound transfer followed.",
		Steps: []Step{
			{Name: "subagent spawned", EventTypes: []string{"agent_spawn"}},
			{Name: "cross-session message", FindingRules: []string{"CROSS_SESSION_MESSAGE", "UNEXPECTED_AGENT_RESUME"}},
			{Name: "outbound transfer", EventTypes: []string{"tool_call"}, Outbound: true},
		},
		MitreATLAS: "AML.T0086", MitreATTACK: "T1048",
	},
}
