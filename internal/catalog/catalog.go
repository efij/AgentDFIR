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
	// Class separates alerts from context.
	//
	// A building block describes something an agent does constantly — a
	// shell command ran, a commit was made, an MCP server is project-scoped.
	// It is input for the chain rules and background for an analyst, not a
	// thing to look at. Emitting them as ordinary findings buried the real
	// ones and inflated the ATT&CK coverage claim: SHELL_EXECUTION is INFO
	// and claimed T1059, MCP_PROJECT_SCOPED_SERVER is INFO, claimed T1195
	// and fired 54 times on one machine.
	//
	// Empty means "detection".
	Class string `json:"class,omitempty"`
}

// ClassBuildingBlock marks context rather than an alert.
const ClassBuildingBlock = "building_block"

// IsBuildingBlock reports whether a rule id is context rather than an alert.
func IsBuildingBlock(id string) bool {
	for _, r := range Builtin {
		if r.ID == id {
			return r.Class == ClassBuildingBlock
		}
	}
	return false
}

// Builtin lists every built-in rule. Keep sorted by package, then ID.
var Builtin = []Rule{
	// ----------------------------------------------------------------- chain
	{ID: "CHAIN_ACTION_THEN_LOG_TAMPER", Package: "chain", Surface: "transcript", MaxSeverity: "CRITICAL",
		Title: "Suspicious Action Followed by Deletion of Agent Logs", Summary: "Toxic combination: destructive/exfil action, then the agent's own logs targeted for deletion.",
		MitreATTACK: "T1070.004", MitreATLAS: "AML.T0101"},
	{ID: "CHAIN_CONTEXT_POISON_TO_EXEC", Package: "chain", Surface: "transcript", MaxSeverity: "CRITICAL",
		Title: "Untrusted Content Rewrote the Agent's Instructions, Then Code Ran", Summary: "Toxic combination: injection in a tool result → agent writes its own instructions/config → shell execution.",
		MitreATTACK: "T1059", MitreATLAS: "AML.T0080.000"},
	{ID: "CHAIN_DOWNLOAD_AND_EXECUTE", Package: "chain", Surface: "command", MaxSeverity: "MEDIUM",
		Title: "Agent Downloaded Content, Then Executed It", Summary: "Toxic combination: curl/wget followed by execution of a script or binary.",
		MitreATTACK: "T1105"},
	{ID: "CHAIN_INJECTION_TO_PUSH", Package: "chain", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Injected Instructions Followed by Code Pushed to a Remote", Summary: "Toxic combination: injection in a tool result → commit → push (supply-chain path).",
		MitreATTACK: "T1195.002", MitreATLAS: "AML.T0010"},
	{ID: "CHAIN_MCP_RESULT_TO_DESTRUCTIVE", Package: "chain", Surface: "transcript", MaxSeverity: "CRITICAL",
		Title: "Poisoned MCP Tool Result Followed by a Destructive Command", Summary: "Toxic combination: instruction content from an MCP tool → destructive command.",
		MitreATTACK: "T1485", MitreATLAS: "AML.T0099"},
	{ID: "CHAIN_ORPHAN_PERSISTENCE", Package: "chain", Surface: "transcript", MaxSeverity: "CRITICAL",
		Title: "Agent With No Verified Parent Changed Configuration, Then Acted", Summary: "Toxic combination: orphan agent → writes config/instructions → executes tools.",
		MitreATTACK: "T1562.001", MitreATLAS: "AML.T0081"},
	{ID: "CHAIN_SECRET_TO_EXFIL", Package: "chain", Surface: "transcript", MaxSeverity: "CRITICAL",
		Title: "Secret Material Accessed, Then Data Left the Host", Summary: "Toxic combination: credential/secret access → upload-shaped command or outbound connection.",
		MitreATTACK: "T1048", MitreATLAS: "AML.T0086"},
	{ID: "CHAIN_SUBAGENT_CROSS_TALK_EXFIL", Package: "chain", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Subagent Spawned, Talked Across Sessions, Then Data Left", Summary: "Toxic combination: spawn → cross-session message → outbound transfer.",
		MitreATTACK: "T1048", MitreATLAS: "AML.T0086"},
	// ---------------------------------------------------------------- detect
	{ID: "AGENT_CONTEXT_POISONING", Package: "detect", Surface: "config", MaxSeverity: "HIGH",
		Title: "Agent Context Poisoning Indicator", Summary: "Instruction-override phrase in standing agent instructions (CLAUDE.md, rules).",
		MitreATLAS: "AML.T0080.000"},
	{ID: "AGENT_GENERATED_COMMIT", Package: "detect", Surface: "command", MaxSeverity: "INFO",
		Title: "Agent Created a Commit", Summary: "Provenance marker: git commit executed by the agent.", Class: ClassBuildingBlock},
	{ID: "AGENT_GENERATED_PUSH", Package: "detect", Surface: "command", MaxSeverity: "LOW",
		Title: "Agent Pushed to a Remote", Summary: "git push executed by the agent; code left the host.", Class: ClassBuildingBlock},
	{ID: "AGENT_IDENTITY_MISMATCH", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Transcript Carries Multiple Session Identities", Summary: "One session file contains records from several sessions (splicing).",
		MitreATTACK: "T1565.001"},
	{ID: "AGENT_SELF_MODIFICATION", Package: "detect", Surface: "command", MaxSeverity: "HIGH",
		Title: "Agent Modified Its Own Configuration", Summary: "Write to the agent's own settings, hooks, instructions or MCP config.",
		MitreATTACK: "T1562.001", MitreATLAS: "AML.T0081"},
	{ID: "AGENT_SPAWN_EXPLOSION", Package: "detect", Surface: "transcript", MaxSeverity: "MEDIUM",
		Title: "Excessive Subagent Spawning", Summary: "Subagent spawns in one session exceed the threshold.",
		MitreATLAS: "AML.T0034.002"},
	{ID: "AI_CLI_HEADLESS_BYPASS", Package: "detect", Surface: "transcript", MaxSeverity: "MEDIUM",
		Title: "AI Agent CLI Run Headless With Approvals Disabled", Summary: "Shell history launches claude/codex/gemini/q/cursor-agent/copilot non-interactively with permission checks off (the s1ngularity shape).",
		MitreATTACK: "T1059", MitreATLAS: "AML.T0103"},
	{ID: "CROSS_SESSION_MESSAGE", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Cross-Agent Communication", Summary: "Message or resume interaction between agents/sessions."},
	{ID: "DESTRUCTIVE_COMMAND", Package: "detect", Surface: "command", MaxSeverity: "MEDIUM",
		Title: "Potentially Destructive Command", Summary: "rm -rf, mkfs, dd, fork bomb, force push.",
		MitreATTACK: "T1485", MitreATLAS: "AML.T0101"},
	{ID: "EGRESS_VIA_TRUSTED_SERVICE", Package: "detect", Surface: "command", MaxSeverity: "HIGH",
		Title: "Traffic Through a Trusted Service Used for Exfiltration", Summary: "Outbound request to a link shortener, screenshot service, serverless edge, blockchain RPC or tunnel; HIGH when upload-shaped or after credential access.",
		MitreATTACK: "T1567", MitreATLAS: "AML.T0086"},
	{ID: "GITHUB_EXFIL_REPO_CREATE", Package: "detect", Surface: "command", MaxSeverity: "MEDIUM",
		Title: "Agent Created a GitHub Repository or Gist", Summary: "gh repo/gist create or a POST to the GitHub repos/gists API \u2014 the exfil path of Shai-Hulud, s1ngularity and the keyv wave; LOW context, MEDIUM for a public repo after credential access.",
		MitreATTACK: "T1567.001", MitreATLAS: "AML.T0086"},
	{ID: "HEADLESS_AGENT_SECRET_HUNT", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Session Opened With an Instruction to Hunt for Secrets", Summary: "First user message tells the agent to search for wallets/keys/credential files and write the list to a file.",
		MitreATTACK: "T1552.001", MitreATLAS: "AML.T0055"},
	{ID: "INVISIBLE_UNICODE_INSTRUCTION", Package: "detect", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Invisible Unicode in Agent-Facing Content", Summary: "Unicode tag / bidi / zero-width characters smuggling instructions.",
		MitreATLAS: "AML.T0068"},
	{ID: "DOWNLOAD_THEN_EXECUTE", Package: "detect", Surface: "command", MaxSeverity: "HIGH",
		Title: "Downloaded File Executed", Summary: "curl/wget saved a file and the same command line ran it or made it executable.",
		MitreATTACK: "T1105", MitreATLAS: "AML.T0011.001"},
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
		MitreATTACK: "T1059", MitreATLAS: "AML.T0050", Class: ClassBuildingBlock},
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
	{ID: "UNEXPECTED_TASK", Package: "detect", Surface: "transcript", MaxSeverity: "LOW",
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
	{ID: "MCP_PACKAGE_TYPOSQUAT", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "HIGH",
		Title: "MCP Server Package Looks Like a Well-Known One", Summary: "Package is one edit, a scope swap or a look-alike character away from a widely installed MCP server (npm and PyPI).",
		MitreATTACK: "T1195.002", MitreATLAS: "AML.T0010.005"},
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
		MitreATTACK: "T1195", Class: ClassBuildingBlock},
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
	{ID: "MCP_TOOL_ADDED", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "LOW",
		Title: "MCP Server Declares New Tools Since Baseline", Summary: "Baseline drift: tools present now that the baseline did not record."},
	{ID: "MCP_TOOL_DEFINITION_CHANGED", Package: "mcpaudit", Surface: "mcp", MaxSeverity: "HIGH",
		Title: "MCP Tool Definition Changed Since Baseline", Summary: "MCP rug-pull: the SHA-256 of a tool's full declaration (description, inputSchema, annotations) differs from the baseline.",
		MitreATTACK: "T1195.002", MitreATLAS: "AML.T0110"},
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
	// ---------------------------------------------------------- rulepack
	{ID: "ENCODED_EXEC_UNRESOLVED", Package: "rulepack", Surface: "command", MaxSeverity: "MEDIUM",
		Title: "Encoded Data Run Through an Interpreter, Payload Not Recoverable", Summary: "A decode step is piped into an interpreter (or eval'd) but the payload is not in the command line.",
		MitreATTACK: "T1027", MitreATLAS: "AML.T0050"},
	{ID: "ENCODED_PAYLOAD_EXECUTED", Package: "rulepack", Surface: "command", MaxSeverity: "HIGH",
		Title: "Encoded Payload Decoded and Run", Summary: "Offline decoder (base64/base32/hex/gzip/zlib/bzip2/UTF-16LE/charcode, up to 4 layers) found a payload that a HIGH+ command rule flags.",
		MitreATTACK: "T1027", MitreATLAS: "AML.T0050"},
	// --------------------------------------------------------------- ioc
	{ID: "KNOWN_INCIDENT_IOC", Package: "ioc", Surface: "transcript", MaxSeverity: "CRITICAL",
		Title: "Indicator of a Known Incident", Summary: "A verified indicator from an embedded incident pack (s1ngularity, Shai-Hulud 1/2, keyv wave, SANDWORM_MODE, postmark-mcp, codexui-android, Amazon Q wiper) or an imported STIX/MISP feed, classified by where it was seen.",
		MitreATTACK: "T1195.002", MitreATLAS: "AML.T0010"},
	// ---------------------------------------------------------- reposcan
	{ID: "REPO_AGENT_CONFIG_HIDDEN_IN_REVIEW", Package: "reposcan", Surface: "config", MaxSeverity: "MEDIUM",
		Title: "Agent Configuration Hidden From Code Review", Summary: ".gitattributes marks agent config paths -diff / binary / linguist-generated so PR diffs hide them.",
		MitreATTACK: "T1564", MitreATLAS: "AML.T0081"},
	{ID: "REPO_AGENT_CONFIG_SYMLINK", Package: "reposcan", Surface: "config", MaxSeverity: "HIGH",
		Title: "Agent Configuration Is a Symbolic Link", Summary: "An agent config or instruction path in the repo is a symlink; targets inside the tree are scanned, outside ones never read.",
		MitreATTACK: "T1036", MitreATLAS: "AML.T0081"},
	{ID: "REPO_AGENT_ENV_OVERRIDE", Package: "reposcan", Surface: "config", MaxSeverity: "HIGH",
		Title: "Repository Settings Override the Agent's Environment", Summary: "Committed settings set ANTHROPIC_BASE_URL, NODE_OPTIONS, BASH_ENV, LD_PRELOAD or a proxy for everyone who opens the repo.",
		MitreATTACK: "T1574", MitreATLAS: "AML.T0081"},
	{ID: "REPO_AGENT_HOOK_AUTORUN", Package: "reposcan", Surface: "config", MaxSeverity: "CRITICAL",
		Title: "Repository Makes the Agent Run a Command Automatically", Summary: "Committed hook, statusLine, credential helper or project MCP command; CRITICAL when it runs at session start and touches the network, credentials or an encoded payload (keyv wave shape).",
		MitreATTACK: "T1546", MitreATLAS: "AML.T0081"},
	{ID: "REPO_AGENT_PERMISSION_WEAKENING", Package: "reposcan", Surface: "config", MaxSeverity: "HIGH",
		Title: "Repository Turns Off the Agent's Safety Prompts", Summary: "Committed bypassPermissions, Bash(*), enableAllProjectMcpServers, Copilot auto-approve or automatic tasks.",
		MitreATTACK: "T1562.001", MitreATLAS: "AML.T0081"},
	{ID: "REPO_CODEX_PROJECT_CONFIG", Package: "reposcan", Surface: "config", MaxSeverity: "HIGH",
		Title: "Repository Ships a Codex Configuration With Commands", Summary: "Project-local .codex/config.toml with MCP or notify commands (CVE-2025-61260 shape).",
		MitreATTACK: "T1546", MitreATLAS: "AML.T0081"},
	{ID: "REPO_CONFIG_UNPARSEABLE", Package: "reposcan", Surface: "config", MaxSeverity: "MEDIUM",
		Title: "Agent Auto-Run Configuration Could Not Be Parsed", Summary: "An autorun config is not valid JSON/JSONC; a file that breaks scanners but still loads is an evasion.",
		MitreATTACK: "T1027"},
	{ID: "REPO_DEVCONTAINER_HOST_COMMAND", Package: "reposcan", Surface: "config", MaxSeverity: "CRITICAL",
		Title: "Dev Container Runs a Command on the Host", Summary: "devcontainer initializeCommand runs on the host before the container exists; CRITICAL when risky.",
		MitreATTACK: "T1546", MitreATLAS: "AML.T0011"},
	{ID: "REPO_EXECUTABLE_PATH_OVERRIDE", Package: "reposcan", Surface: "config", MaxSeverity: "HIGH",
		Title: "Repository Points an Editor Tool at a File It Ships", Summary: "Workspace settings point an interpreter or tool path (python, git, eslint, terminal profile) at a file inside the repo.",
		MitreATTACK: "T1574", MitreATLAS: "AML.T0011"},
	{ID: "REPO_FILE_OVERSIZED", Package: "reposcan", Surface: "config", MaxSeverity: "MEDIUM",
		Title: "Agent Configuration File Larger Than the Scan Limit", Summary: "Agent config or instruction file exceeds the scan limit; the prefix is still checked.",
		MitreATTACK: "T1027"},
	{ID: "REPO_GIT_EXEC_CONFIG", Package: "reposcan", Surface: "config", MaxSeverity: "HIGH",
		Title: "Repository Git Config Runs a Command", Summary: ".git/config core.fsmonitor / hooksPath / sshCommand / askpass or a shell credential helper.",
		MitreATTACK: "T1546", MitreATLAS: "AML.T0011"},
	{ID: "REPO_GIT_REF_INJECTION", Package: "reposcan", Surface: "config", MaxSeverity: "HIGH",
		Title: "Branch or Tag Name Carries Shell Syntax", Summary: "Ref name with $( ` ; | & > \u2014 the Codex branch-name token-theft shape.",
		MitreATTACK: "T1059.004", MitreATLAS: "AML.T0011"},
	{ID: "REPO_INSTRUCTION_INJECTION", Package: "reposcan", Surface: "config", MaxSeverity: "CRITICAL",
		Title: "Instruction Override in a File the Agent Loads", Summary: "AGENTS.md / CLAUDE.md / rules files with injection phrases, invisible Unicode (tags = CRITICAL) or 'fetch this URL and follow it'.",
		MitreATTACK: "T1204", MitreATLAS: "AML.T0051.001"},
	{ID: "REPO_LIFECYCLE_SCRIPT_RISK", Package: "reposcan", Surface: "config", MaxSeverity: "MEDIUM",
		Title: "Install Script Does More Than Build", Summary: "package.json install/prepare scripts that download-and-run, touch credentials, decode payloads or call trusted-service egress.",
		MitreATTACK: "T1195.002", MitreATLAS: "AML.T0010"},
	{ID: "REPO_VSCODE_AUTORUN_TASK", Package: "reposcan", Surface: "config", MaxSeverity: "CRITICAL",
		Title: "Repository Runs a Task When the Folder Opens", Summary: ".vscode/tasks.json or .code-workspace task with runOn folderOpen (JSONC and per-OS commands parsed); CRITICAL when risky.",
		MitreATTACK: "T1546", MitreATLAS: "AML.T0011"},
	// ----------------------------------------------------------- journal
	{ID: "JOURNAL_TAMPERED", Package: "journal", Surface: "transcript", MaxSeverity: "CRITICAL",
		Title: "Monitor Journal Was Edited", Summary: "The monitor's hash-chained transcript journal does not verify, or the monitor found its previous journal broken at start.",
		MitreATTACK: "T1070"},
	{ID: "MONITOR_GAP", Package: "journal", Surface: "transcript", MaxSeverity: "INFO",
		Title: "Monitor Stopped Without Closing Its Journal", Summary: "A journal start record follows no stop record: the monitor was killed; changes in the gap are not journaled."},
	{ID: "TRANSCRIPT_DELETED", Package: "journal", Surface: "transcript", MaxSeverity: "INFO",
		Title: "Journaled Transcript Not in the Case", Summary: "A transcript the monitor journaled is not among the collected files.",
		MitreATTACK: "T1070.004"},
	{ID: "TRANSCRIPT_REPLACED", Package: "journal", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Transcript File Was Replaced While Monitored", Summary: "device:inode changed under a journaled transcript (atomic-rename rewrite).",
		MitreATTACK: "T1070"},
	{ID: "TRANSCRIPT_REWRITTEN", Package: "journal", Surface: "transcript", MaxSeverity: "CRITICAL",
		Title: "Transcript Differs From What the Monitor Recorded", Summary: "Collected transcript bytes no longer match the SHA-256 the monitor journaled when they were written.",
		MitreATTACK: "T1070", MitreATLAS: "AML.T0101"},
	{ID: "TRANSCRIPT_TRUNCATED", Package: "journal", Surface: "transcript", MaxSeverity: "HIGH",
		Title: "Transcript Is Shorter Than the Monitor Recorded", Summary: "Journaled transcript content is missing from the collected file, or the monitor saw it shrink.",
		MitreATTACK: "T1070"},
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
