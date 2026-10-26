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
			// Upload-shaped, not merely outbound: on a real machine "read
			// .env, later curl a README" was most of the CRITICALs.
			{Name: "upload-shaped command", EventTypes: []string{"tool_call"}, Upload: true},
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
			// A download that lands in a file: curl -o/-O, wget without -O-.
			// A header check, a status probe (-o /dev/null) or a response
			// read on stdout is not "downloaded content". On a real machine
			// the loose form was 165 findings, none a download-and-run.
			{Name: "download", EventTypes: []string{"tool_call"}, CommandRegex: `(\bcurl\b[^|;&\n]*\s(-[a-zA-Z]*O\b|--remote-name|(-o|--output)\s*["']?([^/\s"'-]|/([^d]|d[^e]|de[^v])))|\bwget\s+(-[a-zA-Z]*\s+)*[^-\s])`},
			// Running a file: `bash x.sh`, `./x`, `chmod +x`. `python3 -c …`
			// and `python3 - <<EOF` run inline code, not a download.
			{Name: "execute", EventTypes: []string{"tool_call"}, CommandRegex: `(chmod\s+\+x|(^|\s|;|&&|\|)(sh|bash|zsh|python3?|node|perl|ruby)\s+[^-\s<|&;]|(^|\s|;|&&|\|)\./[A-Za-z0-9_])`},
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
	// v4 (docs/detection-v4.md): combinations no earlier chain covers.
	{
		ID: "CHAIN_CROSS_TOOL_EXFIL", Severity: "HIGH", Scope: "session", WindowMinutes: 60,
		Title:       "Credential Material Collected, Then Sent Out Through an MCP Tool",
		Description: "The agent collected credential material (a credential store, a private key, a staged or archived secret, a planted canary, or a secrets MCP tool) and then called an MCP tool that sends, posts or publishes. CHAIN_SECRET_TO_EXFIL watches shell uploads; this is the same story through a different tool, which a shell-only rule never sees. A possible exfiltration path: the MCP call's arguments are not in the transcript events, so what was sent is unconfirmed.",
		Steps: []Step{
			{Name: "credential material collected", FindingRules: []string{"SECRET_ACCESS", "AGENT_SENSITIVE_DATA_STAGING", "AGENT_CREDENTIAL_STORE_ACCESS", "SSH_PRIVATE_KEY_READ", "CREDENTIAL_DIR_ARCHIVE", "CLOUD_CREDENTIAL_EXPORT", "BROWSER_CREDENTIAL_ACCESS", "KUBE_SECRET_DUMP"},
				Or: []Step{{EventTypes: []string{"tool_call"}, MCP: true, ToolRegex: `(secret|credential|password|passwd|vault|keychain|1password|bitwarden)`}}},
			{Name: "MCP tool that sends data out", EventTypes: []string{"tool_call"}, MCP: true, ToolRegex: `(send|post|upload|publish|comment|message|e?mail|gist|webhook|share|tweet|paste|put_object|issue)`},
		},
		MitreATLAS: "AML.T0086", MitreATTACK: "T1567",
		FalsePositive: "An agent asked to file an issue or post a message after rotating a key. Open the MCP call's raw transcript line to see what it carried.",
	},
	{
		ID: "CHAIN_MCP_RESULT_TO_PRIVILEGED", Severity: "HIGH", Scope: "session", WindowMinutes: 60,
		Title:       "Instructions in an MCP Tool Result, Then Credentials Touched or Data Sent",
		Description: "An MCP tool returned instruction-override content, and the agent then read credential material, widened its own permissions or ran an upload-shaped command in the same session. CHAIN_MCP_RESULT_TO_DESTRUCTIVE covers the destructive follow-up; this covers the privileged ones. The order is recorded; that the result caused the action is possible, not proven.",
		Steps: []Step{
			{Name: "instructions in an MCP tool result", EventTypes: []string{"tool_result"}, FindingRules: []string{"MCP_TOOL_POISONING", "TOOL_POISONING_INDICATOR", "PROMPT_INJECTION_INDICATOR"}},
			{Name: "privileged action", FindingRules: []string{"SENSITIVE_FILE_READ", "AGENT_CREDENTIAL_STORE_ACCESS", "SSH_PRIVATE_KEY_READ", "CLOUD_CREDENTIAL_EXPORT", "AGENT_SENSITIVE_DATA_STAGING", "AGENT_TOOL_PERMISSION_ESCALATION", "NESTED_AGENT_PERMISSION_BYPASS"},
				Or: []Step{{EventTypes: []string{"tool_call"}, Upload: true}}},
		},
		MitreATLAS: "AML.T0099", MitreATTACK: "T1552",
		FalsePositive: "A documentation tool that quotes injection examples, followed by unrelated credential work the person asked for. Read the tool result.",
	},
	{
		ID: "CHAIN_PERMISSION_ESCALATION_TO_IMPACT", Severity: "HIGH", Scope: "session", WindowMinutes: 120,
		Title:       "Permissions Widened, Then Something Destructive or an Upload Ran",
		Description: "The session's permissions widened (bypass mode entered, the agent granted itself tools, a nested agent launched with checks off, or a denied tool ran) and a destructive command, a logging shutdown or an upload followed. The widening is what let the later action run without a person approving it.",
		Steps: []Step{
			{Name: "permissions widened", FindingRules: []string{"AGENT_TOOL_PERMISSION_ESCALATION", "NESTED_AGENT_PERMISSION_BYPASS", "AGENT_PERMISSION_BOUNDARY_CROSSING"}},
			// v5: cloud mutations through the CLIs (deletions, IAM grants,
			// updates) complete the chain too, so a widened session that
			// changes a cloud account is one story with the widening.
			{Name: "destructive action, logging shutdown or upload", FindingRules: []string{"DESTRUCTIVE_COMMAND", "CLOUD_DATA_DESTRUCTION", "CLOUD_RESOURCE_DELETION", "CLOUD_RECOVERY_PROTECTION_REMOVED", "DISK_WIPE", "LOG_DELETION", "AGENT_AUDIT_COVERAGE_LOSS"},
				Or: []Step{{EventTypes: []string{"tool_call"}, Upload: true},
					{FindingRules: []string{"CLOUD_IAM_PERSISTENCE"}},
					{EventTypes: []string{"tool_call"}, CommandRegex: cloudMutation}}},
		},
		MitreATLAS: "AML.T0081", MitreATTACK: "T1562.001",
		FalsePositive: "A person running a cleanup in bypass mode on purpose. Ask who switched the mode and whether the follow-up was the task.",
	},
	// v4.5 (docs/detection-v45.md): transfer routes the earlier chains do
	// not see. CHAIN_SECRET_TO_EXFIL's upload step is curl/scp/rsync-shaped,
	// so object-storage copies and git pushes never completed it.
	{
		ID: "CHAIN_STAGED_DATA_TO_TRANSFER", Severity: "HIGH", Scope: "session", WindowMinutes: 60,
		Title:       "Data Staged Into an Archive or Temp File, Then Copied Off the Host",
		Description: "The agent collected data into a staging file (a credential directory archived, a credential file encoded into a temp directory, a database dumped, or the project or home directory archived into a temp directory) and then copied something to object storage, a remote host, a paste or webhook service, or pushed to a URL remote. The order is recorded; that the staged file is what left is possible, not proven: commands name paths, not contents.",
		Steps: []Step{
			{Name: "data staged", FindingRules: []string{"CREDENTIAL_DIR_ARCHIVE", "AGENT_SENSITIVE_DATA_STAGING", "DATABASE_DUMP"},
				Or: []Step{{EventTypes: []string{"tool_call"}, CommandRegex: stagingIntoTemp}}},
			{Name: "copied off the host", FindingRules: []string{"CLOUD_STORAGE_UPLOAD", "REMOTE_COPY_TO_HOST", "CURL_FILE_UPLOAD", "GIT_PUSH_TO_URL", "PASTE_SITE_DESTINATION", "WEBHOOK_C2_EXFIL"},
				Or: []Step{{EventTypes: []string{"tool_call"}, Upload: true}}},
		},
		MitreATLAS: "AML.T0086", MitreATTACK: "T1567",
		FalsePositive: "A release or backup job asked of the agent: archive, then upload to the organization's bucket. Check the destination bucket or host.",
	},
	{
		ID: "CHAIN_SECRET_TO_NEW_REMOTE_PUSH", Severity: "HIGH", Scope: "session", WindowMinutes: 120,
		Title:       "Sensitive Data Read, New git Remote or Repository Created, Then Pushed",
		Description: "The agent read credential or sensitive material, then configured a git remote or created a repository or gist, then pushed. A repository the project never used is a transfer channel that looks like ordinary work. The push's contents are not in the transcript: what was pushed is unconfirmed.",
		Steps: []Step{
			{Name: "sensitive data read", FindingRules: []string{"SENSITIVE_FILE_READ", "SECRET_ACCESS", "AGENT_SENSITIVE_DATA_STAGING", "CREDENTIAL_DIR_ARCHIVE", "SSH_PRIVATE_KEY_READ", "DATABASE_DUMP", "CLOUD_CREDENTIAL_EXPORT", "KUBE_SECRET_DUMP", "AGENT_CREDENTIAL_STORE_ACCESS"}},
			{Name: "new remote or repository", FindingRules: []string{"GIT_REMOTE_ADDED", "GITHUB_EXFIL_REPO_CREATE"},
				Or: []Step{{EventTypes: []string{"tool_call"}, CommandRegex: `\bgit\s+remote\s+(add|set-url)\s|\bgh\s+(repo\s+create|gist\s+create)\b`}}},
			{Name: "pushed", FindingRules: []string{"AGENT_GENERATED_PUSH", "GIT_PUSH_TO_URL"},
				Or: []Step{{EventTypes: []string{"tool_call"}, CommandRegex: `\bgit\s+push\b`}}},
		},
		MitreATLAS: "AML.T0086", MitreATTACK: "T1567.001",
		FalsePositive: "Setting up a fork after reading a project's .env for configuration. Check the new remote's owner.",
	},
	// v5 (docs/attack-chains.md): linked chains. Each names what its steps
	// share, so a match says why the events belong together. Steps citing
	// MCP_TOOL_IDENTITY_DRIFT, AGENT_AUTONOMOUS_RECON_SEQUENCE,
	// AGENT_SKILL_SUPPLY_CHAIN_CHANGE or AGENT_CREDENTIAL_TO_EXTERNAL_TOOL
	// build on v5 detection rules; finding_rules are not checked against
	// the catalog, so a chain naming one still validates without it.
	{
		ID: "CHAIN_SKILL_POISON_TO_EXEC", Severity: "HIGH", Scope: "case", Link: LinkSkill, WindowMinutes: 1440,
		Title:       "Skill Written From an Untrusted Source, Then Loaded and Followed by a Command",
		Description: "A skill's files were written with content that came from a tool result, a subagent, a hidden-instruction pattern or an unbaselined change; later the same skill was invoked or read (by any agent in the case), and the agent that loaded it then ran a shell command. The order and the shared skill are recorded; that the skill caused the command is possible, not proven.",
		Steps: []Step{
			{Name: "skill written from an untrusted source", FileRegex: skillDir,
				FindingRules: []string{"INSTRUCTION_FROM_TOOL_RESULT", "INSTRUCTION_INJECTION_PHRASE", "INSTRUCTION_WRITTEN_BY_SUBAGENT", "SKILL_HIDDEN_INSTRUCTIONS", "AGENT_SKILL_SUPPLY_CHAIN_CHANGE", "MCP_TOOL_POISONING", "INVISIBLE_UNICODE_INSTRUCTION"}},
			{Name: "same skill invoked or read", EventTypes: []string{"tool_call"}, Tools: []string{"Skill"},
				Or: []Step{{EventTypes: []string{"tool_call"}, Tools: readTools, FileRegex: skillDir}}},
			{Name: "the loading agent ran a command", EventTypes: []string{"tool_call"}, CommandRegex: `\S`, Link: LinkAgent},
		},
		MitreATLAS: "AML.T0110", MitreATTACK: "T1059",
		FalsePositive: "A person asking the agent to write a skill from documentation it fetched, then using it. Sequence is not causation: read the skill's diff and the command.",
	},
	{
		ID: "CHAIN_MCP_RUG_PULL_TO_ACTION", Severity: "HIGH", Scope: "session", Link: LinkMCPTool, WindowMinutes: 120,
		Title:       "MCP Tool Changed Under the Agent, Was Called Again, Then a Consequential Action Followed",
		Description: "An MCP tool's definition or its server's identity changed (a different tool-definition digest or serverInfo between calls, or a definition that differs from the baseline), the agent then called that same tool, and the same agent went on to read credentials, change permissions, delete, push or upload. Config-baseline findings take part only when they cite an event; a single call to the changed tool with nothing after it does not complete the chain.",
		Steps: []Step{
			{Name: "MCP tool definition or server identity changed", FindingRules: []string{"MCP_TOOL_IDENTITY_DRIFT", "MCP_TOOL_DEFINITION_CHANGED", "MCP_SERVER_CHANGED"}},
			{Name: "changed tool called", EventTypes: []string{"tool_call"}, MCP: true,
				Or: []Step{{EventTypes: []string{"tool_call"}, ToolRegex: `^mcp__`}}},
			{Name: "consequential action", FindingRules: consequentialRules, Link: LinkAgent,
				Or: []Step{{EventTypes: []string{"tool_call"}, Upload: true}, {EventTypes: []string{"tool_call"}, CommandRegex: cloudMutation}}},
		},
		MitreATLAS: "AML.T0109", MitreATTACK: "T1195.002",
		FalsePositive: "A server upgrade that rewords a tool, followed by work the person asked for. Diff the two tool definitions; sequence is not causation.",
	},
	{
		ID: "CHAIN_TOOL_RESPONSE_TO_SECRET_EXFIL", Severity: "CRITICAL", Scope: "session", WindowMinutes: 60,
		Title:       "Instructions in a Tool Response, Then Credentials Read, Then Data Sent Out",
		Description: "A tool response carried instruction-override content (or an instruction file was written from tool output), the agent then read credential material, and data left the host: an upload-shaped command, an object-storage or remote copy, a paste or webhook destination, or an MCP tool that sends. CHAIN_MCP_RESULT_TO_PRIVILEGED and CHAIN_SECRET_TO_EXFIL each see two of these steps; this is the whole path. What was sent is not in the transcript; the order is recorded, causation is not.",
		Steps: []Step{
			{Name: "instructions in a tool response", EventTypes: []string{"tool_result"}, FindingRules: []string{"MCP_TOOL_POISONING", "TOOL_POISONING_INDICATOR", "PROMPT_INJECTION_INDICATOR", "INVISIBLE_UNICODE_INSTRUCTION"},
				Or: []Step{{FindingRules: []string{"INSTRUCTION_FROM_TOOL_RESULT"}}, {EventTypes: []string{"tool_result"}, TextRegex: injectionPhrases}}},
			{Name: "credential material read", FindingRules: credentialRules,
				Or: []Step{{EventTypes: []string{"tool_call"}, MCP: true, ToolRegex: `(secret|credential|password|passwd|vault|keychain|1password|bitwarden)`}}},
			{Name: "data sent off the host", FindingRules: []string{"CLOUD_STORAGE_UPLOAD", "REMOTE_COPY_TO_HOST", "CURL_FILE_UPLOAD", "GIT_PUSH_TO_URL", "PASTE_SITE_DESTINATION", "WEBHOOK_C2_EXFIL", "POTENTIAL_DATA_EXFILTRATION", "AGENT_CREDENTIAL_TO_EXTERNAL_TOOL"},
				Or: []Step{{EventTypes: []string{"tool_call"}, Upload: true}, {EventTypes: []string{"tool_call"}, MCP: true, ToolRegex: mcpSendTools}}},
		},
		MitreATLAS: "AML.T0110.002", MitreATTACK: "T1567",
		FalsePositive: "A documentation page quoting injection examples, followed by a deploy the person asked for; sequence is not causation. Check the destination and whether the person asked for the credential work.",
	},
	{
		ID: "CHAIN_SHARED_MEMORY_TO_SUBAGENT", Severity: "MEDIUM", Scope: "case", Link: LinkFile, WindowMinutes: 1440,
		Title:       "One Agent Wrote a Shared Instruction File, Another Read It and Acted",
		Description: "An agent wrote a shared instruction or memory file (CLAUDE.md, AGENTS.md, a memory or rules file, an agent definition); a different agent or subagent, in any session of the case, later read that same file and then ran a command, called an MCP tool or wrote a file. Files an agent loads at start-up without a read tool call are not recorded as reads and cannot complete this chain. Order and the shared file are recorded; influence is not.",
		Steps: []Step{
			{Name: "agent wrote a shared instruction file", EventTypes: []string{"tool_call"}, Tools: writeTools, FileRegex: sharedInstructionPaths,
				Or: []Step{{FindingRules: []string{"INSTRUCTION_WRITTEN_BY_SUBAGENT", "INSTRUCTION_FILE_WRITTEN_BY_AGENT", "INSTRUCTION_FROM_TOOL_RESULT"}, FileRegex: sharedInstructionPaths}}},
			{Name: "a different agent read the same file", EventTypes: []string{"tool_call"}, Tools: readTools, FileRegex: sharedInstructionPaths, DifferentAgent: true},
			{Name: "the reader acted", EventTypes: []string{"tool_call"}, CommandRegex: `\S`, Link: LinkAgent,
				Or: []Step{{EventTypes: []string{"tool_call"}, MCP: true}, {EventTypes: []string{"tool_call"}, Tools: writeTools}}},
		},
		MitreATLAS: "AML.T0118.000", MitreATTACK: "T1080",
		FalsePositive: "Multi-agent setups coordinate through shared notes by design, and sequence is not causation. Read what the writer added and whether the reader's action follows from it.",
	},
	{
		ID: "CHAIN_BROWSER_TOKEN_TO_ACCOUNT_ACTION", Severity: "HIGH", Scope: "session", WindowMinutes: 60,
		Title:       "Browser Cookies or Saved Credentials Read, Then an Authenticated Account Action",
		Description: "The agent read a browser cookie or credential store and the same agent then sent an authenticated request (curl/wget/httpie with a cookie or Authorization header) or changed an account through the gh or cloud CLIs. Which token the request carried is not in the transcript; the order is recorded, causation is not.",
		Steps: []Step{
			{Name: "browser cookie or credential store read", FindingRules: []string{"BROWSER_CREDENTIAL_ACCESS"},
				Or: []Step{{EventTypes: []string{"tool_call"}, CommandRegex: browserStores}, {EventTypes: []string{"tool_call"}, FileRegex: browserStores}}},
			{Name: "authenticated request or account change", EventTypes: []string{"tool_call"}, CommandRegex: authenticatedRequest, Link: LinkAgent,
				Or: []Step{{EventTypes: []string{"tool_call"}, CommandRegex: ghMutation}, {EventTypes: []string{"tool_call"}, CommandRegex: cloudMutation}}},
		},
		MitreATLAS: "AML.T0113", MitreATTACK: "T1550.004",
		FalsePositive: "Debugging a web app with an exported session cookie the person handed over. Ask whether the person asked for the cookie to be used, and against which service.",
	},
	{
		ID: "CHAIN_AGENT_RECON_TO_IMPACT", Severity: "HIGH", Scope: "session", Link: LinkTarget, WindowMinutes: 120,
		Title:       "Agent Enumerated a Target, Then Destroyed or Changed That Same Target",
		Description: "The agent ran discovery (an autonomous recon sequence, agent-config discovery, a port scan, or cloud, Kubernetes or find enumeration) and then ran a destructive or privileged action against a target named in that discovery: the same cloud resource ID, bucket URI, absolute path or host. Targets are compared exactly; a path under a listed directory is a different target. Discovery is routine; the shared target is what joins the two.",
		Steps: []Step{
			{Name: "discovery", FindingRules: []string{"AGENT_AUTONOMOUS_RECON_SEQUENCE", "AGENT_CONFIG_DISCOVERY", "NETWORK_PORT_SCAN"},
				Or: []Step{{EventTypes: []string{"tool_call"}, CommandRegex: discoveryCommand}}},
			{Name: "destructive or privileged action on the discovered target", FindingRules: []string{"DESTRUCTIVE_COMMAND", "CLOUD_DATA_DESTRUCTION", "CLOUD_RESOURCE_DELETION", "CLOUD_RECOVERY_PROTECTION_REMOVED", "CLOUD_IAM_PERSISTENCE", "DISK_WIPE"},
				Or: []Step{{EventTypes: []string{"tool_call"}, CommandRegex: cloudMutation}, {EventTypes: []string{"tool_call"}, CommandRegex: `\bkubectl\s+(delete|drain|scale|patch|replace)\b`}}},
		},
		MitreATLAS: "AML.T0116", MitreATTACK: "T1485",
		FalsePositive: "Listing a bucket or namespace before the cleanup the person asked for. Recon can be legitimate and sequence is not causation; check the instruction before the action.",
	},
	{
		ID: "CHAIN_ADAPTIVE_RETRY_TO_BYPASS", Severity: "HIGH", Scope: "session", Link: LinkTarget, WindowMinutes: 30,
		Title:       "State Change Refused or Failed, Then a Different Method Succeeded on the Same Target",
		Description: "A state-changing call was denied (recorded result or approval decision) or failed, and the agent then reached the same target with a different tool or program, and that call recorded success. AGENT_UNEXPECTED_AUTONOMOUS_RETRY covers the same action repeated; this is the route around the refusal. It needs recorded outcomes: a call with no recorded status never matches, and completion is never read as approval.",
		Steps: []Step{
			{Name: "state change denied or failed", EventTypes: []string{"tool_call"}, ResultStatus: []string{"denied", "error"}, CommandRegex: stateChangingCommand,
				Or: stateChangingAlternatives(Step{ResultStatus: []string{"denied", "error"}}, Step{ApprovalState: []string{"denied"}})},
			{Name: "different method succeeded on the same target", EventTypes: []string{"tool_call"}, ResultStatus: []string{"ok"}, CommandRegex: stateChangingCommand, DifferentMethod: true,
				Or: stateChangingAlternatives(Step{ResultStatus: []string{"ok"}})},
		},
		MitreATLAS:    "AML.T0117",
		FalsePositive: "A tool that fails for a mundane reason (a missing flag, a locked file) and a correct second attempt. A failure is not a refusal: read the first call's result before calling it a bypass.",
	},
}

// v5 vocabularies shared by the linked chains.
var (
	writeTools = []string{"Write", "Edit", "MultiEdit", "NotebookEdit", "apply_patch", "write_file", "edit_file", "replace"}
	readTools  = []string{"Read", "read_file", "read_many_files", "view"}
	// credentialRules are findings that say credential material was read.
	credentialRules = []string{"SECRET_ACCESS", "SENSITIVE_FILE_READ", "AGENT_CREDENTIAL_STORE_ACCESS", "SSH_PRIVATE_KEY_READ", "CLOUD_CREDENTIAL_EXPORT", "BROWSER_CREDENTIAL_ACCESS", "KUBE_SECRET_DUMP", "CREDENTIAL_DIR_ARCHIVE", "AGENT_SENSITIVE_DATA_STAGING"}
	// consequentialRules: an action with effect beyond the session —
	// credentials, permissions, destruction, publication, transfer.
	consequentialRules = append(append([]string{}, credentialRules...),
		"DESTRUCTIVE_COMMAND", "CLOUD_DATA_DESTRUCTION", "CLOUD_RESOURCE_DELETION", "CLOUD_IAM_PERSISTENCE", "DISK_WIPE", "LOG_DELETION",
		"AGENT_SELF_MODIFICATION", "AGENT_TOOL_PERMISSION_ESCALATION", "AGENT_GENERATED_PUSH", "GIT_PUSH_TO_URL", "CURL_FILE_UPLOAD",
		"CLOUD_STORAGE_UPLOAD", "REMOTE_COPY_TO_HOST", "AGENT_CREDENTIAL_TO_EXTERNAL_TOOL", "AGENT_UNAUTHORIZED_RESOURCE_CHANGE")
)

// stateChangingAlternatives returns, for each status predicate, the write
// tool, MCP and shell forms of a state-changing call carrying it. The
// shell form under the first predicate is the step itself.
func stateChangingAlternatives(status ...Step) []Step {
	var out []Step
	for i, st := range status {
		for _, shape := range []Step{
			{CommandRegex: stateChangingCommand},
			{Tools: writeTools},
			{MCP: true, ToolRegex: `(write|create|update|delete|remove|send|post|put|push|exec|run|deploy|merge|upload|move|rename)`},
		} {
			if i == 0 && shape.CommandRegex != "" {
				continue
			}
			shape.EventTypes = []string{"tool_call"}
			shape.ResultStatus, shape.ApprovalState = st.ResultStatus, st.ApprovalState
			out = append(out, shape)
		}
	}
	return out
}

const (
	// skillDir: any file inside a skill directory (.claude/skills/<name>/,
	// a plugin's skills/<name>/, .codex/skills/<name>/).
	skillDir = `(^|/)skills/[^/]+/`
	// sharedInstructionPaths: standing instructions and memory one agent
	// can leave for another.
	sharedInstructionPaths = `((^|/)(CLAUDE|AGENTS|GEMINI|MEMORY|memory)\.md$|(^|/)(\.cursorrules|\.windsurfrules|\.clinerules|copilot-instructions\.md)$|(^|/)(\.claude/(agents|commands|memory|rules)|\.cursor/rules|\.github/instructions|\.memory|memory)/)`
	mcpSendTools           = `(send|post|upload|publish|comment|message|e?mail|gist|webhook|share|tweet|paste|put_object|issue)`
	// browserStores: a browser profile's cookie, login or key store.
	browserStores = `((Google/Chrome|Chromium|BraveSoftware|Microsoft/Edge|Microsoft Edge|Vivaldi|Opera|Arc/User Data|Firefox/Profiles|\.mozilla/firefox|Library/Cookies)[^|;&\n]*(Cookies|Login Data|Local State|logins\.json|key4\.db|cookies\.sqlite|\.binarycookies)|Cookies\.binarycookies)`
	// authenticatedRequest: an HTTP client sending a cookie or a bearer.
	authenticatedRequest = `\b(curl|wget|http|https|xh)\b[^|;&\n]*(\s(-b|--cookie|--load-cookies)[\s=]|(-H|--header)[\s=]*["']?(cookie|authorization|x-api-key|private-token|x-auth-token|x-csrf-token)\s*:|\s--oauth2-bearer\s)`
	// ghMutation: a gh call that changes something on the account.
	ghMutation = `\bgh\s+(api\s+[^|;&\n]*(-X|--method)\s*(POST|PUT|PATCH|DELETE)\b|repo\s+(create|delete|edit|fork|rename)\b|pr\s+(create|merge|close|edit|review)\b|issue\s+(create|close|edit|comment|delete)\b|release\s+(create|delete|upload|edit)\b|secret\s+(set|delete)\b|gist\s+create\b|workflow\s+run\b|ssh-key\s+add\b|auth\s+refresh\b)`
	// cloudMutation: aws/gcloud/gsutil/az calls that create, change or
	// delete; list/describe/get calls do not match.
	cloudMutation = `(\baws\s+[a-z0-9-]+\s+(delete|put|create|update|attach|detach|modify|terminate|remove|disable|revoke|authorize|stop|deregister|schedule-key-deletion)-[a-z0-9-]+|\baws\s+s3\s+(rm|rb|mv)\b|\bgcloud\s+([a-z0-9-]+\s+){1,4}(delete|create|update|deploy|add-iam-policy-binding|remove-iam-policy-binding|set-iam-policy|disable)\b|\bgsutil\s+(rm|rb|iam\s+ch|acl\s+ch)\b|\baz\s+([a-z0-9-]+\s+){1,4}(delete|create|update|set|purge)\b)`
	// discoveryCommand: enumeration of cloud, cluster, network or a
	// directory tree. Plain ls/stat are too common to count.
	discoveryCommand = `(\bfind\s+[/~]|\baws\s+[a-z0-9-]+\s+(list|describe|get)-[a-z0-9-]+|\baws\s+s3\s+ls\b|\bgcloud\s+([a-z0-9-]+\s+){1,4}(list|describe)\b|\bgsutil\s+ls\b|\baz\s+([a-z0-9-]+\s+){1,4}(list|show)\b|\bkubectl\s+(get|describe)\b|\b(nmap|masscan)\b)`
	// stateChangingCommand: a shell call that deletes, moves, overwrites,
	// changes permissions, pushes or mutates a remote system.
	stateChangingCommand = `(\b(rm|rmdir|mv|cp|chmod|chown|chattr|dd|truncate|shred|unlink|tee|install|ln)\s|\bsed\s+-i|\bfind\b[^|;&\n]*\s-(delete|exec)\b|\bgit\s+(push|reset|clean|checkout|commit|rebase|filter-branch)\b|\bkubectl\s+(delete|apply|patch|scale|replace|drain)\b|\bterraform\s+(apply|destroy|import|state\s+rm)\b|\bcurl\b[^|;&\n]*(-X|--request)\s*(POST|PUT|DELETE|PATCH)\b|\b(DROP|TRUNCATE|DELETE\s+FROM|UPDATE\s+\w+\s+SET)\b|[^<>2&]>\s*[^&\s>]|` + cloudMutation + `)`
)

// stagingIntoTemp: an archive written into a temp directory whose inputs
// are the working tree, the home directory, a git directory or a
// credential directory. `tar czf /tmp/src.tgz .` matches; `tar czf
// dist.tgz dist/` (a build artifact in the tree) does not.
const stagingIntoTemp = `(?i)(\btar\s+-?[a-z]*c[a-z]*\s+(-f\s*)?|\bzip\s+-[a-z]*r[a-z]*\s+(-q\s+)?|\b7z\s+a\s+)["']?(/tmp/|/var/tmp/|/dev/shm/|/private/tmp/|\$\{?TMPDIR\}?/|%TEMP%\\|\$env:TEMP\\)\S*\s+([^|;&\n]*\s)?["']?(\.|\./|~|~/|\$HOME|\$\{HOME\}|/Users/[^/\s]+/?|/home/[^/\s]+/?|\S*\.git|\S*\.ssh|\S*\.aws|\S*\.gnupg|\S*\.kube)["']?(\s|$)`
