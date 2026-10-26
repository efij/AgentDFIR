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
		MitreATLAS: "AML.T0081", MitreATTACK: "T1685",
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
			{Name: "destructive action, logging shutdown or upload", FindingRules: []string{"DESTRUCTIVE_COMMAND", "CLOUD_DATA_DESTRUCTION", "CLOUD_RESOURCE_DELETION", "CLOUD_RECOVERY_PROTECTION_REMOVED", "DISK_WIPE", "LOG_DELETION", "AGENT_AUDIT_COVERAGE_LOSS"},
				Or: []Step{{EventTypes: []string{"tool_call"}, Upload: true}}},
		},
		MitreATLAS: "AML.T0081", MitreATTACK: "T1685",
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
}

// stagingIntoTemp: an archive written into a temp directory whose inputs
// are the working tree, the home directory, a git directory or a
// credential directory. `tar czf /tmp/src.tgz .` matches; `tar czf
// dist.tgz dist/` (a build artifact in the tree) does not.
const stagingIntoTemp = `(?i)(\btar\s+-?[a-z]*c[a-z]*\s+(-f\s*)?|\bzip\s+-[a-z]*r[a-z]*\s+(-q\s+)?|\b7z\s+a\s+)["']?(/tmp/|/var/tmp/|/dev/shm/|/private/tmp/|\$\{?TMPDIR\}?/|%TEMP%\\|\$env:TEMP\\)\S*\s+([^|;&\n]*\s)?["']?(\.|\./|~|~/|\$HOME|\$\{HOME\}|/Users/[^/\s]+/?|/home/[^/\s]+/?|\S*\.git|\S*\.ssh|\S*\.aws|\S*\.gnupg|\S*\.kube)["']?(\s|$)`
