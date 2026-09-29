package mitigate

// Mode says what can be done about a rule's findings.
//
// The case is cumulative: every scan re-reads every transcript ever
// collected, so a finding about a command that ran in March fires in every
// scan for the life of the case. Only findings about the present state of
// a file go away when the file is fixed. Everything else is permanent
// evidence, and the honest measure of progress is "none since the
// guardrail went in".
type Mode string

const (
	// Fix: the finding is about a file that is in that state right now.
	// Edit it and the finding is gone next scan.
	Fix Mode = "fix"
	// Prevent: the finding is about something the agent already did. A
	// guardrail stops the next one; the count since it went in shows it.
	Prevent Mode = "prevent"
	// Manual: past behaviour with no config control. A person acts.
	Manual Mode = "manual"
	// None: evidence quality, not agent behaviour. Better collection helps.
	None Mode = "none"
)

// fixRules fire on the present state of a config file this package edits.
var fixRules = map[string]string{
	"UNPINNED_MCP_PACKAGE": "mcp-pin",
	"MCP_UNPINNED_PACKAGE": "mcp-pin",
	"MCP_AUTO_APPROVE":     "mcp-autoapprove",
	"MCP_AUTO_APPROVE_ALL": "mcp-autoapprove",
}

// noneRules describe the evidence, not the agent. No config removes an
// orphan from a transcript that already exists.
var noneRules = map[string]string{
	"ORPHAN_AGENT":                  "Collect the parent session too (agentdfir run collects every agent on the machine); orphans are often a parent transcript that was never copied.",
	"AGENT_IDENTITY_MISMATCH":       "Collect every agent profile on the machine so the identity can be matched.",
	"UNEXPECTED_AGENT_RESUME":       "Review the session; resuming is normal, resuming someone else's is not.",
	"TIMESTOMP_INDICATOR":           "Add endpoint logs (--endpoint) so file times have an independent witness.",
	"MCP_GATEWAY_BACKEND_ERRORS":    "Check the MCP gateway's backend health; this is about the gateway, not the agent.",
	"MCP_GATEWAY_CONTRADICTED_CALL": "Compare the gateway log with the transcript line; one of them is wrong.",
	"MCP_GATEWAY_UNLOGGED_CALL":     "Route every MCP server through the gateway so no call goes unrecorded.",
	"MCP_GATEWAY_DENIED_CALL":       "The gateway already blocked it. Review why the agent tried.",
	"ENDPOINT_CONTRADICTED_COMMAND": "The OS did not see what the transcript claims. Treat the transcript line as unreliable.",
	"UNLOGGED_AGENT_ACTIVITY":       "The OS saw activity the agent never logged. Review the process tree around that time.",
	"UNLOGGED_AGENT_NETWORK":        "The OS saw a connection the agent never logged. Check the destination.",
	"MCP_SERVER_REMOVED":            "Informational: a server was removed since the baseline.",
	"AGENT_SPAWN_EXPLOSION":         "Tuning, not a fix: many helper agents is how some people work.",
	"UNEXPECTED_TASK":               "Tuning, not a fix: nested helpers are normal for large tasks.",
}

// manualSteps are the human actions for past behaviour. Rules without an
// entry get the generic review step.
var manualSteps = map[string][]string{
	"CHAIN_SECRET_TO_EXFIL":             {"Rotate every secret the chain touched; it may have left the machine.", "Check the destination in the chain against the services you use."},
	"POTENTIAL_SECRET_EXPOSURE":         {"If the value is real, rotate it. It is now stored in the agent's history.", "If it was also pasted into an issue, pull request or commit, deleting the text is not enough: edit history, forks and caches keep it. Rotate it."},
	"CLOUD_RESOURCE_DELETION":           {"Check the cloud's activity log for what was actually deleted, and restore from soft-delete or backup while the retention window is still open."},
	"CLOUD_DESTRUCTIVE_BURST":           {"Disable or rotate the identity's credentials now, then find where they were stored or leaked.", "Restore what you can from soft-delete and backups while the retention window is open."},
	"CLOUD_RECOVERY_PROTECTION_REMOVED": {"Put the lock or backup protection back now, then check whether anything was deleted after it was removed."},
	"SECRET_ACCESS":                     {"If the honeytoken or secret is real, rotate it and find out what read it."},
	"GIT_CREDENTIAL_EXPOSURE":           {"Rotate the git credential the agent read."},
	"BROWSER_CREDENTIAL_ACCESS":         {"Change the passwords of the accounts stored in that browser profile and sign out other sessions."},
	"AGENT_CREDENTIAL_STORE_ACCESS":     {"Sign the agent out and back in so its stored token is replaced."},
	"TOOLCHAIN_CREDENTIAL_FILE_ACCESS":  {"Rotate the registry or cloud token in the file the agent read."},
	"CURL_FILE_UPLOAD":                  {"Find out what file was sent and to whom; if it was not yours to send, treat it as a leak."},
	"POTENTIAL_DATA_EXFILTRATION":       {"Check what was sent and where; the command is in the finding."},
	"INSTRUCTION_FROM_TOOL_RESULT":      {"Open the instruction file and remove any line you did not write."},
	"INSTRUCTION_INJECTION_PHRASE":      {"Open the instruction file and remove the injected text."},
	"AGENT_CONTEXT_POISONING":           {"Remove the injected text from the agent's memory or instruction file."},
	"MEMORY_INSTRUCTION_CALLOUT":        {"Remove the standing instruction from the memory file if you did not write it."},
	"AGENT_ADDS_MCP_SERVER":             {"Check the MCP server the agent added; remove it if you did not ask for it."},
	"TOOL_POISONING_INDICATOR":          {"Read the tool or skill description; remove the plugin if it tells the agent to do things you did not ask."},
	"MCP_TOOL_DESCRIPTION_POISONING":    {"Remove or disable the MCP server whose tool description carries instructions."},
	"MCP_TOOL_POISONING":                {"Treat that MCP server's answers as untrusted; remove it if it is not yours."},
	"MCP_REMOTE_FETCH_COMMAND":          {"Replace the MCP command that downloads code at start-up with a pinned, installed package."},
	"CONFIG_HOOK_REMOTE_FETCH":          {"Replace the hook that downloads a script with a local copy you have reviewed."},
	"MCP_SECRET_IN_CONFIG":              {"Move the secret out of the MCP config into your keychain or an environment variable, then rotate it."},
	"INSECURE_MCP_TRANSPORT":            {"Switch the MCP server URL to https, unless it is on this machine."},
	"MCP_INSECURE_TRANSPORT":            {"Switch the MCP server URL to https, unless it is on this machine."},
	"PROMPT_INJECTION_INDICATOR":        {"Read where the text came from; nothing to rotate unless the agent acted on it."},
	"CROSS_SESSION_MESSAGE":             {"Check whether you set up the agents to talk to each other."},
	"GIT_REMOTE_ADDED":                  {"Check the new git remote; remove it if it is not yours."},
	"GIT_PUSH_TO_URL":                   {"Check what was pushed and to where."},
	"PACKAGE_PUBLISH":                   {"Check the published package version; unpublish it if it was not intended."},
	"KEY_MATERIAL_GENERATION":           {"Find where the generated key was used or sent."},
	"SSH_KEY_WRITE":                     {"Remove any key in authorized_keys you do not recognise."},
	"CRON_PERSISTENCE":                  {"Remove any scheduled job you did not create (crontab -l, ~/Library/LaunchAgents)."},
	"SERVICE_PERSISTENCE":               {"Remove any service or launch agent you did not create."},
	"SHELL_RC_PERSISTENCE":              {"Remove lines in your shell startup files you did not write."},
}

// ModeOf classifies a rule.
func ModeOf(rule string) Mode {
	if _, ok := fixRules[rule]; ok {
		return Fix
	}
	if _, ok := noneRules[rule]; ok {
		return None
	}
	if len(PacksForRule(rule)) > 0 {
		return Prevent
	}
	return Manual
}

// FixControl names the fix control for a Fix rule.
func FixControl(rule string) string { return fixRules[rule] }

// StepsFor returns the human steps for a rule.
func StepsFor(rule string) []string {
	if s, ok := manualSteps[rule]; ok {
		return s
	}
	if s, ok := noneRules[rule]; ok {
		return []string{s}
	}
	return []string{"Open the finding, read the story and the log line, then mark it true positive, benign or false positive."}
}
