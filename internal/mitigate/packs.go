package mitigate

import "sort"

// Level is how a guardrail responds when the agent tries the thing.
type Level string

const (
	// Deny blocks the action outright.
	Deny Level = "deny"
	// Ask makes the agent stop and ask the person first. Nothing is
	// blocked, so ask packs cost a click, not a broken workflow.
	Ask Level = "ask"
)

// CodexRule is one execpolicy prefix rule. Codex matches argv tokens
// exactly, so a rule names the command and the leading arguments.
type CodexRule struct {
	Pattern []string
}

// Pack is one versioned set of guardrails: the unit a person picks. The
// same intent renders into each agent's own permission syntax.
type Pack struct {
	ID    string
	Title string // what it protects, in plain words
	Why   string // what it stops, one sentence
	Cost  string // what it will get in the way of, one sentence
	Level Level  // default level; --deny raises an ask pack
	// Friction: 0 never gets in the way of legitimate work … 3 blocks
	// daily work. Confidence: how often a hit is a real problem.
	Friction   int
	Confidence int
	DefaultOn  bool
	Rules      []string // rule ids whose recurrence this prevents
	ATLAS      []string // MITRE ATLAS mitigation ids
	Claude     []string // Claude Code permission patterns
	ClaudeHook bool     // install the log-guard PreToolUse hook
	Cursor     []string // Cursor CLI permission patterns (deny level only: Cursor has no ask list)
	Codex      []CodexRule
	// Setting is a Claude Code settings key this pack sets (FIX-style).
	Setting *Setting
}

// Setting is one scalar in ~/.claude/settings.json.
type Setting struct {
	Path  []string
	Value string
}

// PackVersion is recorded in the ledger so a later release can say
// exactly which patterns an earlier apply wrote.
const PackVersion = 1

// secretReads are credential files no coding agent needs to read itself.
// The tools that use them (aws, ssh, kubectl, gh) still read them; only
// the agent's own Read tool is refused.
var secretReads = []string{
	"~/.aws/**", "~/.ssh/**", "~/.config/gcloud/**", "~/.azure/**", "~/.kube/config",
	"~/.docker/config.json", "~/.netrc", "~/.git-credentials", "~/.pypirc", "~/.npmrc",
	"~/.config/gh/hosts.yml", "~/.gnupg/**", "~/.claude/.credentials.json", "~/.codex/auth.json",
	"~/Library/Keychains/**",
	"~/Library/Application Support/Google/Chrome/*/Login Data",
	"~/Library/Application Support/Google/Chrome/*/Cookies",
	"~/Library/Application Support/Firefox/Profiles/**/logins.json",
	"~/Library/Application Support/Firefox/Profiles/**/cookies.sqlite",
	"~/.mozilla/firefox/**/logins.json",
	"~/.config/google-chrome/*/Login Data",
}

func wrap(tool string, paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, tool+"("+p+")")
	}
	return out
}

func cat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// agentLogs are the agents' own activity records: the evidence this tool
// reads. Only transcripts are listed, not the directories that hold them,
// because Claude Code keeps its memory files under ~/.claude/projects too.
var agentLogs = []string{
	"~/.claude/projects/**/*.jsonl", "~/.claude/history.jsonl",
	"~/.codex/sessions/**", "~/.codex/history.jsonl", "~/.gemini/tmp/**",
}

// Packs lists every guardrail pack, most protective and least disruptive
// first. Keep IDs stable: they are what people type and what the ledger
// records.
var Packs = []Pack{
	{
		ID: "log-protect", Title: "Keep the agents' own logs",
		Why:   "Stops an agent deleting or rewriting its transcripts, which is how an agent hides what it did.",
		Cost:  "None. Nothing legitimate deletes its own conversation history.",
		Level: Deny, Friction: 0, Confidence: 100, DefaultOn: true,
		Rules:      []string{"LOG_DELETION", "CHAIN_ACTION_THEN_LOG_TAMPER", "HISTORY_CLEARING", "SESSION_TAMPERING", "TRACE_GAP", "OS_LOG_TAMPER"},
		ATLAS:      []string{"AML.M0024", "AML.M0028"},
		Claude:     cat(wrap("Write", agentLogs), wrap("Edit", agentLogs)),
		ClaudeHook: true,
		Cursor:     []string{"Write(~/.cursor/chats/**)"},
		Codex: []CodexRule{
			{Pattern: []string{"rm", "-rf", "~/.codex/sessions"}}, {Pattern: []string{"rm", "-rf", "~/.codex"}},
			{Pattern: []string{"rm", "~/.codex/history.jsonl"}},
		},
	},
	{
		ID: "secret-paths", Title: "Keep credential files away from the agent",
		Why:   "Stops the agent reading cloud keys, SSH keys, tokens and browser passwords into its conversation.",
		Cost:  "None for coding work. aws, ssh, gh and kubectl still read their own files; only the agent's Read tool is refused.",
		Level: Deny, Friction: 0, Confidence: 100, DefaultOn: true,
		Rules: []string{"CHAIN_SECRET_TO_EXFIL", "POTENTIAL_SECRET_EXPOSURE", "SENSITIVE_FILE_READ", "SECRET_ACCESS",
			"BROWSER_CREDENTIAL_ACCESS", "AGENT_CREDENTIAL_STORE_ACCESS", "TOOLCHAIN_CREDENTIAL_FILE_ACCESS",
			"GIT_CREDENTIAL_EXPOSURE", "SSH_PRIVATE_KEY_READ", "CLOUD_CREDENTIAL_EXPORT", "CREDENTIAL_DIR_ARCHIVE",
			"SHADOW_FILE_ACCESS", "KUBE_SECRET_DUMP", "MEMORY_CREDENTIAL_DUMP"},
		ATLAS: []string{"AML.M0005", "AML.M0028"},
		Claude: cat(wrap("Read", secretReads), []string{
			"Bash(security find-generic-password*)", "Bash(security find-internet-password*)", "Bash(security dump-keychain*)",
		}),
		Cursor: cat(wrap("Read", secretReads), []string{"Shell(security)"}),
		Codex: []CodexRule{
			{Pattern: []string{"security", "find-generic-password"}}, {Pattern: []string{"security", "find-internet-password"}},
			{Pattern: []string{"security", "dump-keychain"}},
		},
	},
	{
		ID: "outbound-upload", Title: "Ask before files are uploaded",
		Why:   "The agent must ask before it sends a local file or data to another computer.",
		Cost:  "One prompt when you really are deploying or uploading.",
		Level: Ask, Friction: 1, Confidence: 90,
		Rules: []string{"CHAIN_SECRET_TO_EXFIL", "CHAIN_SUBAGENT_CROSS_TALK_EXFIL", "POTENTIAL_DATA_EXFILTRATION", "CURL_FILE_UPLOAD",
			"REMOTE_COPY_TO_HOST", "CLOUD_STORAGE_UPLOAD", "ENV_DUMP_TO_NETWORK", "PASTE_SITE_DESTINATION", "WEBHOOK_C2_EXFIL"},
		ATLAS: []string{"AML.M0028", "AML.M0029"},
		Claude: []string{"Bash(curl * -d *)", "Bash(curl * --data*)", "Bash(curl * -F *)", "Bash(curl * -T *)", "Bash(curl * --upload-file*)",
			"Bash(wget * --post-file*)", "Bash(scp *)", "Bash(rsync *:*)", "Bash(rclone *)", "Bash(aws s3 cp *)", "Bash(aws s3 sync *)",
			"Bash(gsutil cp *)", "Bash(az storage blob upload*)", "Bash(nc *)", "Bash(ncat *)"},
		Cursor: []string{"Shell(scp)", "Shell(rclone)", "Shell(nc)", "Shell(ncat)"},
		Codex:  []CodexRule{{Pattern: []string{"scp"}}, {Pattern: []string{"rclone"}}, {Pattern: []string{"aws", "s3", "cp"}}, {Pattern: []string{"aws", "s3", "sync"}}, {Pattern: []string{"nc"}}},
	},
	{
		ID: "download-exec", Title: "Ask before running downloaded scripts",
		Why:   "The agent must ask before it pipes something from the internet straight into a shell.",
		Cost:  "One prompt when you install tools with curl | sh (AgentDFIR's own installer is one).",
		Level: Ask, Friction: 1, Confidence: 70,
		Rules:  []string{"CHAIN_DOWNLOAD_AND_EXECUTE", "CURL_PIPE_SHELL", "DOWNLOAD_THEN_EXECUTE", "BASE64_PIPE_SHELL", "POWERSHELL_ENCODED_OR_REMOTE_EXEC", "PACKAGE_INSTALL_FROM_URL"},
		ATLAS:  []string{"AML.M0029", "AML.M0011"},
		Claude: []string{"Bash(curl * | sh*)", "Bash(curl * | bash*)", "Bash(wget * | sh*)", "Bash(wget * | bash*)", "Bash(* | base64 -d | sh*)", "Bash(iex *)", "Bash(pip install http*)", "Bash(npm install http*)"},
	},
	{
		ID: "self-modify", Title: "Ask before the agent changes its own settings",
		Why:   "The agent must ask before it edits its own permissions, hooks or MCP servers, the usual way an injected instruction makes itself permanent.",
		Cost:  "A prompt when you ask the agent to change its own settings or add an MCP server.",
		Level: Ask, Friction: 2, Confidence: 80,
		Rules: []string{"AGENT_SELF_MODIFICATION", "CHAIN_CONTEXT_POISON_TO_EXEC", "CHAIN_ORPHAN_PERSISTENCE", "AGENT_ADDS_MCP_SERVER",
			"AGENT_CONFIG_SHELL_WRITE", "MEMORY_INSTRUCTION_CALLOUT", "INSTRUCTION_FROM_TOOL_RESULT", "INSTRUCTION_WRITTEN_BY_SUBAGENT", "CONFIG_HOOK_REMOTE_FETCH"},
		ATLAS: []string{"AML.M0031", "AML.M0026"},
		Claude: cat(wrap("Write", []string{"~/.claude/settings.json", "~/.claude/settings.local.json", "~/.claude.json", "~/.claude/hooks/**", ".claude/settings.json", ".mcp.json"}),
			wrap("Edit", []string{"~/.claude/settings.json", "~/.claude/settings.local.json", "~/.claude.json", "~/.claude/hooks/**", ".claude/settings.json", ".mcp.json"}),
			[]string{"Bash(claude mcp add*)", "Bash(codex mcp add*)"}),
		Codex: []CodexRule{{Pattern: []string{"codex", "mcp", "add"}}, {Pattern: []string{"claude", "mcp", "add"}}},
	},
	{
		ID: "no-bypass", Title: "Turn off 'skip all permission checks'",
		Why:   "Removes the mode where the agent runs everything without asking, so the other guardrails cannot be switched off with one flag.",
		Cost:  "--dangerously-skip-permissions stops working for Claude Code on this machine.",
		Level: Deny, Friction: 2, Confidence: 90,
		Rules:   []string{"PERMISSION_BYPASS_ENABLED", "PERMISSION_ESCALATION", "NESTED_AGENT_PERMISSION_BYPASS"},
		ATLAS:   []string{"AML.M0026"},
		Setting: &Setting{Path: []string{"permissions", "disableBypassPermissionsMode"}, Value: "disable"},
	},
	{
		ID: "destructive", Title: "Ask before destructive commands",
		Why:   "The agent must ask before rm -rf, force-pushes and hard resets.",
		Cost:  "Prompts during everyday cleanup work. Most people leave this off.",
		Level: Ask, Friction: 3, Confidence: 40,
		Rules:  []string{"DESTRUCTIVE_COMMAND", "CHAIN_MCP_RESULT_TO_DESTRUCTIVE", "DISK_WIPE", "BULK_FILE_ENCRYPTION"},
		ATLAS:  []string{"AML.M0029"},
		Claude: []string{"Bash(rm -rf *)", "Bash(rm -fr *)", "Bash(git push --force*)", "Bash(git push -f*)", "Bash(git reset --hard*)", "Bash(git clean -fd*)"},
		Codex:  []CodexRule{{Pattern: []string{"rm", "-rf"}}, {Pattern: []string{"git", "push", "--force"}}, {Pattern: []string{"git", "reset", "--hard"}}},
	},
	{
		ID: "persistence", Title: "Ask before anything is set to run on its own",
		Why:   "The agent must ask before it adds cron jobs, launch agents, shell startup lines or SSH keys that outlive the session.",
		Cost:  "A prompt when you really are setting up a scheduled job.",
		Level: Ask, Friction: 1, Confidence: 85,
		Rules: []string{"CRON_PERSISTENCE", "SERVICE_PERSISTENCE", "SHELL_RC_PERSISTENCE", "SSH_KEY_WRITE", "GIT_HOOK_INSTALL", "LD_PRELOAD_INJECT",
			"SUDOERS_NOPASSWD_PERSIST", "WINDOWS_RUN_KEY", "WINDOWS_SCHEDULED_TASK", "NEW_ACCOUNT_CREATED"},
		ATLAS: []string{"AML.M0029", "AML.M0026"},
		Claude: cat([]string{"Bash(crontab *)", "Bash(launchctl load*)", "Bash(launchctl bootstrap*)", "Bash(systemctl enable*)", "Bash(schtasks *)"},
			wrap("Write", []string{"~/Library/LaunchAgents/**", "~/.ssh/authorized_keys", "~/.zshrc", "~/.bashrc", "~/.bash_profile", "~/.profile", ".git/hooks/**"}),
			wrap("Edit", []string{"~/.ssh/authorized_keys", "~/.zshrc", "~/.bashrc", "~/.bash_profile", "~/.profile"})),
		Codex: []CodexRule{{Pattern: []string{"crontab"}}, {Pattern: []string{"launchctl", "load"}}, {Pattern: []string{"systemctl", "enable"}}},
	},
}

// PackByID returns one pack.
func PackByID(id string) (Pack, bool) {
	for _, p := range Packs {
		if p.ID == id {
			return p, true
		}
	}
	return Pack{}, false
}

// DefaultPacks are the packs selected when nothing is chosen.
func DefaultPacks() []string {
	var out []string
	for _, p := range Packs {
		if p.DefaultOn {
			out = append(out, p.ID)
		}
	}
	return out
}

// PacksForRule lists the packs that prevent a rule from recurring.
func PacksForRule(rule string) []string {
	var out []string
	for _, p := range Packs {
		for _, r := range p.Rules {
			if r == rule {
				out = append(out, p.ID)
				break
			}
		}
	}
	sort.Strings(out)
	return out
}
