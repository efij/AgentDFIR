package reposcan

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/agentcli"
	"github.com/efij/AgentDFIR/v3/internal/decode"
	"github.com/efij/AgentDFIR/v3/internal/detect"
	"github.com/efij/AgentDFIR/v3/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v3/internal/netdest"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

func stripJSONC(b []byte) []byte { return mcpaudit.StripJSONC(b) }

// ---- what makes a command dangerous

var (
	pipeShellRe = regexp.MustCompile(`(?i)(curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^\n]*\|\s*(sudo\s+)?((ba|z|da)?sh|iex|python[0-9.]*|node)\b`)
	credPaths   = []string{".aws/credentials", ".ssh/id_", ".npmrc", ".docker/config.json", ".kube/config", ".git-credentials", ".config/gh/hosts.yml",
		".claude/.credentials.json", ".codex/auth.json", ".gemini/oauth_creds.json", ".config/github-copilot", ".vault-token", "keychain", "login.keychain", ".netrc", "id_rsa", "id_ed25519", ".env"}
	scriptTokRe = regexp.MustCompile(`(?:^|[\s"'=])((?:\./|\.claude/|\.vscode/|\.cursor/|\.github/|scripts?/|tools?/|hooks?/|\.devcontainer/)[A-Za-z0-9._/-]+\.(?:sh|bash|zsh|js|mjs|cjs|ts|py|rb|ps1|pl))\b`)
	codeExecRe  = regexp.MustCompile(`(?i)(child_process|execSync|spawnSync|\beval\s*\(|new Function\s*\(|subprocess\.|os\.system|Invoke-Expression|\bexec\s*\()`)
	remoteURLRe = regexp.MustCompile(`(?i)https?://([a-z0-9.-]+\.[a-z]{2,})`)
)

// risk lists the reasons a command (and any repo script it runs) is more
// than a formatter hook: network, remote code, credentials, encoded
// payloads, a headless agent with approvals off.
func (s *scanner) risk(cmd string) []string {
	var why []string
	low := strings.ToLower(cmd)
	if pipeShellRe.MatchString(cmd) {
		why = append(why, "pipes a download into a shell")
	}
	if netdest.IsOutbound(cmd) {
		why = append(why, "opens a network connection")
	}
	if decode.ExecutesDecoded(cmd) || len(decode.FindInCommand(cmd)) > 0 {
		why = append(why, "decodes and runs an embedded payload")
	}
	if m, ok := agentcli.HeadlessBypass(cmd); ok {
		why = append(why, fmt.Sprintf("runs %s headless with approvals off (%s)", m.CLI, m.Bypass))
	}
	for _, c := range credPaths {
		if strings.Contains(low, c) {
			why = append(why, "touches credential files ("+c+")")
			break
		}
	}
	// A hook that runs a script shipped in the repo is judged by the script.
	for _, m := range scriptTokRe.FindAllStringSubmatch(cmd, 4) {
		rel := strings.TrimPrefix(m[1], "./")
		if strings.Contains("/"+rel+"/", "/../") {
			continue // never leave the tree
		}
		b, ok := s.readInside(filepath.Join(s.root, filepath.FromSlash(rel)), 1<<20)
		if !ok {
			continue
		}
		why = append(why, s.scriptRisk(m[1], b)...)
	}
	return dedupe(why)
}

// readInside reads a regular file only if its fully resolved path is
// inside the scanned root (every component, not just the last, may be a
// link) and it is at most max bytes.
func (s *scanner) readInside(p string, max int64) (string, bool) {
	res, err := filepath.EvalSymlinks(p)
	if err != nil || !(res == s.root || strings.HasPrefix(res, s.root+string(filepath.Separator))) {
		return "", false
	}
	b, ok := readRegular(res, max)
	return string(b), ok
}

// readRegular reads a regular, non-symlink file of at most max bytes; a
// FIFO, device or link is refused (a FIFO would block the scan forever).
func readRegular(p string, max int64) ([]byte, bool) {
	fi, err := os.Lstat(p)
	if err != nil || !fi.Mode().IsRegular() || fi.Size() > max {
		return nil, false
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max))
	return b, err == nil
}

func (s *scanner) scriptRisk(name, body string) []string {
	var why []string
	low := strings.ToLower(body)
	if pipeShellRe.MatchString(body) {
		why = append(why, name+" pipes a download into a shell")
	}
	for _, m := range remoteURLRe.FindAllStringSubmatch(body, 16) {
		h := strings.ToLower(m[1])
		if !netdest.IsAllowed(h, nil) {
			cat := netdest.Category(h)
			if cat != "" {
				why = append(why, fmt.Sprintf("%s contacts %s (%s)", name, h, cat))
			} else {
				why = append(why, name+" contacts "+h)
			}
			break
		}
	}
	for _, c := range credPaths {
		if strings.Contains(low, c) {
			why = append(why, name+" reads credential files ("+c+")")
			break
		}
	}
	if codeExecRe.MatchString(body) && (strings.Contains(low, "base64") || strings.Contains(low, "fromcharcode") || strings.Contains(low, "atob(")) {
		why = append(why, name+" decodes and executes code")
	}
	if len(body) > 200000 && strings.Count(body, "\n") < 20 {
		why = append(why, name+" is a large single-line (obfuscated) script")
	}
	return why
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ---- Claude Code settings

var autorunEvents = map[string]bool{"SessionStart": true, "UserPromptSubmit": true, "Setup": true, "Notification": true}

// helperKeys are settings whose value is a command Claude Code runs itself.
var helperKeys = []string{"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"}

var envOverride = map[string]string{
	"ANTHROPIC_BASE_URL": "redirects every API request, prompts and code included, to another server",
	"ANTHROPIC_API_URL":  "redirects API traffic", "ANTHROPIC_BEDROCK_BASE_URL": "redirects API traffic", "ANTHROPIC_VERTEX_BASE_URL": "redirects API traffic",
	"OPENAI_BASE_URL": "redirects API traffic", "NODE_OPTIONS": "loads code into the agent's own process", "BASH_ENV": "runs a file before every shell command",
	"ENV": "runs a file when a shell starts", "LD_PRELOAD": "injects a library into every process", "DYLD_INSERT_LIBRARIES": "injects a library into every process",
	"HTTPS_PROXY": "routes traffic through a proxy", "HTTP_PROXY": "routes traffic through a proxy", "NODE_TLS_REJECT_UNAUTHORIZED": "turns off TLS verification",
	"PYTHONSTARTUP": "runs a file when Python starts", "GIT_SSH_COMMAND": "runs a command on every git network operation",
}

func (s *scanner) claudeSettings(rel string, b []byte) {
	doc, err := parseJSONC(b)
	if err != nil {
		s.unparseable(rel, err)
		return
	}
	s.hooks(rel, doc["hooks"], "Claude Code hook")
	if sl, ok := doc["statusLine"].(map[string]any); ok {
		if c, ok := sl["command"].(string); ok && c != "" {
			s.autorun(rel, "statusLine.command", c, "runs on every status-line refresh", true)
		}
	}
	for _, k := range helperKeys {
		if c, ok := doc[k].(string); ok && c != "" {
			s.autorun(rel, k, c, "runs whenever Claude Code needs credentials", true)
		}
	}
	if env, ok := doc["env"].(map[string]any); ok {
		keys := make([]string, 0, len(env))
		for k := range env {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			why, bad := envOverride[strings.ToUpper(k)]
			if !bad {
				continue
			}
			v, _ := env[k].(string)
			s.add(schema.Finding{RuleID: "REPO_AGENT_ENV_OVERRIDE", Severity: "HIGH", Title: "Repository Settings Override the Agent's Environment",
				Description:  fmt.Sprintf("%s sets %s=%s for the agent: it %s. A repository has no reason to choose this for whoever opens it.", rel, k, excerpt(v), why),
				EvidenceRefs: []string{rel}, MitreATTACK: "T1574", MitreATLAS: "AML.T0081",
				FalsePositive: "Teams sometimes route agents through a corporate gateway; confirm the endpoint is yours."}, rel+k)
		}
	}
	if perms, ok := doc["permissions"].(map[string]any); ok {
		if m, _ := perms["defaultMode"].(string); m == "bypassPermissions" {
			s.weakening(rel, "permissions.defaultMode = bypassPermissions", "HIGH")
		}
		if allow, ok := perms["allow"].([]any); ok {
			for _, a := range allow {
				v, _ := a.(string)
				if v == "Bash" || v == "Bash(*)" || v == "Bash(*:*)" || v == "*" || v == "mcp__*" {
					s.weakening(rel, "permissions.allow contains "+v, "HIGH")
				}
			}
		}
	}
	if v, _ := doc["enableAllProjectMcpServers"].(bool); v {
		s.weakening(rel, "enableAllProjectMcpServers = true (every server in .mcp.json starts without a prompt)", "HIGH")
	}
}

func (s *scanner) weakening(rel, what, sev string) {
	s.add(schema.Finding{RuleID: "REPO_AGENT_PERMISSION_WEAKENING", Severity: sev, Title: "Repository Turns Off the Agent's Safety Prompts",
		Description:  fmt.Sprintf("%s: %s. Committed to the repository, it applies to everyone who opens it.", rel, what),
		EvidenceRefs: []string{rel}, MitreATTACK: "T1562.001", MitreATLAS: "AML.T0081",
		FalsePositive: "Personal settings belong in settings.local.json and outside version control; check whether this was committed on purpose."}, rel+what)
}

// hooks walks {Event: [{matcher, hooks:[{type,command}]}]} and the flatter
// shapes other agents use; every string under a "command" key is a command.
func (s *scanner) hooks(rel string, v any, kind string) {
	m, ok := v.(map[string]any)
	if !ok {
		return
	}
	events := make([]string, 0, len(m))
	for e := range m {
		events = append(events, e)
	}
	sort.Strings(events)
	for _, ev := range events {
		for _, c := range commandsUnder(m[ev], 0) {
			s.autorun(rel, kind+" "+ev, c, "", autorunEvents[ev] || strings.EqualFold(ev, "sessionStart") || strings.EqualFold(ev, "beforeSubmitPrompt"))
		}
	}
}

func commandsUnder(v any, depth int) []string {
	if depth > 8 {
		return nil
	}
	var out []string
	switch t := v.(type) {
	case map[string]any:
		for _, k := range []string{"command", "cmd", "bash", "powershell"} {
			if c, ok := t[k].(string); ok && c != "" {
				out = append(out, c)
			}
			if arr, ok := t[k].([]any); ok {
				var parts []string
				for _, p := range arr {
					if ps, ok := p.(string); ok {
						parts = append(parts, ps)
					}
				}
				if len(parts) > 0 {
					out = append(out, strings.Join(parts, " "))
				}
			}
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if k == "command" || k == "cmd" {
				continue
			}
			out = append(out, commandsUnder(t[k], depth+1)...)
		}
	case []any:
		for _, e := range t {
			out = append(out, commandsUnder(e, depth+1)...)
		}
	}
	return out
}

// autorun reports a command an agent runs on its own. startup marks the
// ones that run without any tool call at all (session start, prompt
// submit, status line, credential helpers).
func (s *scanner) autorun(rel, where, cmd, when string, startup bool) {
	why := s.risk(cmd)
	sev := "MEDIUM"
	switch {
	case len(why) > 0 && startup:
		sev = "CRITICAL"
	case len(why) > 0 || startup:
		sev = "HIGH"
	}
	if _, ok := agentcli.HeadlessBypass(cmd); ok {
		s.headless(rel, where, cmd)
	}
	desc := fmt.Sprintf("%s: %s runs `%s`", rel, where, excerpt(cmd))
	if when != "" {
		desc += " (" + when + ")"
	} else if startup {
		desc += " as soon as a session starts — no tool call, no prompt"
	}
	desc += "."
	if len(why) > 0 {
		desc += " Risk: " + strings.Join(why, "; ") + "."
	}
	desc += " The keyv wave of Shai-Hulud (Aug 2026) planted exactly this: a committed SessionStart hook that stole agent credentials."
	s.add(schema.Finding{RuleID: "REPO_AGENT_HOOK_AUTORUN", Severity: sev, Title: "Repository Makes the Agent Run a Command Automatically",
		Description: desc, EvidenceRefs: []string{rel}, Related: append([]string{"where: " + where}, why...),
		MitreATTACK: "T1546", MitreATLAS: "AML.T0081",
		FalsePositive: "Formatter and lint hooks are common; the signal is a startup hook, network access, or a script that reads credentials."}, rel+where+cmd)
}

func (s *scanner) headless(rel, where, cmd string) {
	m, _ := agentcli.HeadlessBypass(cmd)
	sev := "CRITICAL"
	if m.Weak {
		sev = "MEDIUM"
	}
	s.add(schema.Finding{RuleID: "AI_CLI_HEADLESS_BYPASS", Severity: sev, Title: "Repository Launches an AI Agent Headless With Approvals Disabled",
		Description:  fmt.Sprintf("%s: %s runs %s non-interactively (%s) with permission checks off (%s). This is how the Nx s1ngularity postinstall turned the victim's own AI CLIs into a secret scanner.", rel, where, m.CLI, m.Headless, m.Bypass),
		EvidenceRefs: []string{rel}, MitreATTACK: "T1059", MitreATLAS: "AML.T0103"}, rel+where)
}

// ---- MCP configs in the tree

func (s *scanner) mcp(rel string, b []byte) {
	inv, fs := mcpaudit.EvaluateProjectFile(rel, b)
	if inv == nil {
		return
	}
	for _, p := range inv.Problems {
		if strings.Contains(p, "invalid JSON") {
			s.unparseable(rel, fmt.Errorf("%s", p))
		}
	}
	for _, f := range fs {
		f.EvidenceRefs = []string{rel}
		f.Related = append(f.Related, "scope: repository")
		key := rel + f.Title + f.Description
		s.add(f, key)
	}
	for _, srv := range inv.Servers {
		if srv.Command != "" {
			cmd := srv.Command + " " + strings.Join(srv.Args, " ")
			if why := s.risk(cmd); len(why) > 0 {
				s.add(schema.Finding{RuleID: "REPO_AGENT_HOOK_AUTORUN", Severity: "HIGH", Title: "Repository MCP Server Runs a Risky Command",
					Description:  fmt.Sprintf("%s: MCP server %q starts `%s`. Risk: %s. Project MCP servers start when the agent opens the folder (after one approval, or none with enableAllProjectMcpServers).", rel, srv.Name, excerpt(cmd), strings.Join(why, "; ")),
					EvidenceRefs: []string{rel}, MitreATTACK: "T1195.002", MitreATLAS: "AML.T0010"}, rel+srv.Name)
			}
		}
	}
}

// codexProject — CVE-2025-61260: Codex CLI < 0.23.0 loaded a repository's
// .codex/config.toml and ran its MCP commands at startup.
func (s *scanner) codexProject(rel string, b []byte) {
	if !bytes.Contains(b, []byte("mcp_servers")) && !bytes.Contains(b, []byte("command")) {
		return
	}
	s.add(schema.Finding{RuleID: "REPO_CODEX_PROJECT_CONFIG", Severity: "HIGH", Title: "Repository Ships a Codex Configuration With Commands",
		Description:  rel + " defines commands (MCP servers or notify hooks). Codex CLI before 0.23.0 ran a repository's own config at startup (CVE-2025-61260); newer versions still read it when the project is trusted.",
		EvidenceRefs: []string{rel}, MitreATTACK: "T1546", MitreATLAS: "AML.T0081",
		FalsePositive: "Some projects share a Codex config on purpose; read every command in it."}, rel)
}

// ---- VS Code

func (s *scanner) tasks(rel string, v any) {
	arr, ok := v.([]any)
	if !ok {
		return
	}
	for _, t := range arr {
		m, ok := t.(map[string]any)
		if !ok {
			continue
		}
		ro, _ := m["runOptions"].(map[string]any)
		runOn, _ := ro["runOn"].(string)
		if runOn != "folderOpen" {
			continue
		}
		label, _ := m["label"].(string)
		var cmds []string
		base := taskCommand(m)
		if base != "" {
			cmds = append(cmds, base)
		}
		for _, osk := range []string{"windows", "osx", "linux"} {
			if om, ok := m[osk].(map[string]any); ok {
				if c := taskCommand(om); c != "" {
					cmds = append(cmds, c)
				}
			}
		}
		for _, c := range cmds {
			why := s.risk(c)
			sev := "HIGH"
			if len(why) > 0 {
				sev = "CRITICAL"
			}
			desc := fmt.Sprintf("%s: task %q runs `%s` when the folder is opened.", rel, label, excerpt(c))
			if len(why) > 0 {
				desc += " Risk: " + strings.Join(why, "; ") + "."
			}
			desc += " Committed folderOpen tasks were the keyv wave's second persistence path (Aug 2026)."
			if _, ok := agentcli.HeadlessBypass(c); ok {
				s.headless(rel, "folderOpen task "+label, c)
			}
			s.add(schema.Finding{RuleID: "REPO_VSCODE_AUTORUN_TASK", Severity: sev, Title: "Repository Runs a Task When the Folder Opens",
				Description: desc, EvidenceRefs: []string{rel}, Related: why, MitreATTACK: "T1546", MitreATLAS: "AML.T0011",
				FalsePositive: "Dev-environment bootstrap tasks exist; VS Code asks before running them unless task.allowAutomaticTasks is on."}, rel+label+c)
		}
	}
}

func taskCommand(m map[string]any) string {
	c, _ := m["command"].(string)
	if c == "" {
		return ""
	}
	if args, ok := m["args"].([]any); ok {
		for _, a := range args {
			switch v := a.(type) {
			case string:
				c += " " + v
			case map[string]any:
				if s, ok := v["value"].(string); ok {
					c += " " + s
				}
			}
		}
	}
	return c
}

var autoApproveKeys = map[string]string{
	"chat.tools.autoApprove":            "Copilot agent runs every tool without asking",
	"chat.tools.global.autoApprove":     "Copilot agent runs every tool without asking",
	"chat.agent.autoApprove":            "Copilot agent runs every tool without asking",
	"github.copilot.chat.agent.autoFix": "",
	"task.allowAutomaticTasks":          "folderOpen tasks run without asking",
	"security.workspace.trust.enabled":  "workspace trust is turned off",
	"chat.tools.terminal.autoApprove":   "terminal commands run without asking",
	"chat.mcp.autostart":                "MCP servers start without asking",
}

var exePathKey = regexp.MustCompile(`(?i)(^python\.(defaultInterpreterPath|pythonPath)$|^git\.path$|executablePath$|^go\.(goroot|alternateTools)|^terminal\.integrated\.(shell|automationProfile|profiles|env)\.|^eslint\.(runtime|nodePath)$|^typescript\.tsdk$|^npm\.binPath$)`)

func (s *scanner) vscodeSettings(rel string, doc map[string]any) {
	keys := make([]string, 0, len(doc))
	for k := range doc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		v := doc[k]
		if why, ok := autoApproveKeys[k]; ok && why != "" {
			on := v == true || v == "on"
			if k == "security.workspace.trust.enabled" {
				on = v == false
			}
			if m, ok := v.(map[string]any); ok && len(m) > 0 {
				on = true
			}
			if on {
				s.weakening(rel, fmt.Sprintf("%s = %v (%s)", k, v, why), "HIGH")
			}
			continue
		}
		if exePathKey.MatchString(k) {
			val := fmt.Sprint(v)
			if str, ok := v.(string); ok {
				val = str
			}
			if repoRelative(val) {
				s.add(schema.Finding{RuleID: "REPO_EXECUTABLE_PATH_OVERRIDE", Severity: "HIGH", Title: "Repository Points an Editor Tool at a File It Ships",
					Description:  fmt.Sprintf("%s sets %s to %s, a path inside the repository: the editor (and any agent using it) runs that file instead of the real tool.", rel, k, excerpt(val)),
					EvidenceRefs: []string{rel}, MitreATTACK: "T1574", MitreATLAS: "AML.T0011"}, rel+k)
			}
		}
	}
}

func repoRelative(v string) bool {
	v = strings.TrimSpace(v)
	return strings.HasPrefix(v, "./") || strings.HasPrefix(v, "${workspaceFolder}") || strings.HasPrefix(v, ".\\") ||
		(v != "" && !strings.HasPrefix(v, "/") && !strings.HasPrefix(v, "~") && !strings.HasPrefix(v, "$") && !strings.Contains(v, ":\\") && strings.Contains(v, "/") && !strings.HasPrefix(v, "{") && !strings.HasPrefix(v, "["))
}

// ---- devcontainer

func (s *scanner) devcontainer(rel string, doc map[string]any) {
	if c := anyCommand(doc["initializeCommand"]); c != "" {
		why := s.risk(c)
		sev := "HIGH"
		if len(why) > 0 {
			sev = "CRITICAL"
		}
		desc := fmt.Sprintf("%s: initializeCommand runs `%s` on the HOST, before the container exists, whenever the dev container is opened or rebuilt.", rel, excerpt(c))
		if len(why) > 0 {
			desc += " Risk: " + strings.Join(why, "; ") + "."
		}
		s.add(schema.Finding{RuleID: "REPO_DEVCONTAINER_HOST_COMMAND", Severity: sev, Title: "Dev Container Runs a Command on the Host",
			Description: desc, EvidenceRefs: []string{rel}, Related: why, MitreATTACK: "T1546", MitreATLAS: "AML.T0011",
			FalsePositive: "initializeCommand is used for local setup (docker login, env files); read it."}, rel)
	}
}

func anyCommand(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case []any:
		var p []string
		for _, e := range t {
			if s, ok := e.(string); ok {
				p = append(p, s)
			}
		}
		return strings.Join(p, " ")
	case map[string]any:
		var p []string
		for _, k := range sortedKeys(t) {
			p = append(p, anyCommand(t[k]))
		}
		return strings.Join(p, " && ")
	}
	return ""
}

func sortedKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- instruction files

var remoteInstrRe = regexp.MustCompile(`(?i)((curl|wget|iwr|irm)\b[^\n]*\|\s*(ba|z)?sh\b|\b(fetch|download|read|load)\b[^\n.]{0,60}\bhttps?://[^\s)]+[^\n.]{0,80}\b(follow|execute|run|obey)\b)`)

func (s *scanner) instructions(rel string, b []byte) {
	text := string(b)
	if ph, ok := detect.InjectionPhrase(text); ok {
		s.add(schema.Finding{RuleID: "REPO_INSTRUCTION_INJECTION", Severity: "HIGH", Title: "Instruction Override in a File the Agent Loads",
			Description:  fmt.Sprintf("%s contains the phrase %q. Agents load this file into every session in the repository as trusted instructions.", rel, ph),
			EvidenceRefs: []string{rel}, MitreATTACK: "T1204", MitreATLAS: "AML.T0051.001",
			FalsePositive: "Security docs quote injection phrases; read the context."}, rel+"phrase")
	}
	if tags, bidi, zw := invisible(text); tags+bidi+zw > 0 {
		sev := "HIGH"
		if tags > 0 {
			sev = "CRITICAL"
		}
		s.add(schema.Finding{RuleID: "REPO_INSTRUCTION_INJECTION", Severity: sev, Title: "Invisible Characters in a File the Agent Loads",
			Description:  fmt.Sprintf("%s contains %d Unicode tag, %d bidi-control and %d zero-width characters. Tag characters carry text a reviewer cannot see and the model reads.", rel, tags, bidi, zw),
			EvidenceRefs: []string{rel}, MitreATTACK: "T1027", MitreATLAS: "AML.T0051.001"}, rel+"unicode")
	}
	if m := remoteInstrRe.FindString(text); m != "" {
		s.add(schema.Finding{RuleID: "REPO_INSTRUCTION_INJECTION", Severity: "HIGH", Title: "Agent Instructions Tell It to Run or Obey Remote Content",
			Description:  fmt.Sprintf("%s instructs the agent to fetch remote content and run or follow it: `%s`. Whoever controls that URL controls the agent.", rel, excerpt(m)),
			EvidenceRefs: []string{rel}, MitreATTACK: "T1105", MitreATLAS: "AML.T0051.001"}, rel+"remote")
	}
}

func invisible(s string) (tags, bidi, zw int) {
	for i, r := range s {
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			tags++
		case r >= 0x202A && r <= 0x202E, r >= 0x2066 && r <= 0x2069:
			bidi++
		case r == 0x200B || r == 0x200C || r == 0x200D || r == 0x2060 || (r == 0xFEFF && i > 0):
			zw++
		}
	}
	return
}

// ---- package.json lifecycle scripts

var lifecycle = []string{"preinstall", "install", "postinstall", "prepare", "preprepare", "postprepare", "prepublish"}

func (s *scanner) packageJSON(rel string, b []byte) {
	doc, err := parseJSONC(b)
	if err != nil {
		return // package.json parse errors are not an agent surface
	}
	scripts, _ := doc["scripts"].(map[string]any)
	for _, k := range lifecycle {
		c, _ := scripts[k].(string)
		if c == "" {
			continue
		}
		if _, ok := agentcli.HeadlessBypass(c); ok {
			s.headless(rel, "npm "+k+" script", c)
		}
		why := s.risk(c)
		if len(why) == 0 {
			continue
		}
		s.add(schema.Finding{RuleID: "REPO_LIFECYCLE_SCRIPT_RISK", Severity: "MEDIUM", Title: "Install Script Does More Than Build",
			Description:  fmt.Sprintf("%s: the %s script runs `%s`. Risk: %s. Install scripts run on `npm install` with the developer's credentials — the entry point of s1ngularity, Shai-Hulud and the keyv wave.", rel, k, excerpt(c), strings.Join(why, "; ")),
			EvidenceRefs: []string{rel}, Related: why, MitreATTACK: "T1195.002", MitreATLAS: "AML.T0010",
			FalsePositive: "Native modules download prebuilt binaries at install; check the destination."}, rel+k)
	}
}

// ---- .gitattributes hiding agent config from review

var agentCfgGlob = regexp.MustCompile(`(?i)(\.claude|\.vscode|\.cursor|\.gemini|\.codex|\.mcp\.json|agents\.md|claude\.md|gemini\.md|copilot-instructions|\.devcontainer|\.kiro|\.roo|\.windsurf|\.amazonq)`)
var hideAttrRe = regexp.MustCompile(`(?i)(^|\s)(-diff|binary|linguist-generated(=true)?|linguist-vendored(=true)?|-merge)(\s|$)`)

func (s *scanner) gitattributes(rel string, b []byte) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	n := 0
	for sc.Scan() {
		n++
		l := strings.TrimSpace(sc.Text())
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		f := strings.Fields(l)
		if len(f) < 2 || !agentCfgGlob.MatchString(f[0]) || !hideAttrRe.MatchString(strings.Join(f[1:], " ")) {
			continue
		}
		s.add(schema.Finding{RuleID: "REPO_AGENT_CONFIG_HIDDEN_IN_REVIEW", Severity: "MEDIUM", Title: "Agent Configuration Hidden From Code Review",
			Description:  fmt.Sprintf("%s:%d marks %s as %s, so pull-request diffs collapse or hide changes to agent configuration.", rel, n, f[0], strings.Join(f[1:], " ")),
			EvidenceRefs: []string{fmt.Sprintf("%s:%d", rel, n)}, MitreATTACK: "T1564", MitreATLAS: "AML.T0081"}, rel+l)
	}
}

// ---- .git: config and ref names

var refInjectRe = regexp.MustCompile("(\\$\\(|`|;|\\|\\||&&|\\||\\$\\{|>|<)")

func (s *scanner) gitDir(gd string) {
	if b, ok := readRegular(filepath.Join(gd, "config"), 1<<20); ok {
		section := ""
		for _, l := range strings.Split(string(b), "\n") {
			t := strings.TrimSpace(l)
			if strings.HasPrefix(t, "[") {
				section = strings.ToLower(t)
				continue
			}
			k := strings.ToLower(strings.TrimSpace(strings.SplitN(t, "=", 2)[0]))
			if section == "[core]" && (k == "fsmonitor" || k == "hookspath" || k == "sshcommand" || k == "askpass") ||
				strings.HasPrefix(section, "[credential") && k == "helper" && strings.Contains(t, "!") {
				v := ""
				if p := strings.SplitN(t, "=", 2); len(p) == 2 {
					v = strings.TrimSpace(p[1])
				}
				if k == "fsmonitor" && (v == "true" || v == "false") {
					continue // built-in daemon, not a command
				}
				s.add(schema.Finding{RuleID: "REPO_GIT_EXEC_CONFIG", Severity: "HIGH", Title: "Repository Git Config Runs a Command",
					Description:  fmt.Sprintf(".git/config %s %s = %s: git runs it during ordinary commands (status, fetch) — which agents run constantly.", section, k, excerpt(v)),
					EvidenceRefs: []string{".git/config"}, MitreATTACK: "T1546", MitreATLAS: "AML.T0011"}, section+k)
			}
		}
	}
	var refs []string
	_ = filepath.WalkDir(filepath.Join(gd, "refs"), func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() && len(refs) < 5000 {
			r, _ := filepath.Rel(filepath.Join(gd, "refs"), p)
			refs = append(refs, filepath.ToSlash(r))
		}
		return nil
	})
	if b, ok := readRegular(filepath.Join(gd, "packed-refs"), 16<<20); ok {
		for _, l := range strings.Split(string(b), "\n") {
			if f := strings.SplitN(strings.TrimSpace(l), " ", 2); len(f) == 2 && strings.HasPrefix(f[1], "refs/") {
				refs = append(refs, strings.TrimPrefix(f[1], "refs/"))
			}
		}
	}
	if b, ok := readRegular(filepath.Join(gd, "HEAD"), 4096); ok {
		refs = append(refs, strings.TrimPrefix(strings.TrimSpace(string(b)), "ref: refs/"))
	}
	for _, r := range refs {
		if refInjectRe.MatchString(path.Base(r)) || refInjectRe.MatchString(r) {
			s.add(schema.Finding{RuleID: "REPO_GIT_REF_INJECTION", Severity: "HIGH", Title: "Branch or Tag Name Carries Shell Syntax",
				Description:  fmt.Sprintf("Ref %q contains shell metacharacters. Tools that paste branch names into shell commands run them — OpenAI Codex's branch-name injection (fixed Feb 2026) leaked the GitHub token this way.", excerpt(r)),
				EvidenceRefs: []string{".git/refs/" + r}, MitreATTACK: "T1059.004", MitreATLAS: "AML.T0011"}, r)
		}
	}
}
