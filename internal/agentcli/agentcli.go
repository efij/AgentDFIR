// Package agentcli recognises AI coding-agent CLIs launched headless with
// their permission checks switched off — the shape of the Nx "s1ngularity"
// compromise (August 2025), whose npm postinstall ran the victim's own
// `claude`, `gemini` and `q` to search the disk for secrets:
//
//	claude --dangerously-skip-permissions -p "<prompt>"
//	gemini --yolo -p "<prompt>"
//	q chat --trust-all-tools --no-interactive "<prompt>"
//
// Matching is on shell stages with quoted prose removed (shellshape.Strip),
// so a `|` or `&` inside the prompt does not split the command, and flags
// in any order or `--flag=value` form are found.
package agentcli

import (
	"path"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/shellshape"
)

// Match is one headless, permission-bypassing agent CLI invocation.
type Match struct {
	CLI      string // claude, codex, gemini, q, cursor-agent, copilot
	Headless string // the flag or subcommand that makes it non-interactive
	Bypass   string // the flag that disables approvals
	// Weak marks a documented CI mode that still sandboxes (codex
	// --full-auto): worth recording, not worth an alert on its own.
	Weak bool
}

// packages map npx/bunx/pnpm dlx package specs to the CLI they launch.
var packages = map[string]string{
	"@anthropic-ai/claude-code": "claude",
	"@openai/codex":             "codex",
	"@google/gemini-cli":        "gemini",
	"@github/copilot":           "copilot",
}

// HeadlessBypass reports the first stage of cmd that launches an agent CLI
// headless with approvals disabled.
func HeadlessBypass(cmd string) (Match, bool) {
	stripped := shellshape.Strip(shellshape.ExpandVars(cmd))
	for _, st := range shellshape.Stages(stripped) {
		if m, ok := stage(strings.Fields(st.Text)); ok {
			return m, true
		}
	}
	return Match{}, false
}

func cliOf(tok string) string {
	t := strings.Trim(tok, `"'`)
	if t == "" {
		return ""
	}
	at := t
	if i := strings.LastIndex(at[1:], "@"); strings.HasPrefix(at, "@") && i >= 0 {
		at = at[:i+1] // @scope/pkg@1.2.3 → @scope/pkg
	} else if i := strings.Index(at, "@"); i > 0 {
		at = at[:i]
	}
	if c, ok := packages[at]; ok {
		return c
	}
	b := path.Base(strings.ReplaceAll(t, `\`, "/"))
	b = strings.TrimSuffix(strings.TrimSuffix(b, ".exe"), ".cmd")
	switch b {
	case "claude", "codex", "gemini", "q", "cursor-agent", "copilot":
		return b
	}
	return ""
}

// launchers are words that run the next word: skip them to reach the CLI.
var launchers = map[string]bool{"sudo": true, "env": true, "exec": true, "nohup": true, "npx": true, "bunx": true, "time": true, "command": true, "node": true, "timeout": true}

func stage(f []string) (Match, bool) {
	i := 0
	for i < len(f) {
		w := f[i]
		switch {
		case strings.Contains(w, "=") && !strings.HasPrefix(w, "-"):
			i++ // VAR=value
			continue
		case launchers[path.Base(w)] || (strings.HasPrefix(w, "-") && i > 0 && launchers[path.Base(f[i-1])]):
			i++
			continue
		case (w == "pnpm" || w == "yarn" || w == "npm") && i+1 < len(f) && (f[i+1] == "dlx" || f[i+1] == "exec" || f[i+1] == "x"):
			i += 2
			continue
		case strings.HasSuffix(w, "cli.js") || strings.HasSuffix(w, ".js") && strings.Contains(w, "claude-code"):
			// node …/@anthropic-ai/claude-code/cli.js
			if strings.Contains(w, "claude-code") {
				return flags("claude", f[i+1:])
			}
		}
		break
	}
	if i >= len(f) {
		return Match{}, false
	}
	cli := cliOf(f[i])
	if cli == "" {
		return Match{}, false
	}
	return flags(cli, f[i+1:])
}

// flagVal splits --flag=value; value is "" for a bare flag.
func flagVal(a string) (string, string) {
	if i := strings.Index(a, "="); i > 0 && strings.HasPrefix(a, "-") {
		return a[:i], strings.Trim(a[i+1:], `"'`)
	}
	return a, ""
}

func flags(cli string, args []string) (Match, bool) {
	m := Match{CLI: cli}
	next := func(i int) string {
		if i+1 < len(args) {
			return strings.Trim(args[i+1], `"'`)
		}
		return ""
	}
	for i, a := range args {
		f, v := flagVal(a)
		val := v
		if val == "" {
			val = next(i)
		}
		switch cli {
		case "claude":
			switch {
			case f == "-p" || f == "--print":
				m.Headless = f
			case f == "--dangerously-skip-permissions":
				m.Bypass = f
			case f == "--permission-mode" && strings.EqualFold(val, "bypassPermissions"):
				m.Bypass = f + " " + val
			}
		case "codex":
			switch {
			case i == 0 && (f == "exec" || f == "e"):
				m.Headless = "exec"
			case f == "--dangerously-bypass-approvals-and-sandbox" || f == "--yolo":
				m.Bypass = f
			case (f == "-s" || f == "--sandbox") && val == "danger-full-access":
				m.Bypass = f + " " + val
			case (f == "-a" || f == "--ask-for-approval") && val == "never":
				m.Bypass = f + " " + val
			case f == "-c" && strings.ReplaceAll(strings.ReplaceAll(val, `"`, ""), " ", "") == "approval_policy=never":
				m.Bypass = "-c approval_policy=never"
			case f == "--full-auto" && m.Bypass == "":
				m.Bypass, m.Weak = f, true
			}
		case "gemini":
			switch {
			case f == "-p" || f == "--prompt":
				m.Headless = f
			case f == "--yolo" || f == "-y":
				m.Bypass = f
			case f == "--approval-mode" && val == "yolo":
				m.Bypass = f + " " + val
			}
		case "q":
			switch {
			case i == 0 && f == "chat":
			case f == "--no-interactive":
				m.Headless = f
			case f == "--trust-all-tools":
				m.Bypass = f
			}
		case "cursor-agent":
			switch {
			case f == "-p" || f == "--print":
				m.Headless = f
			case f == "--force" || f == "-f":
				m.Bypass = f
			}
		case "copilot":
			switch {
			case f == "-p" || f == "--prompt":
				m.Headless = f
			case f == "--allow-all-tools":
				m.Bypass = f
			}
		}
	}
	if m.Bypass != "" && m.Bypass != "--full-auto" {
		m.Weak = false
	}
	return m, m.Headless != "" && m.Bypass != ""
}
