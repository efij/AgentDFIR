package extinv

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/decode"
	"github.com/efij/AgentDFIR/v3/internal/netdest"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/shellshape"
)

// Findings derived from the inventory. Heuristics, deliberately
// conservative: each names what it saw so an analyst can check it in the
// entry file. None of them is proof of compromise on its own.

func finding(id, sev, title, desc string, refs []string, attack, atlas, fp string, related ...string) schema.Finding {
	return schema.Finding{
		RuleID: id, Severity: sev, Title: title, Description: desc,
		EvidenceRefs: refs,
		Status:       schema.StateObserved, // files on disk are observed fact
		Endpoint:     schema.StateUnknown,
		MitreATTACK:  attack, MitreATLAS: atlas, FalsePositive: fp,
		Related: related,
	}
}

func extLabel(x Extension) string {
	l := x.ID
	if x.Version != "" {
		l += "@" + x.Version
	}
	return l + " (" + x.Editor + ")"
}

// Evaluate runs every rule over the inventory.
func Evaluate(inv *Inventory) []schema.Finding {
	var out []schema.Finding
	for _, x := range inv.Extensions {
		out = append(out, extensionFindings(x)...)
	}
	scripts := map[string]scriptVerdict{} // one read per hook script, however many hooks run it
	for _, p := range inv.Plugins {
		out = append(out, pluginFindings(p, scripts)...)
	}
	for _, s := range inv.Skills {
		out = append(out, skillFindings(s)...)
	}
	for _, m := range inv.Marketplaces {
		if m.Default {
			continue
		}
		out = append(out, finding("PLUGIN_MARKETPLACE_UNTRUSTED", "INFO", "Plugin Marketplace From a Non-Default Source",
			fmt.Sprintf("Marketplace %q (%s %s) was added to %s alongside the built-in one. Every plugin installed from it runs its hooks and MCP servers with the agent's privileges; whoever controls that source controls the next update.", m.Name, m.Kind, m.Location, m.Host),
			[]string{m.Evidence}, "T1195.002", "AML.T0010.005",
			"Teams and plugin authors add their own marketplaces routinely; check that you recognize the source.",
			"marketplace: "+m.Name, "source: "+m.Location))
	}
	return out
}

func extensionFindings(x Extension) []schema.Finding {
	var out []schema.Finding
	refs := []string{x.Dir}
	if x.Main != "" {
		refs = []string{x.Main}
	}
	rel := []string{"extension: " + x.ID, "editor: " + x.Editor}
	if x.Version != "" {
		rel = append(rel, "version: "+x.Version)
	}
	s := x.signals

	// EXTENSION_INVISIBLE_CODE
	if s.InvisibleRun >= invisibleRunThreshold || (s.PUARun >= puaRunThreshold && (s.Decoder || s.DynamicExec)) {
		sev := "HIGH"
		extra := ""
		if s.Decoder && s.DynamicExec {
			sev = "CRITICAL"
			extra = " The same code does arithmetic on the variation-selector ranges (a decoder) and executes strings dynamically — the GlassWorm loader shape."
		}
		what := fmt.Sprintf("a run of %d consecutive invisible characters (variation selectors, tag, zero-width or filler code points; %d in total)", s.InvisibleRun, s.InvisibleTotal)
		if s.InvisibleRun < invisibleRunThreshold {
			what = fmt.Sprintf("a run of %d consecutive private-use characters next to dynamic code execution", s.PUARun)
		}
		r := append([]string{}, refs...)
		if s.InvisibleOffset >= 0 && x.Main != "" {
			r[0] = fmt.Sprintf("%s @%d", x.Main, s.InvisibleOffset)
		}
		out = append(out, finding("EXTENSION_INVISIBLE_CODE", sev, "Invisible Characters Hidden in Extension Code",
			fmt.Sprintf("Extension %s carries %s in its entry code. Characters that render as nothing can carry a whole program inside what looks like an empty string; the GlassWorm worm (Oct 2025) spread through Open VSX and VS Code extensions this way and stole developer tokens.%s", extLabel(x), what, extra),
			r, "T1027", "", "Legitimate code does not contain long runs of invisible characters; localized text and emoji produce isolated ones. Inspect the bytes at the offset.", rel...))
	}

	// EXTENSION_OBFUSCATED_LOADER
	if len(s.Loader) > 0 {
		sev := "HIGH"
		if len(s.Loader) >= 2 {
			sev = "CRITICAL"
		}
		out = append(out, finding("EXTENSION_OBFUSCATED_LOADER", sev, "Extension Code Decodes or Fetches Code and Runs It",
			fmt.Sprintf("Extension %s: %s. An extension runs with the editor's access to every file, terminal and token in the workspace; a loader that only reveals its code at run time is how second stages are delivered.", extLabel(x), strings.Join(s.Loader, "; ")),
			refs, "T1059.007", "", "Some bundlers and license checks evaluate generated code; read the surrounding code before concluding.", append(rel, s.Loader...)...))
	}

	// EXTENSION_SIDELOADED_UNSIGNED
	switch {
	case x.Present && x.Source == "vsix":
		out = append(out, finding("EXTENSION_SIDELOADED_UNSIGNED", "INFO", "Extension Installed From a VSIX File",
			fmt.Sprintf("Extension %s was installed from a VSIX file rather than from the editor's marketplace. Marketplace review and publisher verification did not apply; where the file came from is the question.", extLabel(x)),
			[]string{x.Dir}, "T1195.002", "", "Internal and pre-release builds are distributed as VSIX files.", rel...))
	case x.Present && !x.Registered && x.registryKnown:
		out = append(out, finding("EXTENSION_SIDELOADED_UNSIGNED", "INFO", "Extension Directory Not in the Editor's Registry",
			fmt.Sprintf("Extension directory %s is not listed in the editor's extensions.json, so the editor recorded no install source or time for it. A directory copied in by hand (or by malware) looks like this; so does a leftover from an uninstall.", x.Dir),
			[]string{x.Dir}, "T1195.002", "", "Editors leave directories behind after uninstall and update; compare with the version the registry lists.", rel...))
	case x.Present && x.Registered && x.Source == "":
		out = append(out, finding("EXTENSION_SIDELOADED_UNSIGNED", "INFO", "Extension Install Source Not Recorded",
			fmt.Sprintf("The editor's registry lists %s without an install source. Older editors and some forks do not record one; it cannot be told apart from a sideload here.", extLabel(x)),
			[]string{x.Dir}, "T1195.002", "", "Common on older VS Code builds and forks.", rel...))
	}

	// EXTENSION_STARTUP_ACTIVATION_WITH_NETWORK
	if x.StartupActivation && s.Network {
		out = append(out, finding("EXTENSION_STARTUP_ACTIVATION_WITH_NETWORK", "LOW", "Extension Starts With the Editor and Uses the Network",
			fmt.Sprintf("Extension %s activates on every editor start (%s) and its entry code contains network calls. It runs before you open anything and can reach the internet without any action from you.", extLabel(x), strings.Join(startupEvents(x.ActivationEvents), ", ")),
			refs, "", "", "Very common: telemetry, update checks and language servers do this. Context for the other findings, not a problem by itself.", rel...))
	}
	return out
}

func startupEvents(ev []string) []string {
	var out []string
	for _, e := range ev {
		if e == "*" || e == "onStartupFinished" {
			out = append(out, e)
		}
	}
	return out
}

// ---- plugin hooks

var (
	// A hook that runs a script shipped with the plugin is judged by the script.
	pluginScriptRe = regexp.MustCompile(`\$\{?CLAUDE_PLUGIN_ROOT\}?/([A-Za-z0-9._/-]+\.(?:sh|bash|zsh|js|mjs|cjs|ts|py|rb|ps1|pl|cmd))`)
	// `bash -c "$(curl …)"`, `sh <(curl …)`, `eval "$(wget -qO- …)"`.
	subshellFetchRe = regexp.MustCompile(`(?i)\b((ba|z|da)?sh|eval|source)\s+(-c\s+)?["']?\$\(\s*(curl|wget)\b|<\(\s*(curl|wget)\b`)
	fetchVerbs      = map[string]bool{"curl": true, "wget": true, "iwr": true, "irm": true, "invoke-webrequest": true, "invoke-restmethod": true}
	shellVerbRe     = regexp.MustCompile(`^((ba|z|da|k)?sh|iex|invoke-expression|python[0-9.]*|node|perl|ruby|pwsh|powershell)$`)
)

// startupHookEvents run without any tool call: the hook fires because a
// session started or a prompt was typed.
var startupHookEvents = map[string]bool{"SessionStart": true, "UserPromptSubmit": true, "Setup": true, "Notification": true}

func pluginFindings(p Plugin, scripts map[string]scriptVerdict) []schema.Finding {
	var out []schema.Finding
	for _, h := range p.Hooks {
		why, strong := hookRisk(h.Command)
		why2, strong2 := hookScriptRisk(p, h.Command, scripts)
		why = append(why, why2...)
		strong = strong || strong2
		if len(why) == 0 {
			continue
		}
		startup := startupHookEvents[h.Event]
		sev := "MEDIUM"
		switch {
		case strong && startup:
			sev = "CRITICAL"
		case strong:
			sev = "HIGH"
		}
		if !p.Registered && sev != "MEDIUM" {
			sev = map[string]string{"CRITICAL": "HIGH", "HIGH": "MEDIUM"}[sev]
		}
		label := p.Name
		if p.Marketplace != "" {
			label += "@" + p.Marketplace
		}
		desc := fmt.Sprintf("Plugin %s (%s) registers a %s hook that runs `%s`. Risk: %s.", label, p.Host, h.Event, excerpt(h.Command), strings.Join(why, "; "))
		if startup {
			desc += " It fires when a session starts or a prompt is sent — no tool call, no approval."
		}
		if !p.Registered {
			desc += " The plugin is not in the install registry (cache leftover or unknown state), so the hook may not be active."
		}
		out = append(out, finding("PLUGIN_HOOK_EXECUTES_REMOTE", sev, "Agent Plugin Hook Downloads or Decodes Code and Runs It",
			desc, []string{firstNonEmpty(h.File, p.Dir)}, "T1105", "AML.T0010.005",
			"Plugins that install a helper on first run use network hooks; the signal is a pipe into a shell, a decoded payload, or a download at session start.",
			"plugin: "+label, "event: "+h.Event))
	}
	return out
}

// pipesDownloadToShell: a download stage whose output flows, through an
// unbroken pipeline, into an interpreter — judged on the command as the
// shell parses it, so `grep -E 'curl|sh'` (a pattern) is not a pipeline.
func pipesDownloadToShell(cmd string) bool {
	if subshellFetchRe.MatchString(cmd) {
		return true
	}
	fetching := false
	for _, st := range shellshape.Stages(shellshape.Strip(shellshape.ExpandVars(cmd))) {
		if !st.Piped {
			fetching = false
		}
		f := strings.Fields(st.Text)
		v := strings.ToLower(shellshape.Verb(st.Text))
		if v == "sudo" && len(f) > 1 {
			v = strings.ToLower(f[1])
		}
		if fetching && shellVerbRe.MatchString(v) {
			return true
		}
		if fetchVerbs[v] {
			fetching = true
		}
	}
	return false
}

// hookRisk judges the hook command itself. strong = remote code or a
// decoded payload is executed; network alone is weaker.
func hookRisk(cmd string) (why []string, strong bool) {
	if pipesDownloadToShell(cmd) || shellshape.DownloadThenExecute(cmd) {
		why = append(why, "downloads code and runs it")
		strong = true
	}
	if decode.ExecutesDecoded(shellshape.Strip(cmd)) || len(decode.FindInCommand(cmd)) > 0 {
		why = append(why, "decodes and runs an embedded payload")
		strong = true
	}
	if !strong && netdest.IsOutbound(cmd) {
		why = append(why, "opens a network connection")
	}
	return why, strong
}

type scriptVerdict struct {
	why    []string
	strong bool
}

// hookScriptRisk reads a script the hook runs from the plugin's own
// directory (bounded; never outside the plugin). A security plugin's own
// guard scripts quote the commands they block and are not judged by them.
func hookScriptRisk(p Plugin, cmd string, cache map[string]scriptVerdict) (why []string, strong bool) {
	if p.tr == nil || shellshape.SelfReferentialPath(p.Dir) {
		return nil, false
	}
	for _, m := range pluginScriptRe.FindAllStringSubmatch(cmd, 4) {
		rel, ok := inside(m[1])
		if !ok {
			continue
		}
		key := p.Dir + "\x00" + rel
		v, done := cache[key]
		if !done {
			v = judgeScript(p, rel)
			cache[key] = v
		}
		why = append(why, v.why...)
		strong = strong || v.strong
	}
	return why, strong
}

// scriptLineRe preselects the lines of a shell script worth parsing:
// downloads, decoders and interpreters.
var scriptLineRe = regexp.MustCompile(`(?i)\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod|base64|xxd|base32|gunzip|zcat|eval|iex|frombase64string|sh|bash|zsh|python[0-9.]*|node|perl|chmod)\b`)

func judgeScript(p Plugin, rel string) scriptVerdict {
	var v scriptVerdict
	b, _, err := p.tr.read(join(p.rel, rel), 1<<20)
	if err != nil {
		return v
	}
	switch strings.ToLower(path.Ext(rel)) {
	case ".js", ".mjs", ".cjs", ".ts":
		s := scanCode(b)
		if len(s.Loader) > 0 {
			v.why = append(v.why, rel+": "+strings.Join(s.Loader, "; "))
			v.strong = true
		}
		if s.InvisibleRun >= invisibleRunThreshold {
			v.why = append(v.why, fmt.Sprintf("%s hides %d consecutive invisible characters", rel, s.InvisibleRun))
			v.strong = true
		}
		return v
	}
	// Shell and other scripts: only the lines that download, decode or run
	// an interpreter are parsed, one line at a time (shell parsing of a
	// whole large script is quadratic); a download saved in one line and
	// run in another is caught on the selected lines joined.
	var sel []string
	for _, line := range strings.Split(string(b), "\n") {
		if len(sel) >= 2000 {
			break
		}
		if len(line) > 4096 || !scriptLineRe.MatchString(line) {
			continue
		}
		sel = append(sel, line)
		switch {
		case !v.strong && pipesDownloadToShell(line):
			v.why = append(v.why, rel+" downloads code and runs it")
			v.strong = true
		case !v.strong && decode.ExecutesDecoded(shellshape.Strip(line)):
			v.why = append(v.why, rel+" decodes and runs an embedded payload")
			v.strong = true
		}
	}
	if !v.strong && shellshape.DownloadThenExecute(strings.Join(sel, "\n")) {
		v.why = append(v.why, rel+" downloads a file and runs it")
		v.strong = true
	}
	return v
}

var secretish = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{24,}`)

// excerpt: at most 120 characters, long tokens masked — enough to
// recognize a command, never enough to carry a secret into a report.
func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = secretish.ReplaceAllStringFunc(s, func(t string) string {
		if strings.Contains(t, "/") && !strings.ContainsAny(t, "+=") {
			return t
		}
		return t[:4] + "…"
	})
	if r := []rune(s); len(r) > 120 {
		s = string(r[:117]) + "…"
	}
	return s
}

// ---- skills

func skillFindings(s Skill) []schema.Finding {
	h := s.hidden
	var out []schema.Finding
	label := s.Name
	if s.Plugin != "" {
		label += " (plugin " + s.Plugin + ")"
	}
	rel := []string{"kind: " + s.Kind, "host: " + s.Host}
	if h.invisible() {
		sev := "MEDIUM"
		if h.Tags > 0 || h.VS >= invisibleRunThreshold {
			sev = "HIGH"
		}
		out = append(out, finding("SKILL_HIDDEN_INSTRUCTIONS", sev, "Invisible Characters in an Agent Skill or Definition",
			fmt.Sprintf("The %s %s contains %d Unicode tag, %d variation-selector, %d bidi-control and %d zero-width characters. The model reads text a reviewer cannot see; a skill is loaded as trusted instructions.", s.Kind, label, h.Tags, h.VS, h.Bidi, h.ZeroWidth),
			[]string{s.Path}, "T1027", "AML.T0110", "Bidi controls occur in right-to-left text and zero-width joiners in emoji; tag characters have no legitimate use here.", rel...))
	}
	switch {
	case h.Phrase != "":
		out = append(out, finding("SKILL_HIDDEN_INSTRUCTIONS", "MEDIUM", "Instruction Override in an Agent Skill or Definition",
			fmt.Sprintf("The %s %s contains the phrase %q. Skills, sub-agent and command definitions are read by the model as trusted instructions whenever they are invoked.", s.Kind, label, h.Phrase),
			[]string{s.Path}, "", "AML.T0110", "Security skills discuss injection phrases to teach the model to resist them; read the context.", rel...))
	case h.QuotedPhrase != "":
		out = append(out, finding("SKILL_HIDDEN_INSTRUCTIONS", "INFO", "Quoted Instruction-Override Phrase in an Agent Skill or Definition",
			fmt.Sprintf("The %s %s quotes the phrase %q. Quoted, it is usually a defensive example of what to refuse; listed so a quote used as cover can still be reviewed.", s.Kind, label, h.QuotedPhrase),
			[]string{s.Path}, "", "AML.T0110", "Defensive skills quote these phrases.", rel...))
	}
	return out
}
