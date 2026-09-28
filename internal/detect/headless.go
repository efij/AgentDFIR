package detect

import (
	"bufio"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/agentcli"
	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/shellshape"
)

// historyNames are the shell histories the host-shell product collects.
var historyNames = map[string]bool{".zsh_history": true, ".bash_history": true, "fish_history": true, "ConsoleHost_history.txt": true}

// maxHistoryBytes bounds how much of one history file is read.
const maxHistoryBytes = 64 << 20

// shellHistoryRules — AI_CLI_HEADLESS_BYPASS in the user's shell history.
//
// Inside an agent transcript the same shape is NESTED_AGENT_PERMISSION_BYPASS
// (an agent starting another agent). In shell history there is no agent
// parent: a person or a script ran it. s1ngularity's postinstall did not use
// a shell, so its launch is not here; a copy-pasted "run this to set up" is.
// MEDIUM: developers script headless agents themselves.
func shellHistoryRules(man *casepkg.Manifest, store *casepkg.Store) []schema.Finding {
	var out []schema.Finding
	for _, a := range man.Current() {
		if !isType(a, "shell_state") || !historyNames[path.Base(strings.ReplaceAll(a.LogicalPath, `\`, "/"))] {
			continue
		}
		f, err := store.Open(a.ArtifactID)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(io.LimitReader(f, maxHistoryBytes))
		sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
		var off int64
		n := 0
		for sc.Scan() && n < 20 {
			line := sc.Text()
			lineOff := off
			off += int64(len(line)) + 1
			cmd := histCommand(line)
			if cmd == "" {
				continue
			}
			m, ok := agentcli.HeadlessBypass(cmd)
			if !ok || m.Weak {
				continue
			}
			n++
			out = append(out, schema.Finding{
				RuleID: "AI_CLI_HEADLESS_BYPASS", Severity: "MEDIUM",
				Title:        "AI Agent CLI Run Headless With Approvals Disabled",
				Description:  fmt.Sprintf("Shell history runs %s non-interactively (%s) with permission checks off (%s): whatever the prompt asks, the agent does without asking. This is how the Nx s1ngularity malware used installed AI CLIs to search for secrets.", m.CLI, m.Headless, m.Bypass),
				EvidenceRefs: []string{artRef(a, lineOff)},
				Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
				MitreATTACK: "T1059", MitreATLAS: "AML.T0103",
				FalsePositive: "Developers script headless agents in trusted CI-like loops; check what the prompt asked for.",
			})
		}
		f.Close()
	}
	return out
}

// histCommand strips zsh extended-history and fish metadata.
func histCommand(l string) string {
	l = strings.TrimSpace(l)
	switch {
	case strings.HasPrefix(l, ": "):
		if i := strings.Index(l, ";"); i >= 0 {
			return strings.TrimSpace(l[i+1:])
		}
	case strings.HasPrefix(l, "- cmd: "):
		return strings.TrimSpace(strings.TrimPrefix(l, "- cmd: "))
	case strings.HasPrefix(l, "when: ") || strings.HasPrefix(l, "paths:"):
		return ""
	}
	return l
}

// The s1ngularity prompt, paraphrased by every write-up: recursively search
// the file system for wallets, keystores, .env files and keys, and write
// the paths to /tmp/inventory.txt. Three parts, close together.
var (
	huntVerbRe   = regexp.MustCompile(`(?i)\b(recursive(ly)?|search|scan|find|enumerate|inventory|locate|crawl)\b`)
	huntTargetRe = regexp.MustCompile(`(?i)(wallet|keystore|metamask|electrum|exodus|phantom|mnemonic|seed phrase|id_rsa|\.env\b|private key|\.npmrc|aws/credentials|\.ssh\b|keychain|ledger)`)
	huntSinkRe   = regexp.MustCompile(`(?i)\b(write|save|append|output|list|record)\b[^.\n]{0,80}(/tmp/\S+|inventory|a file|\.txt)`)
	// The first message of an analyst's own session about the incident
	// quotes the prompt; so does a detection rule. Those are not the attack.
	huntAboutRe = regexp.MustCompile(`(?i)\b(malware|analy[sz]e|detect(ion)?|ioc|incident|s1ngularity|write-?up|threat|forensic|sigma|yara|rule)\b`)
)

const huntPrefix = 256 << 10 // first user message is near the top

// headlessSecretHunt — HEADLESS_AGENT_SECRET_HUNT: the first user message of
// a session instructs the agent to hunt for credentials and write them to a
// file. Only the opening message counts; later messages that discuss such a
// prompt are conversation, not a launch.
func headlessSecretHunt(man *casepkg.Manifest, store *casepkg.Store) []schema.Finding {
	var out []schema.Finding
	for _, a := range man.Current() {
		if !isType(a, "agent_session") || shellshape.SelfReferentialPath(a.LogicalPath) {
			continue
		}
		f, err := store.Open(a.ArtifactID)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(io.LimitReader(f, huntPrefix))
		sc.Buffer(make([]byte, 0, 64<<10), huntPrefix)
		var off int64
		for sc.Scan() {
			line := sc.Text()
			lineOff := off
			off += int64(len(line)) + 1
			if !strings.Contains(line, `"role":"user"`) && !strings.Contains(line, `"type":"user"`) && !strings.Contains(line, `"role": "user"`) {
				continue
			}
			if strings.Contains(line, `"tool_result"`) || strings.Contains(line, `"function_call_output"`) {
				continue
			}
			if secretHuntPrompt(line) {
				out = append(out, schema.Finding{
					RuleID: "HEADLESS_AGENT_SECRET_HUNT", Severity: "HIGH",
					Title:        "Session Opened With an Instruction to Hunt for Secrets",
					Description:  "The first user message of this session tells the agent to search the file system for wallets, keys or credential files and write what it finds to a file — the Nx s1ngularity prompt shape. Check what launched the session (a package install script, a hook) and what the agent read.",
					EvidenceRefs: []string{artRef(a, lineOff)},
					Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
					MitreATTACK: "T1552.001", MitreATLAS: "AML.T0055",
					FalsePositive: "A user asking an agent to audit their own machine for leaked keys reads the same; check who started the session.",
				})
			}
			break // only the first user message
		}
		f.Close()
	}
	return out
}

func secretHuntPrompt(s string) bool {
	if huntAboutRe.MatchString(s) {
		return false
	}
	for _, v := range huntVerbRe.FindAllStringIndex(s, 8) {
		lo, hi := v[0], v[1]+400
		if hi > len(s) {
			hi = len(s)
		}
		win := s[lo:hi]
		targets := map[string]bool{}
		for _, m := range huntTargetRe.FindAllString(win, -1) {
			targets[strings.ToLower(m)] = true
		}
		if len(targets) >= 2 && huntSinkRe.MatchString(win) {
			return true
		}
	}
	return false
}
