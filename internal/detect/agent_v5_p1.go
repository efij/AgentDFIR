// v5 agent-behaviour rules (P1/P2): sequences inside one agent's event
// stream, and the scope a delegated agent was given versus what it did.
//
// Each rule was checked against the existing catalog first; the dedupe
// verdicts, thresholds and what each rule deliberately does not cover are in
// docs/detection-v5.md. None of them states an intent. Autonomous
// discovery can be legitimate, a sequence is not causation, a definition
// that omits a tool is not proof the call was unauthorized when it ran, and
// a field the parser did not fill is never read as "clean".
package detect

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/accounts"
	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/netdest"
	"github.com/efij/AgentDFIR/v5/internal/schema"
	"github.com/efij/AgentDFIR/v5/internal/shellshape"
)

// agentRulesV5P1 runs the v5 P1/P2 rules. man may be nil: the delegation
// rule then has no agent definitions or extra directories to compare with
// and reports only what the events alone show.
func agentRulesV5P1(ix *eventIndex, pkgDir string, man *casepkg.Manifest) []schema.Finding {
	var out []schema.Finding
	out = append(out, autonomousRecon(ix)...)
	out = append(out, adaptiveAttack(ix)...)
	out = append(out, resourceExhaustion(ix)...)
	out = append(out, multimodalTrigger(ix)...)
	var defs []agentDef
	var dirs []extraDir
	if man != nil {
		store := casepkg.NewStore(pkgDir, man)
		defs = loadAgentDefs(store, man)
		dirs = loadExtraDirs(store, man)
	}
	out = append(out, delegationScope(ix, defs, dirs)...)
	return out
}

// strongestState is the evidence state a multi-event finding carries: the
// best-corroborated of its events, so endpoint confirmation of any step is
// not lost, and OBSERVED otherwise.
func strongestState(evs []schema.Event) string {
	st := schema.StateObserved
	for _, e := range evs {
		switch e.Corroboration {
		case schema.StateCorroborated:
			return schema.StateCorroborated
		case schema.StatePartial:
			st = schema.StatePartial
		}
	}
	return st
}

// ---------------------------------------------------------------------------
// AGENT_AUTONOMOUS_RECON_SEQUENCE

// Recon thresholds. A run is the agent's tool calls between two
// instructions (a person's prompt, or the parent's message to a subagent).
// It is reported when, inside one sliding window, it holds at least
// reconMinActions discovery calls spanning at least reconMinKinds distinct
// resource kinds. Six calls over three kinds in ten minutes is above what
// orientation in a repository produces (git status, ls, reading a README
// are not discovery here) and below a scripted sweep.
const (
	reconMinActions = 6
	reconMinKinds   = 3
	reconWindow     = 10 * time.Minute
	reconMaxRun     = 256 // bound on the calls one run keeps
	reconMaxRefs    = 6
)

// Discovery classifiers, per shell stage after quoted prose and heredoc
// bodies are set aside (shellshape.Strip). Credential paths reuse
// sensitivePathRe (SENSITIVE_FILE_READ), agent configuration reuses the
// AGENT_CONFIG_DISCOVERY file set, metadata endpoints reuse netdest.
var (
	reconAgentCfgRe  = regexp.MustCompile(`(?i)(\.claude/settings(\.local)?\.json|(^|/|~)\.mcp\.json|\.cursor/mcp\.json|claude_desktop_config\.json|\.codex/config\.toml|\.gemini/settings\.json|(^|/|~)\.claude\.json)$`)
	reconAgentCLIRe  = regexp.MustCompile(`(?i)^(claude|codex|gemini)\s+mcp\s+(list|get)\b`)
	reconSystemRe    = regexp.MustCompile(`(?i)^(whoami|id|uname|sw_vers|systeminfo|lsb_release|groups|w|who|last|csrutil\s+status|system_profiler|getent\s+(passwd|group)|dscl\s+\.\s+(-)?list|net\s+(user|localgroup|group)|sudo\s+-l|ps\s+(aux|-ef|-e\b|ax))\b`)
	reconSystemFile  = regexp.MustCompile(`^(/etc/(passwd|group|os-release|sudoers)|/proc/(version|cpuinfo|self/status))$`)
	reconNetworkRe   = regexp.MustCompile(`(?i)^(ifconfig|ipconfig|netstat|ss\s+-|arp\s+-|route\s+(-n|print)|ip\s+(a|addr|address|r|route|link|neigh)\b|nmap|masscan|zmap|traceroute|tracert|nslookup|dig|scutil\s+--(dns|proxy)|networksetup\s+-list)\b`)
	reconNetworkFile = regexp.MustCompile(`^/etc/(hosts|resolv\.conf)$`)
	reconCloudRe     = regexp.MustCompile(`(?i)^(aws\s+(\S+\s+(list-|describe-|get-caller-identity)|s3\s+ls|configure\s+list)|gcloud\s+(.+\s)?(list|describe)\b|gcloud\s+(config|auth)\s+list|az\s+(account\s+(show|list)|.+\s(list|show)\b)|kubectl\s+(get|describe|auth\s+can-i|config\s+(view|get-contexts)|cluster-info)\b|doctl\s+.+\slist\b|terraform\s+state\s+(list|show))`)
	reconSCMRe       = regexp.MustCompile(`(?i)^(gh\s+(auth\s+status|api\s+user\b|repo\s+list|org\s+list)|glab\s+auth\s+status|git\s+config\s+(--list|-l\b|--get-regexp|--global\s+--list))`)
	reconSecretRe    = regexp.MustCompile(`(?i)^(security\s+(find-generic-password|find-internet-password|dump-keychain)|gh\s+auth\s+token|aws\s+(secretsmanager\s+(list-secrets|get-secret-value)|ssm\s+get-parameters?)|vault\s+(kv\s+)?(get|list|read)|gcloud\s+secrets\s+(list|versions\s+access)|az\s+keyvault\s+secret\s+(list|show)|op\s+(read|item\s+(get|list))|kubectl\s+get\s+secrets?)\b`)
	reconEnvRe       = regexp.MustCompile(`(?i)^(printenv|set|export\s+-p|export|declare\s+-x|(get-childitem|gci|dir|ls)\s+env:)$|^printenv\s|^(cat|strings)\s+/proc/(self|\d+)/environ\b`)
)

// discoveryKinds returns the resource kinds a tool call enumerates or
// reads, or nil when it is not discovery. Paths under scratch space or the
// tool's own development tree are not counted.
func discoveryKinds(e schema.Event) []string {
	if e.EventType != schema.EventToolCall {
		return nil
	}
	set := map[string]bool{}
	fileKind := func(p string) {
		p = strings.TrimSpace(strings.Trim(p, `"'`))
		if p == "" || IsScratchPath(p) || shellshape.SelfReferentialPath(p) {
			return
		}
		switch {
		case reconAgentCfgRe.MatchString(p):
			set["agent_config"] = true
		case reconSystemFile.MatchString(p):
			set["system"] = true
		case reconNetworkFile.MatchString(p):
			set["network"] = true
		default:
			if _, ok := containsSensitivePath(p); ok {
				set["credential"] = true
			}
		}
	}
	switch e.Tool {
	case "Read", "Grep", "Glob", "NotebookRead", "LS":
		fileKind(e.File)
		if p := e.SafeArgs["path"]; p != "" {
			fileKind(p)
		}
	}
	cmd := e.FullCommand()
	if cmd != "" && e.Command != "" {
		readOnly := IsReadOnlyCommand(cmd)
		for _, st := range shellshape.Stages(shellshape.Strip(shellshape.ExpandVars(cmd))) {
			text := strings.TrimSpace(st.Text)
			f := strings.Fields(text)
			if len(f) == 0 {
				continue
			}
			if f[0] == "sudo" && len(f) > 1 && f[1] != "-l" {
				text, f = strings.Join(f[1:], " "), f[1:]
			}
			switch {
			case reconSecretRe.MatchString(text):
				set["credential"] = true
			case reconAgentCLIRe.MatchString(text):
				set["agent_config"] = true
			case reconCloudRe.MatchString(text):
				set["cloud"] = true
			case reconSCMRe.MatchString(text):
				set["scm"] = true
			case reconNetworkRe.MatchString(text):
				set["network"] = true
			case reconSystemRe.MatchString(text):
				set["system"] = true
			case reconEnvRe.MatchString(text) || (f[0] == "env" && allFlags(f[1:])):
				set["environment"] = true
			}
			for _, d := range netdest.Extract(text) {
				if netdest.IsCloudMetadata(d) {
					set["cloud"] = true
				}
			}
			if readOnly && readOnlyVerbs[shellshape.Verb(text)] {
				for _, a := range f[1:] {
					if !strings.HasPrefix(a, "-") {
						fileKind(a)
					}
				}
			}
		}
	}
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func allFlags(f []string) bool {
	for _, a := range f {
		if !strings.HasPrefix(a, "-") {
			return false
		}
	}
	return true
}

// AGENT_AUTONOMOUS_RECON_SEQUENCE — an agent ran a burst of discovery
// calls (credentials, environment, system, network, cloud, code-hosting
// identity, its own agent configuration) spanning several resource kinds,
// with no instruction between them. Each call on its own is ordinary; the
// breadth without a prompt asking for it is the question. A trace gap
// inside the run ends it: a lost line may have been the instruction.
func autonomousRecon(ix *eventIndex) []schema.Finding {
	type hit struct {
		ev    schema.Event
		kinds []string
	}
	var out []schema.Finding
	for _, agent := range ix.agents {
		var run []hit
		reported := false
		for _, i := range ix.byAgent[agent] {
			e := ix.events[i]
			if isInstruction(e) || e.EventType == schema.EventTraceGap {
				run, reported = run[:0], false
				continue
			}
			kinds := discoveryKinds(e)
			if kinds == nil || reported || multiSessionStore(e) {
				continue
			}
			run = append(run, hit{e, kinds})
			if len(run) > reconMaxRun {
				run = run[1:]
			}
			// Slide the window: calls older than reconWindow before this
			// one no longer belong to the same burst. Without clocks the
			// order alone links them.
			if t, ok := parseTS(e.Timestamp); ok {
				for len(run) > 0 {
					t0, ok := parseTS(run[0].ev.Timestamp)
					if !ok || t.Sub(t0) <= reconWindow {
						break
					}
					run = run[1:]
				}
			}
			if len(run) < reconMinActions {
				continue
			}
			kindSet := map[string]bool{}
			for _, h := range run {
				for _, k := range h.kinds {
					kindSet[k] = true
				}
			}
			if len(kindSet) < reconMinKinds {
				continue
			}
			reported = true
			kindList := make([]string, 0, len(kindSet))
			for k := range kindSet {
				kindList = append(kindList, k)
			}
			sort.Strings(kindList)
			evs := make([]schema.Event, 0, len(run))
			var refs []string
			for _, h := range run {
				evs = append(evs, h.ev)
				if len(refs) < reconMaxRefs {
					refs = append(refs, ref(h.ev))
				}
			}
			state := strongestState(evs)
			sev, conf := "MEDIUM", "MEDIUM"
			reasons := []string{fmt.Sprintf("%d discovery calls over %d resource kinds with no instruction between them (thresholds: %d calls, %d kinds, %s window)",
				len(run), len(kindList), reconMinActions, reconMinKinds, reconWindow)}
			if kindSet["credential"] && state == schema.StateCorroborated {
				sev, conf = "HIGH", "HIGH"
				reasons = append(reasons, "credential discovery is part of the burst and an independent witness corroborates at least one of its calls")
			}
			first := run[0].ev
			out = append(out, schema.Finding{
				RuleID: "AGENT_AUTONOMOUS_RECON_SEQUENCE", Severity: sev,
				Title: "Agent Ran a Discovery Sweep Without an Instruction",
				Description: fmt.Sprintf("Between two instructions the agent issued %d discovery calls spanning %s, starting with %s. Each call is ordinary on its own; together they enumerate the environment without a prompt asking for it in between.",
					len(run), strings.Join(kindList, ", "), describeCall(first)),
				SessionID: e.SessionID, AgentID: e.AgentID,
				Related:      []string{"resource kinds: " + strings.Join(kindList, ", "), "first discovery call: " + ref(first)},
				EvidenceRefs: refs,
				Status:       state, Endpoint: schema.StateUnknown,
				MitreATTACK: "T1082", MitreATLAS: "AML.T0116",
				Confidence: conf, Reasons: reasons, Timestamp: first.Timestamp,
				FalsePositive: "Autonomous discovery can be legitimate: debugging a broken toolchain, a cloud task, or an onboarding prompt (\"figure out how this machine is set up\") produces the same burst. The instruction before the run decides; read it. Sequence is not intent.",
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AGENT_ADAPTIVE_ATTACK_SEQUENCE

// adaptiveWindow bounds how long after a blocked call a different method
// toward the same target still counts as the same attempt; adaptiveMaxOpen
// bounds the blocked calls one agent keeps open at a time.
const (
	adaptiveWindow  = 30 * time.Minute
	adaptiveMaxOpen = 16
)

// accessDeniedRe is a failure that is an access-control decision, not a
// bug: the OS, a cloud API or an HTTP server refused. Ordinary failures
// (a failing test, a missing file, a typo) are deliberately not blocks.
var accessDeniedRe = regexp.MustCompile(`(?i)(permission denied|operation not permitted|access ?denied|unauthorizedoperation|not authorized to perform|\b403 forbidden\b|\bforbidden\b.{0,40}\b403\b|\b(401|403)\b.{0,20}(unauthorized|forbidden)|EACCES|EPERM|insufficient (permissions|privileges)|requires (root|sudo|elevated) privileges|must be run as root)`)

// userFeedbackRe is the start of the text a client appends to a rejection
// when the person typed what to do instead. The summary is cut at 200
// characters, so the phrase is matched by its head.
var userFeedbackRe = regexp.MustCompile(`(?i)to tell you how to proc|the user said:`)

// blockedKind says why a tool call was blocked, or "" when it was not.
// policy is true for a refusal or a recorded denial (the user, a deny rule,
// an approval decision); false for an access-control error.
func blockedKind(call, res schema.Event) (kind string, policy bool) {
	switch {
	case userFeedbackRe.MatchString(res.Summary):
		return "", false // the rejection carries the person's next instruction
	case refusal(res) != "":
		return refusal(res), true
	case res.ResultStatus == "denied" || call.ResultStatus == "denied":
		return "denied (recorded result status)", true
	case res.ApprovalState == "denied" || call.ApprovalState == "denied":
		return "denied by the recorded approval decision", true
	case (res.Result == "error" || res.ResultStatus == "error") && accessDeniedRe.MatchString(res.Summary):
		return "refused with an access-control error", false
	}
	return "", false
}

// target is one thing a call acts on. Equality is exact on (kind, key):
//
//	file    cleaned absolute path (relative paths resolved against the
//	        call's recorded cwd; unresolvable relative paths are dropped)
//	host    lower-cased host name without port (URL host, ssh/scp host,
//	        nc host, recorded network destination); loopback excluded
//	cloud   recorded resource_id, an ARN, or a bucket (s3://, gs://, az://)
//	secret  the secret store a command reads (keychain, aws-secretsmanager,
//	        aws-ssm, vault, gcp-secretmanager, azure-keyvault[:vault],
//	        1password, kubernetes-secret)
type target struct{ kind, key string }

var (
	arnRe        = regexp.MustCompile(`\barn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d*:[A-Za-z0-9/_+=.@:-]+`)
	bucketRe     = regexp.MustCompile(`\b(s3|gs|az)://([A-Za-z0-9._-]+)`)
	secretStores = []struct {
		re    *regexp.Regexp
		store string
	}{
		{regexp.MustCompile(`(?i)^security\s+(find-generic-password|find-internet-password|dump-keychain|export)\b`), "keychain"},
		{regexp.MustCompile(`(?i)^aws\s+secretsmanager\b`), "aws-secretsmanager"},
		{regexp.MustCompile(`(?i)^aws\s+ssm\s+get-parameters?\b`), "aws-ssm"},
		{regexp.MustCompile(`(?i)^vault\b`), "vault"},
		{regexp.MustCompile(`(?i)^gcloud\s+secrets\b`), "gcp-secretmanager"},
		{regexp.MustCompile(`(?i)^az\s+keyvault\b`), "azure-keyvault"},
		{regexp.MustCompile(`(?i)^op\s+(read|item|document)\b`), "1password"},
		{regexp.MustCompile(`(?i)^kubectl\s+(get|describe)\s+secrets?\b`), "kubernetes-secret"},
	}
	vaultNameRe = regexp.MustCompile(`--vault-name[ =]([A-Za-z0-9-]+)`)
)

func loopbackHost(h string) bool {
	switch strings.Trim(h, "[]") {
	case "localhost", "127.0.0.1", "0.0.0.0", "::1":
		return true
	}
	return false
}

// cleanTarget normalizes a path argument into an absolute, cleaned path.
func cleanTarget(p, cwd string) (string, bool) {
	p = strings.TrimLeft(strings.Trim(strings.TrimSpace(p), `"'`), "<>")
	p = strings.TrimRight(p, ";,)")
	if p == "" || strings.ContainsAny(p, "$*`") {
		return "", false
	}
	switch {
	case strings.HasPrefix(p, "/"), strings.HasPrefix(p, "~/"):
	case strings.HasPrefix(cwd, "/") && (strings.HasPrefix(p, "./") || strings.Contains(p, "/") || strings.Contains(p, ".")):
		p = cwd + "/" + p
	default:
		return "", false
	}
	p = path.Clean(p)
	if strings.HasPrefix(p, "/dev/") || p == "/" || IsScratchPath(p) {
		return "", false
	}
	return p, true
}

// targetsOf returns the targets a tool call acts on, deduplicated.
func targetsOf(e schema.Event) []target {
	seen := map[target]bool{}
	var out []target
	add := func(t target) {
		if t.key == "" || seen[t] || len(out) >= 32 {
			return
		}
		seen[t] = true
		out = append(out, t)
	}
	addFile := func(p string) {
		if c, ok := cleanTarget(p, e.Cwd); ok {
			add(target{"file", c})
		}
	}
	addHost := func(h string) {
		h = strings.ToLower(netdest.Host(strings.TrimSpace(h)))
		if h != "" && !loopbackHost(h) {
			add(target{"host", h})
		}
	}
	addFile(e.File)
	for _, k := range []string{"file_path", "path", "notebook_path"} {
		addFile(e.SafeArgs[k])
	}
	if e.NetworkDest != "" {
		addHost(e.NetworkDest)
	}
	if u := e.SafeArgs["url"]; u != "" {
		if h, ok := netdest.URLHost(u); ok {
			addHost(h)
		}
	}
	if h := e.SafeArgs["host"]; h != "" {
		addHost(h)
	}
	if e.ResourceID != "" {
		add(target{"cloud", e.ResourceID})
	}
	if r := e.SafeArgs["resource_id"]; r != "" {
		add(target{"cloud", r})
	}
	if e.Command == "" {
		return out
	}
	cmd := e.FullCommand()
	for _, d := range netdest.Extract(cmd) {
		addHost(d)
	}
	for _, m := range arnRe.FindAllString(cmd, 8) {
		add(target{"cloud", m})
	}
	for _, m := range bucketRe.FindAllStringSubmatch(cmd, 8) {
		add(target{"cloud", strings.ToLower(m[1]) + "://" + m[2]})
	}
	for _, st := range shellshape.Stages(shellshape.Strip(shellshape.ExpandVars(cmd))) {
		text := strings.TrimSpace(st.Text)
		f := strings.Fields(text)
		for len(f) > 0 && privPrefix[f[0]] {
			f = f[1:]
		}
		if len(f) == 0 {
			continue
		}
		rest := strings.Join(f, " ")
		for _, s := range secretStores {
			if s.re.MatchString(rest) {
				key := s.store
				if m := vaultNameRe.FindStringSubmatch(rest); m != nil && s.store == "azure-keyvault" {
					key += ":" + strings.ToLower(m[1])
				}
				add(target{"secret", key})
			}
		}
		for _, a := range f[1:] {
			if strings.HasPrefix(a, "-") || strings.Contains(a, "://") {
				continue
			}
			if strings.HasPrefix(a, "/") || strings.HasPrefix(a, "~/") || strings.HasPrefix(a, ">") {
				addFile(a)
			}
		}
	}
	return out
}

// privPrefix are wrappers that run the rest of the line with other
// privileges. They are part of the method: `sudo cat` is a different
// method from `cat`.
var privPrefix = map[string]bool{"sudo": true, "doas": true, "pkexec": true, "runas": true, "gsudo": true}

// subcommandCLIs take the operation as their next word(s); the method is
// the program plus that operation.
var subcommandCLIs = map[string]int{"aws": 2, "gcloud": 2, "az": 2, "kubectl": 1, "gh": 1, "git": 1,
	"security": 1, "vault": 1, "op": 1, "docker": 1, "gsutil": 1, "doctl": 2}

// methodOf names how a call acts: the tool, and for shell calls the
// privilege wrapper, program and (for multi-command CLIs) the operation of
// the stage that names one of its targets. MCP calls are server/tool.
func methodOf(e schema.Event, tg target) string {
	if e.MCPServer != "" {
		return "mcp:" + e.MCPServer + "/" + e.MCPTool
	}
	if e.Command == "" {
		return e.Tool
	}
	stages := shellshape.Stages(shellshape.Strip(shellshape.ExpandVars(e.FullCommand())))
	pick := ""
	for _, st := range stages {
		if pick == "" {
			pick = st.Text
		}
		if tg.kind == "file" && strings.Contains(st.Text, path.Base(tg.key)) ||
			tg.kind == "host" && strings.Contains(strings.ToLower(st.Text), tg.key) {
			pick = st.Text
			break
		}
	}
	f := strings.Fields(pick)
	var parts []string
	for len(f) > 0 && (privPrefix[f[0]] || strings.Contains(f[0], "=") && !strings.HasPrefix(f[0], "-")) {
		if privPrefix[f[0]] {
			parts = append(parts, f[0])
		}
		f = f[1:]
	}
	if len(f) == 0 {
		return e.Tool + ":" + strings.Join(parts, " ")
	}
	v := path.Base(f[0])
	parts = append(parts, v)
	if n := subcommandCLIs[v]; n > 0 {
		for _, a := range f[1:] {
			if n == 0 {
				break
			}
			if strings.HasPrefix(a, "-") {
				continue
			}
			parts = append(parts, a)
			n--
		}
	}
	return e.Tool + ":" + strings.Join(parts, " ")
}

// effectOf classifies what a call does to its target: read, change,
// network or delegate. MCP calls count as change: their effect is not in
// the events.
func effectOf(e schema.Event) string {
	switch {
	case e.MCPServer != "":
		return "change"
	case e.Command != "":
		cmd := e.FullCommand()
		if IsReadOnlyCommand(cmd) {
			return "read"
		}
		if netdest.IsOutbound(cmd) {
			return "network"
		}
		return "change"
	}
	switch e.Tool {
	case "Read", "Grep", "Glob", "NotebookRead", "LS":
		return "read"
	case "WebFetch", "WebSearch":
		return "network"
	case "Task", "Agent":
		return "delegate"
	}
	return "change"
}

// AGENT_ADAPTIVE_ATTACK_SEQUENCE — a call toward a target was blocked
// (refused by the user, denied by a rule or a recorded approval decision,
// or refused with an access-control error), and before any new instruction
// the agent reached the same target by a materially different method: a
// different tool, a different program or CLI operation, or the same
// program under sudo. AGENT_UNEXPECTED_AUTONOMOUS_RETRY owns the same
// action repeated; this rule skips any pair that rule would call the same.
// Checking a file it may not change (denied write, then a read) is not an
// attempt and is not reported.
func adaptiveAttack(ix *eventIndex) []schema.Finding {
	type blocked struct {
		call, res schema.Event
		kind      string
		policy    bool
		targets   []target
		effect    string
	}
	var out []schema.Finding
	for _, agent := range ix.agents {
		var open []blocked
		for _, i := range ix.byAgent[agent] {
			e := ix.events[i]
			if isInstruction(e) || e.EventType == schema.EventTraceGap {
				open = open[:0]
				continue
			}
			if e.EventType == schema.EventToolResult {
				call, ok := ix.callOf(e)
				if !ok {
					continue
				}
				if kind, policy := blockedKind(call, e); kind != "" && len(open) < adaptiveMaxOpen {
					if tg := targetsOf(call); len(tg) > 0 {
						open = append(open, blocked{call, e, kind, policy, tg, effectOf(call)})
					}
				}
				continue
			}
			if e.EventType != schema.EventToolCall || len(open) == 0 {
				continue
			}
			eff := effectOf(e)
			tgs := targetsOf(e)
			for j := 0; j < len(open); j++ {
				b := open[j]
				if b.call.EventID == e.EventID || !within(b.call, e, adaptiveWindow) {
					continue
				}
				if same, _ := sameAction(b.call, e); same {
					continue
				}
				if eff == "read" && b.effect != "read" {
					continue
				}
				var hitT target
				found := false
				for _, a := range b.targets {
					for _, t := range tgs {
						if a == t && methodOf(b.call, a) != methodOf(e, t) {
							hitT, found = a, true
							break
						}
					}
					if found {
						break
					}
				}
				if !found {
					continue
				}
				sev := "MEDIUM"
				outcome := "The second method was refused as well or has no recorded result."
				_, completed := ix.completed(e)
				if completed {
					outcome = "The second method completed: its recorded result is neither an error nor a refusal."
					if b.policy {
						sev = "HIGH"
					}
				}
				out = append(out, schema.Finding{
					RuleID: "AGENT_ADAPTIVE_ATTACK_SEQUENCE", Severity: sev,
					Title: "Agent Switched Method After Being Blocked From a Target",
					Description: fmt.Sprintf("A %s was %s. Before any new instruction the agent reached the same %s (%s) by a different method: %s (%s instead of %s). %s",
						describeCall(b.call), b.kind, hitT.kind, hitT.key, describeCall(e), methodOf(e, hitT), methodOf(b.call, hitT), outcome),
					SessionID: e.SessionID, AgentID: e.AgentID,
					Related:      []string{"blocked call: " + ref(b.call), "block: " + ref(b.res), "target: " + hitT.kind + " " + hitT.key},
					EvidenceRefs: []string{ref(e), ref(b.res)},
					Status:       e.Corroboration, Endpoint: schema.StateUnknown,
					MitreATTACK: "T1548", MitreATLAS: "AML.T0117",
					Confidence: "MEDIUM", Timestamp: e.Timestamp,
					Reasons: []string{"the block and the second method are in the agent's own transcript with no instruction between them",
						"the target is equal by kind and normalized value; the method differs by tool, program, CLI operation or privilege wrapper"},
					FalsePositive: "Trying another way after an error is also how agents fix legitimate problems (a missing permission, a tool that cannot read a format). The block, the target and the prompt before it decide. Sequence is not causation: the second call may not have been driven by the first one's failure.",
				})
				open = append(open[:j], open[j+1:]...)
				break
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AGENT_RESOURCE_EXHAUSTION

// Resource thresholds. A loop is the same tool with the same arguments
// (ArgsDigest, or the exact shell command line when no digest was
// recorded) called loopMinRepeats times within loopWindow: a poller that
// sleeps 30 s between checks stays under it. The rate is more than
// rateMaxCalls tool calls of one agent within rateWindow, several times
// what parallel tool use produces. Subagent fan-out stays with
// AGENT_SPAWN_EXPLOSION.
const (
	loopMinRepeats  = 25
	loopWindow      = 10 * time.Minute
	rateMaxCalls    = 120
	rateWindow      = time.Minute
	loopMaxKeys     = 4096 // distinct call shapes tracked per agent
	loopMaxCmdBytes = 4096 // longer command lines are keyed by their head
)

// loopKey identifies "the same call". Without a digest only shell commands
// are comparable (the command is the whole input); other tools are not
// keyed, because equal names with unknown arguments are not equal calls.
func loopKey(e schema.Event) string {
	if e.ArgsDigest != "" {
		return e.Tool + "\x00" + e.MCPServer + "\x00" + e.MCPTool + "\x00" + e.ArgsDigest
	}
	if e.Command == "" {
		return ""
	}
	c := strings.Join(strings.Fields(e.FullCommand()), " ")
	if len(c) > loopMaxCmdBytes {
		c = c[:loopMaxCmdBytes]
	}
	return e.Tool + "\x00cmd\x00" + c
}

// AGENT_RESOURCE_EXHAUSTION — one agent repeated the same tool call with
// the same arguments many times in a short window (a loop), or issued tool
// calls at a rate no interactive task needs. Events without a timestamp
// are not counted: a window cannot be established without a clock.
func resourceExhaustion(ix *eventIndex) []schema.Finding {
	var out []schema.Finding
	for _, agent := range ix.agents {
		type win struct {
			ts  []time.Time
			evs []schema.Event
		}
		loops := map[string]*win{}
		loopHit := false
		var rate win
		rateHit := false
		for _, i := range ix.byAgent[agent] {
			e := ix.events[i]
			if e.EventType != schema.EventToolCall || multiSessionStore(e) {
				continue
			}
			t, ok := parseTS(e.Timestamp)
			if !ok {
				continue
			}
			if !rateHit {
				rate.ts, rate.evs = append(rate.ts, t), append(rate.evs, e)
				for len(rate.ts) > 0 && t.Sub(rate.ts[0]) > rateWindow {
					rate.ts, rate.evs = rate.ts[1:], rate.evs[1:]
				}
				if len(rate.ts) > rateMaxCalls {
					rateHit = true
					first := rate.evs[0]
					out = append(out, schema.Finding{
						RuleID: "AGENT_RESOURCE_EXHAUSTION", Severity: "MEDIUM",
						Title:       "Agent Tool-Call Rate Far Above Interactive Use",
						Description: fmt.Sprintf("The agent issued %d tool calls within %s (threshold %d). Runaway loops and injected fan-out directives spend compute, API budget and rate limits at this pace.", len(rate.ts), rateWindow, rateMaxCalls),
						SessionID:   e.SessionID, AgentID: e.AgentID,
						Related:      []string{"first call in the window: " + ref(first)},
						EvidenceRefs: []string{ref(first), ref(e)},
						Status:       strongestState(rate.evs), Endpoint: schema.StateUnknown,
						MitreATTACK: "T1496", MitreATLAS: "AML.T0034.002",
						Confidence: "MEDIUM", Timestamp: first.Timestamp,
						Reasons:       []string{"counted from the transcript's own timestamps on each tool call"},
						FalsePositive: "Batch jobs a person started on purpose (a codemod over thousands of files) run this fast. Read the prompt that started the run; tune nothing silently.",
					})
				}
			}
			if loopHit {
				continue
			}
			k := loopKey(e)
			if k == "" {
				continue
			}
			w := loops[k]
			if w == nil {
				if len(loops) >= loopMaxKeys {
					continue
				}
				w = &win{}
				loops[k] = w
			}
			w.ts, w.evs = append(w.ts, t), append(w.evs, e)
			for len(w.ts) > 0 && t.Sub(w.ts[0]) > loopWindow {
				w.ts, w.evs = w.ts[1:], w.evs[1:]
			}
			if len(w.ts) < loopMinRepeats {
				continue
			}
			loopHit = true
			first := w.evs[0]
			basis := "the same argument digest"
			if e.ArgsDigest == "" {
				basis = "the same command line"
			}
			out = append(out, schema.Finding{
				RuleID: "AGENT_RESOURCE_EXHAUSTION", Severity: "MEDIUM",
				Title: "Agent Repeated the Same Tool Call in a Loop",
				Description: fmt.Sprintf("The agent called %s with %s %d times within %s (threshold %d). A loop like this burns compute and API budget without progress.",
					describeCall(e), basis, len(w.ts), w.ts[len(w.ts)-1].Sub(w.ts[0]).Round(time.Second), loopMinRepeats),
				SessionID: e.SessionID, AgentID: e.AgentID,
				Related:      []string{"first call of the loop: " + ref(first)},
				EvidenceRefs: []string{ref(first), ref(e)},
				Status:       strongestState(w.evs), Endpoint: schema.StateUnknown,
				MitreATTACK: "T1496", MitreATLAS: "AML.T0034.002",
				Confidence: "MEDIUM", Timestamp: first.Timestamp,
				Reasons:       []string{"calls are equal by " + basis + "; timestamps are the transcript's own"},
				FalsePositive: "Polling a build or a deployment with the same command is routine when it sleeps between checks; a tight poll without a sleep matches. Check the interval between the cited calls.",
			})
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// AGENT_MULTIMODAL_TRIGGER_CHAIN

var nonTextModality = map[string]bool{"image": true, "audio": true, "document": true}

// AGENT_MULTIMODAL_TRIGGER_CHAIN — non-text input (an image, audio or a
// document) entered the turn, and the agent then made a consequential call
// (a state-changing shell command, a write, an MCP call, a fetch or a
// delegation) with no text instruction from a person in between. A prompt
// that carries both text and an attachment is an instruction and starts no
// chain. Input that arrived in a tool result (content the agent fetched)
// rates MEDIUM when the follow-up is a shell command, MCP call or fetch;
// everything else is LOW. No finding without a recorded input_modality.
func multimodalTrigger(ix *eventIndex) []schema.Finding {
	var out []schema.Finding
	for _, agent := range ix.agents {
		var pending *schema.Event
		for _, i := range ix.byAgent[agent] {
			e := ix.events[i]
			mod := modalityOf(e)
			switch {
			case e.EventType == schema.EventTraceGap:
				pending = nil
				continue
			case e.EventType == schema.EventHumanPrompt || e.EventType == schema.EventAgentMessage:
				text := strings.TrimSpace(e.Summary)
				if nonTextModality[mod] && (text == "" || autoPromptRe.MatchString(text)) {
					p := e
					pending = &p
				} else if isInstruction(e) {
					pending = nil
				}
				continue
			case e.EventType == schema.EventToolResult && nonTextModality[mod]:
				p := e
				pending = &p
				continue
			}
			if pending == nil || e.EventType != schema.EventToolCall || !highRisk(e) {
				continue
			}
			src := *pending
			pending = nil
			fromTool := src.EventType == schema.EventToolResult
			sev := "LOW"
			if fromTool && (e.Command != "" || e.MCPServer != "" || e.Tool == "WebFetch") {
				sev = "MEDIUM"
			}
			origin := "a prompt that carried only the attachment"
			if fromTool {
				origin = "a tool result (content the agent fetched)"
			}
			related := []string{"non-text input: " + ref(src)}
			if fromTool {
				if c, ok := ix.callOf(src); ok {
					related = append(related, "fetched by: "+ref(c))
				}
			}
			out = append(out, schema.Finding{
				RuleID: "AGENT_MULTIMODAL_TRIGGER_CHAIN", Severity: sev,
				Title: "Consequential Action Right After Non-Text Input",
				Description: fmt.Sprintf("%s input arrived in %s, and the agent's next consequential call was %s, with no text instruction from a person in between. Instructions hidden in an image, audio or document channel are not visible in the transcript text.",
					capitalize(modalityOf(src)), origin, describeCall(e)),
				SessionID: e.SessionID, AgentID: e.AgentID,
				Related:      related,
				EvidenceRefs: []string{ref(e), ref(src)},
				Status:       e.Corroboration, Endpoint: schema.StateUnknown,
				MitreATTACK: "T1027", MitreATLAS: "AML.T0129",
				Confidence: "LOW", Timestamp: e.Timestamp,
				Reasons:       []string{"the modality is the parser's record of the input; its content is not inspected", "order within the turn only: the action may follow from earlier instructions"},
				FalsePositive: "A screenshot of an error followed by a fix, or a document the person asked the agent to act on, is the normal shape. Sequence is not causation: the content of the input is not read, so whether it carried an instruction is unknown.",
			})
		}
	}
	return out
}

func modalityOf(e schema.Event) string { return strings.ToLower(strings.TrimSpace(e.InputModality)) }

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// ---------------------------------------------------------------------------
// AGENT_DELEGATION_SCOPE_EXPANSION

// Bounds on what the agent-definition and settings readers take in.
const (
	maxAgentDefBytes = 256 << 10
	maxAgentDefs     = 512
	maxDefLines      = 200
	maxExtraDirs     = 64
	delegMaxRefs     = 4
)

// agentDef is the declared scope of one collected agent definition
// (Claude Code .claude/agents/<name>.md or a plugin's agents/<name>.md).
type agentDef struct {
	name       string
	plugin     string   // plugin directory name for plugin agents, "" for user agents
	tools      []string // declared `tools:`; nil when the key is absent (inherits all)
	declared   bool
	disallowed []string
	art        casepkg.ArtifactRecord
	profile    string
	mtime      time.Time
	hasTime    bool
}

// isAgentDefArtifact reports the collected files that define agents.
func isAgentDefArtifact(a casepkg.ArtifactRecord) (plugin string, ok bool) {
	lp := strings.ReplaceAll(a.LogicalPath, `\`, "/")
	if a.Status != casepkg.StatusOK || a.ArtifactID == "" || !strings.HasSuffix(strings.ToLower(lp), ".md") || a.Size > maxAgentDefBytes {
		return "", false
	}
	switch {
	case a.CollectorRule == "claude.agents":
		return "", true
	case a.CollectorRule == "claude.plugins":
		i := strings.LastIndex(lp, "/agents/")
		if i < 0 {
			return "", false
		}
		// plugins/cache/<marketplace>/<plugin>/<version>/agents/x.md or
		// plugins/marketplaces/<m>/plugins/<plugin>/agents/x.md: the plugin
		// is the nearest directory that is not a version.
		dirs := strings.Split(lp[:i], "/")
		for k := len(dirs) - 1; k >= 0; k-- {
			d := dirs[k]
			if d == "" || versionDirRe.MatchString(d) {
				continue
			}
			return d, true
		}
	}
	return "", false
}

var versionDirRe = regexp.MustCompile(`^v?\d+(\.\d+)*([-+].*)?$|^[0-9a-f]{7,40}$`)

// parseAgentDef reads the YAML front matter of an agent definition: name,
// tools and disallowedTools. Only the simple forms clients write are
// understood (comma list, [a, b], or "- a" lines); anything else leaves the
// field undeclared rather than guessed.
func parseAgentDef(data []byte, fallbackName string) (agentDef, bool) {
	d := agentDef{name: fallbackName}
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4096), 64<<10)
	if !sc.Scan() || strings.TrimSpace(sc.Text()) != "---" {
		return d, false
	}
	var key string
	var list *[]string
	closed := false
	for n := 0; sc.Scan() && n < maxDefLines; n++ {
		line := strings.TrimRight(sc.Text(), "\r")
		if strings.TrimSpace(line) == "---" {
			closed = true
			break
		}
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "- ") && list != nil {
			*list = append(*list, unquote(strings.TrimSpace(t[2:])))
			continue
		}
		list = nil
		i := strings.IndexByte(line, ':')
		if i <= 0 || strings.HasPrefix(line, " ") {
			continue
		}
		key = strings.TrimSpace(line[:i])
		val := strings.TrimSpace(line[i+1:])
		switch key {
		case "name":
			if v := unquote(val); v != "" {
				d.name = v
			}
		case "tools", "disallowedTools", "disallowed-tools":
			dst := &d.tools
			if key != "tools" {
				dst = &d.disallowed
			} else {
				d.declared = true
			}
			*dst = append([]string{}, splitToolList(val)...)
			if val == "" {
				list = dst
			}
		}
	}
	if !closed {
		return agentDef{name: fallbackName}, false
	}
	if d.declared && len(d.tools) == 0 && list == nil {
		// "tools:" with nothing after it and no list lines declares nothing.
		d.declared = false
	}
	return d, true
}

func splitToolList(v string) []string {
	v = strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(v), "["), "]"))
	if v == "" {
		return nil
	}
	var out []string
	depth, start := 0, 0
	for i := 0; i <= len(v); i++ {
		if i < len(v) {
			switch v[i] {
			case '(':
				depth++
				continue
			case ')':
				depth--
				continue
			case ',':
				if depth > 0 {
					continue
				}
			default:
				continue
			}
		}
		if t := unquote(strings.TrimSpace(v[start:i])); t != "" && len(out) < 256 {
			out = append(out, t)
		}
		start = i + 1
	}
	return out
}

func unquote(s string) string { return strings.Trim(strings.TrimSpace(s), `"'`) }

// loadAgentDefs reads every collected agent definition.
func loadAgentDefs(store *casepkg.Store, man *casepkg.Manifest) []agentDef {
	var out []agentDef
	for _, a := range man.Current() {
		plugin, ok := isAgentDefArtifact(a)
		if !ok || len(out) >= maxAgentDefs {
			continue
		}
		f, err := store.Open(a.ArtifactID)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxAgentDefBytes))
		f.Close()
		if err != nil {
			continue
		}
		base := path.Base(strings.ReplaceAll(a.LogicalPath, `\`, "/"))
		d, ok := parseAgentDef(data, strings.TrimSuffix(base, path.Ext(base)))
		if !ok {
			continue
		}
		d.plugin, d.art = plugin, a
		d.profile = accounts.Key(a.LogicalPath, a.Product)
		d.mtime, d.hasTime = parseTS(a.ModTimeUTC)
		out = append(out, d)
	}
	return out
}

// extraDir is a directory a settings file adds to the agent's workspace
// (permissions.additionalDirectories).
type extraDir struct {
	dir     string
	profile string
}

func loadExtraDirs(store *casepkg.Store, man *casepkg.Manifest) []extraDir {
	var out []extraDir
	for _, a := range man.Current() {
		if _, ok := isSettingsArtifact(a); !ok || a.Size > maxSettingsBytes {
			continue
		}
		f, err := store.Open(a.ArtifactID)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, maxSettingsBytes))
		f.Close()
		if err != nil {
			continue
		}
		var doc struct {
			Permissions struct {
				AdditionalDirectories []string `json:"additionalDirectories"`
			} `json:"permissions"`
		}
		if json.Unmarshal(data, &doc) != nil {
			continue
		}
		for _, d := range doc.Permissions.AdditionalDirectories {
			if len(out) >= maxExtraDirs {
				break
			}
			if d = strings.TrimSpace(d); strings.HasPrefix(d, "/") {
				out = append(out, extraDir{dir: path.Clean(d), profile: accounts.Key(a.LogicalPath, a.Product)})
			}
		}
	}
	return out
}

// toolListed reports whether a declared tool list names a tool. Entries
// may carry an argument pattern (Bash(git:*)), which narrows the tool but
// still names it; mcp__server names every tool of that server.
func toolListed(list []string, tool string) bool {
	for _, t := range list {
		base := t
		if i := strings.IndexByte(t, '('); i > 0 {
			base = t[:i]
		}
		base = strings.TrimSpace(base)
		switch {
		case base == "*" || base == tool:
			return true
		case spawnAliases[base] && spawnAliases[tool]:
			return true
		case strings.HasPrefix(base, "mcp__"):
			b := strings.TrimSuffix(strings.TrimSuffix(base, "*"), "__")
			if tool == b || strings.HasPrefix(tool, b+"__") {
				return true
			}
		}
	}
	return false
}

// spawnTools are the delegation tools whose call starts a subagent.
var spawnTools = map[string]bool{"Task": true, "Agent": true, "spawn_agent": true}

// declaredType is the agent type the spawn call asked for, from the
// allowlisted arguments the parser recorded.
func declaredType(call schema.Event) string {
	for _, k := range []string{"subagent_type", "agent_type"} {
		if v := strings.TrimSpace(call.SafeArgs[k]); v != "" {
			return v
		}
	}
	return ""
}

// findDef resolves an agent type to its collected definition, preferring
// the subagent's own login profile. A plugin agent is "<plugin>:<name>".
// Ambiguity across profiles resolves to nothing.
func findDef(defs []agentDef, typ string, sub schema.Event) (agentDef, bool) {
	plugin, name := "", typ
	if i := strings.LastIndexByte(typ, ':'); i > 0 {
		plugin, name = typ[:i], typ[i+1:]
	}
	prof := accounts.Key(sub.SourcePath, sub.Product)
	var cands []agentDef
	for _, d := range defs {
		if d.name == name && d.plugin == plugin {
			cands = append(cands, d)
		}
	}
	for _, d := range cands {
		if d.profile == prof {
			return d, true
		}
	}
	if len(cands) == 1 && prof == "unknown" {
		return cands[0], true
	}
	return agentDef{}, false
}

// underDir reports whether p is dir or inside it.
func underDir(p, dir string) bool {
	p, dir = path.Clean(p), path.Clean(dir)
	return p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/")
}

// writesOf returns the absolute paths a subagent call changes.
func writesOf(e schema.Event) []string {
	var raw []string
	switch {
	case e.Command != "":
		cmd := shellshape.ExpandVars(e.FullCommand())
		raw = append(WriteTargets(cmd), DeleteTargets(cmd)...)
	case e.Tool == "Write" || e.Tool == "Edit" || e.Tool == "MultiEdit" || e.Tool == "NotebookEdit":
		raw = []string{e.File}
	}
	var out []string
	for _, p := range raw {
		if c, ok := cleanTarget(p, e.Cwd); ok && strings.HasPrefix(c, "/") && len(out) < 16 {
			out = append(out, c)
		}
	}
	return out
}

// AGENT_DELEGATION_SCOPE_EXPANSION — a delegated agent acted outside the
// scope it was given. Two shapes, one finding each per subagent:
//
//   - it called a tool its collected definition does not list in `tools:`
//     (or lists in `disallowedTools:`). The subagent is linked to its spawn
//     call by ParentToolCallID, or by the spawn record naming its agent id;
//     the definition by the spawn call's recorded subagent_type. Without a
//     declared type, a collected definition, or a `tools:` key, nothing is
//     compared.
//   - it changed files outside the parent's recorded working directory and
//     the additionalDirectories of the collected settings. Reads are not
//     counted; scratch space is not counted.
func delegationScope(ix *eventIndex, defs []agentDef, dirs []extraDir) []schema.Finding {
	// Spawn calls by id, and the spawn call each child was started by.
	spawnCalls := map[string][]int{}
	childCall := map[string]string{}
	for i, e := range ix.events {
		switch {
		case e.EventType == schema.EventToolCall && spawnTools[e.Tool] && e.ToolCallID != "":
			if len(spawnCalls[e.ToolCallID]) < 4 {
				spawnCalls[e.ToolCallID] = append(spawnCalls[e.ToolCallID], i)
			}
		case e.EventType == schema.EventAgentSpawn && e.TaskID != "" && e.ToolCallID != "":
			if _, ok := childCall[e.TaskID]; !ok {
				childCall[e.TaskID] = e.ToolCallID
			}
		}
	}
	var out []schema.Finding
	for _, agent := range ix.agents {
		idx := ix.byAgent[agent]
		parentCallID := ""
		for _, i := range idx {
			if p := ix.events[i].ParentToolCallID; p != "" {
				parentCallID = p
				break
			}
		}
		if parentCallID == "" {
			parentCallID = childCall[agent]
		}
		if parentCallID == "" || len(idx) == 0 {
			continue
		}
		sub := ix.events[idx[0]]
		var spawn schema.Event
		found := false
		for _, ci := range spawnCalls[parentCallID] {
			c := ix.events[ci]
			if c.AgentID == agent {
				continue // a call cannot spawn its own caller
			}
			if !found || c.SessionID == sub.SessionID {
				spawn, found = c, true
			}
		}
		if !found {
			continue
		}

		// Shape 1: tools outside the declared list.
		if typ := declaredType(spawn); typ != "" {
			if def, ok := findDef(defs, typ, sub); ok && (def.declared || len(def.disallowed) > 0) {
				var bad []schema.Event
				names := map[string]bool{}
				var nameList []string
				for _, i := range idx {
					e := ix.events[i]
					if e.EventType != schema.EventToolCall || e.Tool == "" {
						continue
					}
					outside := (def.declared && !toolListed(def.tools, e.Tool)) || toolListed(def.disallowed, e.Tool)
					if !outside {
						continue
					}
					bad = append(bad, e)
					if !names[e.Tool] && len(nameList) < 8 {
						names[e.Tool] = true
						nameList = append(nameList, e.Tool)
					}
				}
				if len(bad) > 0 {
					sev := "MEDIUM"
					for _, e := range bad {
						if _, ok := ix.completed(e); ok && highRisk(e) {
							sev = "HIGH"
							break
						}
					}
					conf, reason := "LOW", "the definition file was modified after the first such call, so its tool list may have been narrowed later"
					if t, ok := parseTS(bad[0].Timestamp); ok && def.hasTime && !def.mtime.After(t) {
						conf, reason = "MEDIUM", "the definition file was last modified before the first such call, so the tool list most likely applied when it ran"
					}
					refs := []string{}
					for _, e := range bad {
						if len(refs) < delegMaxRefs {
							refs = append(refs, ref(e))
						}
					}
					out = append(out, schema.Finding{
						RuleID: "AGENT_DELEGATION_SCOPE_EXPANSION", Severity: sev,
						Title: "Subagent Used Tools Outside Its Declared List",
						Description: fmt.Sprintf("Subagent %s was started as %q (spawn call %s). Its definition %s declares the tools it may use, and the subagent called %d tool(s) outside that list: %s.",
							agent, typ, ref(spawn), def.art.LogicalPath, len(bad), strings.Join(nameList, ", ")),
						SessionID: sub.SessionID, AgentID: agent, ParentAgentID: spawn.AgentID,
						Related:      []string{"spawn call: " + ref(spawn), "agent definition: " + artRef(def.art, 0)},
						EvidenceRefs: refs,
						Status:       strongestState(bad), Endpoint: schema.StateUnknown,
						MitreATTACK: "T1548", MitreATLAS: "AML.T0053",
						Confidence: conf, Timestamp: bad[0].Timestamp,
						Reasons:       []string{reason, "the subagent is linked to its spawn call by recorded ids; the definition by the recorded subagent type"},
						FalsePositive: "The definition was edited after the run, a project-level definition of the same name (not collected) was the one in force, or the client grants a helper tool implicitly. A definition mismatch is not proof the call was unauthorized.",
					})
				}
			}
		}

		// Shape 2: writes outside the parent's working directory.
		cwd := strings.ReplaceAll(spawn.Cwd, `\`, "/")
		if !strings.HasPrefix(cwd, "/") {
			continue
		}
		roots := []string{path.Clean(cwd)}
		prof := accounts.Key(spawn.SourcePath, spawn.Product)
		for _, d := range dirs {
			if d.profile == prof {
				roots = append(roots, d.dir)
			}
		}
		var bad []schema.Event
		var paths []string
		for _, i := range idx {
			e := ix.events[i]
			if e.EventType != schema.EventToolCall {
				continue
			}
			for _, p := range writesOf(e) {
				inside := strings.HasPrefix(p, "~/") // home-relative: cannot be placed, never counted
				for _, r := range roots {
					if underDir(p, r) {
						inside = true
					}
				}
				if inside {
					continue
				}
				if len(bad) == 0 || bad[len(bad)-1].EventID != e.EventID {
					bad = append(bad, e)
				}
				if len(paths) < 8 {
					paths = append(paths, p)
				}
			}
		}
		if len(bad) == 0 {
			continue
		}
		sev := "LOW"
		for _, e := range bad {
			if _, ok := ix.completed(e); ok {
				sev = "MEDIUM"
				break
			}
		}
		refs := []string{}
		for _, e := range bad {
			if len(refs) < delegMaxRefs {
				refs = append(refs, ref(e))
			}
		}
		out = append(out, schema.Finding{
			RuleID: "AGENT_DELEGATION_SCOPE_EXPANSION", Severity: sev,
			Title: "Subagent Changed Files Outside the Parent's Working Directory",
			Description: fmt.Sprintf("Subagent %s was started from %s (spawn call %s) and changed %d path(s) outside it and outside any collected additional directory: %s.",
				agent, cwd, ref(spawn), len(paths), strings.Join(paths, ", ")),
			SessionID: sub.SessionID, AgentID: agent, ParentAgentID: spawn.AgentID,
			Related:      []string{"spawn call: " + ref(spawn)},
			EvidenceRefs: refs,
			Status:       strongestState(bad), Endpoint: schema.StateUnknown,
			MitreATTACK: "T1548", MitreATLAS: "AML.T0053",
			Confidence: "LOW", Timestamp: bad[0].Timestamp,
			Reasons:       []string{"the parent's working directory is the cwd recorded on the spawn call; write targets are read from the call's file argument or command line"},
			FalsePositive: "Directories added with --add-dir or a project setting outside the collection widen the workspace without a trace in these files, and a person may have asked for the edit. Outside the cwd is not the same as unauthorized.",
		})
	}
	return out
}
