// v4 agent-behaviour rules: accountability and control-boundary questions
// that need the whole event stream of a session (and sometimes the
// collected settings) rather than one command line.
//
// Every rule here was checked against the existing catalog first; the
// dedupe verdicts and what each rule deliberately does not cover are in
// docs/detection-v4.md. Sequences are reported as "possible", never as a
// confirmed outcome: a transcript records what the agent asked for and what
// the client handed back, and only a second witness confirms the rest.
package detect

import (
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/accounts"
	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/schema"
	"github.com/efij/AgentDFIR/v4/internal/shellshape"
)

// RunAgentRules evaluates the v4 agent-behaviour rules over the decoded
// events of one package. man may be nil (rules that need collected files
// are skipped); events are not modified.
func RunAgentRules(events []schema.Event, pkgDir string, man *casepkg.Manifest) []schema.Finding {
	ix := newEventIndex(events)
	var out []schema.Finding
	out = append(out, autonomousRetry(ix)...)
	out = append(out, unverifiedSuccessClaim(ix)...)
	out = append(out, externalArtifactExecution(ix)...)
	out = append(out, permissionModeEscalation(ix)...)
	out = append(out, identitySwitch(ix)...)
	if man != nil {
		store := casepkg.NewStore(pkgDir, man)
		out = append(out, permissionBoundaryCrossing(ix, loadDenyRules(store, man))...)
		out = append(out, clockAnomaly(ix, man)...)
		out = append(out, crossSessionSecretReuse(events, pkgDir, man, store)...)
	}
	out = append(out, runV5Rules(ix, pkgDir, man)...)
	return sortBySeverity(out)
}

// eventIndex is the shared view the rules read: events grouped by agent
// and by session in recorded order, and tool calls and results paired by
// their call id.
type eventIndex struct {
	events    []schema.Event
	byAgent   map[string][]int
	bySession map[string][]int
	agents    []string
	sessions  []string
	call      map[string]int // tool call id → tool_call event
	result    map[string]int // tool call id → tool_result event
}

func newEventIndex(events []schema.Event) *eventIndex {
	ix := &eventIndex{events: events, byAgent: map[string][]int{}, bySession: map[string][]int{},
		call: map[string]int{}, result: map[string]int{}}
	for i, e := range events {
		if e.AgentID != "" {
			ix.byAgent[e.AgentID] = append(ix.byAgent[e.AgentID], i)
		}
		if e.SessionID != "" {
			ix.bySession[e.SessionID] = append(ix.bySession[e.SessionID], i)
		}
		if e.ToolCallID == "" {
			continue
		}
		key := e.SourceArtifact + "\x00" + e.ToolCallID
		switch e.EventType {
		case schema.EventToolCall:
			if _, seen := ix.call[key]; !seen {
				ix.call[key] = i
			}
		case schema.EventToolResult:
			if _, seen := ix.result[key]; !seen {
				ix.result[key] = i
			}
		}
	}
	order := func(m map[string][]int) []string {
		keys := make([]string, 0, len(m))
		for k, idx := range m {
			sort.SliceStable(idx, func(a, b int) bool { return events[idx[a]].Sequence < events[idx[b]].Sequence })
			keys = append(keys, k)
		}
		sort.Strings(keys)
		return keys
	}
	ix.agents = order(ix.byAgent)
	ix.sessions = order(ix.bySession)
	return ix
}

// resultOf returns the tool_result paired with a tool call.
func (ix *eventIndex) resultOf(call schema.Event) (schema.Event, bool) {
	if call.ToolCallID == "" {
		return schema.Event{}, false
	}
	i, ok := ix.result[call.SourceArtifact+"\x00"+call.ToolCallID]
	if !ok {
		return schema.Event{}, false
	}
	return ix.events[i], true
}

// callOf returns the tool call a result answers.
func (ix *eventIndex) callOf(res schema.Event) (schema.Event, bool) {
	if res.ToolCallID == "" {
		return schema.Event{}, false
	}
	i, ok := ix.call[res.SourceArtifact+"\x00"+res.ToolCallID]
	if !ok {
		return schema.Event{}, false
	}
	return ix.events[i], true
}

// Refusal texts the clients write into a tool result when the call did not
// run. The user's rejection, a deny rule and an approval that was never
// given are different facts, and the findings say which one it was.
var (
	userRejectRe = regexp.MustCompile(`(?i)doesn'?t want to proceed with this tool use|tool use was rejected|user rejected tool use`)
	ruleDenyRe   = regexp.MustCompile(`(?i)permission to use \S+.{0,200}?(has been|was) denied`)
	notGrantedRe = regexp.MustCompile(`(?i)this command requires approval|requested permissions? to use .{0,160}haven'?t granted|MCP request blocked`)
)

// refusal classifies a tool result as a refusal, or returns "".
func refusal(e schema.Event) string {
	if e.EventType != schema.EventToolResult {
		return ""
	}
	switch {
	case userRejectRe.MatchString(e.Summary):
		return "rejected by the user"
	case ruleDenyRe.MatchString(e.Summary):
		return "denied by a permission rule"
	case notGrantedRe.MatchString(e.Summary):
		return "refused because approval was not given"
	}
	return ""
}

// completed reports whether a call has a recorded result that is neither an
// error nor a refusal. No result at all is "unknown", not "completed".
func (ix *eventIndex) completed(call schema.Event) (schema.Event, bool) {
	res, ok := ix.resultOf(call)
	if !ok || res.Result == "error" || refusal(res) != "" {
		return res, false
	}
	return res, true
}

// autoPromptRe matches user-role lines the client writes on the person's
// behalf: they are not a new instruction.
var autoPromptRe = regexp.MustCompile(`^(\[Request interrupted|<command-|<local-command|Caveat: |<system-reminder>|This session is being continued)`)

// isInstruction reports whether an event is a new instruction to the agent:
// a person's prompt, or the parent's message to a subagent.
func isInstruction(e schema.Event) bool {
	switch e.EventType {
	case schema.EventHumanPrompt:
		return !autoPromptRe.MatchString(strings.TrimSpace(e.Summary))
	case schema.EventAgentMessage:
		return true
	}
	return false
}

// highRisk reports whether a tool call changes something or reaches out:
// the calls a refusal or a failure is worth following up on. Reads and
// searches are not.
func highRisk(e schema.Event) bool {
	if e.EventType != schema.EventToolCall {
		return false
	}
	switch {
	case e.Command != "":
		return !IsReadOnlyCommand(e.FullCommand())
	case e.MCPServer != "":
		return true
	}
	switch e.Tool {
	case "Write", "Edit", "MultiEdit", "NotebookEdit", "WebFetch", "Task", "Agent":
		return true
	}
	return false
}

// sameAction reports whether b repeats a: the same tool on the same file, or
// a command line with the same program and mostly the same words.
func sameAction(a, b schema.Event) (same, exact bool) {
	if a.Tool != b.Tool {
		return false, false
	}
	switch {
	case a.Command != "" || b.Command != "":
		ca, cb := strings.Join(strings.Fields(a.FullCommand()), " "), strings.Join(strings.Fields(b.FullCommand()), " ")
		if ca == cb {
			return true, true
		}
		if shellshape.Verb(ca) != shellshape.Verb(cb) {
			return false, false
		}
		return jaccard(strings.Fields(ca), strings.Fields(cb)) >= 0.5, false
	case a.File != "" || b.File != "":
		return a.File == b.File, a.File == b.File
	}
	return true, false
}

func jaccard(a, b []string) float64 {
	set := map[string]int{}
	for _, w := range a {
		set[w] |= 1
	}
	for _, w := range b {
		set[w] |= 2
	}
	both := 0
	for _, v := range set {
		if v == 3 {
			both++
		}
	}
	if len(set) == 0 {
		return 0
	}
	return float64(both) / float64(len(set))
}

func describeCall(e schema.Event) string {
	switch {
	case e.Command != "":
		return fmt.Sprintf("%s command %q", e.Tool, trimTo(e.Command, 120))
	case e.File != "":
		return fmt.Sprintf("%s on %s", e.Tool, e.File)
	case e.Tool != "":
		return e.Tool + " call"
	}
	return "tool call"
}

func trimTo(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// AGENT_UNEXPECTED_AUTONOMOUS_RETRY — a call was refused (the user rejected
// it, a deny rule blocked it, or approval was never given) and the agent
// issued the same or a near-identical state-changing call again before any
// new instruction arrived. Ordinary retries after a failure (a test that
// failed, a typo) are not refusals and are not reported.
func autonomousRetry(ix *eventIndex) []schema.Finding {
	type pending struct {
		call, res schema.Event
		kind      string
	}
	var out []schema.Finding
	for _, agent := range ix.agents {
		var open []pending
		for _, i := range ix.byAgent[agent] {
			e := ix.events[i]
			if isInstruction(e) {
				open = open[:0]
				continue
			}
			if kind := refusal(e); kind != "" {
				if call, ok := ix.callOf(e); ok && highRisk(call) && len(open) < 16 {
					open = append(open, pending{call, e, kind})
				}
				continue
			}
			if e.EventType != schema.EventToolCall || !highRisk(e) {
				continue
			}
			for j := 0; j < len(open); j++ {
				p := open[j]
				if p.call.EventID == e.EventID {
					continue
				}
				same, exact := sameAction(p.call, e)
				if !same {
					continue
				}
				sev, conf := "MEDIUM", "MEDIUM"
				outcome := "The repeated call was refused again or has no recorded result."
				reasons := []string{"the refusal and the repeated call are both in the agent's own transcript, with no new instruction between them"}
				if _, ok := ix.completed(e); ok {
					sev = "HIGH"
					outcome = "The repeated call completed: its recorded result is neither an error nor a refusal."
				}
				if exact {
					conf = "HIGH"
					reasons = append(reasons, "the repeated call is identical to the refused one")
				} else {
					reasons = append(reasons, "the repeated call is similar to, not identical with, the refused one")
				}
				out = append(out, schema.Finding{
					RuleID: "AGENT_UNEXPECTED_AUTONOMOUS_RETRY", Severity: sev,
					Title: "Agent Retried an Action After It Was Refused",
					Description: fmt.Sprintf("A %s was %s, and the agent issued it again before any new instruction from a person. %s",
						describeCall(p.call), p.kind, outcome),
					SessionID: e.SessionID, AgentID: e.AgentID,
					Related:      []string{"refused call: " + ref(p.call), "refusal: " + ref(p.res)},
					EvidenceRefs: []string{ref(e), ref(p.res)},
					Status:       e.Corroboration, Endpoint: schema.StateUnknown,
					MitreATTACK: "T1548", // Abuse Elevation Control Mechanism (the approval step)
					Confidence:  conf, Reasons: reasons, Timestamp: e.Timestamp,
					FalsePositive: "A person may have approved the retry outside the transcript (a second terminal, a policy change), or the agent may be re-asking for approval on purpose. Read the refusal and the line before the retry.",
				})
				open = append(open[:j], open[j+1:]...)
				break
			}
		}
	}
	return out
}

// Model text that announces success, and text that admits trouble. A reply
// that does both ("the push failed, so I committed locally — done") is not
// a false claim.
var (
	successClaimRe = regexp.MustCompile(`(?i)(\bsuccessfully\b|\bsucceeded\b|\bhas been (created|deployed|pushed|written|updated|fixed|deleted|removed|installed|committed|sent|uploaded|applied|merged|published|saved)\b|\ball (the )?(tests|checks) (now )?(pass|passed|are passing)\b|\bis now (live|deployed|fixed|working|running)\b|\bcompleted successfully\b|^(done|all done|finished)\b)`)
	troubleRe      = regexp.MustCompile(`(?i)(fail|error|couldn'?t|could not|cannot|can'?t|unable|didn'?t|did not|not (succeed|work|run)|denied|rejected|refused|blocked|permission|retry|instead|however|unfortunately|\bbut\b)`)
)

// AGENT_UNVERIFIED_SUCCESS_CLAIM — a state-changing call came back as an
// error or a refusal, and the agent's very next message announced success
// without any further tool call. The model's narrative is a claim; this
// rule reports the claim that contradicts the recorded result.
func unverifiedSuccessClaim(ix *eventIndex) []schema.Finding {
	var out []schema.Finding
	for _, agent := range ix.agents {
		var failed *schema.Event
		var failedCall schema.Event
		for _, i := range ix.byAgent[agent] {
			e := ix.events[i]
			switch {
			case isInstruction(e), e.EventType == schema.EventToolCall:
				failed = nil
			case e.EventType == schema.EventToolResult:
				if e.Result != "error" && refusal(e) == "" {
					continue
				}
				if call, ok := ix.callOf(e); ok && highRisk(call) {
					f := e
					failed, failedCall = &f, call
				}
			case e.EventType == schema.EventModelResponse && failed != nil:
				text := strings.TrimSpace(e.Summary)
				if successClaimRe.MatchString(text) && !troubleRe.MatchString(text) {
					out = append(out, schema.Finding{
						RuleID: "AGENT_UNVERIFIED_SUCCESS_CLAIM", Severity: "MEDIUM",
						Title: "Agent Claimed Success After a Failed or Refused Action",
						Description: fmt.Sprintf("The %s came back as an error or a refusal, and the agent's next message claims success with no tool call in between: %q. The claim contradicts the recorded result.",
							describeCall(failedCall), trimTo(text, 160)),
						SessionID: e.SessionID, AgentID: e.AgentID,
						Related:      []string{"failed call: " + ref(failedCall)},
						EvidenceRefs: []string{ref(e), ref(*failed)},
						Status:       schema.StateReported, Endpoint: schema.StateUnknown,
						Confidence: "MEDIUM", Timestamp: e.Timestamp,
						Reasons:       []string{"the failure is the client's own error flag or refusal text; the success wording is the model's narrative"},
						FalsePositive: "The success may refer to an earlier step, or the error flag may be a tool that reports warnings as errors. Read the failed result and the whole reply.",
					})
				}
				failed = nil
			}
		}
	}
	return out
}

// AGENT_EXTERNAL_ARTIFACT_EXECUTION — one tool call saved a downloaded
// file, and a later call in the same session ran that same file. The
// single-command shape is DOWNLOAD_THEN_EXECUTE; this is the split one that
// a per-command rule cannot see, linked by the file path rather than by
// time alone (CHAIN_DOWNLOAD_AND_EXECUTE pairs any download with any run).
func externalArtifactExecution(ix *eventIndex) []schema.Finding {
	const window = 60 * time.Minute
	var out []schema.Finding
	for _, s := range ix.sessions {
		type dl struct {
			ev   schema.Event
			path string
			used bool // one finding per download: chmod +x then ./x is one story
		}
		var downloads []dl
		for _, i := range ix.bySession[s] {
			e := ix.events[i]
			if e.EventType != schema.EventToolCall || e.Command == "" {
				continue
			}
			cmd := e.FullCommand()
			reported := false
			for _, x := range executedPaths(cmd) {
				if reported {
					break
				}
				for k := range downloads {
					d := &downloads[k]
					if d.used || d.ev.EventID == e.EventID || !samePath(d.path, x) || !within(d.ev, e, window) {
						continue
					}
					d.used = true
					out = append(out, schema.Finding{
						RuleID: "AGENT_EXTERNAL_ARTIFACT_EXECUTION", Severity: "HIGH",
						Title: "Agent Ran a File It Had Downloaded Earlier",
						Description: fmt.Sprintf("An earlier command saved %s from the network, and this later command runs it (%s). The payload touched disk and ran without review in between.",
							d.path, trimTo(e.Command, 120)),
						SessionID: e.SessionID, AgentID: e.AgentID,
						Related:      []string{"download: " + ref(d.ev)},
						EvidenceRefs: []string{ref(e), ref(d.ev)},
						Status:       e.Corroboration, Endpoint: schema.StateUnknown,
						MitreATTACK: "T1105", MitreATLAS: "AML.T0011.001",
						Confidence: "HIGH", Timestamp: e.Timestamp,
						Reasons:       []string{"the executed path is the path the earlier download wrote"},
						FalsePositive: "Toolchain bootstraps (rustup, nvm, installer scripts) are fetched and run on purpose. Check the URL in the download command and the prompt that asked for it.",
					})
					reported = true
					break
				}
			}
			for _, p := range downloadedPaths(cmd) {
				if len(downloads) < 256 {
					downloads = append(downloads, dl{ev: e, path: p})
				}
			}
		}
	}
	return out
}

func within(a, b schema.Event, d time.Duration) bool {
	ta, ok1 := parseTS(a.Timestamp)
	tb, ok2 := parseTS(b.Timestamp)
	if !ok1 || !ok2 {
		return true // no clock: order alone links them
	}
	return tb.Sub(ta) >= 0 && tb.Sub(ta) <= d
}

// samePath compares two shell paths: exactly when both are absolute,
// otherwise by file name (a relative path's directory is the session's cwd,
// which the command line does not repeat).
func samePath(a, b string) bool {
	a, b = strings.Trim(a, `"'`), strings.Trim(b, `"'`)
	if a == "" || b == "" {
		return false
	}
	if strings.HasPrefix(a, "/") && strings.HasPrefix(b, "/") {
		return path.Clean(a) == path.Clean(b)
	}
	return path.Base(a) == path.Base(b)
}

// downloadedPaths returns the files a curl/wget command line saves.
func downloadedPaths(cmd string) []string {
	var out []string
	for _, st := range shellshape.Stages(shellshape.Strip(shellshape.ExpandVars(cmd))) {
		v := shellshape.Verb(st.Text)
		if v != "curl" && v != "wget" {
			continue
		}
		f := strings.Fields(st.Text)
		named := false
		for i, a := range f {
			switch {
			case a == "-o" || a == "--output" || (a == "-O" && v == "wget") || a == "--output-document":
				if i+1 < len(f) && f[i+1] != "-" && f[i+1] != "/dev/null" {
					out = append(out, strings.Trim(f[i+1], `"'`))
				}
				named = true
			case strings.HasPrefix(a, "--output=") || strings.HasPrefix(a, "--output-document="):
				out = append(out, a[strings.IndexByte(a, '=')+1:])
				named = true
			}
		}
		if named {
			continue
		}
		if v == "wget" || hasArg(f, "-O") || hasArg(f, "--remote-name") {
			for _, u := range f {
				if strings.Contains(u, "://") {
					u = strings.Trim(u, `"'`)
					if q := strings.IndexAny(u, "?#"); q >= 0 {
						u = u[:q]
					}
					if b := path.Base(u); b != "" && b != "." && b != "/" && !strings.Contains(b, ":") {
						out = append(out, b)
					}
				}
			}
		}
	}
	return out
}

// executedPaths returns the files a command line runs or marks executable.
func executedPaths(cmd string) []string {
	var out []string
	for _, st := range shellshape.Stages(shellshape.Strip(shellshape.ExpandVars(cmd))) {
		f := strings.Fields(st.Text)
		for len(f) > 0 && (strings.Contains(f[0], "=") && !strings.HasPrefix(f[0], "-") || f[0] == "sudo" || f[0] == "exec" || f[0] == "nohup") {
			f = f[1:]
		}
		if len(f) == 0 {
			continue
		}
		v := f[0]
		base := path.Base(v)
		switch {
		case base == "chmod":
			if hasArg(f, "+x") || hasArg(f, "u+x") || hasArg(f, "a+x") || hasArg(f, "755") || hasArg(f, "0755") || hasArg(f, "700") {
				for _, a := range f[1:] {
					if !strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "+") && !strings.ContainsAny(a[:1], "0123456789") && !strings.HasPrefix(a, "u+") && !strings.HasPrefix(a, "a+") {
						out = append(out, a)
					}
				}
			}
		case base == "sh" || base == "bash" || base == "zsh" || base == "dash" || base == "source" || base == "." ||
			base == "perl" || base == "node" || base == "ruby" || base == "php" || strings.HasPrefix(base, "python"):
			for _, a := range f[1:] {
				if strings.HasPrefix(a, "-") {
					if a == "-c" || a == "-m" || a == "-e" {
						break // inline code or a module, not a file
					}
					continue
				}
				out = append(out, a)
				break
			}
		case strings.HasPrefix(v, "./") || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~/"):
			out = append(out, v)
		}
	}
	return out
}

func hasArg(f []string, want string) bool {
	for _, a := range f {
		if a == want {
			return true
		}
	}
	return false
}

// permissionRank orders the approval modes the clients record, narrowest
// first. Modes not listed are not ranked and never count as broadening.
var permissionRank = map[string]int{"plan": 0, "default": 1, "acceptEdits": 2, "auto": 2, "bypassPermissions": 4}

// broadenRe is content that widens what the agent may do without asking,
// when a command writes it into the agent's own configuration.
var broadenRe = regexp.MustCompile(`(?i)(bypassPermissions|dangerously-skip-permissions|"allow"\s*:|permissions\.allow|allowedTools|alwaysAllow|autoApprove|enableAllProjectMcpServers|approval_policy\s*=\s*"?never|sandbox_mode\s*=\s*"?danger-full-access|trust_level\s*=\s*"?trusted)`)

// claudeConfigGrantRe is the CLI spelling of the same grant.
var claudeConfigGrantRe = regexp.MustCompile(`(?i)\bclaude\s+config\s+(set|add)\b[^;\n|&]*(allowedTools|autoApprove|bypass|dangerously)`)

// AGENT_TOOL_PERMISSION_ESCALATION — the permissions in effect widened
// during a session: the client recorded the session moving into
// bypassPermissions after a narrower mode, or the agent itself wrote an
// allow rule, auto-approve list or bypass setting into its own
// configuration. AGENT_SELF_MODIFICATION reports every write to that
// configuration; this rule reports the writes whose content is a grant.
func permissionModeEscalation(ix *eventIndex) []schema.Finding {
	var out []schema.Finding
	for _, s := range ix.sessions {
		last, lastEv := "", schema.Event{}
		reportedMode := false
		for _, i := range ix.bySession[s] {
			e := ix.events[i]
			if m := e.PermissionMode; m != "" && !reportedMode {
				r, ranked := permissionRank[m]
				lr, lranked := permissionRank[last]
				if ranked && lranked && r == permissionRank["bypassPermissions"] && lr < r {
					reportedMode = true
					out = append(out, schema.Finding{
						RuleID: "AGENT_TOOL_PERMISSION_ESCALATION", Severity: "MEDIUM",
						Title:       "Session Switched to Bypass-Permissions Mode",
						Description: fmt.Sprintf("The client recorded permission mode %q earlier in this session and %q from this line on: tool calls after it ran without per-call approval.", last, m),
						SessionID:   e.SessionID, AgentID: e.AgentID,
						Related:      []string{"previous mode recorded at: " + ref(lastEv)},
						EvidenceRefs: []string{ref(e)},
						Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
						MitreATTACK: "T1685", MitreATLAS: "AML.T0081",
						Confidence: "HIGH", Timestamp: e.Timestamp,
						Reasons:       []string{"the mode is the client's own record on each transcript line"},
						FalsePositive: "A person switching modes on purpose (Shift+Tab in a session launched with bypass allowed). Ask who was at the keyboard.",
					})
				}
				last, lastEv = m, e
			}
			if e.EventType != schema.EventToolCall || e.Command == "" {
				continue
			}
			cmd := e.FullCommand()
			grant := claudeConfigGrantRe.MatchString(cmd)
			if !grant && broadenRe.MatchString(cmd) && !IsReadOnlyCommand(cmd) {
				for _, t := range WriteTargets(shellshape.ExpandVars(cmd)) {
					if selfCfgRe.MatchString(t) && !IsScratchPath(t) {
						grant = true
						break
					}
				}
			}
			if !grant {
				continue
			}
			out = append(out, schema.Finding{
				RuleID: "AGENT_TOOL_PERMISSION_ESCALATION", Severity: "HIGH",
				Title:       "Agent Granted Itself Broader Tool Permissions",
				Description: fmt.Sprintf("Agent command writes an allow rule, auto-approve list or bypass setting into its own configuration (%s). Later calls the grant covers will not ask a person.", trimTo(e.Command, 160)),
				SessionID:   e.SessionID, AgentID: e.AgentID,
				EvidenceRefs: []string{ref(e)},
				Status:       e.Corroboration, Endpoint: schema.StateUnknown,
				MitreATTACK: "T1685", MitreATLAS: "AML.T0081",
				Confidence: "MEDIUM", Timestamp: e.Timestamp,
				Reasons:       []string{"the grant is read from the command line; the configuration file as it was afterwards is not compared"},
				FalsePositive: "A person asking the agent to allow a tool it keeps prompting for. Check the prompt before the command.",
			})
		}
	}
	return out
}

// identitySwitchRe is a command that changes which cloud, code-hosting or
// AI identity later commands run as.
var identitySwitchRe = regexp.MustCompile(`(?i)(\bgh\s+auth\s+(switch|login\s+[^;\n|&]*--with-token)\b|\baws\s+sts\s+assume-role(-with-web-identity|-with-saml)?\b|\bgcloud\s+(config\s+set\s+(core/)?account|auth\s+activate-service-account)\b|\baz\s+(login\s+[^;\n|&]*--service-principal|account\s+set)\b|\bexport\s+(AWS_PROFILE|CLOUDSDK_CORE_ACCOUNT|GOOGLE_APPLICATION_CREDENTIALS)=|\bGH_TOKEN=\$\(\s*gh\s+auth\s+token\s+[^)]*--user\b)`)

// AI_SESSION_IDENTITY_SWITCH — the identity behind related activity
// changed. Two shapes: one session id whose records sit under two different
// AI login profiles (accounts.Key: a transcript copied or resumed under
// another login), and an agent command that switches the cloud or
// code-hosting identity later commands run as.
func identitySwitch(ix *eventIndex) []schema.Finding {
	var out []schema.Finding
	for _, s := range ix.sessions {
		profiles := map[string]schema.Event{}
		var keys []string
		for _, i := range ix.bySession[s] {
			e := ix.events[i]
			if multiSessionStore(e) || e.SourcePath == "" {
				continue
			}
			k := accounts.Key(e.SourcePath, e.Product)
			if k == "unknown" {
				continue
			}
			if _, ok := profiles[k]; !ok {
				profiles[k] = e
				keys = append(keys, k)
			}
		}
		if len(keys) < 2 {
			continue
		}
		var refs []string
		for _, k := range keys {
			if len(refs) < 4 {
				refs = append(refs, ref(profiles[k]))
			}
		}
		first := profiles[keys[0]]
		out = append(out, schema.Finding{
			RuleID: "AI_SESSION_IDENTITY_SWITCH", Severity: "MEDIUM",
			Title:       "One Session Recorded Under Several AI Logins",
			Description: fmt.Sprintf("Records of session %s sit under %d different login profiles (%s). The same conversation continued under another account, or its transcript was copied between profiles.", s, len(keys), strings.Join(keys, ", ")),
			SessionID:   s, AgentID: first.AgentID,
			EvidenceRefs: refs,
			Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
			MitreATTACK: "T1078", Confidence: "MEDIUM", Timestamp: first.Timestamp,
			Reasons:       []string{"the account of a record is the login profile its transcript was collected from"},
			FalsePositive: "Moving a profile directory or syncing transcripts between machines with different profile names. Ask whether both logins belong to the same person.",
		})
	}
	for _, s := range ix.sessions {
		for _, i := range ix.bySession[s] {
			e := ix.events[i]
			if e.EventType != schema.EventToolCall || e.Command == "" {
				continue
			}
			m := identitySwitchRe.FindString(e.FullCommand())
			if m == "" {
				continue
			}
			out = append(out, schema.Finding{
				RuleID: "AI_SESSION_IDENTITY_SWITCH", Severity: "LOW",
				Title:       "Agent Switched the Identity Its Commands Run As",
				Description: fmt.Sprintf("Agent command changes the cloud or code-hosting identity for what follows (%s). Actions after it in this session are attributable to that identity, not the one the session started with.", strings.TrimSpace(m)),
				SessionID:   e.SessionID, AgentID: e.AgentID,
				EvidenceRefs: []string{ref(e)},
				Status:       e.Corroboration, Endpoint: schema.StateUnknown,
				MitreATTACK: "T1078", Confidence: "MEDIUM", Timestamp: e.Timestamp,
				Reasons:       []string{"read from the command line; whether the switch succeeded is in the tool result"},
				FalsePositive: "Switching to the account a task needs (a release account, a second GitHub login) is routine when the person asked for it.",
			})
		}
	}
	return out
}

// AGENT_SESSION_CLOCK_ANOMALY — timestamps inside one transcript that
// cannot be true: dated after the file was collected, a tool result
// recorded before the call it answers, or dates before AI coding agents
// existed. SESSION_TAMPERING already counts plain backward steps and
// TIMESTOMP_INDICATOR compares the file's mtime; neither looks at these.
func clockAnomaly(ix *eventIndex, man *casepkg.Manifest) []schema.Finding {
	const tolerance = 5 * time.Minute
	collected := map[string]time.Time{}
	logical := map[string]string{}
	for _, a := range man.Current() {
		if t, ok := parseTS(a.CollectedUTC); ok {
			collected[a.ArtifactID] = t
		}
		logical[a.ArtifactID] = a.LogicalPath
	}
	floor := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	type stats struct {
		future, early, ancient int
		sample                 schema.Event
		sampled                bool
	}
	per := map[string]*stats{}
	var order []string
	note := func(e schema.Event) *stats {
		st := per[e.SourceArtifact]
		if st == nil {
			st = &stats{}
			per[e.SourceArtifact] = st
			order = append(order, e.SourceArtifact)
		}
		if !st.sampled {
			st.sample, st.sampled = e, true
		}
		return st
	}
	for _, e := range ix.events {
		if e.SourceArtifact == "" || multiSessionStore(e) || e.TimestampSrc != "transcript" {
			continue
		}
		t, ok := parseTS(e.Timestamp)
		if !ok {
			continue
		}
		if c, ok := collected[e.SourceArtifact]; ok && t.After(c.Add(tolerance)) {
			note(e).future++
		}
		if t.Before(floor) {
			note(e).ancient++
		}
		if e.EventType == schema.EventToolResult {
			if call, ok := ix.callOf(e); ok {
				if ct, ok := parseTS(call.Timestamp); ok && ct.Sub(t) > time.Minute {
					note(e).early++
				}
			}
		}
	}
	var out []schema.Finding
	for _, art := range order {
		st := per[art]
		var parts []string
		if st.future > 0 {
			parts = append(parts, fmt.Sprintf("%d record(s) dated after the file was collected", st.future))
		}
		if st.early > 0 {
			parts = append(parts, fmt.Sprintf("%d tool result(s) recorded more than a minute before their call", st.early))
		}
		if st.ancient > 0 {
			parts = append(parts, fmt.Sprintf("%d record(s) dated before 2021", st.ancient))
		}
		out = append(out, schema.Finding{
			RuleID: "AGENT_SESSION_CLOCK_ANOMALY", Severity: "MEDIUM",
			Title:       "Transcript Timestamps That Cannot Be True",
			Description: fmt.Sprintf("%s: %s. Times inside this transcript were set by something other than a running client, or the host clock was wrong while it was written.", logical[art], strings.Join(parts, "; ")),
			SessionID:   st.sample.SessionID, AgentID: st.sample.AgentID,
			EvidenceRefs: []string{ref(st.sample)},
			Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
			MitreATTACK: "T1565.001", Confidence: "MEDIUM", Timestamp: st.sample.Timestamp,
			Reasons:       []string{"compared against the collection time recorded in the sealed manifest, and against the paired tool call"},
			FalsePositive: "A host clock that was wrong (VM resume, dead CMOS battery) produces the same pattern; compare with the case clock data in case.json.",
		})
	}
	return out
}
