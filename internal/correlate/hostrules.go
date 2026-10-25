package correlate

import (
	"encoding/base64"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Host-witness rules added in v4.5 after a dedupe of the proposed
// detection table against every existing rule (docs/detection-v45.md).
// Each reads what the operating system recorded, never what the
// transcript says, and each declares the telemetry it needs. When that
// telemetry is absent the rule is not evaluated and says so in its
// HostRuleCoverage entry: it never fires, and its silence is never
// evidence that the act did not happen.
//
//	WIN_AGENT_SUSPICIOUS_POWERSHELL  an agent-descended PowerShell with an
//	                                 encoded command, hidden window, download
//	                                 cradle, AMSI/Defender tampering (Sysmon 1,
//	                                 4688 with command lines, 4104/4103 joined
//	                                 to the process tree by pid)
//	AGENT_PRIVILEGE_ELEVATION        sudo / su / pkexec / polkit records with a
//	                                 target identity, from a process descended
//	                                 from the agent (auth.log, journal, eslogger)
//	AGENT_LOGGING_DISRUPTED          an agent-descended process stopping, killing
//	                                 or clearing a logging source; an event log
//	                                 cleared (1102/104) during an agent session
//	AGENT_EVIDENCE_SOURCE_DELETED    an agent-descended process deleting agent
//	                                 transcripts, shell history or OS logs
//	PACKAGE_SCRIPT_TOUCHED_AGENT     a process descended from a package install
//	                                 (npm/pip/gem/cargo/composer lifecycle
//	                                 scripts) launching an agent CLI, writing the
//	                                 agent's configuration or reading its login

// HostRuleCoverage says whether a host rule could be evaluated with the
// telemetry that was imported, and what was missing when it could not.
type HostRuleCoverage struct {
	Rule      string `json:"rule"`
	Evaluated bool   `json:"evaluated"`
	Partial   string `json:"partial,omitempty"` // evaluated, but one branch lacks its telemetry
	Missing   string `json:"missing,omitempty"` // why it was not evaluated
}

const (
	maxHostRuleLines = 5
	maxPackageRoots  = 20
	hostPIDSlack     = 2 * time.Second
	hostAncestorHops = 32
	logClearPad      = 2 * time.Minute
	psDecodeMax      = 4096
)

// hostView is the record set the host rules share: every record that
// carries process identity, the process index and the agent lineage.
type hostView struct {
	recs     []endpoint.Record
	names    map[string]bool
	lineage  []bool
	byPID    map[int][]int // process records per pid, in time order
	byExec   map[string]int
	hasProc  bool // process telemetry with parent linkage (not sightings)
	winProc  bool // Windows process records
	hasFile  bool
	sessions []sessionWindow
}

func newHostView(events []schema.Event, records []endpoint.Record, opts EndpointOptions) *hostView {
	v := &hostView{names: agentBinaryNames(opts.AgentBinaries), byPID: map[int][]int{}, byExec: map[string]int{}}
	for _, r := range records {
		switch r.Kind {
		case "process":
			if endpoint.IsSighting(r) {
				continue // auth.log / journal process lines carry no parent: never lineage input
			}
		case "file", "network", "syscall", "auth", "script", endpoint.KindSignal, "log-clear":
		default:
			continue
		}
		v.recs = append(v.recs, r)
	}
	sort.SliceStable(v.recs, func(i, j int) bool { return v.recs[i].Time.Before(v.recs[j].Time) })
	for i, r := range v.recs {
		switch r.Kind {
		case "process":
			if r.PID != 0 && (r.PPID != 0 || r.ParentExecID != "" || r.ParentExe != "") {
				v.hasProc = true
			}
			if r.PID != 0 {
				v.byPID[r.PID] = append(v.byPID[r.PID], i)
			}
			if r.ExecID != "" {
				v.byExec[r.ExecID] = i
			}
			if strings.Contains(r.Exe, `\`) || strings.HasSuffix(strings.ToLower(r.Exe), ".exe") {
				v.winProc = true
			}
		case "file":
			v.hasFile = true
		}
	}
	v.lineage = agentLineage(v.recs, v.names)
	v.sessions = agentSessions(events)
	return v
}

// procAt returns the process record for pid current at t: the latest one
// started at or before t (plus clock slack), or -1.
func (v *hostView) procAt(pid int, t time.Time) int {
	best := -1
	for _, i := range v.byPID[pid] {
		if v.recs[i].Time.After(t.Add(hostPIDSlack)) {
			break
		}
		best = i
	}
	return best
}

// attributed reports whether record i was produced by a process that
// descends from the agent. Records without a parent pid (auth.log sudo,
// PowerShell script blocks) are joined to the process record of their
// own pid. The agent's own records are not "descended": the rules judge
// what the agent started, and the agent's housekeeping (deleting its own
// old transcripts) is not an act of its tools.
func (v *hostView) attributed(i int) bool {
	r := v.recs[i]
	if v.isLineageRoot(i) {
		return false
	}
	if v.lineage[i] {
		return true
	}
	if r.PID == 0 {
		return false
	}
	if j := v.procAt(r.PID, r.Time); j >= 0 && j != i {
		return v.lineage[j]
	}
	return false
}

// isLineageRoot reports whether a non-process record was produced by the
// agent process itself: its pid resolves to a process record that is an
// agent binary and does not itself descend from an agent. The record's own
// Exe and Cmdline are not trusted for this (a tool can name itself
// anything); only the process telemetry's record of that pid is. Auth and
// signal records are never exempt.
func (v *hostView) isLineageRoot(i int) bool {
	r := v.recs[i]
	switch r.Kind {
	case "process", "auth", endpoint.KindSignal:
		return false
	}
	if r.PID == 0 {
		return false
	}
	j := v.procAt(r.PID, r.Time)
	if j < 0 || j == i {
		return false
	}
	p := v.recs[j]
	return agentProcess(v.names, p.Exe, p.Cmdline) && !v.lineage[j]
}

// ancestors calls fn for each process-record ancestor of record i (parent
// first), by parent pid at the record's time and by Tetragon exec_id,
// bounded. fn returns true to stop.
func (v *hostView) ancestors(i int, fn func(j int) bool) {
	r := v.recs[i]
	seen := map[int]bool{i: true}
	// Records with no parent link (script blocks, auth.log) start at the
	// process record of their own pid.
	cur := -1
	switch {
	case r.ParentExecID != "":
		if j, ok := v.byExec[r.ParentExecID]; ok {
			cur = j
		}
	case r.PPID != 0:
		cur = v.procAt(r.PPID, r.Time)
	case r.Kind != "process" && r.PID != 0:
		if j := v.procAt(r.PID, r.Time); j >= 0 && j != i {
			if fn(j) {
				return
			}
			seen[j] = true
			pr := v.recs[j]
			if pr.ParentExecID != "" {
				if k, ok := v.byExec[pr.ParentExecID]; ok {
					cur = k
				}
			} else if pr.PPID != 0 {
				cur = v.procAt(pr.PPID, pr.Time)
			}
		}
	}
	for hop := 0; hop < hostAncestorHops && cur >= 0 && !seen[cur]; hop++ {
		seen[cur] = true
		if fn(cur) {
			return
		}
		p := v.recs[cur]
		next := -1
		if p.ParentExecID != "" {
			if k, ok := v.byExec[p.ParentExecID]; ok {
				next = k
			}
		}
		if next < 0 && p.PPID > 1 {
			next = v.procAt(p.PPID, p.Time)
		}
		cur = next
	}
}

// inSession returns the agent session whose time range (padded) holds t.
func (v *hostView) inSession(t time.Time, pad time.Duration) (sessionWindow, bool) {
	for _, s := range v.sessions {
		if !t.Before(s.start.Add(-pad)) && !t.After(s.end.Add(pad)) {
			return s, true
		}
	}
	return sessionWindow{}, false
}

// hostHits collects lines and refs for one finding.
type hostHits struct {
	first time.Time
	n     int
	lines []string
	refs  []string
}

func (h *hostHits) add(r endpoint.Record, what string) {
	if h.n == 0 || r.Time.Before(h.first) {
		h.first = r.Time
	}
	h.n++
	if len(h.lines) < maxHostRuleLines {
		h.lines = append(h.lines, fmt.Sprintf("%s %s pid %d: %s", r.Time.UTC().Format(time.RFC3339), r.Source, r.PID, trim(what, 200)))
		h.refs = append(h.refs, r.Source+" "+r.Ref)
	}
}

// HostRules runs the v4.5 host-witness rules over imported telemetry.
// It never changes an event's corroboration state.
func HostRules(events []schema.Event, records []endpoint.Record, opts EndpointOptions) ([]schema.Finding, []HostRuleCoverage) {
	v := newHostView(events, records, opts)
	var out []schema.Finding
	var cov []HostRuleCoverage
	for _, rule := range []func(*hostView) ([]schema.Finding, HostRuleCoverage){
		(*hostView).powershell, (*hostView).privilege, (*hostView).logging, (*hostView).evidenceDeletion, (*hostView).packageScripts,
	} {
		f, c := rule(v)
		out = append(out, f...)
		cov = append(cov, c)
	}
	return out, cov
}

const lineageMissing = "no process telemetry with parent linkage (Sysmon 1 / Security 4688, auditd EXECVE, eslogger exec, Tetragon process_exec), so nothing can be tied to the agent's process tree"

// ------------------------------------------------- WIN_AGENT_SUSPICIOUS_POWERSHELL

var (
	psEncodedRe = regexp.MustCompile(`(?i)(?:^|\s)[-/]e(?:c|n|nc|nco|ncod|ncode|ncoded|ncodedc|ncodedco|ncodedcom|ncodedcomm|ncodedcomma|ncodedcomman|ncodedcommand)?\s+([A-Za-z0-9+/=]{16,})`)
	psHiddenRe  = regexp.MustCompile(`(?i)(?:^|\s)[-/]w(?:i|in|ind|indo|indow|indows|indowst|indowsty|indowstyl|indowstyle)?\s+(?:h|hi|hid|hidd|hidde|hidden|1)\b`)
	// Content that has no place in an agent's routine shell work: a
	// download handed to the interpreter, decoded code run, AMSI or
	// Defender switched off, well-known offensive cmdlets.
	psContentRe = regexp.MustCompile(`(?i)((\biex\b|invoke-expression)[^\n]{0,200}(downloadstring|downloadfile|invoke-webrequest|\biwr\b|net\.webclient|invoke-restmethod|\birm\b|frombase64string)|(downloadstring|downloadfile|invoke-webrequest|\biwr\b|invoke-restmethod|\birm\b)[^\n]{0,200}\|\s*(iex|invoke-expression)\b|amsiutils|amsiinitfailed|amsiscanbuffer|set-mppreference[^\n]{0,120}-disable\w*\s+(\$true|1)|add-mppreference[^\n]{0,60}-exclusion\w*|invoke-mimikatz|invoke-shellcode|\[(system\.)?reflection\.assembly\]::load|start-bitstransfer[^\n]{0,200}(\.exe|\.ps1|\.dll)\b)`)
)

func isPowerShell(r endpoint.Record) bool {
	n := exeName(r.Exe)
	if n == "" {
		n = exeName(firstToken(r.Cmdline))
	}
	return n == "powershell" || n == "pwsh" || n == "powershell_ise"
}

// psDecode decodes a -EncodedCommand payload (UTF-16LE base64), bounded.
func psDecode(b64 string) string {
	if len(b64) > psDecodeMax*2 {
		b64 = b64[:psDecodeMax*2]
	}
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		if raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(b64, "=")); err != nil {
			return ""
		}
	}
	if len(raw) > psDecodeMax {
		raw = raw[:psDecodeMax]
	}
	u := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		u = append(u, uint16(raw[i])|uint16(raw[i+1])<<8)
	}
	s := string(utf16.Decode(u))
	return strings.Map(func(r rune) rune {
		if r < 0x20 && r != '\n' && r != '\t' {
			return ' '
		}
		return r
	}, s)
}

// psWhy explains what made a PowerShell command line or script block
// suspicious, or "".
func psWhy(text string, cmdline bool) string {
	var why []string
	if cmdline {
		if m := psEncodedRe.FindStringSubmatch(text); m != nil {
			w := "encoded command"
			if d := psDecode(m[1]); d != "" {
				w += " (decodes to: " + trim(d, 120) + ")"
				if psContentRe.MatchString(d) {
					w += ", a download/execute or defence-tampering payload"
				}
			}
			why = append(why, w)
		}
		if psHiddenRe.MatchString(text) {
			why = append(why, "hidden window")
		}
	}
	if m := psContentRe.FindString(text); m != "" {
		why = append(why, "content: "+trim(m, 80))
	}
	return strings.Join(why, "; ")
}

func (v *hostView) powershell() ([]schema.Finding, HostRuleCoverage) {
	c := HostRuleCoverage{Rule: "WIN_AGENT_SUSPICIOUS_POWERSHELL"}
	scripts := false
	for _, r := range v.recs {
		if r.Kind == "script" {
			scripts = true
			break
		}
	}
	if !v.winProc {
		if scripts {
			c.Missing = "PowerShell script-block records are present, but no Windows process telemetry (Sysmon 1, Security 4688 with command lines) ties them to the agent's process tree"
		} else {
			c.Missing = "no Windows process telemetry with command lines (Sysmon 1, Security 4688) and no PowerShell 4104/4103 records"
		}
		return nil, c
	}
	c.Evaluated = true
	if !scripts {
		c.Partial = "no PowerShell script-block (4104) or module (4103) records: script content was not checked, only command lines"
	}
	h := &hostHits{}
	for i, r := range v.recs {
		var why string
		switch {
		case r.Kind == "process" && isPowerShell(r):
			why = psWhy(r.Cmdline, true)
		case r.Kind == "script":
			why = psWhy(r.Cmdline, false)
		}
		if why == "" || !v.attributed(i) {
			continue
		}
		h.add(r, why+" | "+r.Cmdline)
	}
	if h.n == 0 {
		return nil, c
	}
	return []schema.Finding{{
		RuleID: "WIN_AGENT_SUSPICIOUS_POWERSHELL", Severity: "HIGH", Title: "Agent-Descended PowerShell Ran an Encoded, Hidden or Download-and-Run Command",
		Description: fmt.Sprintf("Windows telemetry shows %d PowerShell command line(s) or script block(s) in the agent's process tree (first at %s) with an encoded command, a hidden window, a download handed to the interpreter, or AMSI/Defender tampering. This is what Windows recorded, independent of the transcript.",
			h.n, h.first.UTC().Format(time.RFC3339)),
		Related: h.lines, EvidenceRefs: h.refs, Timestamp: h.first.UTC().Format(time.RFC3339),
		Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1059.001", MitreATLAS: "AML.T0050",
		FalsePositive: "Vendor installers (Chocolatey, Scoop) use the download-and-run idiom; an agent asked to install one runs it. Encoded commands with hidden windows have almost no legitimate use from an agent.",
	}}, c
}

// ------------------------------------------------------- AGENT_PRIVILEGE_ELEVATION

// privTarget returns the identity a privilege record switches to.
func privTarget(r endpoint.Record) string {
	if r.PrivTo != "" {
		return r.PrivTo
	}
	if strings.HasPrefix(r.Resource, "USER=") {
		return strings.TrimPrefix(r.Resource, "USER=")
	}
	return ""
}

func isPrivChange(r endpoint.Record) bool {
	if r.Kind != "auth" {
		return false
	}
	op := strings.ToLower(r.Operation)
	switch {
	case op == "sudo", op == "su", op == "pkexec", strings.HasPrefix(op, "polkit "):
	default:
		return false // logons, ssh, pam failures, 4672/4648 (WIN_AGENT_EXPLICIT_CREDENTIALS)
	}
	to := privTarget(r)
	from := firstNonEmptyStr(r.PrivFrom, r.User)
	return to != "" && to != from
}

func (v *hostView) privilege() ([]schema.Finding, HostRuleCoverage) {
	c := HostRuleCoverage{Rule: "AGENT_PRIVILEGE_ELEVATION"}
	privRecs, win4672 := false, false
	for _, r := range v.recs {
		if isPrivChange(r) {
			privRecs = true
		}
		if r.Kind == "auth" && r.Operation == "special-privileges" {
			win4672 = true
		}
	}
	note4672 := ""
	if win4672 {
		note4672 = "; Security 4672 records are present but name no process, so they cannot be tied to the agent (4648 is WIN_AGENT_EXPLICIT_CREDENTIALS)"
	}
	switch {
	case !privRecs:
		c.Missing = "no privilege-change records (auth.log / secure / journal sudo, su, pkexec, polkit; eslogger sudo, su)" + note4672
		return nil, c
	case !v.hasProc:
		c.Missing = "privilege-change records are present, but " + lineageMissing + note4672
		return nil, c
	}
	c.Evaluated = true
	c.Partial = strings.TrimPrefix(note4672, "; ")
	h := &hostHits{}
	granted := 0
	for i, r := range v.recs {
		if !isPrivChange(r) || !v.attributed(i) {
			continue
		}
		state := "granted"
		if r.Failed != "" {
			state = "refused (" + r.Failed + ")"
		} else {
			granted++
		}
		what := fmt.Sprintf("%s %s → %s, %s", r.Operation, firstNonEmptyStr(r.PrivFrom, r.User, "?"), privTarget(r), state)
		if r.Cmdline != "" {
			what += ": " + r.Cmdline
		}
		h.add(r, what)
	}
	if h.n == 0 {
		return nil, c
	}
	sev := "HIGH"
	if granted == 0 {
		sev = "MEDIUM"
	}
	return []schema.Finding{{
		RuleID: "AGENT_PRIVILEGE_ELEVATION", Severity: sev, Title: "Agent-Descended Process Switched to Another Identity (sudo, su, pkexec)",
		Description: fmt.Sprintf("The operating system recorded %d privilege change(s) by a process in the agent's process tree (%d granted, first at %s). An agent that obtains another identity can do anything that identity can, outside the agent's own permission checks.",
			h.n, granted, h.first.UTC().Format(time.RFC3339)),
		Related: h.lines, EvidenceRefs: h.refs, Timestamp: h.first.UTC().Format(time.RFC3339),
		Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1548.003",
		FalsePositive: "A person who asked the agent to install a system package or restart a service, with a cached sudo ticket. Check the command each change ran.",
	}}, c
}

// --------------------------------------------------------- AGENT_LOGGING_DISRUPTED

// loggingDaemons are processes, units and launchd labels that collect
// the telemetry an investigation depends on.
var loggingDaemons = []string{"auditd", "eslogger", "syslogd", "rsyslogd", "rsyslog", "syslog-ng", "systemd-journald", "journald",
	"osqueryd", "falcon-sensor", "falcond", "falcon", "sysmon", "sysmon64", "sysmondrv", "tetragon", "falco", "auditbeat", "filebeat",
	"elastic-agent", "wazuh-agent", "fluent-bit", "td-agent", "datadog-agent", "logd", "santad", "eventlog"}

func namesLoggingDaemon(arg string) bool {
	a := strings.ToLower(strings.Trim(arg, `"'`))
	a = strings.TrimSuffix(strings.TrimSuffix(a, ".service"), ".exe")
	base := a
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	for _, d := range loggingDaemons {
		if base == d || strings.HasSuffix(base, "."+d) { // com.apple.auditd, system/com.apple.logd
			return true
		}
	}
	return false
}

var psLogClearRe = regexp.MustCompile(`(?i)\b(clear-eventlog|clear-winevent)\b|\bstop-service\b[^;|\n]*\b(eventlog|sysmon64|sysmon)\b|\bwevtutil(\.exe)?\s+(cl|clear-log)\b|\bwevtutil(\.exe)?\s+(sl|set-log)\b[^;|\n]*/e:false|\bauditpol(\.exe)?\s+/(clear|remove)\b`)

// loggingStop reports what in a command line stops, kills or clears a
// logging source, or "". Each invocation is judged on its argv, so a
// `grep auditd` or `systemctl status auditd` never matches.
func loggingStop(cmd string) string {
	why := ""
	forEachInvocation(cmd, func(argv []string) bool {
		argv = unwrap(argv)
		if len(argv) == 0 {
			return false
		}
		prog, args := exeName(argv[0]), argv[1:]
		low := make([]string, len(args))
		for i, a := range args {
			low[i] = strings.ToLower(a)
		}
		anyDaemon := func(from int) bool {
			for _, a := range args[min(from, len(args)):] {
				if namesLoggingDaemon(a) {
					return true
				}
			}
			return false
		}
		has := func(s string) bool {
			for _, a := range low {
				if a == s {
					return true
				}
			}
			return false
		}
		switch prog {
		case "systemctl":
			for i, a := range low {
				if strings.HasPrefix(a, "-") {
					continue
				}
				if (a == "stop" || a == "disable" || a == "mask" || a == "kill") && anyDaemon(i+1) {
					why = "logging service stopped: " + strings.Join(argv, " ")
				}
				break
			}
		case "service":
			if len(args) >= 2 && namesLoggingDaemon(args[0]) && (low[1] == "stop" || low[1] == "disable") {
				why = "logging service stopped: " + strings.Join(argv, " ")
			}
		case "auditctl":
			for i, a := range low {
				if a == "-d" && args[i] == "-D" || a == "-e0" || (a == "-e" && i+1 < len(low) && low[i+1] == "0") {
					why = "audit rules removed or auditing disabled: " + strings.Join(argv, " ")
				}
			}
		case "pkill", "killall", "taskkill":
			if anyDaemon(0) {
				why = "logging process killed: " + strings.Join(argv, " ")
			}
		case "launchctl":
			if len(low) > 0 && (low[0] == "unload" || low[0] == "bootout" || low[0] == "disable" || low[0] == "remove" || low[0] == "kill") && anyDaemon(1) {
				why = "logging daemon unloaded: " + strings.Join(argv, " ")
			}
			for _, a := range low {
				if strings.Contains(a, "com.apple.auditd") || strings.Contains(a, "com.apple.logd") || strings.Contains(a, "com.apple.syslogd") {
					if len(low) > 0 && (low[0] == "unload" || low[0] == "bootout" || low[0] == "disable" || low[0] == "remove") {
						why = "logging daemon unloaded: " + strings.Join(argv, " ")
					}
				}
			}
		case "log":
			if len(low) > 0 && low[0] == "config" && strings.Contains(strings.Join(low, " "), "level:off") {
				why = "unified logging silenced: " + strings.Join(argv, " ")
			}
		case "journalctl":
			for _, a := range low {
				if strings.HasPrefix(a, "--vacuum-") {
					why = "journal vacuumed: " + strings.Join(argv, " ")
				}
			}
		case "wevtutil":
			if len(low) > 0 && (low[0] == "cl" || low[0] == "clear-log") {
				why = "event log cleared: " + strings.Join(argv, " ")
			}
			if len(low) > 0 && (low[0] == "sl" || low[0] == "set-log") && has("/e:false") {
				why = "event log disabled: " + strings.Join(argv, " ")
			}
		case "auditpol":
			if has("/clear") || has("/remove") {
				why = "audit policy cleared: " + strings.Join(argv, " ")
			}
		case "sysmon", "sysmon64":
			if has("-u") || has("/u") {
				why = "Sysmon uninstalled: " + strings.Join(argv, " ")
			}
		case "fltmc":
			if len(low) >= 2 && (low[0] == "unload" || low[0] == "detach") && strings.Contains(low[1], "sysmondrv") {
				why = "Sysmon driver unloaded: " + strings.Join(argv, " ")
			}
		case "sc":
			if len(low) >= 2 && (low[0] == "stop" || low[0] == "delete" || low[0] == "config") && namesLoggingDaemon(args[1]) {
				why = "logging service stopped: " + strings.Join(argv, " ")
			}
		case "powershell", "pwsh":
			if m := psLogClearRe.FindString(strings.Join(args, " ")); m != "" {
				why = "PowerShell: " + m
			}
		}
		return why != ""
	})
	return why
}

// wrappers run the rest of their argv as a command.
var wrappers = map[string]bool{"sudo": true, "doas": true, "env": true, "nohup": true, "time": true, "command": true, "exec": true,
	"nice": true, "ionice": true, "timeout": true, "stdbuf": true, "setsid": true, "runuser": true}

// wrapperValued are wrapper options that take a separate value.
var wrapperValued = map[string]bool{"-u": true, "-g": true, "-C": true, "-D": true, "-h": true, "-p": true, "-r": true, "-t": true,
	"-n": true, "-c": true, "-s": true, "-k": true}

// unwrap drops leading wrapper programs (sudo, env, nohup, timeout …),
// their options and environment assignments, bounded.
func unwrap(argv []string) []string {
	for hop := 0; hop < 8 && len(argv) > 0 && wrappers[exeName(argv[0])]; hop++ {
		w := exeName(argv[0])
		argv = argv[1:]
		for len(argv) > 0 {
			a := argv[0]
			switch {
			case a == "--":
				argv = argv[1:]
			case strings.HasPrefix(a, "-"):
				argv = argv[1:]
				if wrapperValued[a] && (w == "sudo" || w == "doas" || w == "runuser") && len(argv) > 0 {
					argv = argv[1:]
				}
				continue
			case strings.Contains(a, "=") && !strings.HasPrefix(a, "/"):
				argv = argv[1:]
				continue
			case (w == "timeout" || w == "nice") && a != "" && a[0] >= '0' && a[0] <= '9':
				argv = argv[1:] // the duration / niceness
			}
			break
		}
	}
	return argv
}

// signalTargetsLogger reads an eslogger signal record's target.
func signalTargetsLogger(r endpoint.Record) (string, bool) {
	i := strings.Index(r.Resource, "target=")
	if i < 0 {
		return "", false
	}
	target := strings.TrimSpace(r.Resource[i+len("target="):])
	if namesLoggingDaemon(target) {
		return r.Resource, true
	}
	return "", false
}

func (v *hostView) logging() ([]schema.Finding, HostRuleCoverage) {
	c := HostRuleCoverage{Rule: "AGENT_LOGGING_DISRUPTED"}
	var clears []int
	signals := false
	for i, r := range v.recs {
		switch r.Kind {
		case "log-clear":
			clears = append(clears, i)
		case endpoint.KindSignal:
			signals = true
		}
	}
	if !v.hasProc && len(clears) == 0 {
		c.Missing = lineageMissing + ", and no event-log-cleared records (EVTX 1102/104)"
		return nil, c
	}
	c.Evaluated = true
	var partial []string
	if !v.hasProc {
		partial = append(partial, "only event-log-cleared records: stop/kill commands need process telemetry")
	}
	if len(clears) > 0 && len(v.sessions) == 0 {
		partial = append(partial, "event-log-cleared records present but no transcript session to place them in")
	}
	if v.hasProc && !signals {
		partial = append(partial, "no signal records (eslogger signal): a logger killed by pid is not visible")
	}
	c.Partial = strings.Join(partial, "; ")

	h := &hostHits{}
	attributedN := 0
	for i, r := range v.recs {
		var what string
		switch r.Kind {
		case "process":
			what = loggingStop(r.Cmdline)
		case "script":
			if m := psLogClearRe.FindString(r.Cmdline); m != "" {
				what = "PowerShell script block: " + m
			}
		case endpoint.KindSignal:
			if t, ok := signalTargetsLogger(r); ok {
				what = "signal sent to a logging process: " + t
			}
		}
		if what == "" || !v.attributed(i) {
			continue
		}
		attributedN++
		h.add(r, what)
	}
	for _, i := range clears {
		r := v.recs[i]
		s, ok := v.inSession(r.Time, logClearPad)
		if !ok {
			continue
		}
		h.add(r, fmt.Sprintf("event log cleared by %s during agent session %s (time overlap; the record names no process)", firstNonEmptyStr(r.User, "an unrecorded account"), s.id))
	}
	if h.n == 0 {
		return nil, c
	}
	sev, attack := "HIGH", "T1562.001"
	desc := fmt.Sprintf("The operating system recorded %d act(s) that stop, kill, silence or clear a logging source, by a process in the agent's process tree or during an agent session (first at %s). Telemetry lost this way also blinds every later check: what follows is under-recorded, never proven absent.",
		h.n, h.first.UTC().Format(time.RFC3339))
	if attributedN == 0 {
		sev, attack = "MEDIUM", "T1070.001"
		desc += " Only time overlap ties these clears to the agent."
	}
	return []schema.Finding{{
		RuleID: "AGENT_LOGGING_DISRUPTED", Severity: sev, Title: "Logging Stopped, Killed or Cleared From the Agent's Process Tree",
		Description: desc, Related: h.lines, EvidenceRefs: h.refs, Timestamp: h.first.UTC().Format(time.RFC3339),
		Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: attack,
		FalsePositive: "Maintenance on a logging pipeline (restarting or replacing a forwarder) asked of the agent; an administrator clearing a log while an agent session happened to be open.",
	}}, c
}

// --------------------------------------------------- AGENT_EVIDENCE_SOURCE_DELETED

// evidencePathRe: files an investigation of agent activity reads.
var evidencePathRe = regexp.MustCompile(`(?i)(/\.claude/projects/.+\.jsonl$|/\.claude/history\.jsonl$|/\.claude/transcripts/|/\.codex/(sessions|archived_sessions)/|/\.codex/history\.jsonl$|/\.gemini/tmp/.+\.json|/\.local/share/opencode/|\.aider\.chat\.history\.md$|/\.(bash|zsh|sh|ksh)_history$|/fish_history$|\\ConsoleHost_history\.txt$|^/var/log/(audit/|auth\.log|secure|syslog|messages|journal/|wtmp|btmp|lastlog)|^/private/var/log/|^/(private/)?var/db/diagnostics/|\\winevt\\logs\\[^\\]+\.evtx$|\.adfir(/|$))`)

// normPath canonicalizes a path argument before it is matched: quotes
// removed, ~ / $HOME / ${HOME} expanded, a relative path resolved against
// the working directory (or the root when it is unknown), duplicate
// separators and . / .. segments collapsed. Windows paths keep their
// backslashes; repeated ones are collapsed.
func normPath(p, cwd string) string {
	p = strings.Trim(strings.TrimSpace(p), `"'`)
	if p == "" {
		return ""
	}
	if len(p) >= 2 && p[1] == ':' || strings.HasPrefix(p, `\\`) || strings.Contains(p, `\`) && !strings.Contains(p, "/") {
		unc := strings.HasPrefix(p, `\\`)
		q := path.Clean(strings.ReplaceAll(p, `\`, "/"))
		if unc {
			q = "/" + q
		}
		return strings.ReplaceAll(q, "/", `\`)
	}
	home := homeOf(cwd)
	switch {
	case p == "~" || p == "$HOME" || p == "${HOME}":
		p = home
	case strings.HasPrefix(p, "~/"):
		p = home + p[1:]
	case strings.HasPrefix(p, "$HOME/"):
		p = home + p[len("$HOME"):]
	case strings.HasPrefix(p, "${HOME}/"):
		p = home + p[len("${HOME}"):]
	}
	if !strings.HasPrefix(p, "/") {
		base := cwd
		if !strings.HasPrefix(base, "/") {
			base = "/"
		}
		p = base + "/" + p
	}
	return path.Clean(p)
}

// homeOf guesses the home directory from a working directory; the home
// patterns are not anchored, so any home works when it is unknown.
func homeOf(cwd string) string {
	for _, pre := range []string{"/Users/", "/home/"} {
		if strings.HasPrefix(cwd, pre) {
			rest := cwd[len(pre):]
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				rest = rest[:i]
			}
			if rest != "" {
				return pre + rest
			}
		}
	}
	if cwd == "/root" || strings.HasPrefix(cwd, "/root/") {
		return "/root"
	}
	return "/home/user"
}

var deleters = map[string]bool{"rm": true, "unlink": true, "shred": true, "srm": true, "truncate": true, "del": true, "erase": true, "remove-item": true, "ri": true}

// deletesEvidence reports an invocation that deletes or empties an
// evidence path.
func deletesEvidence(cmd, cwd string) string {
	why := ""
	check := func(argv []string) bool {
		for k, a := range argv {
			if !deleters[exeName(a)] {
				continue
			}
			for _, arg := range argv[k+1:] {
				if strings.HasPrefix(arg, "-") {
					continue
				}
				if evidencePathRe.MatchString(normPath(arg, cwd)) {
					why = strings.Join(argv[k:], " ")
					return true
				}
			}
			return false
		}
		return false
	}
	if forEachInvocation(cmd, check) {
		return why
	}
	// Windows command lines: the shell-style lexer reads \ as an escape,
	// so the raw whitespace-separated words are judged as well.
	if strings.Contains(cmd, `\`) {
		check(strings.Fields(cmd))
	}
	return why
}

func (v *hostView) evidenceDeletion() ([]schema.Finding, HostRuleCoverage) {
	c := HostRuleCoverage{Rule: "AGENT_EVIDENCE_SOURCE_DELETED"}
	if !v.hasProc {
		c.Missing = lineageMissing
		return nil, c
	}
	c.Evaluated = true
	if !v.hasFile {
		c.Partial = "no file telemetry (Sysmon 23/26, auditd PATH, eslogger unlink, Tetragon unlink): only deleting command lines were checked"
	}
	h := &hostHits{}
	for i, r := range v.recs {
		var what string
		switch r.Kind {
		case "file":
			if r.FileOp == "delete" && evidencePathRe.MatchString(normPath(r.FilePath, r.Cwd)) {
				what = "deleted " + r.FilePath
			}
		case "process":
			what = deletesEvidence(r.Cmdline, r.Cwd)
		}
		if what == "" || !v.attributed(i) {
			continue
		}
		h.add(r, what)
	}
	if h.n == 0 {
		return nil, c
	}
	return []schema.Finding{{
		RuleID: "AGENT_EVIDENCE_SOURCE_DELETED", Severity: "HIGH", Title: "Agent-Descended Process Deleted Transcripts, Shell History or System Logs",
		Description: fmt.Sprintf("The operating system recorded %d deletion(s) of evidence sources (agent transcripts, shell history, system or audit logs) by a process in the agent's process tree (first at %s). The agent's own housekeeping (its client pruning old transcripts) is not counted.",
			h.n, h.first.UTC().Format(time.RFC3339)),
		Related: h.lines, EvidenceRefs: h.refs, Timestamp: h.first.UTC().Format(time.RFC3339),
		Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1070.004", MitreATLAS: "AML.T0101",
		FalsePositive: "A person asking the agent to clean up old sessions or rotate a log by hand.",
	}}, c
}

// ---------------------------------------------------- PACKAGE_SCRIPT_TOUCHED_AGENT

// agentPackages are agent CLIs distributed through package managers. An
// install of one of these is the agent being installed or updated, and
// its scripts are expected to touch the agent's files.
var agentPackages = []string{"@anthropic-ai/claude-code", "@openai/codex", "@google/gemini-cli", "opencode-ai", "@github/copilot",
	"@sourcegraph/amp", "aider-chat", "@qwen-code/qwen-code", "@cursor/cli"}

// installCommand reports whether argv installs or builds packages (and so
// runs their lifecycle or build scripts), and returns its text.
func installCommand(cmd string) (string, bool) {
	found := ""
	forEachInvocation(cmd, func(argv []string) bool {
		for k := 0; k < len(argv) && k < 3; k++ {
			p, rest := exeName(argv[k]), argv[k+1:]
			if (p == "node" || p == "nodejs") && len(rest) > 0 {
				switch exeName(rest[0]) {
				case "npm-cli.js", "yarn.js", "pnpm.cjs", "pnpm.js":
					p, rest = "npm", rest[1:]
				}
			}
			if (p == "python" || p == "python3") && len(rest) >= 2 && rest[0] == "-m" {
				p, rest = exeName(rest[1]), rest[2:]
			}
			sub := ""
			for _, a := range rest {
				if !strings.HasPrefix(a, "-") {
					sub = strings.ToLower(a)
					break
				}
			}
			ok := false
			switch p {
			case "npm", "pnpm", "cnpm", "bun":
				ok = sub == "install" || sub == "i" || sub == "add" || sub == "ci" || sub == "update" || sub == "up" || sub == "rebuild" || sub == "install-test" || sub == "it"
			case "yarn":
				ok = sub == "" || sub == "install" || sub == "add" || sub == "upgrade"
			case "pip", "pip3", "pipx":
				ok = sub == "install"
			case "uv":
				ok = sub == "add" || sub == "sync" || (sub == "pip" || sub == "tool") && strings.Contains(strings.Join(rest, " "), "install")
			case "poetry", "pdm":
				ok = sub == "install" || sub == "add"
			case "gem":
				ok = sub == "install"
			case "cargo":
				ok = sub == "install" || sub == "build"
			case "composer":
				ok = sub == "install" || sub == "require" || sub == "update"
			}
			if ok {
				found = strings.Join(argv[k:], " ")
				return true
			}
		}
		return false
	})
	return found, found != ""
}

// plainVersion: a semver (or a prefix of one) or a dist-tag. Aliases
// (npm:), URLs, git and file references, ranges and markers are not.
var plainVersion = regexp.MustCompile(`^(v?\d+(\.\d+){0,2}(-[0-9a-z.]+)?(\+[0-9a-z.]+)?|latest|next|stable)$`)

// agentSpec reports whether a package spec is exactly an agent CLI from
// its default source: the bare name, optionally @version / @dist-tag
// (npm) or [extras] and ==version (pip).
func agentSpec(spec string) bool {
	s := strings.ToLower(spec)
	if s == "" || strings.ContainsAny(s, ": \t\\;") {
		return false // npm:alias, file:, git+…, URLs, PEP 508 markers / "name @ url"
	}
	name, ver := s, ""
	if strings.HasPrefix(s, "@") {
		if i := strings.Index(s[1:], "@"); i >= 0 {
			name, ver = s[:i+1], s[i+2:]
		}
		if strings.Count(name, "/") != 1 {
			return false
		}
	} else {
		if strings.Contains(s, "/") || strings.Contains(s, "@") {
			return false
		}
		if i := strings.Index(s, "=="); i >= 0 {
			name, ver = s[:i], s[i+2:]
		} else if strings.ContainsAny(s, "<>!~=") {
			return false
		}
		if i := strings.IndexByte(name, '['); i >= 0 {
			if !strings.HasSuffix(name, "]") {
				return false
			}
			name = name[:i]
		}
	}
	if ver != "" && !plainVersion.MatchString(ver) {
		return false
	}
	return agentPackageSet[name]
}

var agentPackageSet = func() map[string]bool {
	m := map[string]bool{}
	for _, p := range agentPackages {
		m[p] = true
	}
	return m
}()

// agentInstallFlags are the only options an agent-only install may carry.
// Anything else (a registry or index override, a user config, an
// abbreviated long option, an attached value) makes it an ordinary
// install: the classification fails closed.
var agentInstallFlags = map[string]bool{"-g": true, "--global": true, "-D": true, "--save-dev": true, "-y": true, "--yes": true, "-q": true, "--quiet": true}

// agentOnlyInstall reports whether a process is exactly the agent CLI
// being installed: its argv is `<pm> install|i|add [allowed flags]
// <agent-spec>...`, argv[0] is the process's own image, and the package
// manager is a real one (node / python only through a known entry point:
// npm-cli.js, yarn.js, pnpm.cjs, or -m pip / -m pipx).
func agentOnlyInstall(exe, cmd string) bool {
	var argv []string
	lex(cmd, false, func(a []string) bool { argv = a; return true })
	if len(argv) < 3 || exeName(argv[0]) != exeName(exe) {
		return false
	}
	pm, rest := exeName(argv[0]), argv[1:]
	switch {
	case pm == "node" || pm == "nodejs":
		switch exeName(rest[0]) {
		case "npm-cli.js":
			pm = "npm"
		case "yarn.js":
			pm = "yarn"
		case "pnpm.cjs":
			pm = "pnpm"
		default:
			return false
		}
		rest = rest[1:]
	case pm == "python" || pm == "python3" || strings.HasPrefix(pm, "python3."):
		if len(rest) < 2 || rest[0] != "-m" || (rest[1] != "pip" && rest[1] != "pipx") {
			return false
		}
		pm, rest = rest[1], rest[2:]
	}
	switch pm {
	case "npm", "pnpm", "yarn", "bun", "pip", "pip3", "pipx":
	default:
		return false
	}
	if len(rest) < 2 || (rest[0] != "install" && rest[0] != "i" && rest[0] != "add") {
		return false
	}
	specs := 0
	for _, a := range rest[1:] {
		if strings.HasPrefix(a, "-") {
			if !agentInstallFlags[a] {
				return false
			}
			continue
		}
		if !agentSpec(a) {
			return false
		}
		specs++
	}
	return specs > 0
}

// insideInstallDir: a path in a package-manager install tree, where an
// agent CLI's own install scripts write.
func insideInstallDir(p string) bool {
	low := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	return strings.Contains(low, "/node_modules/") || strings.Contains(low, "/site-packages/") || strings.Contains(low, "/.bun/install/") ||
		strings.Contains(low, "/pipx/venvs/") || strings.Contains(low, "/.local/share/uv/tools/")
}

var (
	// agentConfigWriteRe: files that change what an agent does on its next run.
	agentConfigWriteRe = regexp.MustCompile(`(?i)(/\.claude/(settings[^/]*\.json$|hooks/|agents/|commands/|skills/|plugins/)|/\.claude\.json$|/\.claude/CLAUDE\.md$|/\.mcp\.json$|/\.codex/(config\.toml$|AGENTS\.md$)|/\.gemini/(settings\.json$|GEMINI\.md$)|/\.cursor/(mcp\.json$|rules/)|/claude_desktop_config\.json$|/\.config/opencode/|/\.copilot/(config|mcp-config)\.json$|/\.aider\.conf\.yml$|[\\/]AppData[\\/]Roaming[\\/]Claude[\\/])`)
	// agentCredentialRe: agent logins and tokens.
	agentCredentialRe = regexp.MustCompile(`(?i)(/\.claude/\.credentials\.json$|/\.codex/auth\.json$|/\.gemini/oauth_creds\.json$|/\.config/github-copilot/(hosts|apps)\.json$|/\.config/opencode/auth\.json$|/\.local/share/opencode/auth\.json$)`)
	agentBypassRe     = regexp.MustCompile(`(?i)(--dangerously-skip-permissions|--dangerously-bypass-approvals-and-sandbox|--yolo\b|--trust-all-tools|--allow-all-tools|--full-auto|(^|\s)-y(\s|$)|--approval-mode[=\s]+yolo)`)
)

func (v *hostView) packageScripts() ([]schema.Finding, HostRuleCoverage) {
	c := HostRuleCoverage{Rule: "PACKAGE_SCRIPT_TOUCHED_AGENT"}
	if !v.hasProc {
		c.Missing = lineageMissing + " (the package install that roots the tree must be visible)"
		return nil, c
	}
	c.Evaluated = true
	if !v.hasFile {
		c.Partial = "no file telemetry: agent configuration writes and login reads were not checked, only agent CLI launches"
	}
	type root struct {
		idx      int
		h        *hostHits
		critical bool
	}
	roots := map[int]*root{}
	var order []int
	isRoot := map[int]int{} // process index → 1 install root, -1 not, 2 install of agent CLIs only
	// rootOf returns the nearest install ancestor and whether that install
	// names only agent CLI packages (the agent being installed).
	rootOf := func(i int) (int, bool) {
		found, agentOnly := -1, false
		v.ancestors(i, func(j int) bool {
			st, ok := isRoot[j]
			if !ok {
				st = -1
				if _, inst := installCommand(v.recs[j].Cmdline); inst {
					st = 1
					if agentOnlyInstall(v.recs[j].Exe, v.recs[j].Cmdline) {
						st = 2
					}
				}
				isRoot[j] = st
			}
			if st != -1 {
				found, agentOnly = j, st == 2
				return true
			}
			return false
		})
		return found, agentOnly
	}
	for i, r := range v.recs {
		var what string
		critical := false
		switch r.Kind {
		case "process":
			argv0 := exeName(firstNonEmptyStr(r.Exe, firstToken(r.Cmdline)))
			if v.names[argv0] {
				what = "agent CLI launched: " + r.Cmdline
				critical = agentBypassRe.MatchString(r.Cmdline)
			}
		case "file":
			switch {
			case (r.FileOp == "create" || r.FileOp == "modify" || r.FileOp == "rename") && agentConfigWriteRe.MatchString(r.FilePath):
				what = "agent configuration written: " + r.FileOp + " " + r.FilePath
			case agentCredentialRe.MatchString(r.FilePath):
				what = "agent login read: " + r.FileOp + " " + r.FilePath
			}
		}
		if what == "" {
			continue
		}
		ri, agentOnly := rootOf(i)
		if ri < 0 {
			continue
		}
		// Installing an agent CLI runs its own scripts, which may start the
		// CLI and write inside its install tree. Logins read and settings
		// written elsewhere still count.
		if agentOnly && ((r.Kind == "process" && !critical) || (r.Kind == "file" && insideInstallDir(r.FilePath))) {
			continue
		}
		rt := roots[ri]
		if rt == nil {
			if len(roots) >= maxPackageRoots {
				continue
			}
			rt = &root{idx: ri, h: &hostHits{}}
			roots[ri] = rt
			order = append(order, ri)
		}
		rt.critical = rt.critical || critical
		rt.h.add(r, what)
	}
	var out []schema.Finding
	for _, ri := range order {
		rt := roots[ri]
		inst := v.recs[ri]
		sev := "HIGH"
		if rt.critical {
			sev = "CRITICAL"
		}
		related := append([]string{fmt.Sprintf("install: %s %s pid %d: %s", inst.Time.UTC().Format(time.RFC3339), inst.Source, inst.PID, trim(inst.Cmdline, 200))}, rt.h.lines...)
		refs := append([]string{inst.Source + " " + inst.Ref}, rt.h.refs...)
		out = append(out, schema.Finding{
			RuleID: "PACKAGE_SCRIPT_TOUCHED_AGENT", Severity: sev, Title: "Package Install Script Launched an AI Agent or Changed Its Configuration",
			Description: fmt.Sprintf("A process descended from the package install %q (pid %d, %s) launched an AI agent CLI, wrote the agent's configuration or read its login (%d action(s), first at %s). Install and build scripts run with the user's rights; one that drives the local agent (often with its permission checks off) or plants settings in it is a package-to-agent compromise path.",
				trim(inst.Cmdline, 120), inst.PID, inst.Time.UTC().Format(time.RFC3339), rt.h.n, rt.h.first.UTC().Format(time.RFC3339)),
			Related: related, EvidenceRefs: refs, Timestamp: rt.h.first.UTC().Format(time.RFC3339),
			Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1195.002", MitreATLAS: "AML.T0011.001",
			FalsePositive: "A package whose purpose is agent integration (an MCP server or plugin installer) writing the agent's settings during install; installing or updating the agent CLI itself is excluded.",
		})
	}
	return out, c
}
