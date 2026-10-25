package correlate

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Windows persistence and credential rules over event log context
// records (see internal/endpoint/evtxkinds.go). Each rule needs the
// operating system's own record of the act (a registry write, a task
// registration, a WMI binding, an explicit-credential logon) and ties it
// to the agent through process identity in the telemetry (pid → a
// process descended from an agent binary) or, for WMI bindings, which
// name no process, through the time of an agent session. The rules never
// change a tool call's corroboration state.
//
// The command-text rules in the rule packs (schtasks /create, reg add
// …\Run) read what the transcript says the agent ran; these read what
// the host recorded, so they also fire when the transcript is silent.

const (
	maxWindowsFindings = 50              // per rule
	pidSlack           = 2 * time.Second // a context record may precede its process record by clock jitter
	taskLookback       = 2 * time.Minute // schtasks process → Task Scheduler registration
	sessionPad         = 2 * time.Minute // around a transcript session, for WMI bindings
)

var (
	runKeyRe     = regexp.MustCompile(`(?i)\\(?:microsoft\\windows\\currentversion\\(?:run|runonce|runonceex|runservices|runservicesonce)|microsoft\\windows\\currentversion\\policies\\explorer\\run)$`)
	serviceKeyRe = regexp.MustCompile(`(?i)\\(?:currentcontrolset|controlset\d{3})\\services\\[^\\]+(\\parameters)?$`)
	taskCmdRe    = regexp.MustCompile(`(?i)(\bschtasks(?:\.exe)?\b[^|;&]*\s/(?:create|change)\b|\b(?:register|set)-scheduledtask\b)`)
)

// windowsPass counts the context records and runs the four rules.
func windowsPass(events []schema.Event, host, ctx []endpoint.Record, opts EndpointOptions, res *EndpointResult) []schema.Finding {
	if len(ctx) == 0 {
		return nil
	}
	res.ContextRecords = len(ctx)
	res.ContextKinds = map[string]int{}
	for _, r := range ctx {
		res.ContextKinds[r.Kind]++
	}
	sort.SliceStable(ctx, func(i, j int) bool { return ctx[i].Time.Before(ctx[j].Time) })
	sort.SliceStable(host, func(i, j int) bool { return host[i].Time.Before(host[j].Time) })
	w := &winRules{host: host, names: agentBinaryNames(opts.AgentBinaries), byPID: map[int][]int{}}
	w.lineage = buildLineage(host, w.names)
	for i, r := range host {
		if r.Kind == "process" && r.PID != 0 {
			w.byPID[r.PID] = append(w.byPID[r.PID], i)
		}
	}
	w.sessions = sessionSpans(events)

	var out []schema.Finding
	count := map[string]int{}
	add := func(f schema.Finding) {
		if count[f.RuleID] < maxWindowsFindings {
			out = append(out, f)
		}
		count[f.RuleID]++
	}
	seen := map[string]bool{}
	for _, r := range ctx {
		switch r.Kind {
		case endpoint.KindRegistry:
			if f, ok := w.registry(r); ok && !seen[f.RuleID+r.Resource+"\\"+r.ValueName] {
				seen[f.RuleID+r.Resource+"\\"+r.ValueName] = true
				add(f)
			}
		case endpoint.KindAuth:
			if f, ok := w.explicitCreds(r); ok {
				add(f)
			}
		case endpoint.KindScheduledTask:
			if f, ok := w.task(r); ok && !seen[f.RuleID+r.Resource] {
				seen[f.RuleID+r.Resource] = true
				add(f)
			}
		case endpoint.KindWMI:
			if f, ok := w.wmi(r); ok && !seen[f.RuleID+r.Resource] {
				seen[f.RuleID+r.Resource] = true
				add(f)
			}
		}
	}
	for _, n := range count {
		if n > maxWindowsFindings {
			res.ContextOmitted += n - maxWindowsFindings
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Timestamp < out[j].Timestamp })
	return out
}

type winRules struct {
	host     []endpoint.Record
	lineage  []bool
	names    map[string]bool
	byPID    map[int][]int
	sessions []span
}

type span struct {
	session    string
	start, end time.Time
}

// agentProc finds the process a context record names by pid: the latest
// process record with that pid starting no later than the record (plus
// clock slack), when it is an agent or descended from one. An image path
// on the context record must agree with it, so a recycled pid does not
// borrow another process's ancestry. A record whose own image is an
// agent binary is the agent itself.
func (w *winRules) agentProc(pid int, exe string, t time.Time) (endpoint.Record, bool) {
	if exe != "" && agentProcess(w.names, exe, "") {
		return endpoint.Record{PID: pid, Exe: exe}, true
	}
	if pid == 0 {
		return endpoint.Record{}, false
	}
	best := w.procAt(pid, t)
	if best < 0 {
		return endpoint.Record{}, false
	}
	p := w.host[best]
	if exe != "" && p.Exe != "" && !strings.EqualFold(baseName(exe), baseName(p.Exe)) {
		return endpoint.Record{}, false
	}
	if w.descended(best) {
		return p, true
	}
	return endpoint.Record{}, false
}

// descended reports whether host process record i, or an ancestor
// visible in the telemetry, is agent lineage. An ancestor may be marked
// through its own parent image when the agent's process record itself
// was not captured. The walk is bounded.
func (w *winRules) descended(i int) bool {
	for hop := 0; i >= 0 && hop < 16; hop++ {
		a := w.host[i]
		if w.lineage[i] || agentProcess(w.names, a.Exe, a.Cmdline) {
			return true
		}
		if a.PPID <= 1 || a.PPID == a.PID {
			return false
		}
		i = w.procAt(a.PPID, a.Time)
	}
	return false
}

// procAt is the index of the latest process record with pid starting no
// later than t (plus clock slack), or -1.
func (w *winRules) procAt(pid int, t time.Time) int {
	best := -1
	for _, i := range w.byPID[pid] {
		if w.host[i].Time.After(t.Add(pidSlack)) {
			break
		}
		best = i
	}
	return best
}

func procWhat(p endpoint.Record) string {
	s := baseName(p.Exe)
	if s == "" {
		s = firstToken(p.Cmdline)
	}
	if p.PID != 0 {
		s += fmt.Sprintf(" (pid %d)", p.PID)
	}
	return s
}

func refsOf(r endpoint.Record, p endpoint.Record) []string {
	refs := []string{r.Source + " " + r.Ref}
	if p.Ref != "" {
		refs = append(refs, p.Source+" "+p.Ref)
	}
	return refs
}

// registry: WIN_AGENT_REGISTRY_PERSISTENCE — a Run/RunOnce value, or a
// service key / ImagePath / ServiceDll, written by an agent-descended
// process.
func (w *winRules) registry(r endpoint.Record) (schema.Finding, bool) {
	where, attack := "", ""
	switch {
	case r.Operation == "set-value" && runKeyRe.MatchString(r.Resource):
		where, attack = "a Run/RunOnce key (runs at every logon)", "T1547.001"
	case serviceKeyRe.MatchString(r.Resource) && (r.Operation == "create-key" ||
		(r.Operation == "set-value" && (strings.EqualFold(r.ValueName, "ImagePath") || strings.EqualFold(r.ValueName, "ServiceDll")))):
		where, attack = "a service definition (runs as a service)", "T1543.003"
	default:
		return schema.Finding{}, false
	}
	p, ok := w.agentProc(r.PID, r.Exe, r.Time)
	if !ok {
		return schema.Finding{}, false
	}
	target := r.Resource
	if r.ValueName != "" {
		target += `\` + r.ValueName
	}
	desc := fmt.Sprintf("Sysmon recorded %s, a process descended from the agent, writing %s at %s: %s", procWhat(p), where, r.Time.Format(time.RFC3339), target)
	if r.Details != "" {
		desc += " = " + trim(r.Details, 200)
	}
	return schema.Finding{
		RuleID: "WIN_AGENT_REGISTRY_PERSISTENCE", Severity: "HIGH", Title: "Agent-Descended Process Wrote a Windows Persistence Registry Key",
		Description: desc + ". Whatever that value names will start again without the agent.", Timestamp: r.Time.UTC().Format(time.RFC3339),
		Related: []string{trim(p.Cmdline, 200)}, EvidenceRefs: refsOf(r, p),
		Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: attack,
		FalsePositive: "Installers the agent was asked to run (a package manager adding its own service or tray program). Judge by the value data.",
	}, true
}

// explicitCreds: WIN_AGENT_EXPLICIT_CREDENTIALS — Security 4648 (a logon
// with explicitly supplied credentials: runas, net use /user, PsExec -u)
// by an agent-descended process.
func (w *winRules) explicitCreds(r endpoint.Record) (schema.Finding, bool) {
	if r.Operation != "explicit-credentials" {
		return schema.Finding{}, false
	}
	p, ok := w.agentProc(r.PID, r.Exe, r.Time)
	if !ok {
		return schema.Finding{}, false
	}
	desc := fmt.Sprintf("Security event 4648 shows %s, a process descended from the agent, logging on with explicitly supplied credentials for %s at %s",
		procWhat(p), firstNonBlank(r.User, "an unnamed account"), r.Time.Format(time.RFC3339))
	if r.SubjectUser != "" {
		desc += " (running as " + r.SubjectUser + ")"
	}
	if r.Resource != "" {
		desc += ", target " + r.Resource
	}
	return schema.Finding{
		RuleID: "WIN_AGENT_EXPLICIT_CREDENTIALS", Severity: "HIGH", Title: "Agent-Descended Process Used Explicit Credentials",
		Description: desc + ". The agent obtained and used a credential other than the session's own.", Timestamp: r.Time.UTC().Format(time.RFC3339),
		Related: []string{trim(p.Cmdline, 200)}, EvidenceRefs: refsOf(r, p),
		Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1078",
		FalsePositive: "A developer asked the agent to map a share or run a tool as another account with credentials they supplied.",
	}, true
}

// task: WIN_AGENT_SCHEDULED_TASK — Task Scheduler 106/140 shortly after an
// agent-descended process ran schtasks /create|/change or
// Register-/Set-ScheduledTask.
func (w *winRules) task(r endpoint.Record) (schema.Finding, bool) {
	if r.Operation != "registered" && r.Operation != "updated" {
		return schema.Finding{}, false
	}
	short := strings.ToLower(r.Resource)
	if i := strings.LastIndexByte(short, '\\'); i >= 0 {
		short = short[i+1:]
	}
	best, named := -1, false
	for j := lowerBound(w.host, r.Time.Add(-taskLookback)); j < len(w.host) && !w.host[j].Time.After(r.Time.Add(pidSlack)); j++ {
		p := w.host[j]
		if p.Kind != "process" || !taskCmdRe.MatchString(p.Cmdline) {
			continue
		}
		if !w.descended(j) {
			continue
		}
		hasName := short != "" && strings.Contains(strings.ToLower(p.Cmdline), short)
		if best < 0 || (hasName && !named) || hasName == named {
			best, named = j, hasName
		}
	}
	if best < 0 {
		return schema.Finding{}, false
	}
	p := w.host[best]
	basis := "within " + taskLookback.String() + " of the registration"
	if named {
		basis = "naming the same task"
	}
	return schema.Finding{
		RuleID: "WIN_AGENT_SCHEDULED_TASK", Severity: "HIGH", Title: "Agent-Descended Process Created a Scheduled Task",
		Description: fmt.Sprintf("Task Scheduler recorded task %q %s at %s; %s, a process descended from the agent, ran %q %s. A scheduled task keeps running after the session ends.",
			r.Resource, r.Operation, r.Time.Format(time.RFC3339), procWhat(p), trim(p.Cmdline, 160), basis),
		Timestamp: r.Time.UTC().Format(time.RFC3339), Related: []string{trim(p.Cmdline, 200)}, EvidenceRefs: refsOf(r, p),
		Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1053.005",
		FalsePositive: "The developer asked for a scheduled job (a nightly build or backup). Judge by the task's action.",
	}, true
}

// wmi: WIN_AGENT_WMI_PERSISTENCE — a permanent WMI event consumer bound
// (WMI-Activity 5861) during an agent session. 5861 names no process,
// so the tie is the session's time only; the description says so.
func (w *winRules) wmi(r endpoint.Record) (schema.Finding, bool) {
	if r.Operation != "consumer-binding" {
		return schema.Finding{}, false
	}
	// Windows ships one permanent binding (the SCM event log consumer);
	// it is re-reported at boot and is not persistence by anyone.
	if strings.Contains(strings.ToLower(r.Resource), "scm event log consumer") {
		return schema.Finding{}, false
	}
	for _, s := range w.sessions {
		if r.Time.Before(s.start.Add(-sessionPad)) || r.Time.After(s.end.Add(sessionPad)) {
			continue
		}
		return schema.Finding{
			RuleID: "WIN_AGENT_WMI_PERSISTENCE", Severity: "HIGH", Title: "WMI Permanent Event Consumer Created During an Agent Session",
			Description: fmt.Sprintf("WMI-Activity event 5861 records a permanent event consumer binding (%s) at %s, inside agent session %s (%s – %s, ±%s). The event names no process, so the tie to the agent is time only. Consumer: %s",
				trim(r.Resource, 160), r.Time.Format(time.RFC3339), s.session, s.start.Format(time.RFC3339), s.end.Format(time.RFC3339), sessionPad, trim(r.Details, 300)),
			SessionID: s.session, Timestamp: r.Time.UTC().Format(time.RFC3339), EvidenceRefs: []string{r.Source + " " + r.Ref},
			Status: schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1546.003",
			FalsePositive: "Management agents (SCCM, monitoring tools) register permanent consumers; check the consumer's class and command.",
		}, true
	}
	return schema.Finding{}, false
}

// sessionSpans: first and last event time of each transcript session.
func sessionSpans(events []schema.Event) []span {
	by := map[string]*span{}
	var order []string
	for _, ev := range events {
		if ev.SessionID == "" {
			continue
		}
		t, ok := parseEventTime(ev.Timestamp)
		if !ok {
			continue
		}
		s := by[ev.SessionID]
		if s == nil {
			s = &span{session: ev.SessionID, start: t, end: t}
			by[ev.SessionID] = s
			order = append(order, ev.SessionID)
		}
		if t.Before(s.start) {
			s.start = t
		}
		if t.After(s.end) {
			s.end = t
		}
	}
	out := make([]span, 0, len(order))
	for _, id := range order {
		out = append(out, *by[id])
	}
	return out
}
