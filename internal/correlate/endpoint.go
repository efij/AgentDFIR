package correlate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/endpoint"
	"github.com/efij/AgentDFIR/internal/netdest"
	"github.com/efij/AgentDFIR/internal/products"
	"github.com/efij/AgentDFIR/internal/schema"
)

// Endpoint correlation: the transcript is witness #1, OS telemetry is
// witness #2. Each agent tool call is matched against process, file and
// network records inside a time window; matches raise OBSERVED →
// CORROBORATED, misses inside the telemetry's coverage lower it to
// CONTRADICTED, and agent-lineage activity with no transcript counterpart
// becomes an UNLOGGED_* finding. Outside coverage nothing changes: absence
// of evidence is UNKNOWN, never a contradiction.

// EndpointOptions tunes the pass.
type EndpointOptions struct {
	Window        time.Duration // match window around a tool call (default 3s)
	KnownDests    []string      // extra allowlisted network destinations
	AgentBinaries []string      // extra agent process names for lineage
}

// EndpointResult summarizes the pass.
type EndpointResult struct {
	Records        int       `json:"records"`
	CoverageStart  time.Time `json:"coverage_start"`
	CoverageEnd    time.Time `json:"coverage_end"`
	ToolCalls      int       `json:"tool_calls_checked"`
	Corroborated   int       `json:"corroborated"`
	Contradicted   int       `json:"contradicted"`
	OutsideCover   int       `json:"outside_coverage"`
	AgentProcesses int       `json:"agent_lineage_processes"`
	Unlogged       int       `json:"unlogged_agent_records"`
}

// Endpoint correlates events in place and returns findings.
func Endpoint(events []schema.Event, records []endpoint.Record, opts EndpointOptions) (*EndpointResult, []schema.Finding) {
	if opts.Window <= 0 {
		opts.Window = 3 * time.Second
	}
	res := &EndpointResult{Records: len(records)}
	if len(records) == 0 {
		return res, nil
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].Time.Before(records[j].Time) })
	res.CoverageStart, res.CoverageEnd = records[0].Time, records[len(records)-1].Time

	agentNames := agentBinaryNames(opts.AgentBinaries)
	lineage := buildLineage(records, agentNames)
	matchedRec := make([]bool, len(records))

	// Pass 1: tool calls → endpoint records.
	var findings []schema.Finding
	for i := range events {
		ev := &events[i]
		if ev.EventType != schema.EventToolCall || (ev.Command == "" && ev.File == "" && ev.NetworkDest == "") {
			continue
		}
		t, ok := parseEventTime(ev.Timestamp)
		if !ok {
			continue
		}
		res.ToolCalls++
		if t.Before(res.CoverageStart.Add(-opts.Window)) || t.After(res.CoverageEnd.Add(opts.Window)) {
			res.OutsideCover++
			continue
		}
		lo, hi := t.Add(-opts.Window), t.Add(opts.Window)
		best, bestScore := -1, 0
		for j := lowerBound(records, lo); j < len(records) && !records[j].Time.After(hi); j++ {
			if matchedRec[j] {
				continue
			}
			if s := score(ev, records[j]); s > bestScore {
				best, bestScore = j, s
			}
		}
		if best >= 0 {
			matchedRec[best] = true
			r := records[best]
			if ev.Corroboration == schema.StateObserved || ev.Corroboration == schema.StateReported || ev.Corroboration == schema.StateUnknown {
				ev.Corroboration = schema.StateCorroborated
			}
			ev.Summary = appendNote(ev.Summary, fmt.Sprintf("corroborated by %s %s (%s)", r.Source, r.Kind, r.Ref))
			res.Corroborated++
			continue
		}
		if ev.Command == "" {
			continue // file/network-only calls without a match stay OBSERVED (telemetry may not cover that kind)
		}
		if !hasKind(records, "process") {
			continue
		}
		ev.Corroboration = schema.StateContradicted
		ev.Summary = appendNote(ev.Summary, "no matching process in endpoint telemetry within ±"+opts.Window.String())
		res.Contradicted++
		findings = append(findings, schema.Finding{
			RuleID: "ENDPOINT_CONTRADICTED_COMMAND", Severity: "HIGH", Title: "Transcript Command Not Seen by the Operating System",
			Description: fmt.Sprintf("Transcript records tool %s running %q at %s, but endpoint telemetry covering that time shows no matching process. Either the command never executed (model narrative recorded as a tool call, or a sandbox/dry-run), the telemetry missed it, or the transcript was altered.", ev.Tool, trim(ev.Command, 160), ev.Timestamp),
			SessionID:   ev.SessionID, AgentID: ev.AgentID,
			EvidenceRefs: []string{fmt.Sprintf("%s:%d (artifact %s, offset %d)", ev.SourcePath, ev.SourceLine, shortID(ev.SourceArtifact), ev.SourceOffset)},
			Status:       schema.StateContradicted, Endpoint: schema.StateContradicted, MitreATTACK: "T1070",
			FalsePositive: "Clock skew beyond the window, execve auditing not enabled for that user, or built-in tool implementations that do not fork a process (e.g. an in-process file read).",
		})
	}

	// Pass 2: agent-lineage endpoint records with no transcript counterpart.
	type group struct {
		count int
		first endpoint.Record
		refs  []string
		lines []string
	}
	unloggedProc := map[string]*group{}
	var unloggedNet []endpoint.Record
	for j, r := range records {
		if !lineage[j] {
			continue
		}
		res.AgentProcesses++
		if matchedRec[j] {
			continue
		}
		switch r.Kind {
		case "process":
			if agentNames[exeName(r.Exe)] || isNoise(r) {
				continue // the agent itself / its runtime helpers
			}
			res.Unlogged++
			key := strings.ToLower(baseName(r.Exe))
			if key == "" {
				key = firstToken(r.Cmdline)
			}
			g := unloggedProc[key]
			if g == nil {
				g = &group{first: r}
				unloggedProc[key] = g
			}
			g.count++
			if len(g.lines) < 3 {
				g.lines = append(g.lines, trim(r.Cmdline, 120))
				g.refs = append(g.refs, r.Ref)
			}
		case "network":
			dest := r.DestHost
			if dest == "" {
				dest = r.DestIP
			}
			if dest == "" || netdest.IsAllowed(dest, opts.KnownDests) || isLoopback(dest) {
				continue
			}
			res.Unlogged++
			unloggedNet = append(unloggedNet, r)
		}
	}
	keys := make([]string, 0, len(unloggedProc))
	for k := range unloggedProc {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g := unloggedProc[k]
		findings = append(findings, schema.Finding{
			RuleID: "UNLOGGED_AGENT_ACTIVITY", Severity: "MEDIUM", Title: "Process Spawned by the Agent Has No Transcript Entry",
			Description:  fmt.Sprintf("Endpoint telemetry shows %d execution(s) of %q under the agent's process tree with no matching tool call in the transcripts (first at %s). Either the transcript is incomplete/edited, a tool ran a subprocess without logging it, or the session was not collected.", g.count, k, g.first.Time.Format(time.RFC3339)),
			Related:      g.lines,
			EvidenceRefs: g.refs,
			Status:       schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1070",
			FalsePositive: "Agents spawn helper processes (linters, git, language servers) that are not individual tool calls; judge by the program and its arguments.",
		})
	}
	for _, r := range unloggedNet {
		dest := r.DestHost
		if dest == "" {
			dest = r.DestIP
		}
		findings = append(findings, schema.Finding{
			RuleID: "UNLOGGED_AGENT_NETWORK", Severity: "HIGH", Title: "Agent Process Connected to a Destination Not in the Transcript",
			Description:  fmt.Sprintf("Endpoint telemetry shows %s (pid %d, under the agent's process tree) connecting to %s:%d at %s; no tool call in the transcripts references that destination. Model-provider and package-registry endpoints are allowlisted, so this is an unexplained outbound connection.", baseName(r.Exe), r.PID, dest, r.DestPort, r.Time.Format(time.RFC3339)),
			EvidenceRefs: []string{r.Ref},
			Status:       schema.StateObserved, Endpoint: schema.StateObserved, MitreATTACK: "T1071",
			FalsePositive: "Telemetry/update checks by the agent runtime, or MCP servers reaching their own APIs; add known hosts with --known-destinations.",
		})
	}
	return res, findings
}

// score rates how well an endpoint record explains a tool call: 0 = no.
func score(ev *schema.Event, r endpoint.Record) int {
	switch r.Kind {
	case "process":
		if ev.Command == "" {
			return 0
		}
		a, b := normalizeCmd(ev.Command), normalizeCmd(r.Cmdline)
		if a == "" || b == "" {
			return 0
		}
		switch {
		case a == b:
			return 100
		case strings.Contains(b, a): // shell wrapper: /bin/zsh -c '<cmd>'
			return 90
		case strings.Contains(a, b) && len(b) > 8: // truncated telemetry
			return 70
		}
		at, bt := strings.Fields(a), strings.Fields(b)
		if len(at) == 0 || len(bt) == 0 {
			return 0
		}
		if exeName(at[0]) == exeName(bt[0]) && tokenOverlap(at, bt) >= 0.6 {
			return 60
		}
		// Compound commands (a && b; a | b): the OS sees each program separately.
		for _, seg := range splitCompound(a) {
			st := strings.Fields(seg)
			if len(st) > 0 && exeName(st[0]) == exeName(bt[0]) && tokenOverlap(st, bt) >= 0.6 {
				return 60
			}
		}
		return 0
	case "file":
		if ev.File == "" || r.FilePath == "" {
			return 0
		}
		fa, fb := strings.ToLower(strings.ReplaceAll(ev.File, "\\", "/")), strings.ToLower(strings.ReplaceAll(r.FilePath, "\\", "/"))
		if fa == fb || strings.HasSuffix(fb, "/"+strings.TrimPrefix(fa, "/")) || strings.HasSuffix(fa, "/"+strings.TrimPrefix(fb, "/")) {
			return 80
		}
		return 0
	case "network":
		if ev.NetworkDest == "" {
			return 0
		}
		want := strings.ToLower(netdest.Host(ev.NetworkDest))
		if want == strings.ToLower(r.DestIP) || (r.DestHost != "" && (want == strings.ToLower(r.DestHost) || strings.HasSuffix(strings.ToLower(r.DestHost), "."+want))) {
			return 80
		}
		return 0
	}
	return 0
}

func tokenOverlap(a, b []string) float64 {
	set := map[string]bool{}
	for _, t := range b {
		set[t] = true
	}
	hit := 0
	for _, t := range a {
		if set[t] {
			hit++
		}
	}
	return float64(hit) / float64(len(a))
}

func splitCompound(cmd string) []string {
	var out []string
	cur := ""
	for _, part := range strings.Fields(cmd) {
		switch part {
		case "&&", "||", ";", "|":
			if cur != "" {
				out = append(out, strings.TrimSpace(cur))
			}
			cur = ""
		default:
			cur += " " + part
		}
	}
	if cur != "" {
		out = append(out, strings.TrimSpace(cur))
	}
	return out
}

// buildLineage marks records whose process (or any ancestor visible in the
// telemetry) is an agent binary.
func buildLineage(records []endpoint.Record, agentNames map[string]bool) []bool {
	// pid → latest process record index (pids recycle; last exec wins within the log).
	byPID := map[int]int{}
	for i, r := range records {
		if r.Kind == "process" && r.PID != 0 {
			byPID[r.PID] = i
		}
	}
	isAgentExe := func(exe, cmd string) bool {
		if agentNames[exeName(exe)] {
			return true
		}
		if ft := firstToken(cmd); ft != "" && agentNames[exeName(ft)] {
			return true
		}
		// node/python running an agent CLI: `node …/claude/cli.js`
		low := strings.ToLower(cmd)
		for name := range agentNames {
			if strings.Contains(low, "/"+name+"/") || strings.Contains(low, "\\"+name+"\\") || strings.Contains(low, "/"+name+".js") || strings.Contains(low, "@anthropic-ai/claude-code") || strings.Contains(low, "@openai/codex") {
				return true
			}
		}
		return false
	}
	out := make([]bool, len(records))
	for i, r := range records {
		if isAgentExe(r.ParentExe, "") {
			out[i] = true
			continue
		}
		// Walk the pid tree (bounded).
		pid := r.PPID
		for hop := 0; hop < 16 && pid > 1; hop++ {
			idx, ok := byPID[pid]
			if !ok {
				break
			}
			p := records[idx]
			if isAgentExe(p.Exe, p.Cmdline) {
				out[i] = true
				break
			}
			pid = p.PPID
		}
		if !out[i] && r.Kind != "process" && isAgentExe(r.Exe, r.Cmdline) {
			// network/file activity performed by the agent process itself
			out[i] = true
		}
	}
	return out
}

func agentBinaryNames(extra []string) map[string]bool {
	names := map[string]bool{"claude": true, "cursor": true, "cursor-agent": true, "codex": true, "gemini": true, "copilot": true,
		"aider": true, "opencode": true, "openclaw": true, "code helper (plugin)": true, "code helper": true, "windsurf": true, "warp": true}
	if prods, err := products.All(); err == nil {
		for _, p := range prods {
			for _, b := range p.Binaries {
				names[strings.ToLower(b)] = true
			}
		}
	}
	for _, e := range extra {
		names[strings.ToLower(e)] = true
	}
	return names
}

// isNoise: runtime helpers every agent spawns that are never tool calls.
func isNoise(r endpoint.Record) bool {
	switch strings.ToLower(baseName(r.Exe)) {
	case "node", "uname", "sw_vers", "getconf", "id", "whoami", "hostname", "tty", "stty", "locale", "which", "env", "printenv":
		return strings.Count(r.Cmdline, " ") <= 1
	}
	return false
}

func hasKind(records []endpoint.Record, kind string) bool {
	for _, r := range records {
		if r.Kind == kind {
			return true
		}
	}
	return false
}

func lowerBound(records []endpoint.Record, t time.Time) int {
	return sort.Search(len(records), func(i int) bool { return !records[i].Time.Before(t) })
}

func isLoopback(h string) bool {
	h = strings.ToLower(h)
	return h == "localhost" || strings.HasPrefix(h, "127.") || h == "::1" || h == "0.0.0.0"
}

func parseEventTime(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000Z"} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// exeName: lower-cased basename without a Windows .exe suffix.
func exeName(p string) string {
	return strings.TrimSuffix(strings.ToLower(baseName(p)), ".exe")
}

func firstToken(cmd string) string {
	f := strings.Fields(cmd)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

func trim(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
