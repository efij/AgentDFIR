package detect

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/schema"
)

// RunStream evaluates the full deterministic rule set by streaming the
// normalized events overlay (normalized/events.jsonl) in two bounded
// passes, instead of holding every event in memory. Memory is bounded by
// session/agent/artifact count, not event count — this is the path
// `triage` uses so multi-hundred-thousand-event packages don't balloon
// RSS. Findings are identical to RunAll for the same input.
//
// entities carries the (small) entity set from normalization, needed by
// rules that depend on sidechain membership.
func RunStream(pkgDir string, entities []schema.Entity, opts Options) ([]schema.Finding, error) {
	eventsPath := filepath.Join(pkgDir, "normalized", "events.jsonl")
	man, err := readManifest(pkgDir)
	if err != nil {
		return nil, err
	}

	sidechain := map[string]bool{}
	for _, e := range entities {
		if e.Kind == "agent" && e.Attributes["sidechain"] == "true" {
			sidechain[e.Label] = true
		}
	}

	// ---- Pass 1: bounded aggregates ----
	agg := &streamAgg{
		completed:     map[string]time.Time{},
		mcpServers:    map[string]string{},
		artSessions:   map[string]map[string]bool{},
		artLatest:     map[string]time.Time{},
		artSample:     map[string]schema.Event{},
		artBreaks:     map[string]int{},
		artRegress:    map[string]int{},
		artLastTS:     map[string]time.Time{},
		spawnCount:    map[string]int{},
		spawnFirst:    map[string]schema.Event{},
		spawnedAgents: map[string]bool{},
		agentSession:  map[string]string{},
		agentRefs:     map[string][]string{},
		agentSessID:   map[string]string{},
		agentSide:     sidechain,
	}
	if err := streamEvents(eventsPath, agg.pass1); err != nil {
		return nil, err
	}

	// ---- Pass 2: per-event rules + sequence rules ----
	p2 := &streamPass2{
		agg: agg, sidechain: sidechain, opts: opts,
		pendingExfil: map[string]schema.Event{},
		seenDest:     map[string]bool{},
		resumeFlag:   map[string]bool{},
	}
	if err := streamEvents(eventsPath, p2.handle); err != nil {
		return nil, err
	}

	findings := p2.findings
	// ---- post-pass aggregate rules ----
	findings = append(findings, agg.orphanAgents()...)
	findings = append(findings, agg.shellExecution()...)
	findings = append(findings, agg.spawnExplosion(opts)...)
	findings = append(findings, agg.identityMismatch()...)
	findings = append(findings, agg.sessionTampering()...)
	findings = append(findings, agg.timestomp(man)...)

	// ---- package content scans (already streaming from raw blobs) ----
	findings = append(findings, permissionBypass(man, pkgDir)...)
	findings = append(findings, permissionEscalation(man, pkgDir)...)
	findings = append(findings, secretExposure(man, pkgDir)...)
	findings = append(findings, promptInjectionIndicator(man, pkgDir)...)
	findings = append(findings, invisibleUnicodeInstruction(man, pkgDir)...)
	if len(opts.Honeytokens) > 0 {
		findings = append(findings, HoneytokenFindings(man, pkgDir, opts.Honeytokens)...)
	}
	return sortBySeverity(findings), nil
}

// streamEvents reads events.jsonl line by line (bounded buffer) and calls
// fn for each. Malformed lines are skipped (they were already recorded as
// trace_gap events during normalization).
func streamEvents(path string, fn func(schema.Event)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var ev schema.Event
		if json.Unmarshal(sc.Bytes(), &ev) == nil {
			fn(ev)
		}
	}
	return sc.Err()
}

type streamAgg struct {
	completed   map[string]time.Time // agentID -> completion ts
	mcpServers  map[string]string    // toolCallID -> mcp server
	artSessions map[string]map[string]bool
	artLatest   map[string]time.Time
	artSample   map[string]schema.Event
	artBreaks   map[string]int
	artRegress  map[string]int
	artLastTS   map[string]time.Time
	spawnCount  map[string]int
	spawnFirst  map[string]schema.Event
	artOrder    []string
	// base-rule aggregates
	spawnedAgents map[string]bool
	agentSession  map[string]string
	agentRefs     map[string][]string
	agentSessID   map[string]string
	agentSide     map[string]bool
	shellCount    int
	shellFirst    schema.Event
}

func (a *streamAgg) pass1(ev schema.Event) {
	if ev.EventType == schema.EventToolResult && ev.TaskID != "" {
		if t, ok := parseTS(ev.Timestamp); ok {
			if cur, seen := a.completed[ev.TaskID]; !seen || t.After(cur) {
				a.completed[ev.TaskID] = t
			}
		}
	}
	if ev.EventType == schema.EventToolCall && ev.Action == "mcp_call" && ev.ToolCallID != "" {
		a.mcpServers[ev.ToolCallID] = ev.MCPServer
	}
	if ev.EventType == schema.EventAgentSpawn {
		a.spawnCount[ev.SessionID]++
		if _, ok := a.spawnFirst[ev.SessionID]; !ok {
			a.spawnFirst[ev.SessionID] = ev
		}
		if ev.TaskID != "" {
			a.spawnedAgents[ev.TaskID] = true
		}
	}
	if ev.AgentID != "" && ev.SessionID != "" {
		a.agentSession[ev.AgentID] = ev.SessionID
	}
	if a.agentSide[ev.AgentID] {
		if len(a.agentRefs[ev.AgentID]) < 3 {
			a.agentRefs[ev.AgentID] = append(a.agentRefs[ev.AgentID], ref(ev))
		}
		a.agentSessID[ev.AgentID] = ev.SessionID
	}
	if ev.EventType == schema.EventToolCall && ev.Action == "shell_execution" {
		if a.shellCount == 0 {
			a.shellFirst = ev
		}
		a.shellCount++
	}
	if art := ev.SourceArtifact; art != "" {
		if a.artSessions[art] == nil {
			a.artSessions[art] = map[string]bool{}
			a.artSample[art] = ev
			a.artOrder = append(a.artOrder, art)
		}
		if ev.SessionID != "" {
			a.artSessions[art][ev.SessionID] = true
		}
		if ev.EventType == schema.EventSessionMeta && ev.Result == "chain_break" {
			a.artBreaks[art]++
		}
		if t, ok := parseTS(ev.Timestamp); ok {
			if last, ok2 := a.artLastTS[art]; ok2 && t.Before(last.Add(-60*time.Second)) {
				a.artRegress[art]++
			}
			a.artLastTS[art] = t
			if t.After(a.artLatest[art]) {
				a.artLatest[art] = t
			}
		}
	}
}

func (a *streamAgg) spawnExplosion(opts Options) []schema.Finding {
	th := opts.SpawnThreshold
	if th <= 0 {
		th = defaultSpawnThreshold
	}
	var out []schema.Finding
	sess := make([]string, 0, len(a.spawnCount))
	for s := range a.spawnCount {
		sess = append(sess, s)
	}
	sort.Strings(sess)
	for _, s := range sess {
		n := a.spawnCount[s]
		if n <= th {
			continue
		}
		out = append(out, schema.Finding{
			RuleID: "AGENT_SPAWN_EXPLOSION", Severity: "MEDIUM", Title: "Excessive Subagent Spawning",
			Description: fmt.Sprintf("%d subagent spawns in one session (threshold %d). Runaway delegation loops amplify cost and blast radius.", n, th),
			SessionID:   s, AgentID: a.spawnFirst[s].AgentID, EvidenceRefs: []string{ref(a.spawnFirst[s])},
			Status: schema.StateObserved, Endpoint: schema.StateUnknown,
			FalsePositive: "Large fan-out tasks legitimately spawn many agents; tune with --spawn-threshold.",
		})
	}
	return out
}

func (a *streamAgg) identityMismatch() []schema.Finding {
	var out []schema.Finding
	for _, art := range a.artOrder {
		set := a.artSessions[art]
		if len(set) < 2 {
			continue
		}
		ids := make([]string, 0, len(set))
		for s := range set {
			ids = append(ids, s)
		}
		sort.Strings(ids)
		out = append(out, schema.Finding{
			RuleID: "AGENT_IDENTITY_MISMATCH", Severity: "HIGH", Title: "Transcript Carries Multiple Session Identities",
			Description:  fmt.Sprintf("Artifact %.12s contains records from %d different sessions. Single-session files should not — indicates splicing or identity confusion.", art, len(set)),
			EvidenceRefs: []string{ref(a.artSample[art])},
			Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
			MitreATTACK:   "T1565.001",
			FalsePositive: "Some products append resumed sessions with new IDs to the same file; confirm with product version.",
		})
	}
	return out
}

func (a *streamAgg) sessionTampering() []schema.Finding {
	var out []schema.Finding
	for _, art := range a.artOrder {
		br, rg := a.artBreaks[art], a.artRegress[art]
		if br == 0 && rg == 0 {
			continue
		}
		sev := "MEDIUM"
		if br > 0 {
			sev = "HIGH"
		}
		out = append(out, schema.Finding{
			RuleID: "SESSION_TAMPERING", Severity: sev, Title: "Transcript Integrity Anomalies",
			Description:  fmt.Sprintf("Artifact %.12s shows %d parent-chain break(s) and %d backward timestamp regression(s) (>60s). OBSERVED events from this artifact carry reduced confidence.", art, br, rg),
			SessionID:    a.artSample[art].SessionID,
			EvidenceRefs: []string{ref(a.artSample[art])},
			Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
			MitreATTACK:   "T1565.001",
			FalsePositive: "Clock adjustments and product bugs can regress timestamps; chain breaks are the stronger signal.",
		})
	}
	return out
}

func (a *streamAgg) timestomp(man *casepkg.Manifest) []schema.Finding {
	var out []schema.Finding
	for _, art := range man.Artifacts {
		if art.Status != casepkg.StatusOK || !isType(art, "agent_session", "prompt_history") {
			continue
		}
		mt, ok := parseTS(art.ModTimeUTC)
		lt, ok2 := a.artLatest[art.ArtifactID]
		if !ok || !ok2 || !mt.Before(lt.Add(-5*time.Minute)) {
			continue
		}
		out = append(out, schema.Finding{
			RuleID: "TIMESTOMP_INDICATOR", Severity: "MEDIUM", Title: "File Modified Before Content It Contains",
			Description:  fmt.Sprintf("%s has filesystem mtime %s but contains an event timestamped %s — a file cannot legitimately predate its own content.", art.LogicalPath, mt.Format(time.RFC3339), lt.Format(time.RFC3339)),
			SessionID:    a.artSample[art.ArtifactID].SessionID,
			EvidenceRefs: []string{ref(a.artSample[art.ArtifactID])},
			Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
			MitreATTACK:   "T1070.006",
			FalsePositive: "Host clock skew or restoring from backup produces the same pattern; correlate with case.json clock data.",
		})
	}
	return out
}

func (a *streamAgg) orphanAgents() []schema.Finding {
	var agents []string
	for id := range a.agentSide {
		agents = append(agents, id)
	}
	sort.Strings(agents)
	var out []schema.Finding
	for _, agentID := range agents {
		if a.spawnedAgents[agentID] {
			continue
		}
		out = append(out, schema.Finding{
			RuleID: "ORPHAN_AGENT", Severity: "HIGH", Title: "Unexpected Agent Activity",
			Description:   "Agent appeared without a verified parent invocation: no Task spawn event or spawn result links any parent agent to this transcript.",
			SessionID:     a.agentSessID[agentID],
			AgentID:       agentID,
			ParentAgentID: "UNKNOWN",
			EvidenceRefs:  a.agentRefs[agentID],
			Status:        schema.StateObserved, Endpoint: schema.StateUnknown,
			FalsePositive: "Spawn evidence may live in a session not collected (partial acquisition) or a format version this parser does not yet link.",
		})
	}
	return out
}

func (a *streamAgg) shellExecution() []schema.Finding {
	if a.shellCount == 0 {
		return nil
	}
	return []schema.Finding{{
		RuleID: "SHELL_EXECUTION", Severity: "INFO", Title: "Shell Execution Present",
		Description:  fmt.Sprintf("%d shell command(s) invoked via a shell tool across the collected sessions.", a.shellCount),
		EvidenceRefs: []string{ref(a.shellFirst)},
		Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
		FalsePositive: "Expected in virtually every coding-agent session; informational context.",
	}}
}

type streamPass2 struct {
	agg          *streamAgg
	sidechain    map[string]bool
	opts         Options
	findings     []schema.Finding
	pendingExfil map[string]schema.Event // session -> sensitive precursor
	seenDest     map[string]bool
	resumeFlag   map[string]bool
}

func (p *streamPass2) handle(ev schema.Event) {
	switch ev.EventType {
	case schema.EventToolCall:
		p.findings = append(p.findings, oneToolCallRules(ev, p)...)
		if f, ok := destructiveOne(ev); ok {
			p.findings = append(p.findings, f)
		}
		if ev.Action == "inter_agent_message" {
			if f, ok := crossMessageOne(ev, p.agg); ok {
				p.findings = append(p.findings, f)
			}
		}
	case schema.EventTraceGap:
		p.findings = append(p.findings, traceGapOne(ev))
	case schema.EventToolResult:
		if server, ok := p.agg.mcpServers[ev.ToolCallID]; ok {
			if f, hit := mcpPoisonOne(ev, server); hit {
				p.findings = append(p.findings, f)
			}
		}
	case schema.EventAgentSpawn:
		if p.sidechain[ev.AgentID] {
			p.findings = append(p.findings, nestedTaskFinding(ev))
		}
	}
	// UNEXPECTED_AGENT_RESUME: activity after recorded completion.
	if done, ok := p.agg.completed[ev.AgentID]; ok && !p.resumeFlag[ev.AgentID] &&
		ev.EventType != schema.EventToolResult {
		if t, ok := parseTS(ev.Timestamp); ok && t.After(done.Add(60*time.Second)) {
			p.resumeFlag[ev.AgentID] = true
			p.findings = append(p.findings, schema.Finding{
				RuleID: "UNEXPECTED_AGENT_RESUME", Severity: "MEDIUM", Title: "Agent Active After Recorded Completion",
				Description: fmt.Sprintf("Agent %s has activity %s after its parent recorded completion at %s.", ev.AgentID, t.Format(time.RFC3339), done.Format(time.RFC3339)),
				SessionID:   ev.SessionID, AgentID: ev.AgentID, EvidenceRefs: []string{ref(ev)},
				Status: ev.Corroboration, Endpoint: schema.StateUnknown,
				FalsePositive: "Legitimate resumes happen when a user re-attaches; check for a preceding human prompt.",
			})
		}
	}
}
