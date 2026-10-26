// Package chain detects toxic combinations: ordered sequences of events
// inside one session (or one agent's lineage) that are individually
// unremarkable or already flagged, but together tell the story of an attack —
// untrusted content came in, the agent's own instructions changed, a shell
// ran, a secret left the host. A matched chain becomes one finding whose
// ChainSteps carry the exact events, in order, so the explorer can draw the
// path from first step to the "boom".
//
// Chains are declarative data. The built-ins live in builtins.go; extra
// chains load from *.chains.json files in the rule-pack directory and are
// validated like any other rule (severity, MITRE ATLAS technique IDs, regexes).
package chain

import (
	"encoding/json"
	"fmt"
	"github.com/efij/AgentDFIR/v4/internal/netdest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/redact"
	"github.com/efij/AgentDFIR/v4/internal/rulepack"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Step is one predicate in a chain. Every non-empty field must hold for an
// event to satisfy the step; list fields are any-of. FindingRules matches an
// event that an existing finding (from any earlier stage) cites as evidence,
// so chains can build on the whole detection catalog instead of re-deriving it.
type Step struct {
	Name         string   `json:"name"`
	EventTypes   []string `json:"event_types,omitempty"`
	Tools        []string `json:"tools,omitempty"`
	ToolRegex    string   `json:"tool_regex,omitempty"` // over the tool name (e.g. mcp__server__send_message)
	MCP          bool     `json:"mcp,omitempty"`        // MCP server must be set on the event
	Network      bool     `json:"network,omitempty"`    // network destination must be set on the event
	CommandRegex string   `json:"command_regex,omitempty"`
	FileRegex    string   `json:"file_regex,omitempty"`
	TextRegex    string   `json:"text_regex,omitempty"` // over command, file, summary, result, destination
	Outbound     bool     `json:"outbound,omitempty"`   // command opens a network connection (netdest.IsOutbound)
	Upload       bool     `json:"upload,omitempty"`     // command sends data out (netdest.IsUpload)
	FindingRules []string `json:"finding_rules,omitempty"`
	// ResultStatus and ApprovalState match the outcome and the approval
	// decision the evidence records (any-of, case-insensitive). An event
	// that records neither never satisfies them: no outcome is inferred.
	ResultStatus  []string `json:"result_status,omitempty"`
	ApprovalState []string `json:"approval_state,omitempty"`
	Or            []Step   `json:"or,omitempty"` // alternatives: the step also matches if any of these does

	// Relations to the previous step's matched event. They belong to the
	// step, not to an alternative, and step 1 has none.
	Link            string `json:"link,omitempty"`             // overrides the chain's link for joining this step to the previous one
	DifferentAgent  bool   `json:"different_agent,omitempty"`  // a different agent (session + agent ID) than the previous step
	DifferentMethod bool   `json:"different_method,omitempty"` // a different tool, or shell program, than the previous step

	cmdRe, fileRe, textRe, toolRe *regexp.Regexp
}

// Chain is one toxic combination.
type Chain struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Severity      string `json:"severity"`
	Scope         string `json:"scope"`          // session | agent | case (case needs an artifact link)
	WindowMinutes int    `json:"window_minutes"` // max span from first to last step; 0 = unlimited
	Steps         []Step `json:"steps"`
	MitreATLAS    string `json:"mitre_atlas,omitempty"`
	MitreATTACK   string `json:"mitre_attack,omitempty"`
	FalsePositive string `json:"false_positive_notes,omitempty"`
	// Link is the join field consecutive steps must share (see link.go):
	// file, network_destination, tool_call_id, mcp_tool, mcp_server,
	// target, skill, session or agent. Empty keeps the v4 behaviour:
	// scope and window only.
	Link string `json:"link,omitempty"`
}

// linkFor is the join kind between step i and step i-1.
func (c *Chain) linkFor(i int) string {
	if i == 0 {
		return ""
	}
	if c.Steps[i].Link != "" {
		return c.Steps[i].Link
	}
	return c.Link
}

// relational reports whether any step constrains its relation to the
// previous one. Chains without relations run exactly as in v4.
func (c *Chain) relational() bool {
	if c.Link != "" {
		return true
	}
	for i := range c.Steps {
		if s := &c.Steps[i]; s.Link != "" || s.DifferentAgent || s.DifferentMethod {
			return true
		}
	}
	return false
}

// Pack is a *.chains.json file.
type Pack struct {
	Pack    string  `json:"pack"`
	Version string  `json:"version"`
	Chains  []Chain `json:"chains"`
}

var validSeverity = map[string]bool{"INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}

// Validate checks a chain definition and compiles its regexes.
func (c *Chain) Validate() error {
	if c.ID == "" || !regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)+$`).MatchString(c.ID) {
		return fmt.Errorf("chain %q: id must be UPPER_SNAKE", c.ID)
	}
	if !validSeverity[c.Severity] {
		return fmt.Errorf("chain %s: bad severity %q", c.ID, c.Severity)
	}
	if c.Scope != "session" && c.Scope != "agent" && c.Scope != "case" {
		return fmt.Errorf("chain %s: scope must be session, agent or case", c.ID)
	}
	if len(c.Steps) < 2 {
		return fmt.Errorf("chain %s: needs at least two steps", c.ID)
	}
	if err := checkLink(c.Link); err != nil {
		return fmt.Errorf("chain %s: %w", c.ID, err)
	}
	// Across sessions and agents, order and a window are not enough to say
	// two events belong together: a case-wide chain must name the shared
	// artifact.
	if c.Scope == "case" && !artifactLinks[c.Link] {
		return fmt.Errorf("chain %s: case scope needs an artifact link (file, network_destination, tool_call_id, mcp_tool, mcp_server, target or skill)", c.ID)
	}
	if c.MitreATLAS != "" && !rulepack.ValidATLAS(c.MitreATLAS) {
		return fmt.Errorf("chain %s: unknown ATLAS technique %s", c.ID, c.MitreATLAS)
	}
	if (c.Severity == "HIGH" || c.Severity == "CRITICAL") && c.MitreATLAS == "" && c.MitreATTACK == "" {
		return fmt.Errorf("chain %s: HIGH/CRITICAL chains need a MITRE mapping", c.ID)
	}
	for i := range c.Steps {
		s := &c.Steps[i]
		if s.Name == "" {
			return fmt.Errorf("chain %s: step %d has no name", c.ID, i+1)
		}
		var err error
		if s.cmdRe, err = compile(s.CommandRegex); err != nil {
			return fmt.Errorf("chain %s step %s: command_regex: %w", c.ID, s.Name, err)
		}
		if s.fileRe, err = compile(s.FileRegex); err != nil {
			return fmt.Errorf("chain %s step %s: file_regex: %w", c.ID, s.Name, err)
		}
		if s.textRe, err = compile(s.TextRegex); err != nil {
			return fmt.Errorf("chain %s step %s: text_regex: %w", c.ID, s.Name, err)
		}
		if s.toolRe, err = compile(s.ToolRegex); err != nil {
			return fmt.Errorf("chain %s step %s: tool_regex: %w", c.ID, s.Name, err)
		}
		if err := checkLink(s.Link); err != nil {
			return fmt.Errorf("chain %s step %s: %w", c.ID, s.Name, err)
		}
		if i == 0 && (s.Link != "" || s.DifferentAgent || s.DifferentMethod) {
			return fmt.Errorf("chain %s step %s: the first step has no previous step to relate to", c.ID, s.Name)
		}
		if len(s.EventTypes)+len(s.Tools)+len(s.FindingRules)+len(s.ResultStatus)+len(s.ApprovalState) == 0 && !s.MCP && !s.Network && !s.Outbound && !s.Upload && s.cmdRe == nil && s.fileRe == nil && s.textRe == nil && s.toolRe == nil {
			return fmt.Errorf("chain %s step %s: no predicate", c.ID, s.Name)
		}
		for j := range s.Or {
			alt := &s.Or[j]
			if alt.Name == "" {
				alt.Name = s.Name
			}
			if alt.Link != "" || alt.DifferentAgent || alt.DifferentMethod {
				return fmt.Errorf("chain %s step %s alternative %d: link, different_agent and different_method belong to the step, not an alternative", c.ID, s.Name, j+1)
			}
			var err error
			if alt.cmdRe, err = compile(alt.CommandRegex); err != nil {
				return fmt.Errorf("chain %s step %s alternative %d: command_regex: %w", c.ID, s.Name, j+1, err)
			}
			if alt.fileRe, err = compile(alt.FileRegex); err != nil {
				return fmt.Errorf("chain %s step %s alternative %d: file_regex: %w", c.ID, s.Name, j+1, err)
			}
			if alt.textRe, err = compile(alt.TextRegex); err != nil {
				return fmt.Errorf("chain %s step %s alternative %d: text_regex: %w", c.ID, s.Name, j+1, err)
			}
			if alt.toolRe, err = compile(alt.ToolRegex); err != nil {
				return fmt.Errorf("chain %s step %s alternative %d: tool_regex: %w", c.ID, s.Name, j+1, err)
			}
		}
	}
	return nil
}

func checkLink(k string) error {
	switch {
	case k == "" || validLink(k):
		return nil
	case k == "secret_fingerprint":
		// Credential fingerprints exist only inside the secret-reuse scan;
		// no event or finding field carries one a chain could join on.
		return fmt.Errorf("link secret_fingerprint is not supported: events carry no credential fingerprint")
	}
	return fmt.Errorf("unknown link %q", k)
}

func compile(re string) (*regexp.Regexp, error) {
	if re == "" {
		return nil, nil
	}
	return regexp.Compile("(?i)" + re)
}

// LoadDir reads every *.chains.json under dir.
func LoadDir(dir string) ([]Chain, error) {
	files, _ := filepath.Glob(filepath.Join(dir, "*.chains.json"))
	var out []Chain
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var p Pack
		if err := json.Unmarshal(data, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		for i := range p.Chains {
			if err := p.Chains[i].Validate(); err != nil {
				return nil, fmt.Errorf("%s: %w", f, err)
			}
		}
		out = append(out, p.Chains...)
	}
	return out, nil
}

// Run evaluates chains over the events, using the findings already produced
// by the other stages for FindingRules predicates. Events must carry
// timestamps for windows to apply; without them the order in the overlay is
// used and windows are ignored.
func Run(events []schema.Event, findings []schema.Finding, chains []Chain) []schema.Finding {
	if len(events) == 0 || len(chains) == 0 {
		return nil
	}
	// finding rule → set of event IDs it cites. Evidence references come in two
	// shapes: "path:line (artifact …, offset N)" from event-level rules and
	// "path (artifact …, byte offset N)" from package-level scans.
	byRef := RefIndex(events)
	flagged := map[string]map[string]bool{} // event id → rule ids
	for _, f := range findings {
		for _, ref := range f.EvidenceRefs {
			if id := EventForRef(byRef, ref); id != "" {
				if flagged[id] == nil {
					flagged[id] = map[string]bool{}
				}
				flagged[id][f.RuleID] = true
			}
		}
	}

	// group by scope key, ordered by timestamp then sequence.
	groups := map[string][]int{}
	for i, e := range events {
		groups["session:"+e.SessionID] = append(groups["session:"+e.SessionID], i)
		if e.AgentID != "" {
			groups["agent:"+e.AgentID] = append(groups["agent:"+e.AgentID], i)
		}
	}
	for k := range groups {
		idx := groups[k]
		sort.SliceStable(idx, func(a, b int) bool {
			ea, eb := events[idx[a]], events[idx[b]]
			if ea.Timestamp != eb.Timestamp {
				return ea.Timestamp < eb.Timestamp
			}
			return ea.Sequence < eb.Sequence
		})
	}

	// Link reasons are shown to analysts; anything secret-shaped in a
	// shared value is masked before it reaches a finding.
	var red *redact.Redactor
	for ci := range chains {
		if chains[ci].relational() {
			red, _ = redact.Parse("secrets")
			break
		}
	}

	var caseGroup []int
	var out []schema.Finding
	for ci := range chains {
		c := &chains[ci]
		if err := c.Validate(); err != nil {
			continue
		}
		if c.Scope == "case" {
			if caseGroup == nil {
				caseGroup = caseOrder(events)
			}
			out = append(out, matchGroup(c, events, relevant(c, events, caseGroup, flagged), flagged, red)...)
			continue
		}
		prefix := "session:"
		if c.Scope == "agent" {
			prefix = "agent:"
		}
		keys := make([]string, 0, len(groups))
		for k := range groups {
			if strings.HasPrefix(k, prefix) && k != prefix {
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			out = append(out, matchGroup(c, events, groups[k], flagged, red)...)
		}
	}
	return out
}

// caseOrder is every event with a usable timestamp, in time order. Across
// sessions the per-session sequence number says nothing about order, so an
// event without a timestamp cannot take part in a case-wide chain.
func caseOrder(events []schema.Event) []int {
	type ts struct {
		i int
		t time.Time
	}
	var v []ts
	for i := range events {
		if t, ok := parseTS(events[i].Timestamp); ok {
			v = append(v, ts{i, t})
		}
	}
	sort.SliceStable(v, func(a, b int) bool {
		ea, eb := &events[v[a].i], &events[v[b].i]
		switch {
		case !v[a].t.Equal(v[b].t):
			return v[a].t.Before(v[b].t)
		case ea.SessionID != eb.SessionID:
			return ea.SessionID < eb.SessionID
		}
		return ea.Sequence < eb.Sequence
	})
	out := make([]int, len(v))
	for k := range v {
		out[k] = v[k].i
	}
	return out
}

// relevant keeps the events that satisfy at least one step of the chain.
// The others can never be matched, and dropping them keeps a case-wide
// search proportional to the candidates rather than to the whole case.
func relevant(c *Chain, events []schema.Event, idx []int, flagged map[string]map[string]bool) []int {
	var out []int
	for _, i := range idx {
		for si := range c.Steps {
			if stepMatches(&c.Steps[si], events[i], flagged) {
				out = append(out, i)
				break
			}
		}
	}
	return out
}

// maxRelationalEvals bounds the candidate checks one linked chain may spend
// on one group, so hostile input cannot turn the search quadratic forever.
const maxRelationalEvals = 4_000_000

// matchGroup finds every non-overlapping instance of the chain in one group:
// the earliest event satisfying step 1, then the first later event satisfying
// step 2, and so on. After a complete match the search resumes after the last
// matched event; incomplete attempts advance the start by one. For a linked
// chain a candidate must also share the link value with the previous step's
// event (and satisfy different_agent / different_method).
func matchGroup(c *Chain, events []schema.Event, idx []int, flagged map[string]map[string]bool, red *redact.Redactor) []schema.Finding {
	var out []schema.Finding
	window := time.Duration(c.WindowMinutes) * time.Minute
	rel := c.relational()
	evals := 0
	start := 0
	for start < len(idx) && len(out) < 20 {
		if !stepMatches(&c.Steps[0], events[idx[start]], flagged) {
			start++
			continue
		}
		matched := []int{idx[start]}
		var shared [][]string
		if rel {
			shared = make([][]string, 1, len(c.Steps))
		}
		var st joinState
		t0, hasT0 := parseTS(events[idx[start]].Timestamp)
		pos := start + 1
		ok := true
		for si := 1; si < len(c.Steps); si++ {
			found := -1
			kind := c.linkFor(si)
			var sh []string
			for ; pos < len(idx); pos++ {
				e := events[idx[pos]]
				if window > 0 && hasT0 {
					if t, ok := parseTS(e.Timestamp); ok && t.Sub(t0) > window {
						break
					}
				}
				if rel {
					if evals++; evals > maxRelationalEvals {
						return out
					}
				}
				if !stepMatches(&c.Steps[si], e, flagged) {
					continue
				}
				if rel {
					v, ok := related(kind, &c.Steps[si], events[matched[len(matched)-1]], e, st)
					if !ok {
						continue
					}
					sh = v
				}
				found = idx[pos]
				pos++
				break
			}
			if found < 0 {
				ok = false
				break
			}
			matched = append(matched, found)
			if rel {
				shared = append(shared, sh)
				st = joinState{kind: kind, shared: sh}
			}
		}
		if !ok {
			start++
			continue
		}
		out = append(out, finding(c, events, matched, shared, red))
		start = pos
	}
	return out
}

func stepMatches(s *Step, e schema.Event, flagged map[string]map[string]bool) bool {
	if stepMatchesOne(s, e, flagged) {
		return true
	}
	for i := range s.Or {
		if stepMatchesOne(&s.Or[i], e, flagged) {
			return true
		}
	}
	return false
}

func stepMatchesOne(s *Step, e schema.Event, flagged map[string]map[string]bool) bool {
	if len(s.EventTypes) > 0 && !containsFold(s.EventTypes, e.EventType) {
		return false
	}
	if len(s.Tools) > 0 && !containsFold(s.Tools, e.Tool) {
		return false
	}
	if s.MCP && e.MCPServer == "" {
		return false
	}
	if s.toolRe != nil && !s.toolRe.MatchString(e.Tool) {
		return false
	}
	if s.Network && e.NetworkDest == "" {
		return false
	}
	if s.Upload && !netdest.IsUpload(e.FullCommand()) {
		return false
	}
	if s.Outbound && !netdest.IsOutbound(e.Command) {
		return false
	}
	if s.cmdRe != nil && !s.cmdRe.MatchString(e.Command) {
		return false
	}
	if s.fileRe != nil && !s.fileRe.MatchString(e.File) {
		return false
	}
	if s.textRe != nil && !s.textRe.MatchString(e.Command+"\n"+e.File+"\n"+e.Summary+"\n"+e.Result+"\n"+e.NetworkDest) {
		return false
	}
	if len(s.ResultStatus) > 0 && !containsFold(s.ResultStatus, e.ResultStatus) {
		return false
	}
	if len(s.ApprovalState) > 0 && !containsFold(s.ApprovalState, e.ApprovalState) {
		return false
	}
	if len(s.FindingRules) > 0 {
		rules := flagged[e.EventID]
		hit := false
		for _, r := range s.FindingRules {
			if rules[r] {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func finding(c *Chain, events []schema.Event, matched []int, shared [][]string, red *redact.Redactor) schema.Finding {
	first, last := events[matched[0]], events[matched[len(matched)-1]]
	f := schema.Finding{
		RuleID: c.ID, Severity: c.Severity, Title: c.Title,
		SessionID: last.SessionID, AgentID: last.AgentID, ParentAgentID: last.ParentAgentID,
		Status: schema.StateObserved, Endpoint: schema.StateUnknown,
		MitreATLAS: c.MitreATLAS, MitreATTACK: c.MitreATTACK, FalsePositive: c.FalsePositive,
	}
	span := ""
	if t0, ok := parseTS(first.Timestamp); ok {
		if t1, ok := parseTS(last.Timestamp); ok {
			span = fmt.Sprintf(" within %s", t1.Sub(t0).Round(time.Second))
		}
	}
	var names, reasons []string
	worst := schema.StateObserved
	for i, ei := range matched {
		e := events[ei]
		names = append(names, fmt.Sprintf("%d. %s", i+1, c.Steps[i].Name))
		f.EvidenceRefs = append(f.EvidenceRefs, evidenceRef(e))
		cs := schema.ChainStep{
			Step: c.Steps[i].Name, EventID: e.EventID, Timestamp: e.Timestamp, AgentID: e.AgentID,
			Summary: describe(e), Evidence: evidenceRef(e),
		}
		if i > 0 && i < len(shared) {
			cs.Link = linkSentence(red, c.linkFor(i), i, i+1, shared[i], &c.Steps[i], events[matched[i-1]], e)
			if cs.Link != "" {
				reasons = append(reasons, cs.Link)
			}
		}
		f.ChainSteps = append(f.ChainSteps, cs)
		switch e.Corroboration {
		case schema.StateCorroborated:
			if worst == schema.StateObserved {
				worst = schema.StateCorroborated
			}
		case schema.StateContradicted:
			worst = schema.StateContradicted
		}
	}
	f.Status = worst
	f.Description = c.Description + " Matched: " + strings.Join(names, " → ") + span + "."
	if len(reasons) > 0 {
		r := strings.Join(reasons, "; ")
		f.LinkReason = strings.ToUpper(r[:1]) + r[1:] + "."
		f.Description += " Linked: " + r + "."
	}
	return f
}

func describe(e schema.Event) string {
	switch {
	case e.Command != "":
		return "$ " + e.Command
	case e.File != "":
		return e.Tool + " " + e.File
	case e.NetworkDest != "":
		return e.Tool + " → " + e.NetworkDest
	}
	if e.Tool != "" && e.Summary == "" {
		return e.Tool
	}
	return e.Summary
}

func evidenceRef(e schema.Event) string {
	art := e.SourceArtifact
	if len(art) > 12 {
		art = art[:12]
	}
	return fmt.Sprintf("%s:%d (artifact %s, offset %d)", e.SourcePath, e.SourceLine, art, e.SourceOffset)
}

// EventForRef resolves an evidence reference to an event id using an index
// keyed "path:line" and "path@offset" (see Run). Exported for the explorer.
func EventForRef(byRef map[string]string, ref string) string {
	i := strings.Index(ref, " (artifact ")
	if i < 0 {
		return byRef[ref]
	}
	head, tail := ref[:i], ref[i:]
	if id := byRef[head]; id != "" {
		return id
	}
	if j := strings.Index(tail, "byte offset "); j >= 0 {
		off := strings.TrimRight(strings.TrimSpace(tail[j+len("byte offset "):]), ")")
		return byRef[head+"@"+off]
	}
	return ""
}

// RefIndex builds the lookup EventForRef needs.
func RefIndex(events []schema.Event) map[string]string {
	byRef := make(map[string]string, len(events)*2)
	for _, e := range events {
		AddRefs(byRef, e.SourcePath, e.SourceLine, e.SourceOffset, e.EventID)
	}
	return byRef
}

// AddRefs registers both reference forms for one event. The explorer builds
// the same index straight from its event index, without ever holding the
// events, so the two key formats live in one place rather than being
// spelled out twice and drifting apart.
func AddRefs(byRef map[string]string, path string, line int, off int64, eventID string) {
	byRef[path+":"+strconv.Itoa(line)] = eventID
	byRef[path+"@"+strconv.FormatInt(off, 10)] = eventID
}

func containsFold(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

func parseTS(s string) (time.Time, bool) {
	if s == "" {
		return time.Time{}, false
	}
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}
