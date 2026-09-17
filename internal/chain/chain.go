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
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/rulepack"
	"github.com/efij/AgentDFIR/internal/schema"
)

// Step is one predicate in a chain. Every non-empty field must hold for an
// event to satisfy the step; list fields are any-of. FindingRules matches an
// event that an existing finding (from any earlier stage) cites as evidence,
// so chains can build on the whole detection catalog instead of re-deriving it.
type Step struct {
	Name         string   `json:"name"`
	EventTypes   []string `json:"event_types,omitempty"`
	Tools        []string `json:"tools,omitempty"`
	MCP          bool     `json:"mcp,omitempty"`     // MCP server must be set on the event
	Network      bool     `json:"network,omitempty"` // network destination must be set on the event
	CommandRegex string   `json:"command_regex,omitempty"`
	FileRegex    string   `json:"file_regex,omitempty"`
	TextRegex    string   `json:"text_regex,omitempty"` // over command, file, summary, result, destination
	FindingRules []string `json:"finding_rules,omitempty"`
	Or           []Step   `json:"or,omitempty"` // alternatives: the step also matches if any of these does

	cmdRe, fileRe, textRe *regexp.Regexp
}

// Chain is one toxic combination.
type Chain struct {
	ID            string `json:"id"`
	Title         string `json:"title"`
	Description   string `json:"description"`
	Severity      string `json:"severity"`
	Scope         string `json:"scope"`          // session | agent
	WindowMinutes int    `json:"window_minutes"` // max span from first to last step; 0 = unlimited
	Steps         []Step `json:"steps"`
	MitreATLAS    string `json:"mitre_atlas,omitempty"`
	MitreATTACK   string `json:"mitre_attack,omitempty"`
	FalsePositive string `json:"false_positive_notes,omitempty"`
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
	if c.Scope != "session" && c.Scope != "agent" {
		return fmt.Errorf("chain %s: scope must be session or agent", c.ID)
	}
	if len(c.Steps) < 2 {
		return fmt.Errorf("chain %s: needs at least two steps", c.ID)
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
		if len(s.EventTypes)+len(s.Tools)+len(s.FindingRules) == 0 && !s.MCP && !s.Network && s.cmdRe == nil && s.fileRe == nil && s.textRe == nil {
			return fmt.Errorf("chain %s step %s: no predicate", c.ID, s.Name)
		}
		for j := range s.Or {
			alt := &s.Or[j]
			if alt.Name == "" {
				alt.Name = s.Name
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
		}
	}
	return nil
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

	var out []schema.Finding
	for ci := range chains {
		c := &chains[ci]
		if err := c.Validate(); err != nil {
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
			out = append(out, matchGroup(c, events, groups[k], flagged)...)
		}
	}
	return out
}

// matchGroup finds every non-overlapping instance of the chain in one group:
// the earliest event satisfying step 1, then the first later event satisfying
// step 2, and so on. After a complete match the search resumes after the last
// matched event; incomplete attempts advance the start by one.
func matchGroup(c *Chain, events []schema.Event, idx []int, flagged map[string]map[string]bool) []schema.Finding {
	var out []schema.Finding
	window := time.Duration(c.WindowMinutes) * time.Minute
	start := 0
	for start < len(idx) && len(out) < 20 {
		if !stepMatches(&c.Steps[0], events[idx[start]], flagged) {
			start++
			continue
		}
		matched := []int{idx[start]}
		t0, hasT0 := parseTS(events[idx[start]].Timestamp)
		pos := start + 1
		ok := true
		for si := 1; si < len(c.Steps); si++ {
			found := -1
			for ; pos < len(idx); pos++ {
				e := events[idx[pos]]
				if window > 0 && hasT0 {
					if t, ok := parseTS(e.Timestamp); ok && t.Sub(t0) > window {
						break
					}
				}
				if stepMatches(&c.Steps[si], e, flagged) {
					found = idx[pos]
					pos++
					break
				}
			}
			if found < 0 {
				ok = false
				break
			}
			matched = append(matched, found)
		}
		if !ok {
			start++
			continue
		}
		out = append(out, finding(c, events, matched))
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
	if s.Network && e.NetworkDest == "" {
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

func finding(c *Chain, events []schema.Event, matched []int) schema.Finding {
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
	var names []string
	worst := schema.StateObserved
	for i, ei := range matched {
		e := events[ei]
		names = append(names, fmt.Sprintf("%d. %s", i+1, c.Steps[i].Name))
		f.EvidenceRefs = append(f.EvidenceRefs, evidenceRef(e))
		f.ChainSteps = append(f.ChainSteps, schema.ChainStep{
			Step: c.Steps[i].Name, EventID: e.EventID, Timestamp: e.Timestamp, AgentID: e.AgentID,
			Summary: describe(e), Evidence: evidenceRef(e),
		})
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
		byRef[e.SourcePath+":"+strconv.Itoa(e.SourceLine)] = e.EventID
		byRef[e.SourcePath+"@"+strconv.FormatInt(e.SourceOffset, 10)] = e.EventID
	}
	return byRef
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
