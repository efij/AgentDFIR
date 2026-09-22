package serve

import (
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/chain"
	"github.com/efij/AgentDFIR/internal/notes"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/schema"
)

// ---- /api/sessions ----
//
// One card per session: what happened in it, how much of it is proven, and
// how bad it looks. Sorted by risk so the analyst starts at the worst one.

type sessionCard struct {
	ID          string         `json:"id"`
	Product     string         `json:"product"`
	Host        string         `json:"host,omitempty"`
	User        string         `json:"user,omitempty"`
	First       string         `json:"first"`
	Last        string         `json:"last"`
	DurationS   int64          `json:"duration_s"`
	Events      int            `json:"events"`
	Prompts     int            `json:"prompts"`
	Responses   int            `json:"responses"`
	ToolCalls   int            `json:"tool_calls"`
	Spawns      int            `json:"spawns"`
	Agents      int            `json:"agents"`
	AgentIDs    []string       `json:"agent_ids"`
	Orphans     int            `json:"orphans"`
	Tools       map[string]int `json:"tools"`
	MCPServers  []string       `json:"mcp_servers"`
	Files       int            `json:"files"`
	Dests       []string       `json:"destinations"`
	States      map[string]int `json:"states"`
	Findings    map[string]int `json:"findings"`
	FindTotal   int            `json:"findings_total"`
	Worst       string         `json:"worst"`
	Chains      int            `json:"chains"`
	ChainTitles []string       `json:"chain_titles"`
	Tags        []string       `json:"tags"`
	FirstPrompt string         `json:"first_prompt"`
	Risk        int            `json:"risk"`
}

func (s *Server) apiSessions(w http.ResponseWriter, r *http.Request) {
	cards := map[string]*sessionCard{}
	files := map[string]map[string]bool{}
	dests := map[string]map[string]bool{}
	mcps := map[string]map[string]bool{}
	agents := map[string]map[string]bool{}
	for _, e := range s.events {
		if e.SessionID == "" {
			continue
		}
		c := cards[e.SessionID]
		if c == nil {
			c = &sessionCard{ID: e.SessionID, Product: e.Product, Host: e.Host, User: e.User, Tools: map[string]int{}, States: map[string]int{}, Findings: map[string]int{}}
			cards[e.SessionID] = c
			files[e.SessionID], dests[e.SessionID], mcps[e.SessionID], agents[e.SessionID] = map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
		}
		c.Events++
		c.States[e.Corroboration]++
		if e.Timestamp != "" {
			if c.First == "" || e.Timestamp < c.First {
				c.First = e.Timestamp
			}
			if e.Timestamp > c.Last {
				c.Last = e.Timestamp
			}
		}
		switch e.EventType {
		case schema.EventHumanPrompt:
			c.Prompts++
			if c.FirstPrompt == "" {
				c.FirstPrompt = sanitize.Terminal(trimTo(e.Summary, 160))
			}
		case schema.EventModelResponse:
			c.Responses++
		case schema.EventToolCall:
			c.ToolCalls++
			if e.Tool != "" {
				c.Tools[sanitize.Terminal(e.Tool)]++
			}
		case schema.EventAgentSpawn:
			c.Spawns++
		}
		if e.AgentID != "" {
			agents[e.SessionID][e.AgentID] = true
		}
		if e.File != "" {
			files[e.SessionID][e.File] = true
		}
		if e.NetworkDest != "" {
			dests[e.SessionID][e.NetworkDest] = true
		}
		if e.MCPServer != "" {
			mcps[e.SessionID][e.MCPServer] = true
		}
	}
	for _, f := range s.findings {
		c := cards[f.SessionID]
		if c == nil {
			continue
		}
		c.Findings[f.Severity]++
		c.FindTotal++
		if sevRank(f.Severity) > sevRank(c.Worst) {
			c.Worst = f.Severity
		}
		if f.RuleID == "ORPHAN_AGENT" {
			c.Orphans++
		}
		if len(f.ChainSteps) > 0 {
			c.Chains++
			if len(c.ChainTitles) < 4 {
				c.ChainTitles = append(c.ChainTitles, sanitize.Terminal(f.Title))
			}
		}
	}
	st, _ := s.notes.Load()
	out := make([]*sessionCard, 0, len(cards))
	for id, c := range cards {
		c.Files = len(files[id])
		c.Dests = topKeys(dests[id], 5)
		c.MCPServers = topKeys(mcps[id], 6)
		c.Agents = len(agents[id])
		c.AgentIDs = topKeys(agents[id], 6)
		if c.First != "" && c.Last != "" {
			if t0, ok := parseTS(c.First); ok {
				if t1, ok := parseTS(c.Last); ok {
					c.DurationS = int64(t1.Sub(t0).Seconds())
				}
			}
		}
		c.Tags = st.Tags[id]
		c.Risk = sevRank(c.Worst)*1000 + c.Chains*300 + c.Findings["CRITICAL"]*50 + c.Findings["HIGH"]*10 + c.States[schema.StateContradicted]*40 + c.Orphans*100
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Risk != out[j].Risk {
			return out[i].Risk > out[j].Risk
		}
		return out[i].Last > out[j].Last
	})
	writeJSON(w, out)
}

func topKeys(m map[string]bool, n int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, sanitize.Terminal(k))
	}
	sort.Strings(keys)
	if len(keys) > n {
		keys = keys[:n]
	}
	return keys
}

func parseTS(s string) (time.Time, bool) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339} {
		if t, err := time.Parse(layout, s); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

// ---- /api/chain ----
//
// The investigation tree behind one finding: the events that triggered it
// (for attack chains, the matched steps in order) and, under each, what led
// there — the human prompt before it, the tool result the agent had just
// consumed, the spawn that created the agent. Every node is an event the
// analyst can open; nothing here is inferred without an evidence line.

type treeNode struct {
	ID       string      `json:"id"`
	Kind     string      `json:"kind"` // finding | step | event | context
	Role     string      `json:"role,omitempty"`
	Label    string      `json:"label"`
	Detail   string      `json:"detail,omitempty"`
	TS       string      `json:"ts,omitempty"`
	EventID  string      `json:"event_id,omitempty"`
	Type     string      `json:"type,omitempty"`
	Agent    string      `json:"agent,omitempty"`
	State    string      `json:"state,omitempty"`
	Findings []string    `json:"findings,omitempty"`
	Pinned   bool        `json:"pinned,omitempty"`
	Children []*treeNode `json:"children,omitempty"`
	More     bool        `json:"more,omitempty"` // context can be expanded further via ?event=
}

func (s *Server) apiChain(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	st, _ := s.notes.Load()
	pinned := map[string]bool{}
	for _, p := range st.Pins {
		pinned[p.Target] = true
	}
	if id := q.Get("event"); id != "" {
		i, ok := s.byID[id]
		if !ok {
			http.NotFound(w, r)
			return
		}
		n := s.eventNode(s.events[i], "event", "", pinned)
		n.Children = s.contextOf(s.events[i], pinned)
		writeJSON(w, n)
		return
	}
	idx, err := strconv.Atoi(q.Get("finding"))
	if err != nil || idx < 0 || idx >= len(s.findings) {
		http.Error(w, "bad finding index", http.StatusBadRequest)
		return
	}
	f := s.findings[idx]
	root := &treeNode{ID: "finding:" + strconv.Itoa(idx), Kind: "finding", Label: sanitize.Terminal(f.Title), Detail: sanitize.Terminal(f.Description), Type: f.RuleID, State: f.Status, Agent: f.AgentID}
	if len(f.ChainSteps) > 0 {
		for i, step := range f.ChainSteps {
			ei, ok := s.byID[step.EventID]
			if !ok {
				root.Children = append(root.Children, &treeNode{ID: "step:" + strconv.Itoa(i), Kind: "step", Role: step.Step, Label: sanitize.Terminal(step.Summary), TS: step.Timestamp})
				continue
			}
			n := s.eventNode(s.events[ei], "step", step.Step, pinned)
			n.Children = s.contextOf(s.events[ei], pinned)
			root.Children = append(root.Children, n)
		}
	} else {
		seen := map[string]bool{}
		for _, ref := range f.EvidenceRefs {
			id := chain.EventForRef(s.byRef, ref)
			if id == "" || seen[id] {
				continue
			}
			seen[id] = true
			n := s.eventNode(s.events[s.byID[id]], "event", "evidence", pinned)
			n.Children = s.contextOf(s.events[s.byID[id]], pinned)
			root.Children = append(root.Children, n)
		}
	}
	writeJSON(w, map[string]any{"finding": idx, "key": notes.FindingKey(f.RuleID, f.EvidenceRefs), "root": root})
}

func (s *Server) eventNode(e schema.Event, kind, role string, pinned map[string]bool) *treeNode {
	label := e.Summary
	switch {
	case e.Command != "":
		label = "$ " + e.Command
	case e.File != "":
		label = e.Tool + " " + e.File
	case e.NetworkDest != "":
		label = e.Tool + " → " + e.NetworkDest
	case e.Tool != "":
		label = e.Tool + " " + e.Summary
	}
	n := &treeNode{ID: "event:" + e.EventID, Kind: kind, Role: role, Label: sanitize.Terminal(trimTo(label, 200)), TS: e.Timestamp,
		EventID: e.EventID, Type: e.EventType, Agent: e.AgentID, State: e.Corroboration, Pinned: pinned["event:"+e.EventID], More: true}
	if rules := s.flagged[e.EventID]; len(rules) > 0 {
		n.Findings = append(n.Findings, rules...)
	}
	return n
}

// contextOf returns the causal neighbours of an event, each an evidence-backed
// event: the prompt that preceded it, the tool result it consumed, the spawn
// that created its agent, and the message a parent sent to a subagent.
func (s *Server) contextOf(e schema.Event, pinned map[string]bool) []*treeNode {
	i, ok := s.byID[e.EventID]
	if !ok {
		return nil
	}
	var out []*treeNode
	add := func(j int, role string) {
		n := s.eventNode(s.events[j], "context", role, pinned)
		n.Children = nil
		out = append(out, n)
	}
	var prompt, consumed, spawn, message = -1, -1, -1, -1
	for j := i - 1; j >= 0 && j > i-4000; j-- {
		p := s.events[j]
		if p.SessionID != e.SessionID && !(p.EventType == schema.EventAgentSpawn && p.TaskID == e.AgentID) {
			continue
		}
		if prompt < 0 && p.EventType == schema.EventHumanPrompt && p.SessionID == e.SessionID {
			prompt = j
		}
		if consumed < 0 && p.EventType == schema.EventToolResult && p.AgentID == e.AgentID && (e.EventType == schema.EventToolCall || e.EventType == schema.EventModelResponse) {
			consumed = j
		}
		if message < 0 && p.EventType == schema.EventAgentMessage && p.AgentID == e.AgentID && !strings.HasPrefix(e.AgentID, "main:") {
			message = j
		}
		if spawn < 0 && p.EventType == schema.EventAgentSpawn && p.TaskID == e.AgentID {
			spawn = j
		}
		if prompt >= 0 && (consumed >= 0 || e.EventType != schema.EventToolCall) && (spawn >= 0 || strings.HasPrefix(e.AgentID, "main:")) {
			break
		}
	}
	if consumed >= 0 {
		add(consumed, "tool result the agent had just consumed")
	}
	if message >= 0 {
		add(message, "instruction delivered to this subagent")
	}
	if spawn >= 0 {
		add(spawn, "spawned this agent")
	}
	if prompt >= 0 {
		add(prompt, "human prompt before this")
	}
	// What this event led to: the tool result of this call, and the next thing the agent did.
	if e.EventType == schema.EventToolCall && e.ToolCallID != "" {
		for j := i + 1; j < len(s.events) && j < i+200; j++ {
			if s.events[j].EventType == schema.EventToolResult && s.events[j].ToolCallID == e.ToolCallID {
				add(j, "result returned to the agent")
				break
			}
		}
	}
	return out
}

// ---- /api/notes ----

func (s *Server) apiNotes(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet, http.MethodHead:
		st, recs := s.notes.Load()
		if len(recs) > 500 {
			recs = recs[len(recs)-500:]
		}
		for i := range recs {
			recs[i].Text = sanitize.Terminal(recs[i].Text)
		}
		writeJSON(w, map[string]any{"state": sanitizeState(st), "history": recs, "path": s.notes.Path()})
	case http.MethodPost:
		var in struct {
			Kind, Target, Value, Text string
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, 64<<10))
		if err != nil || json.Unmarshal(body, &in) != nil {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		switch in.Kind {
		case notes.KindVerdict:
			if in.Value != "" && in.Value != "true_positive" && in.Value != "benign" &&
				in.Value != "false_positive" && in.Value != "needs_review" {
				http.Error(w, "bad verdict", http.StatusBadRequest)
				return
			}
		case notes.KindPin:
			if in.Value != "on" && in.Value != "off" {
				http.Error(w, "bad pin value", http.StatusBadRequest)
				return
			}
		case notes.KindTag:
			if in.Value != "add" && in.Value != "remove" || strings.TrimSpace(in.Text) == "" {
				http.Error(w, "bad tag", http.StatusBadRequest)
				return
			}
		case notes.KindNote:
			if strings.TrimSpace(in.Text) == "" {
				http.Error(w, "empty note", http.StatusBadRequest)
				return
			}
		default:
			http.Error(w, "bad kind", http.StatusBadRequest)
			return
		}
		rec, err := s.notes.Append(in.Kind, in.Target, in.Value, strings.TrimSpace(in.Text))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		st, _ := s.notes.Load()
		writeJSON(w, map[string]any{"record": rec, "state": sanitizeState(st)})
	default:
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
	}
}

func sanitizeState(st *notes.State) *notes.State {
	for k, v := range st.Verdicts {
		v.Note = sanitize.Terminal(v.Note)
		st.Verdicts[k] = v
	}
	for k, list := range st.Notes {
		for i := range list {
			list[i].Text = sanitize.Terminal(list[i].Text)
		}
		st.Notes[k] = list
	}
	for i := range st.Pins {
		st.Pins[i].Note = sanitize.Terminal(st.Pins[i].Note)
	}
	for k, tags := range st.Tags {
		st.Tags[k] = sanitizeAll(tags)
	}
	return st
}
