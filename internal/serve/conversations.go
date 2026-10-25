package serve

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"sort"
	"sync"

	"github.com/efij/AgentDFIR/v4/internal/overlay"
	"github.com/efij/AgentDFIR/v4/internal/sanitize"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Conversations that never touched an agent's transcript: chats read from a
// provider's account export (ChatGPT, Claude.ai, DeepSeek, Gemini Apps) and
// AI-service pages read from browser history. They are two different kinds
// of evidence and the page says which one each conversation is: an export
// is the provider's record of what was said; browser history is visits
// only, never content.

// aiProducts are the products whose sessions the conversations view lists,
// with the evidence class each one is.
var aiProducts = map[string]string{
	"chatgpt": "provider_export", "claude-ai": "provider_export", "deepseek": "provider_export", "gemini-apps": "provider_export",
	"browser": "browser-history",
}

// Results the export parser writes on messages that are not on the
// conversation's current branch.
const (
	branchAlternate  = "export:alternate-branch"
	branchUnresolved = "export:branch-unresolved"
)

type convCache struct {
	once     sync.Once
	branches map[string]int // session -> messages on another branch
	entOnce  sync.Once
	ents     map[string]schema.Entity
}

// sessionEntities is the richest entity recorded per session id: the
// export's conversation title, the browser group's label. Several records
// can name one session; the one with the most attributes wins.
func (s *Server) sessionEntities() map[string]schema.Entity {
	s.conv.entOnce.Do(func() {
		s.conv.ents = map[string]schema.Entity{}
		for _, e := range s.entities {
			if e.Kind != "session" {
				continue
			}
			if prev, ok := s.conv.ents[e.EntityID]; !ok || len(e.Attributes) > len(prev.Attributes) {
				s.conv.ents[e.EntityID] = e
			}
		}
	})
	return s.conv.ents
}

// sessionLabel is a session's readable name when the evidence records one
// that is not just its id, sanitized; "" otherwise.
func (s *Server) sessionLabel(id string) string {
	e := s.sessionEntities()["session:"+id]
	l := e.Label
	if l == "" || l == id {
		l = e.Attributes["title"]
	}
	if l == id {
		return ""
	}
	return sanitize.Terminal(trimTo(l, 200))
}

// branchCounts computes, once, how many messages of each export
// conversation sit on another branch: the index does not carry an event's
// result, so this reads the export events back once.
func (s *Server) branchCounts() map[string]int {
	s.conv.once.Do(func() {
		s.conv.branches = map[string]int{}
		for i, n := 0, s.idx.Len(); i < n; i++ {
			e := s.idx.At(i)
			if aiProducts[e.Product] != "provider_export" || (e.EventType != schema.EventHumanPrompt && e.EventType != schema.EventModelResponse && e.EventType != schema.EventToolCall && e.EventType != schema.EventToolResult) {
				continue
			}
			if ev, err := s.idx.Event(i); err == nil && (ev.Result == branchAlternate || ev.Result == branchUnresolved) {
				s.conv.branches[e.SessionID]++
			}
		}
	})
	return s.conv.branches
}

// ---- /api/conversations ----

func (s *Server) apiConversations(w http.ResponseWriter, r *http.Request) {
	type card struct {
		ID, Product, Class, First, Last string
		Events, Prompts, Responses      int
		ToolCalls                       int
	}
	cards := map[string]*card{}
	var order []string
	for i, n := 0, s.idx.Len(); i < n; i++ {
		e := s.idx.At(i)
		class, ok := aiProducts[e.Product]
		if !ok || e.SessionID == "" {
			continue
		}
		c := cards[e.SessionID]
		if c == nil {
			c = &card{ID: e.SessionID, Product: e.Product, Class: class}
			cards[e.SessionID] = c
			order = append(order, e.SessionID)
		}
		c.Events++
		switch e.EventType {
		case schema.EventHumanPrompt:
			c.Prompts++
		case schema.EventModelResponse:
			c.Responses++
		case schema.EventToolCall:
			c.ToolCalls++
		}
		if e.Timestamp != "" {
			if c.First == "" || e.Timestamp < c.First {
				c.First = e.Timestamp
			}
			if e.Timestamp > c.Last {
				c.Last = e.Timestamp
			}
		}
	}
	if len(cards) == 0 {
		writeJSON(w, map[string]any{"available": false, "reason": "This case holds no AI-service export and no browser history.",
			"howto": []string{"agentdfir collect --ai-export <export.zip>", "agentdfir collect --product claude --include-browser"}})
		return
	}
	branches, ents := s.branchCounts(), s.sessionEntities()
	items := make([]map[string]any, 0, len(cards))
	for _, id := range order {
		c := cards[id]
		ent := ents["session:"+id]
		label := s.sessionLabel(id)
		attrs := map[string]string{}
		for _, k := range []string{"service", "service_name", "page_kind", "visit_rows", "browsers", "browser_visit_count", "first_visit", "last_visit", "conversation_id", "schema_variant", "model", "title"} {
			if v := ent.Attributes[k]; v != "" {
				attrs[k] = sanitize.Terminal(trimTo(v, 200))
			}
		}
		if ent.Attributes["evidence_class"] != "" {
			c.Class = ent.Attributes["evidence_class"]
		}
		items = append(items, map[string]any{
			"id": sanitize.Terminal(id), "label": label, "product": c.Product, "class": sanitize.Terminal(c.Class),
			"first": c.First, "last": c.Last, "events": c.Events, "prompts": c.Prompts, "responses": c.Responses, "tool_calls": c.ToolCalls,
			"branches": branches[id], "attributes": attrs, "named": label != "",
		})
	}
	sort.SliceStable(items, func(a, b int) bool {
		la, lb := items[a]["last"].(string), items[b]["last"].(string)
		if la != lb {
			return la > lb
		}
		return items[a]["id"].(string) < items[b]["id"].(string)
	})
	writeJSON(w, map[string]any{"available": true, "items": items})
}

// ---- /api/conversation?session= ----

// apiConversation returns one conversation's messages in time order, each
// marked when it is on a branch the conversation moved away from (or one
// the export does not resolve). Bounded: a long conversation shows its
// first maxMessages and says how many more there are.
func (s *Server) apiConversation(w http.ResponseWriter, r *http.Request) {
	const maxMessages = 1000
	id := r.URL.Query().Get("session")
	var rows []int
	for i, n := 0, s.idx.Len(); i < n; i++ {
		e := s.idx.At(i)
		if id != "" && e.SessionID == id {
			if _, ok := aiProducts[e.Product]; ok {
				rows = append(rows, i)
			}
		}
	}
	if len(rows) == 0 {
		http.NotFound(w, r)
		return
	}
	rows = s.byTime(rows, "conv\x00"+id)
	total := len(rows)
	if len(rows) > maxMessages {
		rows = rows[:maxMessages]
	}
	msgs := make([]map[string]any, 0, len(rows))
	for _, i := range rows {
		ev, err := s.idx.Event(i)
		if err != nil {
			continue
		}
		branch := ""
		switch ev.Result {
		case branchAlternate:
			branch = "alternate"
		case branchUnresolved:
			branch = "unresolved"
		}
		text := ev.Summary
		if text == "" {
			text = ev.Tool
		}
		msgs = append(msgs, map[string]any{
			"id": ev.EventID, "ts": ev.Timestamp, "type": ev.EventType, "actor": ev.ActorType, "action": sanitize.Terminal(ev.Action),
			"tool": sanitize.Terminal(ev.Tool), "text": sanitize.Terminal(trimTo(text, 4000)), "branch": branch, "state_label": schema.Label(ev.Corroboration),
			"flags": s.flagged[ev.EventID],
		})
	}
	writeJSON(w, map[string]any{"session": sanitize.Terminal(id), "total": total, "truncated": total > len(msgs), "messages": msgs})
}

// ---- /api/extensions ----

// apiExtensions serves detections/extensions.json (inventory + findings)
// when the analysis wrote one, sanitized and with every list bounded.
func (s *Server) apiExtensions(w http.ResponseWriter, r *http.Request) {
	data, err := overlay.ReadFile(filepath.Join(s.pkg, "detections", "extensions.json"))
	if err != nil {
		s.missing(w, "This case has no extension and plugin inventory (detections/extensions.json). It was analyzed by an older version, or no editor or agent plugin directory was collected.")
		return
	}
	var v map[string]any
	if json.Unmarshal(data, &v) != nil {
		s.missing(w, "The extension inventory in this case could not be read.")
		return
	}
	writeJSON(w, map[string]any{"available": true, "data": boundLists(sanitizeJSON(v), 2000, 0)})
}

// boundLists cuts every array in a decoded JSON value to max entries and
// records how many were dropped next to it ("<key>_omitted").
func boundLists(v any, max, depth int) any {
	if depth > 32 {
		return nil
	}
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			if l, ok := val.([]any); ok && len(l) > max {
				t[k+"_omitted"] = len(l) - max
				val = l[:max]
			}
			t[k] = boundLists(val, max, depth+1)
		}
		return t
	case []any:
		for i := range t {
			t[i] = boundLists(t[i], max, depth+1)
		}
		return t
	}
	return v
}
