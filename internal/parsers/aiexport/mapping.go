package aiexport

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// ChatGPT and DeepSeek store a conversation as a message tree:
//
//	{"title", "create_time", "current_node", "mapping": {
//	    "<id>": {"id", "parent", "children": [...], "message": {...}}}}
//
// Regenerating an answer or editing a prompt adds a sibling branch; the
// export keeps every branch and names the one on screen in current_node.
// The active branch is the parent chain from current_node to the root.
// Every other message is still emitted, marked export:alternate-branch.
// DeepSeek exports have no current_node: a fork there is marked
// export:branch-unresolved, because which branch was on screen is not
// recorded and is not guessed.

type mappingNode struct {
	ID       string          `json:"id"`
	Parent   *string         `json:"parent"`
	Children []string        `json:"children"`
	Message  json.RawMessage `json:"message"`
}

// treeMessage is the tolerant union of ChatGPT and DeepSeek message shapes.
type treeMessage struct {
	ID         string          `json:"id"`
	Author     json.RawMessage `json:"author"`
	CreateTime json.RawMessage `json:"create_time"`
	Content    json.RawMessage `json:"content"`
	Recipient  json.RawMessage `json:"recipient"`
	Metadata   json.RawMessage `json:"metadata"`
	// DeepSeek
	Model      json.RawMessage `json:"model"`
	InsertedAt json.RawMessage `json:"inserted_at"`
	Fragments  json.RawMessage `json:"fragments"`
	Files      json.RawMessage `json:"files"`
}

type located struct {
	node mappingNode
	off  int64
	line int
	ptr  string
}

func (p *parser) parseMappingConversations(r io.Reader) error {
	err := walkArray(r, MaxElementBytes, func(el element) error {
		p.mappingConversation(el)
		return nil
	})
	if we, ok := err.(*walkError); ok {
		p.gap("", we.Offset, we.Line, pointer(we.Index), "conversations array: "+we.Error())
		return nil
	}
	return err
}

func (p *parser) mappingConversation(el element) {
	conv := map[string]member{}
	if _, err := membersOf(el.Raw, 4096, func(m member) { conv[m.Key] = m }); err != nil {
		p.gap("", el.Offset, el.Line, pointer(el.Index), "conversation is not a JSON object")
		return
	}
	sid := firstString(conv, "conversation_id", "id")
	if sid == "" {
		sid = fmt.Sprintf("%s-conv-%d", shortID(p.art.ArtifactID), el.Index)
	}
	title := str(conv["title"].Raw)
	defaultModel := str(conv["default_model_slug"].Raw)
	current := str(conv["current_node"].Raw)

	mm, ok := conv["mapping"]
	if !ok {
		p.gap(sid, el.Offset, el.Line, pointer(el.Index), "conversation has no mapping")
		return
	}
	nodes := map[string]*located{}
	var order []string
	truncated, err := membersOf(mm.Raw, maxNodes, func(m member) {
		var n mappingNode
		rel := mm.RelOff + m.RelOff
		loc := &located{off: el.Offset + rel, line: lineOf(el.Raw, el.Line, rel), ptr: pointer(el.Index, "mapping", m.Key)}
		if json.Unmarshal(m.Raw, &n) != nil {
			p.gap(sid, loc.off, loc.line, loc.ptr, "mapping node is not a node object")
			return
		}
		if n.ID == "" {
			n.ID = m.Key
		}
		loc.node = n
		if _, dup := nodes[n.ID]; !dup {
			order = append(order, n.ID)
		}
		nodes[n.ID] = loc
	})
	if err != nil {
		p.gap(sid, el.Offset+mm.RelOff, lineOf(el.Raw, el.Line, mm.RelOff), pointer(el.Index, "mapping"), "mapping is not a JSON object")
		return
	}
	if truncated {
		p.gap(sid, el.Offset+mm.RelOff, lineOf(el.Raw, el.Line, mm.RelOff), pointer(el.Index, "mapping"),
			fmt.Sprintf("mapping holds more than %d nodes; the rest are preserved unparsed", maxNodes))
	}

	// Active branch: the parent chain of current_node.
	active := map[string]bool{}
	hasCurrent := false
	if c, ok := nodes[current]; ok && current != "" {
		hasCurrent = true
		for steps := 0; c != nil && steps <= len(nodes) && !active[c.node.ID]; steps++ {
			active[c.node.ID] = true
			if c.node.Parent == nil {
				break
			}
			c = nodes[*c.node.Parent]
		}
	}

	attrs := map[string]string{"title": title, "conversation_id": sid, "default_model": defaultModel,
		"current_node": current, "nodes": strconv.Itoa(len(nodes))}
	if g := str(conv["gizmo_id"].Raw); g != "" {
		attrs["gizmo_id"] = g
	}
	p.describeSession(sid, attrs)
	head := p.base(sid)
	at(&head, el.Offset, el.Line, pointer(el.Index))
	if f, ok := num(conv["create_time"].Raw); ok {
		epochTime(&head, "create_time", f)
	} else if s := firstString(conv, "create_time", "inserted_at", "created_at"); s != "" {
		isoTime(&head, "inserted_at", s)
	}
	branchNote := "active branch from current_node"
	if !hasCurrent {
		branchNote = "export does not name the current branch"
	}
	p.meta(head, "export:conversation", fmt.Sprintf("conversation %q (%d nodes; %s)", title, len(nodes), branchNote))

	// Depth-first from every root, children in export order. visited is
	// the cycle guard; a node reachable from no root is reported.
	visited := map[string]bool{}
	type item struct {
		id       string
		pastFork bool
	}
	var stack []item
	for i := len(order) - 1; i >= 0; i-- {
		n := nodes[order[i]].node
		if n.Parent == nil || *n.Parent == "" || nodes[*n.Parent] == nil {
			stack = append(stack, item{id: n.ID})
		}
	}
	for len(stack) > 0 {
		it := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		loc := nodes[it.id]
		if loc == nil || visited[it.id] {
			continue
		}
		visited[it.id] = true
		result := resultActive
		switch {
		case hasCurrent && !active[it.id]:
			result = resultAlternate
		case !hasCurrent && it.pastFork:
			result = resultUnresolved
		}
		p.treeMessage(sid, defaultModel, loc, result)
		fork := it.pastFork || len(loc.node.Children) > 1
		for i := len(loc.node.Children) - 1; i >= 0; i-- {
			stack = append(stack, item{id: loc.node.Children[i], pastFork: fork})
		}
	}
	if unreached := len(nodes) - len(visited); unreached > 0 {
		p.gap(sid, el.Offset+mm.RelOff, lineOf(el.Raw, el.Line, mm.RelOff), pointer(el.Index, "mapping"),
			fmt.Sprintf("%d mapping node(s) unreachable from a root (parent cycle or dangling reference); preserved unparsed", unreached))
	}
}

// treeMessage emits the events of one mapping node.
func (p *parser) treeMessage(sid, defaultModel string, loc *located, result string) {
	raw := loc.node.Message
	if len(raw) == 0 || string(raw) == "null" {
		return // structural root
	}
	var m treeMessage
	if json.Unmarshal(raw, &m) != nil {
		p.gap(sid, loc.off, loc.line, loc.ptr+"/message", "message is not an object")
		return
	}
	ev := p.base(sid)
	ev.Result = result
	at(&ev, loc.off, loc.line, loc.ptr+"/message")
	if f, ok := num(m.CreateTime); ok {
		epochTime(&ev, "create_time", f)
	} else if s := str(m.InsertedAt); s != "" {
		isoTime(&ev, "inserted_at", s)
	} else if f, ok := num(m.InsertedAt); ok {
		epochTime(&ev, "inserted_at", f)
	}
	if len(m.Fragments) > 0 && string(m.Fragments) != "null" {
		p.deepseekMessage(ev, m, loc)
		return
	}
	var author struct {
		Role string `json:"role"`
		Name string `json:"name"`
	}
	_ = json.Unmarshal(m.Author, &author)
	var md struct {
		ModelSlug   string            `json:"model_slug"`
		Attachments []json.RawMessage `json:"attachments"`
		Hidden      bool              `json:"is_visually_hidden_from_conversation"`
	}
	_ = json.Unmarshal(m.Metadata, &md)
	recipient := str(m.Recipient)

	text, kind, assets := gptContent(m.Content)
	switch author.Role {
	case "user":
		if text != "" {
			p.prompt(ev, text)
		} else if len(assets) == 0 && len(md.Attachments) == 0 {
			p.meta(ev, result, "empty user message ("+kind+")")
		}
	case "assistant":
		ev.Model = md.ModelSlug
		if ev.Model == "" {
			ev.Model = str(m.Model)
		}
		switch {
		case recipient != "" && recipient != "all":
			p.toolCall(ev, recipient, m.ID, text)
		case text != "":
			if kind == "thoughts" || kind == "reasoning_recap" {
				text = "[reasoning] " + text
			}
			p.reply(ev, text)
		default:
			p.meta(ev, result, "empty assistant message ("+kind+")")
		}
	case "tool":
		ev.Model = ""
		p.toolResult(ev, author.Name, "", text)
	case "system":
		s := "system message"
		if kind == "user_editable_context" {
			s = "custom instructions (user_editable_context)"
		}
		if md.Hidden {
			s += ", hidden from the conversation view"
		}
		if text != "" {
			s += ": " + text
		}
		p.meta(ev, result, s)
	default:
		p.meta(ev, result, fmt.Sprintf("message from role %q: %s", trim(author.Role, 30), text))
	}
	listed := map[string]bool{}
	for i, a := range md.Attachments {
		if i >= maxAttachments {
			break
		}
		var att struct {
			ID       string `json:"id"`
			Name     string `json:"name"`
			MimeType string `json:"mime_type"`
		}
		_ = json.Unmarshal(a, &att)
		listed[att.ID] = true
		p.attachment(ev, att.Name, att.ID, att.MimeType)
	}
	for i, a := range assets {
		if i >= maxAttachments {
			break
		}
		// An image part points at the same file metadata.attachments
		// already named ("file-service://file-X" for attachment "file-X").
		if id := a[0][strings.LastIndex(a[0], "/")+1:]; id != "" && listed[id] {
			continue
		}
		p.attachment(ev, "", a[0], a[1])
	}
}

// gptContent extracts the readable text of a ChatGPT content object, its
// content_type, and the asset pointers (id, kind) it references.
func gptContent(raw json.RawMessage) (text, kind string, assets [][2]string) {
	var c struct {
		ContentType  string            `json:"content_type"`
		Parts        []json.RawMessage `json:"parts"`
		Text         json.RawMessage   `json:"text"`
		Result       string            `json:"result"`
		Summary      json.RawMessage   `json:"summary"`
		URL          string            `json:"url"`
		Title        string            `json:"title"`
		Name         string            `json:"name"`
		Content      json.RawMessage   `json:"content"`
		UserProfile  string            `json:"user_profile"`
		Instructions string            `json:"user_instructions"`
		Thoughts     []struct {
			Summary string `json:"summary"`
			Content string `json:"content"`
		} `json:"thoughts"`
	}
	if json.Unmarshal(raw, &c) != nil {
		// Some tools store content as a bare string.
		return str(raw), "string", nil
	}
	kind = c.ContentType
	var b []string
	add := func(s string) {
		if s = strings.TrimSpace(s); s != "" {
			b = append(b, s)
		}
	}
	for i, part := range c.Parts {
		if i >= maxBlocks {
			break
		}
		if s, ok := strOK(part); ok {
			add(s)
			continue
		}
		var obj struct {
			ContentType  string `json:"content_type"`
			AssetPointer string `json:"asset_pointer"`
			Text         string `json:"text"`
		}
		if json.Unmarshal(part, &obj) == nil {
			add(obj.Text)
			if obj.AssetPointer != "" || (obj.ContentType != "" && obj.Text == "") {
				assets = append(assets, [2]string{obj.AssetPointer, obj.ContentType})
			}
		}
	}
	add(str(c.Text))
	add(c.Result)
	add(str(c.Summary))
	if c.URL != "" || c.Title != "" {
		add(strings.TrimSpace(c.Title + " " + c.URL))
	}
	if kind == "system_error" {
		add(c.Name)
	}
	add(str(c.Content))
	if c.UserProfile != "" || c.Instructions != "" {
		add(c.UserProfile)
		add(c.Instructions)
	}
	for _, t := range c.Thoughts {
		add(t.Summary)
		add(t.Content)
	}
	return strings.Join(b, "\n"), kind, assets
}

// deepseekMessage emits a DeepSeek message: one event per fragment.
func (p *parser) deepseekMessage(ev schema.Event, m treeMessage, loc *located) {
	ev.Model = str(m.Model)
	var frags []json.RawMessage
	if json.Unmarshal(m.Fragments, &frags) != nil {
		p.gap(ev.SessionID, loc.off, loc.line, loc.ptr+"/message/fragments", "fragments is not an array")
		return
	}
	for i, raw := range frags {
		if i >= maxBlocks {
			break
		}
		var f struct {
			Type    string `json:"type"`
			Content string `json:"content"`
			Results []struct {
				URL   string `json:"url"`
				Title string `json:"title"`
			} `json:"results"`
		}
		fe := ev
		fe.SourceJSONPath = fmt.Sprintf("%s/message/fragments/%d", loc.ptr, i)
		if json.Unmarshal(raw, &f) != nil {
			p.gap(ev.SessionID, loc.off, loc.line, fe.SourceJSONPath, "fragment is not an object")
			continue
		}
		switch strings.ToUpper(f.Type) {
		case "REQUEST":
			fe.Model = ""
			p.prompt(fe, f.Content)
		case "RESPONSE":
			p.reply(fe, f.Content)
		case "THINK":
			p.reply(fe, "[reasoning] "+f.Content)
		case "SEARCH":
			var hits []string
			for j, r := range f.Results {
				if j >= 20 {
					break
				}
				hits = append(hits, strings.TrimSpace(r.Title+" "+r.URL))
			}
			detail := f.Content
			if len(hits) > 0 {
				detail = strings.TrimSpace(detail + " results: " + strings.Join(hits, "; "))
			}
			p.toolCall(fe, "search", "", detail)
		default:
			p.meta(fe, ev.Result, fmt.Sprintf("fragment %s: %s", trim(f.Type, 30), f.Content))
		}
	}
	var files []struct {
		ID       string `json:"id"`
		FileName string `json:"file_name"`
		Name     string `json:"name"`
	}
	if json.Unmarshal(m.Files, &files) == nil {
		for i, f := range files {
			if i >= maxAttachments {
				break
			}
			name := f.FileName
			if name == "" {
				name = f.Name
			}
			p.attachment(ev, name, f.ID, "")
		}
	}
}

// ---- small JSON helpers ----

func strOK(raw json.RawMessage) (string, bool) {
	var s string
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, &s) != nil {
		return "", false
	}
	return s, true
}

func str(raw json.RawMessage) string {
	s, _ := strOK(raw)
	return s
}

func num(raw json.RawMessage) (float64, bool) {
	var f float64
	if len(raw) == 0 || string(raw) == "null" || json.Unmarshal(raw, &f) != nil {
		return 0, false
	}
	return f, true
}

func firstString(m map[string]member, keys ...string) string {
	for _, k := range keys {
		if s := str(m[k].Raw); s != "" {
			return s
		}
	}
	return ""
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
