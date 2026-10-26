package aiexport

import (
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/schema"
	"github.com/efij/AgentDFIR/v5/internal/toolargs"
)

// Claude.ai exports a flat, already-linearized message list per
// conversation:
//
//	{"uuid", "name", "created_at", "chat_messages": [
//	    {"uuid", "sender": "human|assistant", "text", "created_at",
//	     "content": [{"type": "text|thinking|tool_use|tool_result", ...}],
//	     "attachments": [{"file_name", "file_type", "extracted_content"}],
//	     "files": [{"file_name"}]}]}
//
// Older exports carry only "text"; newer ones carry content blocks, and
// then the blocks are read and "text" (a flattened copy) is not.

type claudeMessage struct {
	UUID        string            `json:"uuid"`
	Sender      string            `json:"sender"`
	Text        string            `json:"text"`
	CreatedAt   string            `json:"created_at"`
	Content     []json.RawMessage `json:"content"`
	Attachments []struct {
		FileName string `json:"file_name"`
		FileType string `json:"file_type"`
	} `json:"attachments"`
	Files []struct {
		FileName string `json:"file_name"`
		FileUUID string `json:"file_uuid"`
		UUID     string `json:"uuid"`
	} `json:"files"`
}

type claudeBlock struct {
	Type      string          `json:"type"`
	Text      string          `json:"text"`
	Thinking  string          `json:"thinking"`
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Input     json.RawMessage `json:"input"`
	ToolUseID string          `json:"tool_use_id"`
	Content   json.RawMessage `json:"content"`
	IsError   bool            `json:"is_error"`
	Start     string          `json:"start_timestamp"`
}

func (p *parser) parseClaudeConversations(r io.Reader) error {
	err := walkArray(r, MaxElementBytes, func(el element) error {
		p.claudeConversation(el)
		return nil
	})
	if we, ok := err.(*walkError); ok {
		p.gap("", we.Offset, we.Line, pointer(we.Index), "conversations array: "+we.Error())
		return nil
	}
	return err
}

func (p *parser) claudeConversation(el element) {
	conv := map[string]member{}
	if _, err := membersOf(el.Raw, 4096, func(m member) { conv[m.Key] = m }); err != nil {
		p.gap("", el.Offset, el.Line, pointer(el.Index), "conversation is not a JSON object")
		return
	}
	sid := firstString(conv, "uuid", "id")
	if sid == "" {
		sid = fmt.Sprintf("%s-conv-%d", shortID(p.art.ArtifactID), el.Index)
	}
	title := str(conv["name"].Raw)
	p.describeSession(sid, map[string]string{"title": title, "conversation_id": sid,
		"summary": str(conv["summary"].Raw), "project_uuid": str(conv["project_uuid"].Raw)})
	head := p.base(sid)
	at(&head, el.Offset, el.Line, pointer(el.Index))
	isoTime(&head, "created_at", str(conv["created_at"].Raw))

	cm, ok := conv["chat_messages"]
	if !ok {
		p.gap(sid, el.Offset, el.Line, pointer(el.Index), "conversation has no chat_messages")
		return
	}
	var msgs []member
	truncated, err := membersOf(cm.Raw, maxMessages, func(m member) { msgs = append(msgs, m) })
	if err != nil {
		p.gap(sid, el.Offset+cm.RelOff, lineOf(el.Raw, el.Line, cm.RelOff), pointer(el.Index, "chat_messages"), "chat_messages is not an array")
		return
	}
	p.meta(head, "export:conversation", fmt.Sprintf("conversation %q (%d messages)", title, len(msgs)))
	if truncated {
		p.gap(sid, el.Offset+cm.RelOff, lineOf(el.Raw, el.Line, cm.RelOff), pointer(el.Index, "chat_messages"),
			fmt.Sprintf("more than %d messages; the rest are preserved unparsed", maxMessages))
	}
	for _, m := range msgs {
		rel := cm.RelOff + m.RelOff
		off, line, ptr := el.Offset+rel, lineOf(el.Raw, el.Line, rel), pointer(el.Index, "chat_messages", m.Index)
		var msg claudeMessage
		if json.Unmarshal(m.Raw, &msg) != nil {
			p.gap(sid, off, line, ptr, "chat message is not a message object")
			continue
		}
		ev := p.base(sid)
		ev.Result = resultActive
		at(&ev, off, line, ptr)
		isoTime(&ev, "created_at", msg.CreatedAt)
		human := msg.Sender == "human" || msg.Sender == "user"
		emitted := false
		for i, raw := range msg.Content {
			if i >= maxBlocks {
				break
			}
			be := ev
			be.SourceJSONPath = fmt.Sprintf("%s/content/%d", ptr, i)
			var b claudeBlock
			if json.Unmarshal(raw, &b) != nil {
				p.gap(sid, off, line, be.SourceJSONPath, "content block is not an object")
				continue
			}
			if b.Start != "" {
				isoTime(&be, "start_timestamp", b.Start)
			}
			switch b.Type {
			case "text":
				if b.Text == "" {
					continue
				}
				if human {
					p.prompt(be, b.Text)
				} else {
					p.reply(be, b.Text)
				}
			case "thinking":
				p.reply(be, "[reasoning] "+b.Thinking)
			case "tool_use":
				toolargs.Apply(&be, b.Input)
				p.toolCall(be, b.Name, b.ID, compactJSON(b.Input))
			case "tool_result":
				be.ResultDigest = toolargs.Digest(b.Content)
				be.ResultStatus = "ok"
				if b.IsError {
					be.ResultStatus = "error"
				}
				p.toolResult(be, b.Name, b.ToolUseID, blockText(b.Content))
			default:
				p.meta(be, resultActive, "content block "+trim(b.Type, 40))
			}
			emitted = true
		}
		if !emitted {
			switch {
			case msg.Text == "":
				p.meta(ev, resultActive, "empty "+trim(msg.Sender, 20)+" message")
			case human:
				p.prompt(ev, msg.Text)
			default:
				p.reply(ev, msg.Text)
			}
		}
		for i, a := range msg.Attachments {
			if i >= maxAttachments {
				break
			}
			p.attachment(ev, a.FileName, "", a.FileType)
		}
		for i, f := range msg.Files {
			if i >= maxAttachments {
				break
			}
			id := f.FileUUID
			if id == "" {
				id = f.UUID
			}
			p.attachment(ev, f.FileName, id, "file")
		}
	}
}

// parseClaudeProjects lists projects and their knowledge documents by
// name. Document content stays in the sealed artifact (and is covered by
// the content rules, which scan the raw file).
func (p *parser) parseClaudeProjects(r io.Reader) error {
	err := walkArray(r, MaxElementBytes, func(el element) error {
		var pr struct {
			UUID           string `json:"uuid"`
			Name           string `json:"name"`
			Description    string `json:"description"`
			CreatedAt      string `json:"created_at"`
			PromptTemplate string `json:"prompt_template"`
			Docs           []struct {
				UUID      string `json:"uuid"`
				Filename  string `json:"filename"`
				CreatedAt string `json:"created_at"`
			} `json:"docs"`
		}
		if json.Unmarshal(el.Raw, &pr) != nil {
			p.gap("", el.Offset, el.Line, pointer(el.Index), "project is not a project object")
			return nil
		}
		sid := "project:" + pr.UUID
		if pr.UUID == "" {
			sid = fmt.Sprintf("project:%s-%d", shortID(p.art.ArtifactID), el.Index)
		}
		p.describeSession(sid, map[string]string{"title": pr.Name, "project_uuid": pr.UUID, "description": pr.Description})
		ev := p.base(sid)
		at(&ev, el.Offset, el.Line, pointer(el.Index))
		isoTime(&ev, "created_at", pr.CreatedAt)
		s := fmt.Sprintf("project %q: %d knowledge document(s)", pr.Name, len(pr.Docs))
		if strings.TrimSpace(pr.PromptTemplate) != "" {
			s += "; project instructions present"
		}
		p.meta(ev, "export:project", s)
		for i, d := range pr.Docs {
			if i >= maxAttachments {
				break
			}
			de := ev
			de.SourceJSONPath = pointer(el.Index, "docs", i)
			isoTime(&de, "created_at", d.CreatedAt)
			p.attachment(de, d.Filename, d.UUID, "project document")
		}
		return nil
	})
	if we, ok := err.(*walkError); ok {
		p.gap("", we.Offset, we.Line, pointer(we.Index), "projects array: "+we.Error())
		return nil
	}
	return err
}

// parseAccount reads the account record(s): ChatGPT user.json (one object)
// or Claude.ai users.json (an array). They tie the export to an account.
func (p *parser) parseAccount(r io.Reader) error {
	data, err := io.ReadAll(io.LimitReader(r, MaxElementBytes+1))
	if err != nil {
		return err
	}
	sid := p.det.Service + "-account"
	one := func(raw json.RawMessage, ptr string) {
		var a struct {
			ID       string `json:"id"`
			UUID     string `json:"uuid"`
			Email    string `json:"email"`
			EmailAdr string `json:"email_address"`
			FullName string `json:"full_name"`
			Plus     *bool  `json:"chatgpt_plus_user"`
		}
		if json.Unmarshal(raw, &a) != nil {
			p.gap(sid, 0, 1, ptr, "account record is not an object")
			return
		}
		id, email := a.ID, a.Email
		if id == "" {
			id = a.UUID
		}
		if email == "" {
			email = a.EmailAdr
		}
		user := "user:" + p.det.Service + ":" + id
		attrs := map[string]string{"service": p.det.Service, "account_id": id, "evidence_class": evidenceClass}
		if email != "" {
			attrs["email"] = email
		}
		if a.FullName != "" {
			attrs["name"] = a.FullName
		}
		if a.Plus != nil {
			attrs["paid_plan"] = strconv.FormatBool(*a.Plus)
		}
		label := email
		if label == "" {
			label = id
		}
		p.addEntity(schema.Entity{EntityID: user, Kind: "user", Label: label, Product: p.det.Product(), Attributes: attrs})
		ev := p.base(sid)
		at(&ev, 0, 1, ptr)
		s := "account record: id " + id
		if email != "" {
			s += ", email " + email
		}
		p.meta(ev, "export:account", s)
	}
	if len(data) > MaxElementBytes {
		p.gap(sid, 0, 1, "", fmt.Sprintf("account file exceeds %d bytes; preserved unparsed", MaxElementBytes))
		return nil
	}
	var arr []json.RawMessage
	if json.Unmarshal(data, &arr) == nil {
		for i, raw := range arr {
			if i >= maxAttachments {
				break
			}
			one(raw, pointer(i))
		}
		return nil
	}
	one(data, "")
	return nil
}

// parseFeedback reads ChatGPT message_feedback.json: thumbs up/down and
// comments the user gave, attached to the conversation they refer to.
func (p *parser) parseFeedback(r io.Reader) error {
	err := walkArray(r, MaxElementBytes, func(el element) error {
		var f struct {
			ConversationID string          `json:"conversation_id"`
			Rating         string          `json:"rating"`
			CreateTime     json.RawMessage `json:"create_time"`
			Content        json.RawMessage `json:"content"`
		}
		if json.Unmarshal(el.Raw, &f) != nil {
			p.gap("", el.Offset, el.Line, pointer(el.Index), "feedback record is not an object")
			return nil
		}
		ev := p.base(f.ConversationID)
		at(&ev, el.Offset, el.Line, pointer(el.Index))
		if v, ok := num(f.CreateTime); ok {
			epochTime(&ev, "create_time", v)
		} else {
			isoTime(&ev, "create_time", str(f.CreateTime))
		}
		s := "message feedback: rating " + f.Rating
		if c := blockText(f.Content); c != "" && c != "{}" {
			s += ": " + c
		}
		p.meta(ev, "export:feedback", s)
		return nil
	})
	if we, ok := err.(*walkError); ok {
		p.gap("", we.Offset, we.Line, pointer(we.Index), "feedback array: "+we.Error())
		return nil
	}
	return err
}

// parseShared reads ChatGPT shared_conversations.json: conversations the
// user published as a share link — a data-exposure fact in its own right.
func (p *parser) parseShared(r io.Reader) error {
	err := walkArray(r, MaxElementBytes, func(el element) error {
		var s struct {
			ID             string `json:"id"`
			ConversationID string `json:"conversation_id"`
			Title          string `json:"title"`
			IsAnonymous    *bool  `json:"is_anonymous"`
		}
		if json.Unmarshal(el.Raw, &s) != nil {
			p.gap("", el.Offset, el.Line, pointer(el.Index), "shared-conversation record is not an object")
			return nil
		}
		ev := p.base(s.ConversationID)
		at(&ev, el.Offset, el.Line, pointer(el.Index))
		anon := "unknown"
		if s.IsAnonymous != nil {
			anon = strconv.FormatBool(*s.IsAnonymous)
		}
		p.meta(ev, "export:shared", fmt.Sprintf("conversation shared by link (share id %s, anonymous %s): %s", s.ID, anon, s.Title))
		return nil
	})
	if we, ok := err.(*walkError); ok {
		p.gap("", we.Offset, we.Line, pointer(we.Index), "shared conversations array: "+we.Error())
		return nil
	}
	return err
}

// compactJSON renders tool input for a summary.
func compactJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return string(raw)
	}
	b, _ := json.Marshal(v)
	return string(b)
}

// blockText flattens a string, or an array of {"type":"text","text":…}
// blocks, to text.
func blockText(raw json.RawMessage) string {
	if s, ok := strOK(raw); ok {
		return s
	}
	var blocks []struct {
		Text string `json:"text"`
	}
	if json.Unmarshal(raw, &blocks) == nil {
		var b []string
		for _, x := range blocks {
			if x.Text != "" {
				b = append(b, x.Text)
			}
		}
		return strings.Join(b, "\n")
	}
	return compactJSON(raw)
}
