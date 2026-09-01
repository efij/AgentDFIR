package genericchat

import (
	"encoding/json"
	"strings"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/schema"
)

// parseVSCodeChat handles VS Code Copilot Chat session files
// (workspaceStorage/<hash>/chatSessions/<uuid>.json):
//
//	{"requesterUsername":"…","requests":[{"message":{"text":"…"},
//	  "response":[{"value":"…"},…],"timestamp":…}]}
func (p *parser) parseVSCodeChat(data []byte, art casepkg.ArtifactRecord, cfg *productCfg, sessionID string) error {
	var doc struct {
		RequesterUsername string `json:"requesterUsername"`
		Requests          []struct {
			Message struct {
				Text string `json:"text"`
			} `json:"message"`
			Response  json.RawMessage `json:"response"`
			Timestamp int64           `json:"timestamp"`
		} `json:"requests"`
	}
	if err := json.Unmarshal(data, &doc); err != nil || doc.Requests == nil {
		p.gap(art, cfg, 0, 1, "unrecognized chat session shape; preserved unparsed")
		return nil
	}
	for i, req := range doc.Requests {
		ts := msToRFC3339(req.Timestamp)
		if txt := strings.TrimSpace(req.Message.Text); txt != "" {
			ev := p.base(art, cfg, sessionID)
			ev.Timestamp = ts
			ev.EventType = schema.EventHumanPrompt
			ev.ActorType = schema.ActorHuman
			ev.User = firstNonEmptyStr(doc.RequesterUsername, ev.User)
			ev.Summary = trim(txt, 200)
			ev.Corroboration = schema.StateObserved
			p.emit(ev, art, 0, i+1)
		}
		if txt := responseText(req.Response); txt != "" {
			ev := p.base(art, cfg, sessionID)
			ev.Timestamp = ts
			ev.EventType = schema.EventModelResponse
			ev.ActorType = schema.ActorModel
			ev.Summary = trim(txt, 200)
			ev.Corroboration = schema.StateReported // narrative, not proof
			p.emit(ev, art, 0, i+1)
		}
	}
	return nil
}

// responseText flattens the heterogeneous response array ([{value:…},
// {kind:…},…]) into text.
func responseText(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var items []struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(raw, &items); err != nil {
		return ""
	}
	var texts []string
	for _, it := range items {
		if strings.TrimSpace(it.Value) != "" {
			texts = append(texts, it.Value)
		}
	}
	return strings.Join(texts, "\n")
}

// parseAiderMarkdown handles .aider.chat.history.md. Aider's chat log is
// markdown: sessions open with "# aider chat started at <ts>", user
// input lines are prefixed "#### ", everything else is assistant
// narrative/output. Repo-local evidence — collected via --path <repo>.
func (p *parser) parseAiderMarkdown(data []byte, art casepkg.ArtifactRecord, cfg *productCfg) error {
	session := "aider"
	var offset int64
	lineNo := 0
	flushBlock := func(block []string, isUser bool, startOff int64, startLine int) {
		text := strings.TrimSpace(strings.Join(block, "\n"))
		if text == "" {
			return
		}
		ev := p.base(art, cfg, session)
		ev.Summary = trim(text, 200)
		if isUser {
			ev.EventType = schema.EventHumanPrompt
			ev.ActorType = schema.ActorHuman
			ev.Corroboration = schema.StateObserved
		} else {
			ev.EventType = schema.EventModelResponse
			ev.ActorType = schema.ActorModel
			ev.Corroboration = schema.StateReported
		}
		p.emit(ev, art, startOff, startLine)
	}

	var block []string
	blockUser := false
	blockOff := int64(0)
	blockLine := 1
	for _, line := range strings.Split(string(data), "\n") {
		lineNo++
		start := offset
		offset += int64(len(line)) + 1
		switch {
		case strings.HasPrefix(line, "# aider chat started at"):
			flushBlock(block, blockUser, blockOff, blockLine)
			block = nil
			session = "aider-" + sanitizeID(strings.TrimSpace(strings.TrimPrefix(line, "# aider chat started at")))
			ev := p.base(art, cfg, session)
			ev.EventType = schema.EventSessionMeta
			ev.ActorType = schema.ActorSystem
			ev.Result = "chat_started"
			ev.Summary = trim(line, 120)
			ev.Corroboration = schema.StateObserved
			p.emit(ev, art, start, lineNo)
		case strings.HasPrefix(line, "#### "):
			if !blockUser || len(block) == 0 {
				flushBlock(block, blockUser, blockOff, blockLine)
				block, blockUser, blockOff, blockLine = nil, true, start, lineNo
			}
			block = append(block, strings.TrimPrefix(line, "#### "))
		case strings.TrimSpace(line) == "":
			flushBlock(block, blockUser, blockOff, blockLine)
			block = nil
		default:
			if blockUser || len(block) == 0 {
				flushBlock(block, blockUser, blockOff, blockLine)
				block, blockUser, blockOff, blockLine = nil, false, start, lineNo
			}
			block = append(block, line)
		}
	}
	flushBlock(block, blockUser, blockOff, blockLine)
	return nil
}

// parseAiderInput handles .aider.input.history:
//
//	# 2026-08-30 10:00:00.000000
//	+run the deploy
func (p *parser) parseAiderInput(data []byte, art casepkg.ArtifactRecord, cfg *productCfg) error {
	var offset int64
	lineNo := 0
	ts := ""
	for _, line := range strings.Split(string(data), "\n") {
		lineNo++
		start := offset
		offset += int64(len(line)) + 1
		switch {
		case strings.HasPrefix(line, "# "):
			ts = strings.TrimSpace(strings.TrimPrefix(line, "# "))
		case strings.HasPrefix(line, "+"):
			ev := p.base(art, cfg, "aider-input")
			ev.Timestamp = ts
			ev.EventType = schema.EventHumanPrompt
			ev.ActorType = schema.ActorHuman
			ev.Summary = trim(strings.TrimPrefix(line, "+"), 200)
			ev.Corroboration = schema.StateObserved
			p.emit(ev, art, start, lineNo)
		}
	}
	return nil
}

func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

func firstNonEmptyStr(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
