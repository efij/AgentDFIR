package genericchat

import (
	"encoding/json"
	"sort"
	"strconv"
	"time"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/schema"
)

// parseExportConversations handles vendor account data exports
// (conversations.json). Two shapes:
//
//	Claude.ai:  [{"uuid","name","created_at","chat_messages":[{"uuid","sender":"human|assistant","text","created_at"}]}]
//	ChatGPT:    [{"title","create_time","mapping":{id:{"message":{"author":{"role"},"create_time","content":{"parts":[…]}}}}}]
//
// Exports are chat transcripts without tool telemetry, so events are
// human_prompt / model_response only; model text stays REPORTED.
func (p *parser) parseExportConversations(data []byte, art casepkg.ArtifactRecord, cfg *productCfg) error {
	var convs []map[string]json.RawMessage
	if err := json.Unmarshal(data, &convs); err != nil {
		p.gap(art, cfg, 0, 1, "conversations.json is not an array of conversations")
		return nil
	}
	for ci, c := range convs {
		id := jsonString(c["uuid"])
		if id == "" {
			id = jsonString(c["id"])
		}
		if id == "" {
			id = "conv-" + strconv.Itoa(ci+1)
		}
		// Claude.ai shape
		if raw, ok := c["chat_messages"]; ok {
			var msgs []struct {
				Sender    string `json:"sender"`
				Text      string `json:"text"`
				CreatedAt string `json:"created_at"`
			}
			if json.Unmarshal(raw, &msgs) == nil {
				for mi, m := range msgs {
					ev := p.base(art, cfg, id)
					ev.Timestamp = m.CreatedAt
					ev.Summary = trim(m.Text, 200)
					if m.Sender == "assistant" {
						ev.EventType, ev.ActorType, ev.Corroboration = schema.EventModelResponse, schema.ActorModel, schema.StateReported
					} else {
						ev.EventType, ev.ActorType, ev.Corroboration = schema.EventHumanPrompt, schema.ActorHuman, schema.StateObserved
					}
					ev.Result = "export"
					p.emit(ev, art, 0, ci*10000+mi+1)
				}
				continue
			}
		}
		// ChatGPT shape
		if raw, ok := c["mapping"]; ok {
			var mapping map[string]struct {
				Message *struct {
					Author struct {
						Role string `json:"role"`
					} `json:"author"`
					CreateTime float64 `json:"create_time"`
					Content    struct {
						Parts []json.RawMessage `json:"parts"`
					} `json:"content"`
				} `json:"message"`
			}
			if json.Unmarshal(raw, &mapping) != nil {
				p.gap(art, cfg, 0, ci+1, "unrecognized conversation mapping")
				continue
			}
			type node struct {
				t    float64
				role string
				text string
			}
			var nodes []node
			for _, n := range mapping {
				if n.Message == nil {
					continue
				}
				var text string
				for _, part := range n.Message.Content.Parts {
					var s string
					if json.Unmarshal(part, &s) == nil {
						text += s
					}
				}
				if text == "" {
					continue
				}
				nodes = append(nodes, node{n.Message.CreateTime, n.Message.Author.Role, text})
			}
			sort.Slice(nodes, func(i, j int) bool { return nodes[i].t < nodes[j].t })
			for mi, n := range nodes {
				ev := p.base(art, cfg, id)
				if n.t > 0 {
					ev.Timestamp = time.Unix(int64(n.t), int64((n.t-float64(int64(n.t)))*1e9)).UTC().Format(time.RFC3339)
				}
				ev.Summary = trim(n.text, 200)
				switch n.role {
				case "assistant":
					ev.EventType, ev.ActorType, ev.Corroboration = schema.EventModelResponse, schema.ActorModel, schema.StateReported
				case "user":
					ev.EventType, ev.ActorType, ev.Corroboration = schema.EventHumanPrompt, schema.ActorHuman, schema.StateObserved
				default: // system / tool
					ev.EventType, ev.ActorType, ev.Corroboration = schema.EventSessionMeta, schema.ActorSystem, schema.StateObserved
					ev.Result = "export:" + trim(n.role, 20)
				}
				if ev.Result == "" {
					ev.Result = "export"
				}
				p.emit(ev, art, 0, ci*10000+mi+1)
			}
			continue
		}
		p.gap(art, cfg, 0, ci+1, "conversation shape not recognized")
	}
	return nil
}

func jsonString(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	return ""
}
