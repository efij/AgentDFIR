package detect

import (
	"fmt"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// Browser-history rules. History is opt-in evidence (--include-browser)
// and proves visits, not content, so these rules stay low and say only
// what a visit shows. Nothing here links a visit to agent activity by
// time: proximity is not causality.

// browserProduct is the product id the browser-history parser stamps.
const browserProduct = "browser"

// AI_WEB_SHARE_LINK_VISITED — the browser recorded a visit to a public
// share link of an AI conversation (ChatGPT /share/, Claude /share/,
// Gemini /share/, Poe /s/, …). One finding per share link: the parser's
// browser_session summary event carries the whole group.
func browserShareLinks(res *schema.Normalized) []schema.Finding {
	var out []schema.Finding
	for _, ev := range res.Events {
		if f, ok := browserShareOne(ev); ok {
			out = append(out, f)
		}
	}
	return out
}

func browserShareOne(ev schema.Event) (schema.Finding, bool) {
	if ev.Product != browserProduct || ev.Action != "browser_session" || ev.Result != "share" {
		return schema.Finding{}, false
	}
	return schema.Finding{
		RuleID: "AI_WEB_SHARE_LINK_VISITED", Severity: "LOW",
		Title: "AI Conversation Share Link in Browser History",
		Description: fmt.Sprintf("The browser recorded a visit to a public share link of an AI conversation (%s). A share link makes a conversation readable by anyone holding the URL; history shows the link was opened, not who created it or what the conversation contained.",
			strings.TrimSpace(firstClause(ev.Summary))),
		SessionID: ev.SessionID, EvidenceRefs: []string{ref(ev)}, Timestamp: ev.Timestamp,
		Status: schema.StateObserved, Endpoint: schema.StateUnknown,
		Related:       []string{"evidence class: browser-history (visit only, no content)"},
		FalsePositive: "Opening a link someone else shared looks the same as viewing one's own share. Ask the provider (or the account's shared-links page) whether this account created it.",
	}, true
}

// firstClause cuts a session summary at its evidence disclaimer.
func firstClause(s string) string {
	if i := strings.Index(s, " — "); i > 0 {
		return s[:i]
	}
	return s
}
