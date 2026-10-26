package detect

import (
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/schema"
)

func TestBrowserShareLinkRuleFiresOncePerShareSession(t *testing.T) {
	share := schema.Event{Product: "browser", EventType: schema.EventSessionMeta, Action: "browser_session", Result: "share",
		SessionID: "web:chatgpt:share:abc", Summary: `ChatGPT share "x" visited 2 time(s) at … (chrome/Default) — browser history proves visits, not conversation content`,
		SourcePath: "Library/Application Support/Google/Chrome/Default/History", SourceArtifact: "aaaa", Timestamp: "2026-10-20T10:00:00Z"}
	visit := share
	visit.Action = "browser_visit"
	conv := share
	conv.Result = "conversation"
	// A transcript that merely mentions a share URL is not browser history.
	transcript := schema.Event{Product: "claude-code", EventType: schema.EventSessionMeta, Action: "browser_session", Result: "share"}

	res := &schema.Normalized{Events: []schema.Event{share, visit, visit, conv, transcript}}
	got := browserShareLinks(res)
	if len(got) != 1 {
		t.Fatalf("findings = %d, want 1: %+v", len(got), got)
	}
	f := got[0]
	if f.RuleID != "AI_WEB_SHARE_LINK_VISITED" || f.Severity != "LOW" || f.Status != schema.StateObserved || f.Timestamp != share.Timestamp || f.SessionID != share.SessionID {
		t.Fatalf("finding = %+v", f)
	}
	if want := `The browser recorded a visit to a public share link of an AI conversation (ChatGPT share "x" visited 2 time(s) at … (chrome/Default)).`; f.Description[:len(want)] != want {
		t.Fatalf("description = %s", f.Description)
	}
	// The per-event path the streaming detector uses agrees.
	n := 0
	for _, ev := range res.Events {
		if _, ok := browserShareOne(ev); ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("stream path fired %d times", n)
	}
}

func TestBrowserEventsAreNotPerArtifactIntegritySubjects(t *testing.T) {
	a := schema.Event{Product: "browser", SessionID: "web:a", SourceArtifact: "h", Timestamp: "2026-10-20T10:00:00Z"}
	b := schema.Event{Product: "browser", SessionID: "web:b", SourceArtifact: "h", Timestamp: "2026-10-19T10:00:00Z"}
	idx1 := schema.Event{Product: "continue", Result: "session_index", SessionID: "s1", SourceArtifact: "i"}
	idx2 := schema.Event{Product: "continue", Result: "session_index", SessionID: "s2", SourceArtifact: "i"}
	res := &schema.Normalized{Events: []schema.Event{a, b, idx1, idx2}}
	if f := identityMismatch(res); len(f) != 0 {
		t.Fatalf("identity mismatch on a multi-session store: %+v", f)
	}
	if f := sessionTampering(res); len(f) != 0 {
		t.Fatalf("tampering on browser history order: %+v", f)
	}
}
