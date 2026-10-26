package suite

import (
	"regexp"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/parsers/browser"
)

// AIApp is one AI assistant application a forensic suite may name as the
// source of a record (a UFDR model's "Source" field, an AXIOM artifact
// name, a prefetch executable).
//
// This is the one list of AI applications the suite readers match on.
// URLs are classified by the browser parser's service table
// (browser.Classify), so a web address is recognized the same way in
// browser history, a UFDR VisitedPage, an AXIOM CSV row and a Plaso line.
// Keys match the browser service keys where both exist.
type AIApp struct {
	Key   string
	Name  string
	Names []string // lower-case names and aliases, matched as whole words
	IDs   []string // lower-case app / package ids, matched exactly or as a prefix
}

// AIApps is the maintained list. Adding an app: append it here, add a
// row to the match test, and list it in docs/forensic-suite-interop.md.
var AIApps = []AIApp{
	{Key: "chatgpt", Name: "ChatGPT", Names: []string{"chatgpt", "chat gpt", "openai chatgpt"}, IDs: []string{"com.openai.chatgpt", "com.openai.chat"}},
	{Key: "claude", Name: "Claude", Names: []string{"claude", "claude ai", "claude by anthropic"}, IDs: []string{"com.anthropic.claude", "com.anthropic.claudefordesktop"}},
	{Key: "gemini", Name: "Gemini", Names: []string{"gemini", "google gemini", "bard"}, IDs: []string{"com.google.android.apps.bard"}},
	{Key: "copilot", Name: "Microsoft Copilot", Names: []string{"copilot", "microsoft copilot", "bing chat"}, IDs: []string{"com.microsoft.copilot"}},
	{Key: "perplexity", Name: "Perplexity", Names: []string{"perplexity", "perplexity ai"}, IDs: []string{"ai.perplexity.app"}},
	{Key: "deepseek", Name: "DeepSeek", Names: []string{"deepseek"}, IDs: []string{"com.deepseek.chat"}},
	{Key: "grok", Name: "Grok", Names: []string{"grok"}, IDs: []string{"ai.x.grok"}},
	{Key: "character-ai", Name: "Character.AI", Names: []string{"character.ai", "character ai", "characterai"}, IDs: []string{"ai.character.app"}},
	{Key: "poe", Name: "Poe", Names: []string{"poe"}, IDs: []string{"com.poe.android", "com.quora.poe"}},
	{Key: "meta-ai", Name: "Meta AI", Names: []string{"meta ai"}, IDs: []string{"com.facebook.stella"}},
	{Key: "mistral", Name: "Le Chat (Mistral)", Names: []string{"le chat", "mistral", "mistral ai"}, IDs: []string{"ai.mistral.chat"}},
}

// agentPathMarkers are path fragments of AI agent and assistant data
// directories. A file-listing row (Autopsy, Plaso fs entries) whose path
// holds one is reported; other rows are only counted.
var agentPathMarkers = []string{
	"/.claude/", "/.claude.json", "/.codex/", "/.cursor/", "/.gemini/", "/.continue/", "/.aider",
	"/appdata/roaming/claude/", "/application support/claude/", "/.config/claude/",
	"/appdata/roaming/chatgpt/", "/application support/com.openai.chat/",
	"/com.openai.chatgpt/", "/com.anthropic.claude/",
}

var wordRe = regexp.MustCompile(`[a-z0-9.]+`)

// MatchApp returns the AI application a source/app name names, or nil.
// The value matches when it is an app id (or starts with one followed by
// '.' or ':'), or when an app name occurs in it as whole words.
func MatchApp(s string) *AIApp {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" || len(s) > 256 {
		return nil
	}
	for i := range AIApps {
		for _, id := range AIApps[i].IDs {
			if s == id || strings.HasPrefix(s, id+".") || strings.HasPrefix(s, id+":") {
				return &AIApps[i]
			}
		}
	}
	words := " " + strings.Join(wordRe.FindAllString(s, 64), " ") + " "
	for i := range AIApps {
		for _, n := range AIApps[i].Names {
			if strings.Contains(words, " "+n+" ") {
				return &AIApps[i]
			}
		}
	}
	return nil
}

// URLMatch is an AI-service URL found in a record.
type URLMatch struct {
	URL   string
	Key   string // browser service key
	Name  string
	Kind  string // conversation, share, app …
	ID    string // conversation/share id carried by the URL
	Field string // the column / field it was found in
}

var urlRe = regexp.MustCompile(`https?://[^\s"'<>\]\[]+`)

// maxURLsPerValue bounds how many URLs one value is searched for.
const maxURLsPerValue = 8

// FindAIURL returns the first AI-service URL in s, or nil.
func FindAIURL(s string) *URLMatch {
	if !strings.Contains(s, "http") {
		return nil
	}
	for _, u := range urlRe.FindAllString(s, maxURLsPerValue) {
		u = strings.TrimRight(u, ".,);")
		if m := browser.Classify(u); m != nil {
			return &URLMatch{URL: u, Key: m.Service.Key, Name: m.Service.Name, Kind: m.Kind, ID: m.ID}
		}
	}
	return nil
}

// agentPath reports whether a file path lies in an AI agent / assistant
// data directory.
func agentPath(p string) bool {
	l := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	for _, m := range agentPathMarkers {
		if strings.Contains(l, m) {
			return true
		}
	}
	return false
}
