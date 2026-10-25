package browser

import (
	"net/url"
	"regexp"
	"strings"
)

// Page kinds a visit is classified into. A conversation or share ID is
// only ever taken from the URL itself; nothing is inferred.
const (
	KindConversation = "conversation" // one chat thread (ChatGPT /c/<id>, Claude /chat/<uuid>, …)
	KindShare        = "share"        // a public share link of a conversation
	KindGPT          = "gpt"          // a custom GPT / Gem / bot page
	KindProject      = "project"      // project / space / notebook container
	KindPage         = "page"         // a published page (Perplexity Pages)
	KindPlayground   = "playground"   // API playground / workbench
	KindConsole      = "console"      // API console: keys, billing, usage
	KindSettings     = "settings"     // account settings of a consumer service
	KindApp          = "app"          // the service, no conversation in the URL
)

// Service is one AI service the parser recognizes in browser history.
type Service struct {
	Key   string // stable id used in session ids and events ("chatgpt")
	Name  string // display name ("ChatGPT")
	Hosts []string
	// PathPrefix, when set, restricts the service to URLs under it on the
	// listed hosts (huggingface.co/chat, x.com/i/grok).
	PathPrefix string
	Routes     []route
}

// route maps a URL path to a page kind. ID is the capture group holding
// the conversation/share/object id (0 = none). Query, when set, takes the
// id from that query parameter instead.
type route struct {
	re    *regexp.Regexp
	kind  string
	id    int
	query string
}

func r(pattern, kind string, id int) route {
	return route{re: regexp.MustCompile(pattern), kind: kind, id: id}
}

// Services is the maintained table of AI-service URLs. Hosts match
// exactly or as a dot-separated suffix (www.perplexity.ai matches
// perplexity.ai); "chatgpt.com.evil.example" matches nothing. Routes are
// tried in order; the first match wins and an unmatched path on a listed
// host is KindApp.
//
// Adding a service: append an entry, add a URL to the table test, and say
// in docs/browser-ai-sessions.md what its URLs prove.
var Services = []Service{
	{Key: "chatgpt", Name: "ChatGPT", Hosts: []string{"chatgpt.com", "chat.openai.com"}, Routes: []route{
		r(`^/g/[^/]+/c/([A-Za-z0-9-]+)`, KindConversation, 1),
		r(`^/c/([A-Za-z0-9-]+)`, KindConversation, 1),
		r(`^/share/(?:e/)?([A-Za-z0-9-]+)`, KindShare, 1),
		r(`^/g/(g-p-[A-Za-z0-9-]+)/project`, KindProject, 1),
		r(`^/g/([A-Za-z0-9-]+)`, KindGPT, 1),
		r(`^/settings`, KindSettings, 0),
	}},
	{Key: "claude", Name: "Claude", Hosts: []string{"claude.ai"}, Routes: []route{
		r(`^/chat/([0-9A-Fa-f-]{8,})`, KindConversation, 1),
		r(`^/share/([0-9A-Fa-f-]{8,})`, KindShare, 1),
		r(`^/project/([0-9A-Fa-f-]{8,})`, KindProject, 1),
		r(`^/settings`, KindSettings, 0),
	}},
	{Key: "gemini", Name: "Gemini", Hosts: []string{"gemini.google.com"}, Routes: []route{
		r(`^/(?:u/\d+/)?app/([0-9A-Fa-f]{6,})`, KindConversation, 1),
		r(`^/(?:u/\d+/)?gem/([^/?#]+)(?:/([0-9A-Fa-f]{6,}))?`, KindGPT, 1),
		r(`^/(?:u/\d+/)?share/([0-9A-Za-z]+)`, KindShare, 1),
	}},
	{Key: "gemini", Name: "Gemini", Hosts: []string{"g.co"}, PathPrefix: "/gemini/share/", Routes: []route{
		r(`^/gemini/share/([0-9A-Za-z]+)`, KindShare, 1),
	}},
	{Key: "copilot", Name: "Microsoft Copilot", Hosts: []string{"copilot.microsoft.com"}, Routes: []route{
		r(`^/chats/([A-Za-z0-9_-]+)`, KindConversation, 1),
		r(`^/shares/([A-Za-z0-9_-]+)`, KindShare, 1),
	}},
	{Key: "m365-copilot", Name: "Microsoft 365 Copilot", Hosts: []string{"m365.cloud.microsoft"}, PathPrefix: "/chat", Routes: nil},
	{Key: "m365-copilot", Name: "Microsoft 365 Copilot", Hosts: []string{"copilot.cloud.microsoft"}, Routes: nil},
	{Key: "perplexity", Name: "Perplexity", Hosts: []string{"perplexity.ai"}, Routes: []route{
		r(`^/search/([^/?#]+)`, KindConversation, 1),
		r(`^/page/([^/?#]+)`, KindPage, 1),
		r(`^/spaces/([^/?#]+)`, KindProject, 1),
		r(`^/settings`, KindSettings, 0),
	}},
	{Key: "deepseek", Name: "DeepSeek", Hosts: []string{"chat.deepseek.com"}, Routes: []route{
		r(`^/a/chat/s/([A-Za-z0-9-]+)`, KindConversation, 1),
		r(`^/share/([A-Za-z0-9-]+)`, KindShare, 1),
	}},
	{Key: "grok", Name: "Grok", Hosts: []string{"grok.com"}, Routes: []route{
		r(`^/chat/([A-Za-z0-9-]+)`, KindConversation, 1),
		r(`^/share/([^/?#]+)`, KindShare, 1),
		r(`^/project/([A-Za-z0-9-]+)`, KindProject, 1),
	}},
	{Key: "grok", Name: "Grok", Hosts: []string{"x.com", "twitter.com"}, PathPrefix: "/i/grok", Routes: []route{
		r(`^/i/grok/share/([^/?#]+)`, KindShare, 1),
		{re: regexp.MustCompile(`^/i/grok`), kind: KindConversation, query: "conversation"},
	}},
	{Key: "mistral", Name: "Le Chat (Mistral)", Hosts: []string{"chat.mistral.ai"}, Routes: []route{
		r(`^/chat/([0-9A-Fa-f-]{8,})`, KindConversation, 1),
	}},
	{Key: "poe", Name: "Poe", Hosts: []string{"poe.com"}, Routes: []route{
		r(`^/chat/([A-Za-z0-9]+)`, KindConversation, 1),
		r(`^/s/([A-Za-z0-9]+)`, KindShare, 1),
	}},
	{Key: "huggingchat", Name: "HuggingChat", Hosts: []string{"huggingface.co"}, PathPrefix: "/chat", Routes: []route{
		r(`^/chat/conversation/([0-9A-Fa-f]+)`, KindConversation, 1),
		r(`^/chat/r/([A-Za-z0-9_-]+)`, KindShare, 1),
		r(`^/chat/assistant/([0-9A-Fa-f]+)`, KindGPT, 1),
	}},
	{Key: "meta-ai", Name: "Meta AI", Hosts: []string{"meta.ai"}, Routes: []route{
		r(`^/(?:c|prompt)/([A-Za-z0-9_-]+)`, KindConversation, 1),
	}},
	{Key: "character-ai", Name: "Character.AI", Hosts: []string{"character.ai"}, Routes: []route{
		r(`^/chat/([A-Za-z0-9_-]+)`, KindConversation, 1),
	}},
	{Key: "notebooklm", Name: "NotebookLM", Hosts: []string{"notebooklm.google.com"}, Routes: []route{
		r(`^/notebook/([0-9A-Fa-f-]{8,})`, KindProject, 1),
	}},
	{Key: "aistudio", Name: "Google AI Studio", Hosts: []string{"aistudio.google.com"}, Routes: []route{
		r(`^/(?:app/)?prompts/([A-Za-z0-9_-]{6,})`, KindConversation, 1),
		r(`^/(?:app/)?apikey`, KindConsole, 0),
	}},
	{Key: "openai-platform", Name: "OpenAI Platform", Hosts: []string{"platform.openai.com"}, Routes: []route{
		r(`^/playground`, KindPlayground, 0),
		r(`^/(?:api-keys|settings|account|usage|organization)`, KindConsole, 0),
	}},
	{Key: "anthropic-console", Name: "Anthropic Console", Hosts: []string{"console.anthropic.com", "platform.claude.com"}, Routes: []route{
		r(`^/workbench(?:/([0-9A-Fa-f-]{8,}))?`, KindPlayground, 1),
		r(`^/(?:settings|account|usage|cost)`, KindConsole, 0),
	}},
}

// Visit classification: the service, the kind of page and the id the URL
// carries ("" when it carries none).
type Match struct {
	Service *Service
	Kind    string
	ID      string
}

// maxURL bounds what is classified; longer values are not AI-service
// page URLs and are not worth a regex walk.
const maxURL = 8 << 10

// Classify returns the AI service a URL belongs to, or nil. Only http(s)
// URLs are considered.
func Classify(raw string) *Match {
	if len(raw) > maxURL {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "https" && u.Scheme != "http") {
		return nil
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if host == "" {
		return nil
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	for i := range Services {
		s := &Services[i]
		if !hostMatches(host, s.Hosts) {
			continue
		}
		if s.PathPrefix != "" && !strings.HasPrefix(path, s.PathPrefix) {
			continue
		}
		for _, rt := range s.Routes {
			m := rt.re.FindStringSubmatch(path)
			if m == nil {
				continue
			}
			id := ""
			switch {
			case rt.query != "":
				id = u.Query().Get(rt.query)
				if !safeID(id) {
					id = ""
				}
			case rt.id > 0 && rt.id < len(m):
				id = m[rt.id]
			}
			kind := rt.kind
			if kind == KindConversation && id == "" {
				kind = KindApp
			}
			return &Match{Service: s, Kind: kind, ID: id}
		}
		return &Match{Service: s, Kind: KindApp}
	}
	return nil
}

func hostMatches(host string, hosts []string) bool {
	for _, h := range hosts {
		if host == h || strings.HasSuffix(host, "."+h) {
			return true
		}
	}
	return false
}

// safeID accepts query-parameter ids made of URL-safe id characters only.
func safeID(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}
