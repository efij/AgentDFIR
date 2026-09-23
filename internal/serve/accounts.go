package serve

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"path"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/sanitize"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// ---- accounts ----
//
// Which AI login each piece of activity ran under. One person often has more
// than one — a work Claude seat and a personal ChatGPT plan, or two Claude
// config directories — and an analyst has to know which one a finding
// belongs to before they can act on it (rotate which key, ask which admin).
//
// The login is not on the events. It lives in the product's own settings in
// each profile directory (~/.claude.json, <CODEX_HOME>/auth.json), and every
// event names the file it came from, so an event's account is the account
// of the profile directory its transcript sits in. Only the identity is read
// out of those files — email, organisation, plan. Tokens and keys never
// leave this file.

// Account is one AI login found in the case.
type Account struct {
	Key     string `json:"key"`   // profile root, e.g. ".claude", ".codex", "cowork:<uuid>"
	Label   string `json:"label"` // what the UI prints
	Product string `json:"product"`
	Email   string `json:"email,omitempty"`
	Org     string `json:"org,omitempty"`
	Plan    string `json:"plan,omitempty"`
	Source  string `json:"source,omitempty"` // the collected file the identity was read from
	Known   bool   `json:"known"`            // false: activity found, login file not collected
	Events  int    `json:"events"`
}

// accountKey maps a logical evidence path to the profile it belongs to.
func accountKey(logical, product string) string {
	p := strings.TrimPrefix(logical, "/")
	if i := strings.Index(p, "local-agent-mode-sessions/"); i >= 0 {
		rest := p[i+len("local-agent-mode-sessions/"):]
		if j := strings.IndexByte(rest, '/'); j > 0 {
			return "cowork:" + rest[:j]
		}
	}
	seg := p
	if i := strings.IndexByte(p, '/'); i >= 0 {
		seg = p[:i]
	}
	if strings.HasPrefix(seg, ".") && seg != "." && seg != ".." {
		// ~/.claude.json belongs to ~/.claude, the default profile.
		if seg == ".claude.json" {
			return ".claude"
		}
		return seg
	}
	if product != "" {
		return product
	}
	return "unknown"
}

var productName = map[string]string{
	"claude-code": "Claude Code", "claude-cowork": "Claude desktop", "codex-cli": "Codex", "codex-app": "Codex app",
	"gemini-cli": "Gemini CLI", "cursor": "Cursor", "copilot-cli": "Copilot CLI", "copilot-chat": "Copilot Chat",
	"cline": "Cline", "roo": "Roo", "openclaw": "OpenClaw", "opencode": "OpenCode", "aider": "Aider", "warp": "Warp",
}

func prettyProduct(p string) string {
	if n := productName[p]; n != "" {
		return n
	}
	return p
}

// loadAccounts reads the identity out of every collected login file and
// counts the events each profile holds.
func (s *Server) loadAccounts() {
	accts := map[string]*Account{}
	claudeByUUID := map[string]*Account{}
	for _, a := range s.arts {
		base := path.Base(a.LogicalPath)
		switch {
		case base == ".claude.json" && a.Product != "claude-cowork":
			if acc := s.claudeAccount(a); acc != nil {
				accts[acc.Key] = acc
			}
		case base == "auth.json" && strings.HasPrefix(a.Product, "codex"):
			if acc := s.codexAccount(a); acc != nil {
				accts[acc.Key] = acc
			}
		}
	}
	for _, acc := range accts {
		if acc.Product == "claude-code" && acc.Source != "" {
			// accountUuid is kept on the struct only for the Cowork match below.
			if u := s.claudeUUID[acc.Key]; u != "" {
				claudeByUUID[u] = acc
			}
		}
	}
	s.acctOf = make([]string, s.idx.Len())
	for i, n := 0, s.idx.Len(); i < n; i++ {
		e := s.idx.At(i)
		k := accountKey(e.SourcePath, e.Product)
		s.acctOf[i] = k
		acc := accts[k]
		if acc == nil {
			acc = &Account{Key: k, Product: e.Product}
			if strings.HasPrefix(k, "cowork:") {
				// Cowork stores sessions under the Claude account's uuid, so
				// the desktop app's work lands on the same person when the
				// CLI's login file was collected too.
				if c := claudeByUUID[strings.TrimPrefix(k, "cowork:")]; c != nil {
					acc.Email, acc.Org, acc.Plan, acc.Source, acc.Known = c.Email, c.Org, c.Plan, c.Source, true
				}
			}
			acc.Label = labelFor(acc)
			accts[k] = acc
		}
		if acc.Product == "" {
			acc.Product = e.Product
			acc.Label = labelFor(acc)
		}
		acc.Events++
	}
	s.accounts = accts
}

func labelFor(a *Account) string {
	name := prettyProduct(a.Product)
	if a.Email != "" {
		l := name + " · " + a.Email
		if a.Org != "" {
			l += " (" + a.Org + ")"
		} else if a.Plan != "" {
			l += " (" + a.Plan + ")"
		}
		return l
	}
	if a.Plan != "" {
		return name + " · " + a.Plan
	}
	if strings.HasPrefix(a.Key, ".") {
		return name + " · profile ~/" + a.Key + " (login not recorded)"
	}
	return name + " (login not recorded)"
}

func (s *Server) claudeAccount(a casepkg.ArtifactRecord) *Account {
	b, err := s.store.ReadAll(a.ArtifactID, 8<<20)
	if err != nil {
		return nil
	}
	var cfg struct {
		OAuth struct {
			UUID    string `json:"accountUuid"`
			Email   string `json:"emailAddress"`
			Org     string `json:"organizationName"`
			Billing string `json:"billingType"`
			Seat    string `json:"seatTier"`
		} `json:"oauthAccount"`
	}
	if json.Unmarshal(b, &cfg) != nil {
		return nil
	}
	key := ".claude"
	if d := path.Dir(strings.TrimPrefix(a.LogicalPath, "/")); d != "." {
		key = accountKey(d+"/x", a.Product)
	}
	acc := &Account{Key: key, Product: "claude-code", Source: a.LogicalPath, Known: cfg.OAuth.Email != "",
		Email: sanitize.Terminal(cfg.OAuth.Email), Org: sanitize.Terminal(cfg.OAuth.Org), Plan: sanitize.Terminal(cfg.OAuth.Seat)}
	if s.claudeUUID == nil {
		s.claudeUUID = map[string]string{}
	}
	s.claudeUUID[key] = cfg.OAuth.UUID
	acc.Label = labelFor(acc)
	return acc
}

// codexAccount reads the email and plan out of the id_token's claims. The
// token is not verified — this is attribution, not authentication — and no
// token or key is kept.
func (s *Server) codexAccount(a casepkg.ArtifactRecord) *Account {
	b, err := s.store.ReadAll(a.ArtifactID, 1<<20)
	if err != nil {
		return nil
	}
	return codexFromAuth(b, a.LogicalPath)
}

func codexFromAuth(b []byte, logical string) *Account {
	var auth struct {
		Mode   string `json:"auth_mode"`
		APIKey string `json:"OPENAI_API_KEY"`
		Tokens struct {
			ID string `json:"id_token"`
		} `json:"tokens"`
	}
	if json.Unmarshal(b, &auth) != nil {
		return nil
	}
	acc := &Account{Key: accountKey(logical, "codex-cli"), Product: "codex-cli", Source: logical}
	if parts := strings.Split(auth.Tokens.ID, "."); len(parts) == 3 {
		if raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "=")); err == nil {
			var claims struct {
				Email string `json:"email"`
				Auth  struct {
					Plan string `json:"chatgpt_plan_type"`
				} `json:"https://api.openai.com/auth"`
			}
			if json.Unmarshal(raw, &claims) == nil {
				acc.Email = sanitize.Terminal(claims.Email)
				if claims.Auth.Plan != "" {
					acc.Plan = "ChatGPT " + sanitize.Terminal(claims.Auth.Plan)
				}
			}
		}
	}
	if acc.Email == "" && auth.APIKey != "" {
		acc.Plan = "API key"
	}
	acc.Known = acc.Email != "" || acc.Plan != ""
	acc.Label = labelFor(acc)
	return acc
}

// accountForPath resolves an evidence reference ("path:line (artifact …)")
// or a logical path to an account key.
func (s *Server) accountForRef(ref, product string) string {
	p := ref
	if i := strings.Index(p, " ("); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndexByte(p, ':'); i > 0 {
		p = p[:i]
	}
	return accountKey(p, product)
}

func (s *Server) apiAccounts(w http.ResponseWriter, r *http.Request) {
	out := make([]*Account, 0, len(s.accounts))
	for _, a := range s.accounts {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].Key < out[j].Key
	})
	writeJSON(w, out)
}

// byTime returns positions ordered by timestamp (overlay order breaks ties),
// cached like text queries: the UI pages through the same ordering.
func (s *Server) byTime(matched []int, key string) []int {
	s.qmu.Lock()
	if hit, ok := s.qhits[key]; ok {
		s.qmu.Unlock()
		return hit
	}
	s.qmu.Unlock()
	out := append([]int(nil), matched...)
	// Undated records go last: at the top they bury the case under
	// "unknown time" rows.
	sort.SliceStable(out, func(a, b int) bool {
		ta, tb := s.idx.At(out[a]).Timestamp, s.idx.At(out[b]).Timestamp
		if (ta == "") != (tb == "") {
			return tb == ""
		}
		return ta < tb
	})
	s.qmu.Lock()
	if len(s.qhits) >= 8 {
		s.qhits = map[string][]int{}
	}
	s.qhits[key] = out
	s.qmu.Unlock()
	return out
}

// mcpExchange returns what an MCP tool call sent and what came back, both
// trimmed and sanitized. The input is read out of the call's own sealed
// transcript line (any JSON object whose id names the call); the answer is
// the tool result with the same call id, a few events later.
func (s *Server) mcpExchange(i int, ev schema.Event) (sent, answer string) {
	if ev.SourceArtifact != "" && ev.SourceArtifact != "live" {
		if f, err := s.store.OpenAt(ev.SourceArtifact, ev.SourceOffset); err == nil {
			line, _ := bufio.NewReaderSize(f, 1<<20).ReadString('\n')
			f.Close()
			var v any
			if json.Unmarshal([]byte(line), &v) == nil {
				if in := findCallInput(v, ev.ToolCallID); in != nil {
					if b, err := json.Marshal(in); err == nil {
						sent = sanitize.Terminal(trimTo(string(b), 300))
					}
				}
			}
		}
	}
	if ev.ToolCallID != "" {
		for j := i + 1; j < s.idx.Len() && j < i+200; j++ {
			if s.idx.At(j).EventType != schema.EventToolResult {
				continue
			}
			r, err := s.idx.Event(j)
			if err != nil || r.ToolCallID != ev.ToolCallID {
				continue
			}
			text := r.Summary
			if text == "" {
				text = r.Result
			}
			answer = sanitize.Terminal(trimTo(text, 300))
			break
		}
	}
	return sent, answer
}

func findCallInput(v any, id string) any {
	switch t := v.(type) {
	case map[string]any:
		if id != "" && (t["id"] == id || t["call_id"] == id) {
			if in, ok := t["input"]; ok {
				return in
			}
			if in, ok := t["arguments"]; ok {
				if str, ok := in.(string); ok {
					var parsed any
					if json.Unmarshal([]byte(str), &parsed) == nil {
						return parsed
					}
				}
				return in
			}
		}
		for _, c := range t {
			if r := findCallInput(c, id); r != nil {
				return r
			}
		}
	case []any:
		for _, c := range t {
			if r := findCallInput(c, id); r != nil {
				return r
			}
		}
	}
	return nil
}
