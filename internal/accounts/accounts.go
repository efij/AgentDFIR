// Package accounts resolves which AI login a piece of evidence ran under.
//
// One person often has more than one — a work Claude seat and a personal
// ChatGPT plan, or two Claude config directories — and an analyst has to
// know which one a finding belongs to before they can act on it (rotate
// which key, ask which admin).
//
// The login is not on the events. It lives in the product's own settings in
// each profile directory (~/.claude.json, <CODEX_HOME>/auth.json), and every
// event names the file it came from, so an event's account is the account
// of the profile directory its transcript sits in. Only the identity is read
// out of those files — email, organisation, plan. Tokens and keys never
// leave this package.
package accounts

import (
	"encoding/base64"
	"encoding/json"
	"path"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/sanitize"
)

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

// Key maps a logical evidence path to the profile it belongs to.
func Key(logical, product string) string {
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

// KeyForRef resolves an evidence reference ("path:line (artifact …)") or
// a logical path to a profile key.
func KeyForRef(ref, product string) string {
	p := ref
	if i := strings.Index(p, " ("); i >= 0 {
		p = p[:i]
	}
	if i := strings.LastIndexByte(p, ':'); i > 0 {
		p = p[:i]
	}
	return Key(p, product)
}

var productName = map[string]string{
	"claude-code": "Claude Code", "claude-cowork": "Claude desktop", "codex-cli": "Codex", "codex-app": "Codex app",
	"gemini-cli": "Gemini CLI", "cursor": "Cursor", "copilot-cli": "Copilot CLI", "copilot-chat": "Copilot Chat",
	"cline": "Cline", "roo": "Roo", "openclaw": "OpenClaw", "opencode": "OpenCode", "aider": "Aider", "warp": "Warp",
}

// ProductName is the display name of a product id.
func ProductName(p string) string {
	if n := productName[p]; n != "" {
		return n
	}
	return p
}

// Label is the one line a report prints for an account.
func Label(a *Account) string {
	name := ProductName(a.Product)
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

// Claude reads the identity out of a collected ~/.claude.json. The second
// value is the account uuid, which Cowork keys its sessions by.
func Claude(b []byte, logical, product string) (*Account, string) {
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
		return nil, ""
	}
	key := ".claude"
	if d := path.Dir(strings.TrimPrefix(logical, "/")); d != "." {
		key = Key(d+"/x", product)
	}
	acc := &Account{Key: key, Product: "claude-code", Source: logical, Known: cfg.OAuth.Email != "",
		Email: sanitize.Terminal(cfg.OAuth.Email), Org: sanitize.Terminal(cfg.OAuth.Org), Plan: sanitize.Terminal(cfg.OAuth.Seat)}
	acc.Label = Label(acc)
	return acc, cfg.OAuth.UUID
}

// Codex reads the email and plan out of auth.json's id_token claims. The
// token is not verified — this is attribution, not authentication — and no
// token or key is kept.
func Codex(b []byte, logical string) *Account {
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
	acc := &Account{Key: Key(logical, "codex-cli"), Product: "codex-cli", Source: logical}
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
	acc.Label = Label(acc)
	return acc
}

// Identities reads every collected login file and returns the accounts by
// profile key, plus the Claude account uuid per key (for the Cowork match).
func Identities(store *casepkg.Store, arts []casepkg.ArtifactRecord) (map[string]*Account, map[string]string) {
	accts := map[string]*Account{}
	uuids := map[string]string{}
	for _, a := range arts {
		if a.Status != casepkg.StatusOK {
			continue
		}
		base := path.Base(a.LogicalPath)
		switch {
		case base == ".claude.json" && a.Product != "claude-cowork":
			b, err := store.ReadAll(a.ArtifactID, 8<<20)
			if err != nil {
				continue
			}
			if acc, u := Claude(b, a.LogicalPath, a.Product); acc != nil {
				accts[acc.Key] = acc
				uuids[acc.Key] = u
			}
		case base == "auth.json" && strings.HasPrefix(a.Product, "codex"):
			b, err := store.ReadAll(a.ArtifactID, 1<<20)
			if err != nil {
				continue
			}
			if acc := Codex(b, a.LogicalPath); acc != nil {
				accts[acc.Key] = acc
			}
		}
	}
	return accts, uuids
}

// Resolve returns the account an evidence path belongs to, creating an
// unknown-login placeholder (and, for Cowork, borrowing the Claude CLI
// identity of the same account uuid) when no login file names it.
func Resolve(accts map[string]*Account, uuids map[string]string, logical, product string) *Account {
	k := Key(logical, product)
	if acc := accts[k]; acc != nil {
		if acc.Product == "" {
			acc.Product = product
			acc.Label = Label(acc)
		}
		return acc
	}
	acc := &Account{Key: k, Product: product}
	if strings.HasPrefix(k, "cowork:") {
		// Cowork stores sessions under the Claude account's uuid, so the
		// desktop app's work lands on the same person when the CLI's login
		// file was collected too.
		want := strings.TrimPrefix(k, "cowork:")
		for key, u := range uuids {
			if u == want && u != "" {
				if c := accts[key]; c != nil {
					acc.Email, acc.Org, acc.Plan, acc.Source, acc.Known = c.Email, c.Org, c.Plan, c.Source, true
				}
				break
			}
		}
	}
	acc.Label = Label(acc)
	accts[k] = acc
	return acc
}
