package accounts

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func TestKey(t *testing.T) {
	cases := map[string]string{
		".claude/projects/p/s1.jsonl":     ".claude",
		".claude.json":                    ".claude",
		".claude-work/projects/p/s.jsonl": ".claude-work",
		".codex/sessions/r.jsonl":         ".codex",
		"Library/Application Support/Claude/local-agent-mode-sessions/acct-1/o/s/a.jsonl": "cowork:acct-1",
	}
	for in, want := range cases {
		if got := Key(in, "cursor"); got != want {
			t.Errorf("Key(%q) = %q, want %q", in, got, want)
		}
	}
	if KeyForRef(".codex/x.jsonl:4 (artifact ab)", "codex-cli") != ".codex" {
		t.Error("KeyForRef did not strip the :line (artifact …) suffix")
	}
}

func TestCodexClaimsNoTokenLeak(t *testing.T) {
	claims, _ := json.Marshal(map[string]any{"email": "bo@example.org", "https://api.openai.com/auth": map[string]any{"chatgpt_plan_type": "plus"}})
	tok := "h." + base64.RawURLEncoding.EncodeToString(claims) + ".sig"
	raw, _ := json.Marshal(map[string]any{"tokens": map[string]any{"id_token": tok}})
	acc := Codex(raw, ".codex/auth.json")
	if acc == nil || acc.Email != "bo@example.org" || acc.Plan != "ChatGPT plus" {
		t.Fatalf("codex account = %+v", acc)
	}
	if strings.Contains(acc.Label, "sig") || strings.Contains(acc.Label, tok) {
		t.Error("token material leaked into the label")
	}
}
