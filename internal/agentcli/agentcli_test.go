package agentcli

import "testing"

func TestHeadlessBypass(t *testing.T) {
	hits := map[string]string{
		`claude --dangerously-skip-permissions -p "Recursively search / for wallets | and & write /tmp/inventory.txt"`: "claude",
		`claude -p "x" --permission-mode=bypassPermissions`:                                                            "claude",
		`claude --print --permission-mode bypassPermissions "go"`:                                                      "claude",
		`gemini --yolo -p "find keys"`:                                                                                 "gemini",
		`gemini --approval-mode=yolo --prompt "find keys"`:                                                             "gemini",
		`q chat --trust-all-tools --no-interactive "find keys"`:                                                        "q",
		`codex exec --dangerously-bypass-approvals-and-sandbox "do it"`:                                                "codex",
		`codex exec -s danger-full-access "do it"`:                                                                     "codex",
		`codex exec -c approval_policy=never "do it"`:                                                                  "codex",
		`npx -y @anthropic-ai/claude-code@2.1.0 -p "x" --dangerously-skip-permissions`:                                 "claude",
		`node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js -p "x" --dangerously-skip-permissions`:            "claude",
		`FOO=1 /opt/homebrew/bin/claude -p "x" --dangerously-skip-permissions`:                                         "claude",
		`cd /tmp && claude -p "x" --dangerously-skip-permissions > out.txt`:                                            "claude",
		`cursor-agent -p "x" --force`:                                                                                  "cursor-agent",
		`copilot -p "x" --allow-all-tools`:                                                                             "copilot",
	}
	for cmd, cli := range hits {
		m, ok := HeadlessBypass(cmd)
		if !ok || m.CLI != cli {
			t.Errorf("%s: got %+v %v, want %s", cmd, m, ok, cli)
		}
	}
	for _, cmd := range []string{
		`claude --dangerously-skip-permissions`, // interactive: NESTED rule's job
		`claude -p "summarise the diff"`,        // headless, approvals on
		`gemini -p "hi"`,
		`grep -rn "claude -p --dangerously-skip-permissions" docs/`,
		`echo "claude -p x --dangerously-skip-permissions" >> notes.md`,
		`q chat "hello"`,
		`codex "fix the test" --yolo`, // interactive
	} {
		if m, ok := HeadlessBypass(cmd); ok {
			t.Errorf("%s: unexpected match %+v", cmd, m)
		}
	}
	m, ok := HeadlessBypass(`codex exec --full-auto "run tests"`)
	if !ok || !m.Weak {
		t.Errorf("codex --full-auto should match as weak: %+v %v", m, ok)
	}
}

func TestHostileTokensNoPanic(t *testing.T) {
	for _, c := range []string{`"" -p x`, `sudo "$(which fmt)" run`, `env "" -p`, `''`, `"`, `@`, `npx @`} {
		HeadlessBypass(c) // must not panic
	}
}
