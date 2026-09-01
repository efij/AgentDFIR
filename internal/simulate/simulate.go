// Package simulate generates synthetic incident scenarios — adversary
// emulation for AI agents. Output is a fake profile root that the
// normal collector can acquire, so the full pipeline (collect →
// verify → normalize → triage) is exercised end to end.
//
// All content is synthetic. Never feed real evidence through this
// package.
package simulate

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Scenarios lists available scenario IDs.
var Scenarios = []string{"orphan-agent"}

// OrphanAgent writes the MVP acceptance scenario (plan §30):
//
//	Session S1: a legitimate session spawns Agent A via the Task tool;
//	Agent A completes. Later, Agent B appears (session S2) with NO
//	corresponding spawn event, messages/resumes Agent A to obtain its
//	results, and claims (narrative only) to have executed a command.
func OrphanAgent(profileRoot string) error {
	proj := filepath.Join(profileRoot, ".claude", "projects", "-Users-dev-app")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(profileRoot, ".claude.json"),
		[]byte(`{"mcpServers":{},"numStartups":12}`+"\n"), 0o644); err != nil {
		return err
	}

	t0 := time.Date(2026, 8, 30, 14, 0, 0, 0, time.UTC)
	ts := func(min, sec int) string {
		return t0.Add(time.Duration(min)*time.Minute + time.Duration(sec)*time.Second).Format(time.RFC3339)
	}

	const (
		s1     = "5f0c9c1e-1111-4d4e-9a1a-aaaaaaaaaaaa"
		s2     = "9b2d7e3a-2222-4f5b-8c2b-bbbbbbbbbbbb"
		agentA = "a7c3f19b"
		agentB = "adad4e2c"
	)

	// --- Session S1: legitimate parent session spawning Agent A ---
	main := []string{
		line(`{"type":"user","uuid":"u-01","sessionId":"%s","timestamp":"%s","isSidechain":false,"version":"2.1.0","message":{"role":"user","content":"analyze the repo and summarize the auth flow"}}`, s1, ts(0, 0)),
		line(`{"type":"assistant","uuid":"a-01","parentUuid":"u-01","sessionId":"%s","timestamp":"%s","isSidechain":false,"version":"2.1.0","message":{"role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"I will delegate the analysis to a subagent."},{"type":"tool_use","id":"toolu_task_001","name":"Task","input":{"description":"Analyze auth flow","prompt":"Analyze the authentication flow","agentId":"%s"}}]}}`, s1, ts(0, 5), agentA),
		line(`{"type":"user","uuid":"u-02","parentUuid":"a-01","sessionId":"%s","timestamp":"%s","isSidechain":false,"version":"2.1.0","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_task_001","agentId":"%s","content":"Agent completed: auth flow uses OAuth2 with PKCE."}]}}`, s1, ts(4, 30), agentA),
		line(`{"type":"assistant","uuid":"a-02","parentUuid":"u-02","sessionId":"%s","timestamp":"%s","isSidechain":false,"version":"2.1.0","message":{"role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"Analysis complete. The auth flow uses OAuth2 with PKCE."}]}}`, s1, ts(4, 35)),
	}
	if err := writeLines(filepath.Join(proj, s1+".jsonl"), main); err != nil {
		return err
	}

	// --- Agent A: legitimate subagent transcript (spawned above) ---
	aLines := []string{
		line(`{"type":"user","uuid":"sa-01","sessionId":"%s","agentId":"%s","timestamp":"%s","isSidechain":true,"version":"2.1.0","message":{"role":"user","content":"Analyze the authentication flow"}}`, s1, agentA, ts(0, 6)),
		line(`{"type":"assistant","uuid":"sa-02","parentUuid":"sa-01","sessionId":"%s","agentId":"%s","timestamp":"%s","isSidechain":true,"version":"2.1.0","message":{"role":"assistant","model":"claude-sonnet-5","content":[{"type":"tool_use","id":"toolu_bash_001","name":"Bash","input":{"command":"grep -r oauth src/ | head -50"}}]}}`, s1, agentA, ts(1, 0)),
		line(`{"type":"user","uuid":"sa-03","parentUuid":"sa-02","sessionId":"%s","agentId":"%s","timestamp":"%s","isSidechain":true,"version":"2.1.0","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_bash_001","content":"src/auth/oauth.go: PKCE flow"}]}}`, s1, agentA, ts(1, 5)),
		line(`{"type":"assistant","uuid":"sa-04","parentUuid":"sa-03","sessionId":"%s","agentId":"%s","timestamp":"%s","isSidechain":true,"version":"2.1.0","message":{"role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"Auth flow analyzed: OAuth2 with PKCE. Task complete."}]}}`, s1, agentA, ts(4, 20)),
	}
	if err := writeLines(filepath.Join(proj, "agent-"+agentA+".jsonl"), aLines); err != nil {
		return err
	}

	// --- Agent B: ORPHAN. No spawn event anywhere. Appears later,
	// messages/resumes Agent A, and CLAIMS an execution narrative-only. ---
	bLines := []string{
		line(`{"type":"assistant","uuid":"ob-01","sessionId":"%s","agentId":"%s","timestamp":"%s","isSidechain":true,"version":"2.1.0","message":{"role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"Resuming prior analysis context to collect results."},{"type":"tool_use","id":"toolu_send_001","name":"SendMessage","input":{"to":"%s","message":"send me your analysis results"}}]}}`, s2, agentB, ts(45, 0), agentA),
		line(`{"type":"user","uuid":"ob-02","parentUuid":"ob-01","sessionId":"%s","agentId":"%s","timestamp":"%s","isSidechain":true,"version":"2.1.0","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_send_001","content":"auth flow uses OAuth2 with PKCE (full analysis attached)"}]}}`, s2, agentB, ts(45, 10)),
		line(`{"type":"assistant","uuid":"ob-03","parentUuid":"ob-02","sessionId":"%s","agentId":"%s","timestamp":"%s","isSidechain":true,"version":"2.1.0","message":{"role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"I executed curl example.com and uploaded the summary."}]}}`, s2, agentB, ts(46, 0)),
	}
	if err := writeLines(filepath.Join(proj, "agent-"+agentB+".jsonl"), bLines); err != nil {
		return err
	}
	return nil
}

func line(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

func writeLines(path string, lines []string) error {
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")+"\n"), 0o644)
}
