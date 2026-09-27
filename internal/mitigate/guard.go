package mitigate

import (
	"encoding/json"
	"io"
	"path/filepath"
	"regexp"
	"strings"
)

// The log guard is the one guardrail that is a program, not a pattern.
// Glob denies are trivially rewritten (`rm -rf ~/.cl*`), and a shell
// script cannot tell the command apart from the transcript_path every
// Claude Code hook receives. So the hook runs `agentdfir guard log`, which
// reads the tool call and refuses the ones that delete or overwrite an
// agent's own activity records.

// GuardInput is the part of a Claude Code PreToolUse payload the guard reads.
type GuardInput struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command  string `json:"command"`
		FilePath string `json:"file_path"`
	} `json:"tool_input"`
}

// Decision is what the guard concluded.
type Decision struct {
	Block  bool
	Reason string
}

var (
	// Paths of the agents' own records. Claude memory files live under
	// ~/.claude/projects too and are deliberately not covered: only the
	// transcripts (.jsonl) and the directories that hold them.
	logPathRe = regexp.MustCompile(`(\.claude/projects(/[^\s'"]*\.jsonl|/?[\s'"*]|/?$|/[^\s'"/]+/?([\s'"*]|$))|\.claude/history\.jsonl|\.codex/(sessions|archived_sessions|history\.jsonl)|\.codex/?([\s'"*]|$)|\.gemini/tmp|\.cursor/chats|\.local/share/opencode|\.claude/?([\s'"*]|$))`)
	// Commands that remove, truncate or overwrite.
	destroyRe = regexp.MustCompile(`(^|[\s;&|(])(rm|unlink|shred|srm|truncate|mv|find\s[^;|&]*-delete|find\s[^;|&]*-exec\s+rm)(\s|$)|(^|[^>&0-9])>\s*[^>&\s]|:\s*>\s*\S`)
)

// GuardLog decides one tool call.
func GuardLog(in GuardInput) Decision {
	switch in.ToolName {
	case "Bash":
		cmd := strings.ReplaceAll(in.ToolInput.Command, `\`, "/")
		if cmd == "" || !destroyRe.MatchString(cmd) {
			return Decision{}
		}
		for _, seg := range splitCommands(cmd) {
			if destroyRe.MatchString(seg) && logPathRe.MatchString(seg+" ") {
				return Decision{Block: true, Reason: "agentdfir log-guard: this command would delete or overwrite an AI agent's own activity log. It was blocked; if you really mean it, run it yourself in a terminal."}
			}
		}
	case "Write", "Edit", "MultiEdit":
		p := filepath.ToSlash(in.ToolInput.FilePath)
		if strings.HasSuffix(p, ".jsonl") && logPathRe.MatchString(p) {
			return Decision{Block: true, Reason: "agentdfir log-guard: agent transcripts are evidence and are not edited by the agent."}
		}
	}
	return Decision{}
}

// splitCommands cuts a shell line into the pieces between ; && || |, so
// "cat ~/.claude/projects/x.jsonl > out.txt" is judged on the redirect
// target, not on the path it reads.
func splitCommands(cmd string) []string {
	f := func(r rune) bool { return r == ';' || r == '&' || r == '|' || r == '\n' }
	var out []string
	for _, s := range strings.FieldsFunc(cmd, f) {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		// For a redirect, only what follows > is written.
		if i := strings.LastIndex(s, ">"); i >= 0 && !strings.HasPrefix(strings.TrimSpace(s), "rm") {
			head := s[:i]
			if !regexp.MustCompile(`(^|\s)(rm|unlink|shred|srm|truncate|mv|find)(\s|$)`).MatchString(head) {
				s = "> " + strings.TrimSpace(s[i+1:])
			}
		}
		out = append(out, s)
	}
	return out
}

// RunGuard reads one payload and returns the process exit code: 2 blocks
// (Claude Code shows the reason to the model), 0 allows. Anything
// unreadable is allowed: a guard that fails closed on malformed input
// would stop every tool call the day the payload format changes.
func RunGuard(r io.Reader, stderr io.Writer) int {
	var in GuardInput
	if err := json.NewDecoder(io.LimitReader(r, 4<<20)).Decode(&in); err != nil {
		return 0
	}
	d := GuardLog(in)
	if d.Block {
		io.WriteString(stderr, d.Reason+"\n")
		return 2
	}
	return 0
}
