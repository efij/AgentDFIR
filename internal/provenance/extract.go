package provenance

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/efij/AgentDFIR/internal/schema"
)

// extractWrite re-reads the raw transcript line behind a tool_call event
// and pulls out the path and the text the agent wrote. Shapes handled:
//
//	Claude Code   Write{file_path,content} · Edit{file_path,new_string} · MultiEdit{file_path,edits[].new_string}
//	              NotebookEdit{notebook_path,new_source}
//	Codex CLI     apply_patch (function_call or shell) — "*** Update/Add File: path" hunks, '+' lines
//	Cline / Roo   <write_to_file><path>…<content>…  ·  <replace_in_file> … =======\n<new>\n>>>>>>> REPLACE
//	Generic       tool input with {path|file_path|filePath|target_file} and {content|contents|code_edit|new_string|text}
//	Shell         echo/printf … > path  ·  >> path  ·  cat <<EOF > path … EOF  ·  tee path
func extractWrite(pkgDir string, ev schema.Event) (Write, bool) {
	raw, ok := readRawLine(pkgDir, ev)
	if !ok {
		// Fall back to the normalized command for shell redirects.
		if ev.Command != "" {
			if p, c, ok := shellWrite(ev.Command); ok {
				return mk(ev, p, c), true
			}
		}
		return Write{}, false
	}
	// Claude / Anthropic-style content array.
	if p, c, ok := anthropicWrite(raw, ev); ok {
		return mk(ev, p, c), true
	}
	// Codex rollout payload.
	if p, c, ok := codexWrite(raw); ok {
		return mk(ev, p, c), true
	}
	// Generic tool call objects (OpenAI tool_calls / Gemini functionCall / OpenCode parts).
	if p, c, ok := genericWrite(raw); ok {
		return mk(ev, p, c), true
	}
	// Cline XML in assistant text.
	if p, c, ok := clineWrite(string(raw)); ok {
		return mk(ev, p, c), true
	}
	if ev.Command != "" {
		if p, c, ok := shellWrite(ev.Command); ok {
			return mk(ev, p, c), true
		}
	}
	return Write{}, false
}

func mk(ev schema.Event, path, content string) Write {
	return Write{Event: ev, Path: path, Content: content, Snippet: trimTo(strings.ReplaceAll(content, "\n", " "), 160)}
}

// readRawLine returns the transcript line an event points at.
func readRawLine(pkgDir string, ev schema.Event) ([]byte, bool) {
	if ev.SourceArtifact == "" || ev.SourceArtifact == "live" {
		return nil, false
	}
	f, err := os.Open(filepath.Join(pkgDir, "raw", ev.SourceArtifact))
	if err != nil {
		return nil, false
	}
	defer f.Close()
	if _, err := f.Seek(ev.SourceOffset, io.SeekStart); err != nil {
		return nil, false
	}
	r := bufio.NewReaderSize(f, 1<<20)
	line, err := r.ReadBytes('\n')
	if err != nil && err != io.EOF {
		return nil, false
	}
	if len(line) > 16<<20 {
		return nil, false
	}
	return line, len(strings.TrimSpace(string(line))) > 0
}

// ---- Claude Code ----

type anthropicMsg struct {
	Message struct {
		Content json.RawMessage `json:"content"`
	} `json:"message"`
	Content json.RawMessage `json:"content"`
}

func anthropicWrite(raw []byte, ev schema.Event) (string, string, bool) {
	var m anthropicMsg
	if json.Unmarshal(raw, &m) != nil {
		return "", "", false
	}
	content := m.Message.Content
	if len(content) == 0 {
		content = m.Content
	}
	var items []struct {
		Type  string          `json:"type"`
		ID    string          `json:"id"`
		Name  string          `json:"name"`
		Input json.RawMessage `json:"input"`
	}
	if json.Unmarshal(content, &items) != nil {
		return "", "", false
	}
	for _, it := range items {
		if it.Type != "tool_use" || (ev.ToolCallID != "" && it.ID != ev.ToolCallID) {
			continue
		}
		var in map[string]any
		if json.Unmarshal(it.Input, &in) != nil {
			continue
		}
		path := str(in["file_path"])
		if path == "" {
			path = str(in["notebook_path"])
		}
		switch it.Name {
		case "Write":
			return path, str(in["content"]), path != ""
		case "Edit":
			return path, str(in["new_string"]), path != ""
		case "NotebookEdit":
			return path, str(in["new_source"]), path != ""
		case "MultiEdit":
			var parts []string
			if edits, ok := in["edits"].([]any); ok {
				for _, e := range edits {
					if em, ok := e.(map[string]any); ok {
						parts = append(parts, str(em["new_string"]))
					}
				}
			}
			return path, strings.Join(parts, "\n"), path != ""
		case "Bash":
			if p, c, ok := shellWrite(str(in["command"])); ok {
				return p, c, true
			}
		}
	}
	return "", "", false
}

// ---- Codex ----

var patchFileRe = regexp.MustCompile(`\*\*\* (?:Update|Add) File: (.+)`)

func codexWrite(raw []byte) (string, string, bool) {
	var rl struct {
		Payload struct {
			Type      string          `json:"type"`
			Name      string          `json:"name"`
			Arguments string          `json:"arguments"`
			Input     json.RawMessage `json:"input"`
		} `json:"payload"`
	}
	if json.Unmarshal(raw, &rl) != nil || rl.Payload.Type == "" {
		return "", "", false
	}
	text := rl.Payload.Arguments
	if text == "" && len(rl.Payload.Input) > 0 {
		text = string(rl.Payload.Input)
	}
	// arguments is JSON: {"command":["apply_patch","*** Begin Patch…"]} or {"patch": "…"} or {"input":"…"}
	var args map[string]any
	if json.Unmarshal([]byte(text), &args) == nil {
		if p := str(args["patch"]); p != "" {
			text = p
		} else if p := str(args["input"]); p != "" {
			text = p
		} else if cmd, ok := args["command"].([]any); ok {
			var parts []string
			for _, c := range cmd {
				parts = append(parts, str(c))
			}
			text = strings.Join(parts, "\n")
			if !strings.Contains(text, "*** Begin Patch") {
				if p, c, ok := shellWrite(strings.Join(parts, " ")); ok {
					return p, c, true
				}
			}
		}
	}
	if !strings.Contains(text, "*** Begin Patch") {
		return "", "", false
	}
	m := patchFileRe.FindStringSubmatch(text)
	if m == nil {
		return "", "", false
	}
	var added []string
	for _, l := range strings.Split(text, "\n") {
		if strings.HasPrefix(l, "+") && !strings.HasPrefix(l, "+++") {
			added = append(added, strings.TrimPrefix(l, "+"))
		}
	}
	return strings.TrimSpace(m[1]), strings.Join(added, "\n"), true
}

// ---- generic tool inputs ----

func genericWrite(raw []byte) (string, string, bool) {
	var doc any
	if json.Unmarshal(raw, &doc) != nil {
		return "", "", false
	}
	var found struct{ path, content string }
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if found.path != "" || depth > 8 {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			p := firstStr(t, "file_path", "filePath", "path", "target_file", "targetFile", "filename")
			c := firstStr(t, "content", "contents", "code_edit", "new_string", "newString", "text", "new_content")
			if p != "" && c != "" {
				found.path, found.content = p, c
				return
			}
			// OpenAI-style stringified arguments.
			if a, ok := t["arguments"].(string); ok {
				var inner map[string]any
				if json.Unmarshal([]byte(a), &inner) == nil {
					walk(inner, depth+1)
				}
			}
			for _, val := range t {
				walk(val, depth+1)
			}
		case []any:
			for _, e := range t {
				walk(e, depth+1)
			}
		}
	}
	walk(doc, 0)
	return found.path, found.content, found.path != ""
}

// ---- Cline / Roo XML tool text ----

var (
	clineWriteRe   = regexp.MustCompile(`(?s)<write_to_file>.*?<path>(.*?)</path>.*?<content>(.*?)</content>`)
	clineReplaceRe = regexp.MustCompile(`(?s)<replace_in_file>.*?<path>(.*?)</path>.*?<diff>(.*?)</diff>`)
	replaceNewRe   = regexp.MustCompile(`(?s)=======\n(.*?)\n>>>>>>> REPLACE`)
)

func clineWrite(text string) (string, string, bool) {
	text = strings.ReplaceAll(text, `\n`, "\n")
	if m := clineWriteRe.FindStringSubmatch(text); m != nil {
		return strings.TrimSpace(m[1]), m[2], true
	}
	if m := clineReplaceRe.FindStringSubmatch(text); m != nil {
		var parts []string
		for _, r := range replaceNewRe.FindAllStringSubmatch(m[2], -1) {
			parts = append(parts, r[1])
		}
		return strings.TrimSpace(m[1]), strings.Join(parts, "\n"), true
	}
	return "", "", false
}

// ---- shell redirects ----

var (
	// heredoc header: `... <<[-]['"]?DELIM['"]? ... > path` or `... > path <<DELIM`
	heredocHdrRe = regexp.MustCompile(`<<-?\s*['"]?(\w+)['"]?`)
	redirectRe   = regexp.MustCompile(`>{1,2}\s*(\S+)`)
	echoRe       = regexp.MustCompile(`(?s)(?:echo|printf)\s+(?:-e\s+|-n\s+)?(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+))\s*>{1,2}\s*(\S+)`)
	teeRe        = regexp.MustCompile(`(?s)(?:echo|printf)\s+(?:"((?:[^"\\]|\\.)*)"|'([^']*)'|(\S+))\s*\|\s*tee\s+(?:-a\s+)?(\S+)`)
)

func shellWrite(cmd string) (string, string, bool) {
	if cmd == "" {
		return "", "", false
	}
	if p, c, ok := heredocWrite(cmd); ok {
		return p, c, true
	}
	if m := echoRe.FindStringSubmatch(cmd); m != nil {
		return cleanPath(m[4]), unescape(m[1] + m[2] + m[3]), true
	}
	if m := teeRe.FindStringSubmatch(cmd); m != nil {
		return cleanPath(m[4]), unescape(m[1] + m[2] + m[3]), true
	}
	return "", "", false
}

func unescape(s string) string {
	return strings.NewReplacer(`\n`, "\n", `\"`, `"`, `\\`, `\`, `\t`, "\t").Replace(s)
}

func cleanPath(p string) string {
	p = strings.Trim(p, `"'`)
	p = strings.TrimSuffix(p, ";")
	return p
}

func firstStr(m map[string]any, keys ...string) string {
	for _, k := range keys {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

func str(v any) string {
	s, _ := v.(string)
	return s
}

// heredocWrite handles `cat <<'EOF' > path … EOF` (either operand order).
// RE2 has no back-references, so the body is cut by hand at the delimiter.
func heredocWrite(cmd string) (string, string, bool) {
	nl := strings.Index(cmd, "\n")
	if nl < 0 {
		return "", "", false
	}
	header, body := cmd[:nl], cmd[nl+1:]
	hm := heredocHdrRe.FindStringSubmatch(header)
	rm := redirectRe.FindStringSubmatch(strings.Replace(header, hm0(hm), "", 1))
	if hm == nil || rm == nil {
		return "", "", false
	}
	delim := hm[1]
	var lines []string
	for _, l := range strings.Split(body, "\n") {
		if strings.TrimSpace(l) == delim {
			return cleanPath(rm[1]), strings.Join(lines, "\n"), true
		}
		lines = append(lines, l)
	}
	return "", "", false
}

func hm0(m []string) string {
	if len(m) == 0 {
		return "\x00"
	}
	return m[0]
}
