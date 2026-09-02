// Package provenance answers "how did this line get here?" for agent
// instruction, memory and configuration files. Injected instructions
// become persistent when an agent writes them into CLAUDE.md, AGENTS.md,
// .cursorrules, hooks or memory; this package attributes every line of
// such a file to the write that produced it — session, agent, tool, time —
// and to what TRIGGERED that write: a human request, the model's own
// initiative, or content that came back from a tool (the injection →
// persistence path).
//
// Deterministic and evidence-linked: content is taken from the sealed
// transcripts, never inferred.
package provenance

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/detect"
	"github.com/efij/AgentDFIR/internal/schema"
)

// MaxFileBytes bounds an instruction file we attribute line by line.
const MaxFileBytes = 4 << 20

// Write is one agent write/edit to a file with the content it produced.
type Write struct {
	Event    schema.Event `json:"event"`
	Path     string       `json:"path"`
	Content  string       `json:"-"`       // text written/added (not persisted in JSON: may be large)
	Snippet  string       `json:"snippet"` // first 160 chars
	Trigger  string       `json:"trigger"` // human_prompt | tool_result | model_response | unknown
	TrigRef  string       `json:"trigger_ref,omitempty"`
	TrigInfo string       `json:"trigger_detail,omitempty"`   // e.g. "mcp:docs", "Bash", or the prompt excerpt
	Prompt   string       `json:"preceding_prompt,omitempty"` // nearest human request before the write (context)
}

// LineAttribution is one line of a target file with its origin.
type LineAttribution struct {
	Line      int    `json:"line"`
	Text      string `json:"text"`
	Written   bool   `json:"attributed"`
	SessionID string `json:"session_id,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	Tool      string `json:"tool,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
	Trigger   string `json:"trigger,omitempty"`
	TrigInfo  string `json:"trigger_detail,omitempty"`
	Prompt    string `json:"preceding_prompt,omitempty"`
	Evidence  string `json:"evidence,omitempty"`
}

// FileReport is the attribution of one instruction file.
type FileReport struct {
	LogicalPath  string            `json:"logical_path"`
	ArtifactID   string            `json:"artifact_id"`
	Product      string            `json:"product"`
	Lines        []LineAttribution `json:"lines"`
	Attributed   int               `json:"attributed_lines"`
	Unattributed int               `json:"unattributed_lines"`
	Writes       int               `json:"writes_seen"`
}

// Report is the full provenance output.
type Report struct {
	Files      []FileReport     `json:"files"`
	OtherWrite []Write          `json:"writes_to_instruction_paths"` // writes to instruction-like paths not among collected files
	Findings   []schema.Finding `json:"findings"`
}

// instructionPathRe recognizes files that steer an agent.
var instructionPathRe = regexp.MustCompile(`(?i)(CLAUDE\.md|AGENTS\.md|GEMINI\.md|\.cursorrules|\.windsurfrules|\.clinerules|copilot-instructions\.md|\.cursor/rules|\.claude/(settings[^/]*\.json|hooks/|agents/|commands/|skills/|memory/|CLAUDE\.md)|\.mcp\.json|\.claude\.json|\.codex/(config\.toml|AGENTS\.md|instructions\.md)|\.gemini/(settings\.json|GEMINI\.md)|\.copilot/(config|mcp-config)\.json|opencode\.json|\.aider\.conf\.yml|memory\.md|\.github/instructions/)`)

// instructionCategories are collected artifact types attributed line by line.
var instructionCategories = map[string]bool{"agent_instructions": true, "agent_definitions": true, "product_config": true, "managed_config": true}

// Run computes provenance for a package. filter, when non-empty, limits
// target files to logical paths containing it.
func Run(pkgDir string, events []schema.Event, filter string) (*Report, error) {
	man, err := readManifest(pkgDir)
	if err != nil {
		return nil, err
	}
	// Index events by session for trigger lookup (chronological order = sequence).
	bySession := map[string][]int{}
	for i, ev := range events {
		bySession[ev.SessionID] = append(bySession[ev.SessionID], i)
	}
	// Collect writes with content from raw transcript lines.
	var writes []Write
	for i, ev := range events {
		if ev.EventType != schema.EventToolCall {
			continue
		}
		w, ok := extractWrite(pkgDir, ev)
		if !ok {
			continue
		}
		w.Trigger, w.TrigRef, w.TrigInfo, w.Prompt = trigger(events, bySession[ev.SessionID], i)
		writes = append(writes, w)
	}
	rep := &Report{}
	// Target files.
	targets := map[string]bool{}
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK || !instructionCategories[a.ArtifactType] || a.Size > MaxFileBytes || a.Size == 0 {
			continue
		}
		if filter != "" && !strings.Contains(a.LogicalPath, filter) {
			continue
		}
		fr, err := attributeFile(pkgDir, a, writes)
		if err != nil || fr == nil {
			continue
		}
		targets[normPath(a.LogicalPath)] = true
		rep.Files = append(rep.Files, *fr)
	}
	// Writes to instruction-like paths that are not collected files.
	for _, w := range writes {
		if !instructionPathRe.MatchString(w.Path) {
			continue
		}
		if filter != "" && !strings.Contains(w.Path, filter) {
			continue
		}
		matched := false
		for t := range targets {
			if pathsMatch(w.Path, t) {
				matched = true
				break
			}
		}
		if !matched {
			rep.OtherWrite = append(rep.OtherWrite, w)
		}
	}
	rep.Findings = evaluate(rep, writes)
	return rep, nil
}

// attributeFile maps each line of the collected file to the latest write
// whose content contains it.
func attributeFile(pkgDir string, a casepkg.ArtifactRecord, writes []Write) (*FileReport, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "raw", a.ArtifactID))
	if err != nil {
		return nil, err
	}
	if !looksText(data) {
		return nil, nil
	}
	fr := &FileReport{LogicalPath: a.LogicalPath, ArtifactID: a.ArtifactID, Product: a.Product}
	var relevant []Write
	for _, w := range writes {
		if pathsMatch(w.Path, a.LogicalPath) {
			relevant = append(relevant, w)
		}
	}
	fr.Writes = len(relevant)
	// Latest first so the most recent write wins.
	sort.SliceStable(relevant, func(i, j int) bool { return relevant[i].Event.Timestamp > relevant[j].Event.Timestamp })
	// Pre-split write contents into line sets.
	sets := make([]map[string]bool, len(relevant))
	for i, w := range relevant {
		sets[i] = map[string]bool{}
		for _, l := range strings.Split(w.Content, "\n") {
			if t := strings.TrimSpace(l); t != "" {
				sets[i][t] = true
			}
		}
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		text := sc.Text()
		la := LineAttribution{Line: n, Text: trimTo(text, 200)}
		t := strings.TrimSpace(text)
		if t != "" && len(t) >= 3 {
			for i, w := range relevant {
				if sets[i][t] {
					la.Written = true
					la.SessionID, la.AgentID, la.Tool, la.Timestamp = w.Event.SessionID, w.Event.AgentID, w.Event.Tool, w.Event.Timestamp
					la.Trigger, la.TrigInfo, la.Prompt = w.Trigger, w.TrigInfo, w.Prompt
					la.Evidence = ref(w.Event)
					break
				}
			}
		}
		if la.Written {
			fr.Attributed++
		} else if t != "" {
			fr.Unattributed++
		}
		fr.Lines = append(fr.Lines, la)
	}
	return fr, nil
}

// trigger finds what fed the model right before it wrote: the nearest
// preceding INPUT event in the same session — a human prompt or a tool
// result (content from outside the conversation). Model narrative is
// skipped (the model always narrates before acting). The nearest human
// prompt is also returned as context for the analyst.
func trigger(events []schema.Event, idxs []int, at int) (kind, ref_, info, prompt string) {
	pos := sort.SearchInts(idxs, at)
	kind = "unknown"
	for k := pos - 1; k >= 0 && k >= pos-200; k-- {
		ev := events[idxs[k]]
		switch ev.EventType {
		case schema.EventHumanPrompt:
			if kind == "unknown" {
				kind, ref_, info = "human_prompt", ref(ev), trimTo(ev.Summary, 120)
			}
			prompt = trimTo(ev.Summary, 120)
			return
		case schema.EventToolResult:
			if kind == "unknown" {
				src := toolSource(events, idxs, k, ev)
				if isWriteTool(src) {
					continue // a write's own "ok" result is not outside content
				}
				kind, ref_, info = "tool_result", ref(ev), src
			}
		}
	}
	return
}

// toolSource names the tool (or MCP server/tool) whose result an event
// carries, resolving through the originating tool_call when the result
// itself is unlabeled.
func toolSource(events []schema.Event, idxs []int, k int, res schema.Event) string {
	src, server, tool := res.Tool, res.MCPServer, res.MCPTool
	if server == "" && res.ToolCallID != "" {
		for j := k - 1; j >= 0 && j >= k-500; j-- {
			c := events[idxs[j]]
			if c.EventType == schema.EventToolCall && c.ToolCallID == res.ToolCallID {
				src, server, tool = c.Tool, c.MCPServer, c.MCPTool
				break
			}
		}
	}
	if server != "" {
		if tool != "" {
			return "mcp:" + server + "/" + tool
		}
		return "mcp:" + server
	}
	if src == "" {
		return "tool_result"
	}
	return src
}

// isWriteTool: tools whose results merely acknowledge a write.
func isWriteTool(name string) bool {
	switch strings.ToLower(name) {
	case "write", "edit", "multiedit", "notebookedit", "write_to_file", "replace_in_file", "apply_patch", "edit_file", "create_file", "str_replace_editor", "str_replace_based_edit_tool":
		return true
	}
	return false
}

// ---- findings ----

func evaluate(rep *Report, writes []Write) []schema.Finding {
	var out []schema.Finding
	seen := map[string]bool{}
	flag := func(f schema.Finding) {
		key := f.RuleID + "|" + strings.Join(f.EvidenceRefs, "|")
		if !seen[key] {
			seen[key] = true
			out = append(out, f)
		}
	}
	for _, fr := range rep.Files {
		for _, la := range fr.Lines {
			if !la.Written {
				continue
			}
			if la.Trigger == "tool_result" {
				flag(schema.Finding{
					RuleID: "INSTRUCTION_FROM_TOOL_RESULT", Severity: "HIGH", Title: "Instruction Line Originated From Tool Output",
					Description: fmt.Sprintf("Line %d of %s (%q) was written by agent %s via %s right after content came back from %s. Text that entered as tool output — not from the user — is now a standing instruction for every future session.", la.Line, fr.LogicalPath, trimTo(la.Text, 80), la.AgentID, la.Tool, la.TrigInfo),
					SessionID:   la.SessionID, AgentID: la.AgentID, EvidenceRefs: []string{la.Evidence},
					Status: schema.StateObserved, Endpoint: schema.StateUnknown, MitreATLAS: "AML.T0051", MitreATTACK: "T1547",
					FalsePositive: "Agents legitimately summarize docs into memory; the risk is what the line instructs.",
				})
			}
			if ph, ok := detect.InjectionPhrase(la.Text); ok {
				flag(schema.Finding{
					RuleID: "INSTRUCTION_INJECTION_PHRASE", Severity: "HIGH", Title: "Instruction File Contains an Override Phrase",
					Description: fmt.Sprintf("Line %d of %s contains %q. Persistent instruction files are loaded into every session; an override phrase here is a standing injection.", la.Line, fr.LogicalPath, ph),
					SessionID:   la.SessionID, AgentID: la.AgentID, EvidenceRefs: []string{fmt.Sprintf("%s:%d (artifact %s)", fr.LogicalPath, la.Line, short(fr.ArtifactID))},
					Status: schema.StateObserved, Endpoint: schema.StateUnknown, MitreATLAS: "AML.T0051",
					FalsePositive: "Security documentation quoting injection phrases.",
				})
			}
			if la.AgentID != "" && !strings.HasPrefix(la.AgentID, "main:") {
				// Main agents carry the "main:<session>" id; subagents are bare ids.
				flag(schema.Finding{
					RuleID: "INSTRUCTION_WRITTEN_BY_SUBAGENT", Severity: "MEDIUM", Title: "Subagent Modified a Persistent Instruction File",
					Description: fmt.Sprintf("Subagent %s wrote line %d of %s. Delegated agents changing the parent's standing instructions widens blast radius and is rarely intended.", la.AgentID, la.Line, fr.LogicalPath),
					SessionID:   la.SessionID, AgentID: la.AgentID, EvidenceRefs: []string{la.Evidence},
					Status: schema.StateObserved, Endpoint: schema.StateUnknown, MitreATTACK: "T1562.001",
					FalsePositive: "Orchestrations that intentionally let subagents maintain memory.",
				})
			}
		}
		if fr.Attributed > 0 {
			flag(schema.Finding{
				RuleID: "INSTRUCTION_FILE_WRITTEN_BY_AGENT", Severity: "INFO", Title: "Agent Wrote to Its Own Instruction File",
				Description:  fmt.Sprintf("%d of %d non-empty lines in %s are attributable to agent writes (%d write events). Review the attributed lines; unattributed lines predate the evidence or were edited outside it.", fr.Attributed, fr.Attributed+fr.Unattributed, fr.LogicalPath, fr.Writes),
				EvidenceRefs: []string{fr.LogicalPath + " (artifact " + short(fr.ArtifactID) + ")"},
				Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
				FalsePositive: "Expected when users ask agents to maintain memory files.",
			})
		}
	}
	for _, w := range rep.OtherWrite {
		if w.Trigger == "tool_result" {
			flag(schema.Finding{
				RuleID: "INSTRUCTION_FROM_TOOL_RESULT", Severity: "HIGH", Title: "Instruction File Written From Tool Output (file not collected)",
				Description: fmt.Sprintf("Agent %s wrote %s via %s right after content came back from %s: %q. The file itself was not in the collection; collect the project to attribute line by line.", w.Event.AgentID, w.Path, w.Event.Tool, w.TrigInfo, w.Snippet),
				SessionID:   w.Event.SessionID, AgentID: w.Event.AgentID, EvidenceRefs: []string{ref(w.Event)},
				Status: schema.StateObserved, Endpoint: schema.StateUnknown, MitreATLAS: "AML.T0051", MitreATTACK: "T1547",
			})
		}
		if ph, ok := detect.InjectionPhrase(w.Content); ok {
			flag(schema.Finding{
				RuleID: "INSTRUCTION_INJECTION_PHRASE", Severity: "HIGH", Title: "Override Phrase Written Into an Instruction File",
				Description: fmt.Sprintf("Agent %s wrote %q into %s.", w.Event.AgentID, ph, w.Path),
				SessionID:   w.Event.SessionID, AgentID: w.Event.AgentID, EvidenceRefs: []string{ref(w.Event)},
				Status: schema.StateObserved, Endpoint: schema.StateUnknown, MitreATLAS: "AML.T0051",
			})
		}
	}
	return out
}

// ---- helpers ----

func readManifest(pkgDir string) (*casepkg.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "manifest.json"))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	var man casepkg.Manifest
	if err := json.Unmarshal(data, &man); err != nil {
		return nil, fmt.Errorf("parse manifest: %w", err)
	}
	return &man, nil
}

func normPath(p string) string { return strings.ToLower(strings.ReplaceAll(p, "\\", "/")) }

// pathsMatch compares an agent-written path with a collected logical path
// (absolute vs profile-relative): equal, or one is a suffix of the other
// at a path boundary.
func pathsMatch(a, b string) bool {
	a, b = normPath(a), normPath(b)
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	a1, b1 := strings.TrimPrefix(a, "/"), strings.TrimPrefix(b, "/")
	return strings.HasSuffix(a1, "/"+b1) || strings.HasSuffix(b1, "/"+a1) || a1 == b1
}

func looksText(b []byte) bool {
	n := len(b)
	if n > 8192 {
		n = 8192
	}
	for i := 0; i < n; i++ {
		if b[i] == 0 {
			return false
		}
	}
	return true
}

func ref(ev schema.Event) string {
	return fmt.Sprintf("%s:%d (artifact %s, offset %d)", ev.SourcePath, ev.SourceLine, short(ev.SourceArtifact), ev.SourceOffset)
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

func trimTo(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		return string(r[:n]) + "…"
	}
	return s
}
