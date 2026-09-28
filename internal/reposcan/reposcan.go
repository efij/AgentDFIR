// Package reposcan checks a repository before an AI agent opens it.
//
// The 2025–2026 incidents moved code execution into files dependency
// scanners never read: a `.claude/settings.json` SessionStart hook and a
// `.vscode/tasks.json` folderOpen task committed by the keyv wave of
// Shai-Hulud (August 2026), a project-local `.codex/config.toml` MCP
// command that ran when `codex` started (CVE-2025-61260), a rogue MCP
// server injected into editor configs (SANDWORM_MODE), a README that
// talked Gemini CLI into running a command. Opening the repo is the
// trigger; this scan runs first.
//
// Read-only and bounded: nothing in the repository is executed, symlinks
// are not followed out of the tree, file sizes are capped, and findings
// carry at most a short, secret-masked excerpt — never file contents —
// so a SARIF upload from CI cannot leak what a symlink pointed at.
package reposcan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/efij/AgentDFIR/v3/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// Options bound the scan.
type Options struct {
	MaxFileBytes int64 // per file read; default 4 MiB
	MaxEntries   int   // walk limit; default 500,000
}

// Result is one scan.
type Result struct {
	Root     string           `json:"root"`
	Files    int              `json:"files_checked"`
	Findings []schema.Finding `json:"findings"`
	Notes    []string         `json:"notes,omitempty"`
}

type scanner struct {
	root string
	opt  Options
	res  *Result
	seen map[string]bool // rule+path+detail dedupe
}

// Scan walks root.
func Scan(root string, o Options) (*Result, error) {
	if o.MaxFileBytes <= 0 {
		o.MaxFileBytes = 4 << 20
	}
	if o.MaxEntries <= 0 {
		o.MaxEntries = 500000
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	// Resolved once, so "inside the tree" compares like with like (on
	// macOS /tmp and /var are themselves links).
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", root)
	}
	s := &scanner{root: abs, opt: o, res: &Result{Root: abs}, seen: map[string]bool{}}
	entries := 0
	err = filepath.WalkDir(abs, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		entries++
		if entries > o.MaxEntries {
			s.res.Notes = append(s.res.Notes, fmt.Sprintf("walk stopped after %d entries", o.MaxEntries))
			return filepath.SkipAll
		}
		rel, _ := filepath.Rel(abs, p)
		rel = filepath.ToSlash(rel)
		lrel := strings.ToLower(rel)
		if d.IsDir() {
			switch strings.ToLower(d.Name()) {
			case "node_modules", "vendor", "__pycache__", ".venv", "venv", "target", ".next", "dist", "build":
				if p != abs {
					return filepath.SkipDir
				}
			case ".git":
				s.gitDir(p)
				return filepath.SkipDir
			}
			return nil
		}
		role := roleOf(lrel)
		if d.Type()&os.ModeSymlink != 0 {
			if role != "" {
				s.symlink(p, rel, role)
			}
			return nil
		}
		if !d.Type().IsRegular() || role == "" {
			return nil
		}
		s.res.Files++
		s.file(p, rel, lrel, role)
		return nil
	})
	sort.SliceStable(s.res.Findings, func(i, j int) bool {
		return sevRank(s.res.Findings[i].Severity) > sevRank(s.res.Findings[j].Severity)
	})
	return s.res, err
}

func sevRank(s string) int {
	switch s {
	case "CRITICAL":
		return 5
	case "HIGH":
		return 4
	case "MEDIUM":
		return 3
	case "LOW":
		return 2
	}
	return 1
}

// ---- roles

const (
	roleClaudeSettings = "claude-settings"
	rolePluginHooks    = "plugin-hooks"
	roleCursorHooks    = "cursor-hooks"
	roleMCP            = "mcp-config"
	roleVSTasks        = "vscode-tasks"
	roleVSSettings     = "vscode-settings"
	roleWorkspace      = "code-workspace"
	roleDevcontainer   = "devcontainer"
	roleInstructions   = "instructions"
	rolePackageJSON    = "package-json"
	roleGitattributes  = "gitattributes"
)

var instrDirs = []string{".cursor/rules/", ".kiro/steering/", ".amazonq/rules/", ".roo/rules/", ".windsurf/rules/", ".clinerules/",
	".github/instructions/", ".github/prompts/", ".claude/agents/", ".claude/commands/", ".claude/skills/", ".gemini/commands/"}

var instrNames = map[string]bool{"agents.md": true, "claude.md": true, "claude.local.md": true, "gemini.md": true, ".cursorrules": true,
	".windsurfrules": true, ".clinerules": true, "copilot-instructions.md": true, ".goosehints": true, "conventions.md": false}

// roleOf classifies a lowercased repo-relative path; "" = not an agent surface.
func roleOf(lrel string) string {
	base := path.Base(lrel)
	switch {
	case lrel == ".claude/settings.json" || lrel == ".claude/settings.local.json" || strings.HasSuffix(lrel, "/.claude/settings.json"):
		return roleClaudeSettings
	case strings.HasSuffix(lrel, "hooks/hooks.json") && (strings.Contains(lrel, "plugin") || strings.HasPrefix(lrel, "hooks/") || strings.Contains(lrel, ".claude/")):
		return rolePluginHooks
	case lrel == ".cursor/hooks.json":
		return roleCursorHooks
	case mcpaudit.IsProjectConfig(lrel):
		return roleMCP
	case lrel == ".vscode/tasks.json":
		return roleVSTasks
	case lrel == ".vscode/settings.json":
		return roleVSSettings
	case strings.HasSuffix(base, ".code-workspace"):
		return roleWorkspace
	case lrel == ".devcontainer/devcontainer.json" || lrel == ".devcontainer.json" || strings.HasPrefix(lrel, ".devcontainer/") && base == "devcontainer.json":
		return roleDevcontainer
	case base == "package.json":
		return rolePackageJSON
	case lrel == ".gitattributes":
		return roleGitattributes
	case instrNames[base]:
		return roleInstructions
	}
	for _, d := range instrDirs {
		if strings.HasPrefix(lrel, d) && (strings.HasSuffix(base, ".md") || strings.HasSuffix(base, ".mdc") || strings.HasSuffix(base, ".txt") || !strings.Contains(base, ".")) {
			return roleInstructions
		}
	}
	return ""
}

// ---- helpers

func (s *scanner) add(f schema.Finding, key string) {
	k := f.RuleID + "\x00" + key
	if s.seen[k] {
		return
	}
	s.seen[k] = true
	if f.Status == "" {
		f.Status = schema.StateObserved
	}
	if f.Endpoint == "" {
		f.Endpoint = schema.StateUnknown
	}
	s.res.Findings = append(s.res.Findings, f)
}

func (s *scanner) read(p, rel string) ([]byte, bool) {
	f, err := os.Open(p)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, s.opt.MaxFileBytes+1))
	if err != nil {
		return nil, false
	}
	if int64(len(b)) > s.opt.MaxFileBytes {
		s.add(schema.Finding{RuleID: "REPO_FILE_OVERSIZED", Severity: "MEDIUM", Title: "Agent Configuration File Larger Than the Scan Limit",
			Description:  fmt.Sprintf("%s is larger than %d bytes. Agents still load it; padding a config file past a scanner's size limit is an evasion. The first %d bytes were checked.", rel, s.opt.MaxFileBytes, s.opt.MaxFileBytes),
			EvidenceRefs: []string{rel}, MitreATTACK: "T1027"}, rel)
		b = b[:s.opt.MaxFileBytes]
	}
	return b, true
}

var secretish = regexp.MustCompile(`[A-Za-z0-9_\-+/=]{24,}`)

// excerpt: ≤120 chars, long tokens masked. Enough to recognise a command,
// never enough to carry a secret out through a SARIF upload.
func excerpt(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = secretish.ReplaceAllStringFunc(s, func(t string) string {
		if strings.Contains(t, "/") && !strings.ContainsAny(t, "+=") {
			return t // paths
		}
		return t[:4] + "…"
	})
	if utf8.RuneCountInString(s) > 120 {
		r := []rune(s)
		s = string(r[:117]) + "…"
	}
	return s
}

func parseJSONC(b []byte) (map[string]any, error) {
	var doc map[string]any
	err := json.Unmarshal(stripJSONC(b), &doc)
	return doc, err
}

func (s *scanner) unparseable(rel string, err error) {
	s.add(schema.Finding{RuleID: "REPO_CONFIG_UNPARSEABLE", Severity: "MEDIUM", Title: "Agent Auto-Run Configuration Could Not Be Parsed",
		Description:  fmt.Sprintf("%s could not be parsed (%v). The agent or editor may still accept it; a file crafted to break scanners while staying loadable is an evasion. Read it by hand.", rel, err),
		EvidenceRefs: []string{rel}, MitreATTACK: "T1027"}, rel)
}

// ---- file dispatch

func (s *scanner) file(p, rel, lrel, role string) {
	b, ok := s.read(p, rel)
	if !ok {
		return
	}
	switch role {
	case roleClaudeSettings:
		s.claudeSettings(rel, b)
		if strings.HasPrefix(lrel, ".claude/") {
			s.mcp(rel, b)
		}
	case rolePluginHooks:
		doc, err := parseJSONC(b)
		if err != nil {
			s.unparseable(rel, err)
			return
		}
		s.hooks(rel, doc["hooks"], "plugin hook")
	case roleCursorHooks:
		doc, err := parseJSONC(b)
		if err != nil {
			s.unparseable(rel, err)
			return
		}
		s.hooks(rel, doc["hooks"], "Cursor hook")
	case roleMCP:
		s.mcp(rel, b)
		if lrel == ".gemini/settings.json" {
			if doc, err := parseJSONC(b); err == nil {
				s.hooks(rel, doc["hooks"], "Gemini CLI hook")
			}
		}
		if lrel == ".codex/config.toml" {
			s.codexProject(rel, b)
		}
	case roleVSTasks:
		doc, err := parseJSONC(b)
		if err != nil {
			s.unparseable(rel, err)
			return
		}
		s.tasks(rel, doc["tasks"])
	case roleVSSettings:
		doc, err := parseJSONC(b)
		if err != nil {
			s.unparseable(rel, err)
			return
		}
		s.vscodeSettings(rel, doc)
	case roleWorkspace:
		doc, err := parseJSONC(b)
		if err != nil {
			s.unparseable(rel, err)
			return
		}
		if t, ok := doc["tasks"].(map[string]any); ok {
			s.tasks(rel, t["tasks"])
		}
		if st, ok := doc["settings"].(map[string]any); ok {
			s.vscodeSettings(rel, st)
		}
	case roleDevcontainer:
		doc, err := parseJSONC(b)
		if err != nil {
			s.unparseable(rel, err)
			return
		}
		s.devcontainer(rel, doc)
	case roleInstructions:
		s.instructions(rel, b)
	case rolePackageJSON:
		s.packageJSON(rel, b)
	case roleGitattributes:
		s.gitattributes(rel, b)
	}
}

func (s *scanner) symlink(p, rel, role string) {
	target, _ := os.Readlink(p)
	resolved, err := filepath.EvalSymlinks(p)
	inside := err == nil && (resolved == s.root || strings.HasPrefix(resolved, s.root+string(filepath.Separator)))
	where := "outside the repository"
	if inside {
		where = "inside the repository"
	}
	s.add(schema.Finding{RuleID: "REPO_AGENT_CONFIG_SYMLINK", Severity: "HIGH", Title: "Agent Configuration Is a Symbolic Link",
		Description:  fmt.Sprintf("%s is a symlink to %s (%s). The agent follows it; a reviewer reading the diff sees only a path. A link out of the tree can also point a scanner at your own secrets.", rel, excerpt(target), where),
		EvidenceRefs: []string{rel}, MitreATTACK: "T1036", MitreATLAS: "AML.T0081"}, rel)
	if inside {
		if fi, err := os.Stat(resolved); err == nil && fi.Mode().IsRegular() {
			s.res.Files++
			s.file(resolved, rel, strings.ToLower(rel), role)
		}
	}
}
