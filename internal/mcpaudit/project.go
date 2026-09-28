package mcpaudit

import (
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// projectConfigs are the MCP config files agents load from a working tree
// (repo-relative, lowercase). A repository that ships one gets its servers
// started by whoever opens it with that agent.
var projectConfigs = map[string]struct {
	host string
	f    format
}{
	".mcp.json":                   {"claude-code", fmtMCPServers},
	".cursor/mcp.json":            {"cursor", fmtMCPServers},
	".vscode/mcp.json":            {"vscode", fmtServers},
	".gemini/settings.json":       {"gemini-cli", fmtMCPServers},
	".codex/config.toml":          {"codex-cli", fmtCodexTOML},
	"opencode.json":               {"opencode", fmtOpenCode},
	".roo/mcp.json":               {"roo-code", fmtMCPServers},
	".kiro/settings/mcp.json":     {"kiro", fmtMCPServers},
	".amazonq/mcp.json":           {"amazon-q", fmtMCPServers},
	".windsurf/mcp.json":          {"windsurf", fmtMCPServers},
	".claude/settings.json":       {"claude-code", fmtClaudeSettings},
	".claude/settings.local.json": {"claude-code", fmtClaudeSettings},
}

// IsProjectConfig reports whether a repo-relative path is an MCP config an
// agent loads from the working tree.
func IsProjectConfig(rel string) bool {
	_, ok := projectConfigs[strings.ToLower(rel)]
	return ok
}

// EvaluateProjectFile parses one repo-relative MCP config and returns its
// inventory and the audit findings (scope "project"). Nothing is resolved:
// the repository is someone else's code, not this host's configuration.
func EvaluateProjectFile(rel string, data []byte) (*Inventory, []schema.Finding) {
	pc, ok := projectConfigs[strings.ToLower(rel)]
	if !ok {
		return nil, nil
	}
	inv := &Inventory{Source: rel, Mode: "package"}
	parseInto(inv, pc.host, "project", rel, rel, pc.f, data)
	finish(inv)
	inv.Configs = []string{rel}
	return inv, Evaluate(inv)
}

// StripJSONC removes JSONC comments and trailing commas (VS Code, Cursor
// and Claude settings files accept both).
func StripJSONC(b []byte) []byte { return stripJSONC(b) }
