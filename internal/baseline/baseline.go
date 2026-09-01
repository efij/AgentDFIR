// Package baseline implements org known-good profiles and package
// diffing — the deterministic mechanism behind every *_CHANGED and
// UNEXPECTED_* detection ("unexpected relative to what?").
package baseline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/casepkg"
)

// configCategories are the artifact categories captured in a baseline.
var configCategories = map[string]bool{
	"product_config":     true,
	"managed_config":     true,
	"agent_definitions":  true,
	"agent_instructions": true,
}

// Baseline is a known-good snapshot of agent configuration state.
type Baseline struct {
	CreatedUTC    string            `json:"created_utc"`
	SourceCaseID  string            `json:"source_case_id"`
	SourcePackage string            `json:"source_package_hashes,omitempty"`
	Artifacts     map[string]string `json:"artifacts"`   // logical_path -> sha256
	Rules         map[string]string `json:"rules"`       // logical_path -> collector rule id
	MCPServers    []string          `json:"mcp_servers"` // declared MCP server names
}

// Snapshot extracts the baseline-relevant state from a sealed package.
func Snapshot(pkgDir string) (*Baseline, error) {
	man, err := readManifest(pkgDir)
	if err != nil {
		return nil, err
	}
	b := &Baseline{
		CreatedUTC:   man.CreatedUTC,
		SourceCaseID: man.CaseID,
		Artifacts:    map[string]string{},
		Rules:        map[string]string{},
	}
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK || !configCategories[a.ArtifactType] {
			continue
		}
		b.Artifacts[a.LogicalPath] = a.ArtifactID
		b.Rules[a.LogicalPath] = a.CollectorRule
		if a.CollectorRule == "claude.config" || strings.HasSuffix(a.LogicalPath, "mcp.json") ||
			strings.HasSuffix(a.LogicalPath, "mcp-config.json") {
			for _, s := range mcpServersFromBlob(filepath.Join(pkgDir, "raw", a.ArtifactID)) {
				b.MCPServers = append(b.MCPServers, s)
			}
		}
	}
	sort.Strings(b.MCPServers)
	return b, nil
}

// Save writes a baseline JSON file.
func (b *Baseline) Save(path string) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// Load reads a baseline JSON file.
func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var b Baseline
	if err := json.Unmarshal(data, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

// Change is one drift item between a baseline and a package.
type Change struct {
	Kind        string // ADDED | REMOVED | MODIFIED | UNEXPECTED_MCP_SERVER
	LogicalPath string
	Rule        string
	Detail      string
}

// Check compares a package against a baseline.
func Check(pkgDir string, base *Baseline) ([]Change, error) {
	cur, err := Snapshot(pkgDir)
	if err != nil {
		return nil, err
	}
	return compare(base.Artifacts, base.Rules, base.MCPServers,
		cur.Artifacts, cur.Rules, cur.MCPServers), nil
}

// Diff compares two sealed packages (config-relevant artifacts).
func Diff(pkgA, pkgB string) ([]Change, error) {
	a, err := Snapshot(pkgA)
	if err != nil {
		return nil, err
	}
	b, err := Snapshot(pkgB)
	if err != nil {
		return nil, err
	}
	return compare(a.Artifacts, a.Rules, a.MCPServers, b.Artifacts, b.Rules, b.MCPServers), nil
}

func compare(oldArt, oldRules map[string]string, oldMCP []string,
	newArt, newRules map[string]string, newMCP []string) []Change {
	var out []Change
	for path, hash := range newArt {
		oldHash, ok := oldArt[path]
		switch {
		case !ok:
			out = append(out, Change{Kind: "ADDED", LogicalPath: path, Rule: newRules[path]})
		case oldHash != hash:
			out = append(out, Change{Kind: "MODIFIED", LogicalPath: path, Rule: newRules[path],
				Detail: fmt.Sprintf("hash %.12s -> %.12s", oldHash, hash)})
		}
	}
	for path := range oldArt {
		if _, ok := newArt[path]; !ok {
			out = append(out, Change{Kind: "REMOVED", LogicalPath: path, Rule: oldRules[path]})
		}
	}
	known := map[string]bool{}
	for _, s := range oldMCP {
		known[s] = true
	}
	for _, s := range newMCP {
		if !known[s] {
			out = append(out, Change{Kind: "UNEXPECTED_MCP_SERVER", LogicalPath: s,
				Detail: "MCP server not present in baseline"})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].LogicalPath < out[j].LogicalPath
	})
	return out
}

// RuleForChange maps a drift item to its detection rule ID.
func RuleForChange(c Change) string {
	switch {
	case c.Kind == "UNEXPECTED_MCP_SERVER":
		return "UNEXPECTED_MCP_SERVER"
	case strings.Contains(c.Rule, "hooks"):
		return "HOOK_CHANGED"
	case strings.Contains(c.Rule, "skills"):
		return "SKILL_CHANGED"
	case strings.Contains(c.Rule, "plugins"):
		return "PLUGIN_CHANGED"
	case strings.Contains(c.Rule, "agents") || strings.Contains(c.Rule, "commands"):
		return "AGENT_DEFINITION_CHANGED"
	case strings.Contains(c.Rule, "config") || strings.Contains(c.Rule, "settings"):
		return "MCP_CONFIG_CHANGED"
	default:
		return "SECURITY_CONTROL_CHANGED"
	}
}

// mcpServersFromBlob extracts declared MCP server names from a config
// blob ({"mcpServers":{name:{...}}}). Hostile input: bounded read,
// tolerant parse, names only (never commands or env).
func mcpServersFromBlob(path string) []string {
	data, err := boundedRead(path, 8<<20)
	if err != nil {
		return nil
	}
	var cfg struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil
	}
	var names []string
	for name := range cfg.MCPServers {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func boundedRead(path string, max int64) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > max {
		return nil, fmt.Errorf("blob exceeds bound")
	}
	return os.ReadFile(path)
}

func readManifest(pkgDir string) (*casepkg.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var man casepkg.Manifest
	if err := json.Unmarshal(data, &man); err != nil {
		return nil, err
	}
	return &man, nil
}
