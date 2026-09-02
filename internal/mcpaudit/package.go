package mcpaudit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/schema"
)

// ScanPackage audits the MCP configuration captured in a sealed package:
// every collected artifact whose logical path is a known MCP config is
// parsed, and cached tool manifests are scanned for description poisoning.
func ScanPackage(pkgDir string) (*Inventory, []schema.Finding, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "manifest.json"))
	if err != nil {
		return nil, nil, fmt.Errorf("read manifest: %w", err)
	}
	var man casepkg.Manifest
	if err := json.Unmarshal(data, &man); err != nil {
		return nil, nil, fmt.Errorf("parse manifest: %w", err)
	}
	inv := &Inventory{Source: pkgDir, Mode: "package"}
	var extra []schema.Finding
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK || a.ArtifactID == "" {
			continue
		}
		blob := filepath.Join(pkgDir, "raw", a.ArtifactID)
		host, scope, f, ok := classify(a.LogicalPath)
		if ok {
			b, rok := readBounded(blob, inv)
			if !rok {
				continue
			}
			inv.Configs = append(inv.Configs, a.LogicalPath)
			parseInto(inv, host, scope, blob, a.LogicalPath, f, b)
			continue
		}
		// Cached tool manifests live in state/config dirs; cheap marker check first.
		if isType(a, "product_config", "product_state", "debug_logs", "managed_config") && a.Size <= MaxConfigBytes {
			b, rok := readBounded(blob, inv)
			if !rok || !bytes.Contains(b, []byte("inputSchema")) {
				continue
			}
			for _, t := range extractTools(b) {
				if ph, ok := injectionPhrase(t.Description); ok {
					extra = append(extra, schema.Finding{
						RuleID: "MCP_TOOL_DESCRIPTION_POISONING", Severity: "CRITICAL", Title: "Instruction Payload in Cached MCP Tool Description",
						Description:  fmt.Sprintf("Cached tool manifest declares tool %q with an instruction-override phrase (%q) in its description. Descriptions enter the model's context every session.", t.Name, ph),
						EvidenceRefs: []string{fmt.Sprintf("%s (artifact %s)", a.LogicalPath, short(a.ArtifactID))},
						Status:       schema.StateObserved, Endpoint: schema.StateUnknown, MitreATLAS: "AML.T0053",
						FalsePositive: "Tools documenting prompt-injection defenses can match; read the full description.",
						Related:       []string{"product: " + a.Product},
					})
				}
			}
		}
	}
	finish(inv)
	return inv, extra, nil
}

// classify maps a logical path to (host, scope, format) using the same
// location table as live mode, plus repo-scoped project files.
func classify(logical string) (host, scope string, f format, ok bool) {
	p := strings.ReplaceAll(logical, "\\", "/")
	for _, loc := range locations {
		for _, rel := range loc.rel {
			r := strings.TrimPrefix(rel, "/")
			if strings.HasSuffix(p, "/"+r) || p == r || strings.HasSuffix(p, r) && strings.HasPrefix(r, ".") {
				return loc.host, loc.scope, loc.format, true
			}
		}
	}
	base := filepath.Base(p)
	if pf, ok := projectFiles[base]; ok {
		// User-level copies of these names are matched above; anything
		// else with the name is project-scoped.
		return pf.host, "project", pf.format, true
	}
	return "", "", 0, false
}

func isType(a casepkg.ArtifactRecord, types ...string) bool {
	for _, t := range types {
		if a.ArtifactType == t {
			return true
		}
	}
	return false
}

func short(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// extractTools walks arbitrary JSON and returns objects shaped like MCP
// tool declarations ({name, description, inputSchema}).
func extractTools(data []byte) []Tool {
	var doc any
	if err := json.Unmarshal(stripJSONC(data), &doc); err != nil {
		return nil
	}
	var out []Tool
	var walk func(v any, depth int)
	walk = func(v any, depth int) {
		if depth > 12 {
			return
		}
		switch t := v.(type) {
		case map[string]any:
			name, _ := t["name"].(string)
			desc, _ := t["description"].(string)
			if _, has := t["inputSchema"]; has && name != "" {
				out = append(out, Tool{Name: name, Description: desc})
			}
			keys := make([]string, 0, len(t))
			for k := range t {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for _, k := range keys {
				walk(t[k], depth+1)
			}
		case []any:
			for _, e := range t {
				walk(e, depth+1)
			}
		}
	}
	walk(doc, 0)
	return out
}
