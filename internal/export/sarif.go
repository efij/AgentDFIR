package export

import (
	"net/url"
	"regexp"
	"sort"
	"strconv"

	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/version"
)

// --- SARIF 2.1.0 ---
//
// Findings as a Static Analysis Results Interchange Format log so they
// load in the GitHub code-scanning tab, VS Code SARIF viewer, and any
// SARIF-aware pipeline. Each finding's first evidence reference becomes
// the physical location (source logical path + line).

var evidenceRefRe = regexp.MustCompile(`^(.*?):(\d+) \(artifact `)

// splitEvidenceRef parses "path:line (artifact …)" into its parts.
func splitEvidenceRef(ref string) (path string, line int) {
	m := evidenceRefRe.FindStringSubmatch(ref)
	if m == nil {
		return "", 0
	}
	n, _ := strconv.Atoi(m[2])
	return m[1], n
}

// WriteSARIF writes findings as a SARIF 2.1.0 log.
func WriteSARIF(findings []schema.Finding, caseID, path string) error {
	return writeJSON(path, SARIF(findings, caseID))
}

// SARIF builds the SARIF document.
func SARIF(findings []schema.Finding, caseID string) map[string]any {
	// Rules: one per distinct rule ID, stable order.
	byID := map[string]schema.Finding{}
	for _, f := range findings {
		if _, ok := byID[f.RuleID]; !ok {
			byID[f.RuleID] = f
		}
	}
	ids := make([]string, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	index := map[string]int{}
	rules := make([]map[string]any, 0, len(ids))
	for i, id := range ids {
		f := byID[id]
		index[id] = i
		props := map[string]any{"tags": []string{"agentdfir", "severity:" + f.Severity}}
		if f.MitreATTACK != "" {
			props["mitre_attack"] = f.MitreATTACK
			props["tags"] = append(props["tags"].([]string), "attack."+f.MitreATTACK)
		}
		if f.MitreATLAS != "" {
			props["mitre_atlas"] = f.MitreATLAS
			props["tags"] = append(props["tags"].([]string), "atlas."+f.MitreATLAS)
		}
		if f.FalsePositive != "" {
			props["false_positive_notes"] = f.FalsePositive
		}
		rules = append(rules, map[string]any{
			"id":                   id,
			"name":                 id,
			"shortDescription":     map[string]any{"text": f.Title},
			"fullDescription":      map[string]any{"text": f.Description},
			"defaultConfiguration": map[string]any{"level": sarifLevel(f.Severity)},
			"properties":           props,
		})
	}

	results := make([]map[string]any, 0, len(findings))
	for _, f := range findings {
		r := map[string]any{
			"ruleId":    f.RuleID,
			"ruleIndex": index[f.RuleID],
			"level":     sarifLevel(f.Severity),
			"message":   map[string]any{"text": f.Title + ": " + f.Description},
			"partialFingerprints": map[string]any{
				"agentdfir/v1": deterministicUUID("sarif", caseID, f.RuleID, f.SessionID, f.AgentID, firstOr(f.EvidenceRefs)),
			},
			"properties": map[string]any{
				"corroboration_state":    f.Status,
				"endpoint_corroboration": f.Endpoint,
				"session_id":             f.SessionID,
				"agent_id":               f.AgentID,
				"parent_agent_id":        f.ParentAgentID,
				"related":                f.Related,
				"evidence_refs":          f.EvidenceRefs,
			},
		}
		var locs []map[string]any
		for _, ref := range f.EvidenceRefs {
			p, line := splitEvidenceRef(ref)
			if p == "" {
				continue
			}
			loc := map[string]any{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": (&url.URL{Path: p}).EscapedPath()},
				},
			}
			if line > 0 {
				loc["physicalLocation"].(map[string]any)["region"] = map[string]any{"startLine": line}
			}
			locs = append(locs, loc)
		}
		if len(locs) > 0 {
			r["locations"] = locs
		}
		results = append(results, r)
	}

	return map[string]any{
		"$schema": "https://json.schemastore.org/sarif-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":           "AgentDFIR",
					"version":        version.Version,
					"informationUri": "https://github.com/efij/AgentDFIR",
					"rules":          rules,
				},
			},
			"automationDetails": map[string]any{"id": "agentdfir/" + caseID},
			"results":           results,
		}},
	}
}

func sarifLevel(sev string) string {
	switch sev {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

func firstOr(list []string) string {
	if len(list) > 0 {
		return list[0]
	}
	return ""
}
