package ioc

import (
	"fmt"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// Findings turns verdict hits into KNOWN_INCIDENT_IOC findings, one per
// incident, indicator and place. Mentions are not findings.
func Findings(vs []Verdict) []schema.Finding {
	var out []schema.Finding
	for _, v := range vs {
		for _, h := range v.Hits {
			title := "Indicator of a Known Incident: " + v.Incident.Title
			if v.Status == "SIMULATED" {
				title = "[SIMULATED] " + title
			}
			when := ""
			if h.FirstSeen != "" {
				when = fmt.Sprintf(" First seen %s", h.FirstSeen)
				if h.LastSeen != "" && h.LastSeen != h.FirstSeen {
					when += ", last " + h.LastSeen
				}
				if h.TimeSrc != "" {
					when += " (" + h.TimeSrc + " time)"
				}
				when += "."
			}
			desc := fmt.Sprintf("%s %s in %s (%d time(s)).%s %s", h.Indicator.Label(), whereText(h.Where), surfaceText(h.Surface), h.Count, when, v.Incident.Summary)
			if h.Indicator.Note != "" {
				desc += " Indicator note: " + h.Indicator.Note + "."
			}
			rel := []string{"incident: " + v.Incident.ID, "indicator: " + h.Indicator.Label(), "where: " + h.Where, "surface: " + h.Surface}
			if h.InWindow != "" {
				rel = append(rel, "inside incident window: "+h.InWindow)
			}
			for _, s := range v.Incident.Sources {
				rel = append(rel, "source: "+s)
			}
			attack := "T1195.002"
			if h.Indicator.Kind == KindDomain || h.Indicator.Kind == KindURL {
				attack = "T1071.001"
			}
			status := h.State
			if status == "" {
				status = schema.StateObserved
			}
			out = append(out, schema.Finding{
				RuleID: "KNOWN_INCIDENT_IOC", Severity: h.Indicator.Severity(h.Where),
				Title: title, Description: strings.TrimSpace(desc),
				EvidenceRefs: []string{h.Evidence}, Related: rel,
				Status: status, Endpoint: schema.StateUnknown,
				MitreATTACK: attack, MitreATLAS: "AML.T0010",
				FalsePositive: "A security write-up, detection rule or test fixture on disk can carry the same strings; check the evidence location.",
			})
		}
	}
	return out
}

func whereText(w string) string {
	switch w {
	case WhereObserved:
		return "observed"
	case WhereOutput:
		return "seen in tool output"
	}
	return "mentioned"
}

func surfaceText(s string) string {
	switch s {
	case "command":
		return "a command the agent ran"
	case "file":
		return "a file the agent touched"
	case "tool_output":
		return "a tool result"
	case "config":
		return "collected configuration or instructions"
	case "shell_history":
		return "shell history"
	case "shell_rc":
		return "a shell startup file"
	case "transcript":
		return "a transcript"
	case "mcp_inventory":
		return "a configured MCP server"
	case "lockfile":
		return "a lockfile (installed dependency)"
	case "filesystem":
		return "a file or directory on disk"
	case "artifact_hash":
		return "a file whose SHA-256 matches"
	}
	return s
}
