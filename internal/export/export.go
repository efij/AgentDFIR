// Package export renders normalized findings and events into
// interoperability formats: STIX 2.1 bundles and OpenTelemetry
// (GenAI/agent semantic conventions). Plan §10, §24.
package export

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/efij/AgentDFIR/internal/schema"
)

// --- STIX 2.1 ---

// WriteSTIX writes findings as a STIX 2.1 bundle (indicator +
// observed-data objects). Deterministic IDs are derived from content so
// re-exports are stable.
func WriteSTIX(findings []schema.Finding, caseID, path string) error {
	objects := []map[string]any{}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, f := range findings {
		id := "indicator--" + deterministicUUID("indicator", caseID, f.RuleID, f.AgentID, f.SessionID)
		obj := map[string]any{
			"type":            "indicator",
			"spec_version":    "2.1",
			"id":              id,
			"created":         now,
			"modified":        now,
			"name":            f.Title,
			"description":     f.Description,
			"indicator_types": []string{"anomalous-activity"},
			"confidence":      confidence(f.Status),
			"labels":          []string{f.RuleID, "severity:" + f.Severity},
		}
		if refs := mitreRefs(f); len(refs) > 0 {
			obj["external_references"] = refs
		}
		objects = append(objects, obj)
	}
	bundle := map[string]any{
		"type":    "bundle",
		"id":      "bundle--" + deterministicUUID("bundle", caseID),
		"objects": objects,
	}
	return writeJSON(path, bundle)
}

func mitreRefs(f schema.Finding) []map[string]string {
	var refs []map[string]string
	if f.MitreATLAS != "" {
		refs = append(refs, map[string]string{"source_name": "mitre-atlas", "external_id": f.MitreATLAS})
	}
	if f.MitreATTACK != "" {
		refs = append(refs, map[string]string{"source_name": "mitre-attack", "external_id": f.MitreATTACK})
	}
	return refs
}

func confidence(state string) int {
	switch state {
	case schema.StateCorroborated:
		return 90
	case schema.StateObserved:
		return 70
	case schema.StateReported:
		return 30
	default:
		return 10
	}
}

// --- OpenTelemetry (GenAI semantic conventions) ---

// WriteOTel writes events as OTLP-style log records mapped to GenAI/agent
// semantic conventions, with AgentDFIR-specific attributes under the
// agentdfir.* namespace (plan §10). One JSON document (OTLP/JSON logs).
func WriteOTel(events []schema.Event, path string) error {
	records := []map[string]any{}
	for _, e := range events {
		attrs := map[string]any{
			"gen_ai.provider.name":          e.Vendor,
			"gen_ai.agent.id":               e.AgentID,
			"gen_ai.operation.name":         otelOperation(e),
			"agentdfir.event_type":          e.EventType,
			"agentdfir.corroboration_state": e.Corroboration,
			"agentdfir.source_artifact":     e.SourceArtifact,
			"agentdfir.source_line":         e.SourceLine,
			"session.id":                    e.SessionID,
		}
		if e.Model != "" {
			attrs["gen_ai.request.model"] = e.Model
		}
		if e.Tool != "" {
			attrs["gen_ai.tool.name"] = e.Tool
		}
		if e.MCPServer != "" {
			attrs["agentdfir.mcp_server"] = e.MCPServer
		}
		if e.ParentAgentID != "" {
			attrs["agentdfir.parent_agent_id"] = e.ParentAgentID
		}
		records = append(records, map[string]any{
			"timeUnixNano": otelTime(e.Timestamp),
			"severityText": "INFO",
			"body":         map[string]any{"stringValue": e.Summary},
			"attributes":   otelAttrs(attrs),
		})
	}
	doc := map[string]any{
		"resourceLogs": []map[string]any{{
			"resource": map[string]any{
				"attributes": otelAttrs(map[string]any{"service.name": "agentdfir"}),
			},
			"scopeLogs": []map[string]any{{
				"scope":      map[string]any{"name": "agentdfir", "version": "0.1"},
				"logRecords": records,
			}},
		}},
	}
	return writeJSON(path, doc)
}

func otelOperation(e schema.Event) string {
	switch e.EventType {
	case schema.EventToolCall:
		return "execute_tool"
	case schema.EventAgentSpawn:
		return "create_agent"
	case schema.EventModelResponse, schema.EventHumanPrompt:
		return "chat"
	default:
		return e.EventType
	}
}

func otelAttrs(m map[string]any) []map[string]any {
	var out []map[string]any
	for k, v := range m {
		var val map[string]any
		switch t := v.(type) {
		case int:
			val = map[string]any{"intValue": t}
		default:
			val = map[string]any{"stringValue": fmt.Sprint(t)}
		}
		out = append(out, map[string]any{"key": k, "value": val})
	}
	return out
}

func otelTime(ts string) string {
	t, err := time.Parse(time.RFC3339, ts)
	if err != nil {
		return "0"
	}
	return fmt.Sprint(t.UnixNano())
}

func deterministicUUID(parts ...string) string {
	h := sha1.New()
	for _, p := range parts {
		h.Write([]byte(p))
		h.Write([]byte{0})
	}
	sum := h.Sum(nil)
	b := sum[:16]
	b[6] = (b[6] & 0x0f) | 0x50 // version 5-ish
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%s-%s-%s-%s-%s",
		hex.EncodeToString(b[0:4]), hex.EncodeToString(b[4:6]),
		hex.EncodeToString(b[6:8]), hex.EncodeToString(b[8:10]),
		hex.EncodeToString(b[10:16]))
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}
