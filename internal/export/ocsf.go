package export

import (
	"bufio"
	"encoding/json"
	"os"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/netdest"
	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/version"
)

// --- OCSF 1.3 (Open Cybersecurity Schema Framework) ---
//
// Events and findings are emitted as OCSF-shaped JSON lines so they land
// in SIEM/lake pipelines (Security Lake, Splunk OCSF add-ons, Sentinel
// normalization) without a custom parser. Mapping:
//
//	tool_call with a shell command  → Process Activity (1007, Launch)
//	tool_call touching a file       → File System Activity (1001)
//	every other event               → API Activity (6003) with api.operation = event type/tool
//	finding                         → Detection Finding (2004)
//
// AgentDFIR-specific facts (corroboration state, agent lineage, MCP server,
// evidence reference) travel under `unmapped` — OCSF's sanctioned place
// for vendor fields — so nothing forensic is lost in translation.

const ocsfVersion = "1.3.0"

func ocsfMetadata(uid, logName string) map[string]any {
	return map[string]any{
		"version":  ocsfVersion,
		"uid":      uid,
		"log_name": logName,
		"product": map[string]any{
			"name":        "AgentDFIR",
			"vendor_name": "AgentDFIR",
			"version":     version.Version,
		},
	}
}

func ocsfTime(ts string) int64 {
	t, err := time.Parse(time.RFC3339Nano, ts)
	if err != nil {
		t, err = time.Parse(time.RFC3339, ts)
		if err != nil {
			return 0
		}
	}
	return t.UnixMilli()
}

// WriteOCSFEvents writes normalized events as OCSF JSON lines.
func WriteOCSFEvents(events []schema.Event, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	for _, e := range events {
		if err := enc.Encode(OCSFEvent(e)); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// OCSFEvent maps one normalized event to an OCSF object.
func OCSFEvent(e schema.Event) map[string]any {
	classUID, categoryUID, activityID, activityName := 6003, 6, 99, "Other"
	obj := map[string]any{}

	switch {
	case e.EventType == schema.EventToolCall && e.Command != "":
		classUID, categoryUID, activityID, activityName = 1007, 1, 1, "Launch"
		name := e.Command
		if i := strings.IndexAny(name, " \t"); i > 0 {
			name = name[:i]
		}
		obj["process"] = map[string]any{"cmd_line": e.Command, "name": name}
	case e.EventType == schema.EventToolCall && e.File != "":
		classUID, categoryUID = 1001, 1
		activityID, activityName = fileActivity(e.Action, e.Tool)
		obj["file"] = map[string]any{"path": e.File, "name": baseName(e.File), "type_id": 1}
	default:
		op := e.EventType
		if e.Tool != "" {
			op = e.Tool
		}
		obj["api"] = map[string]any{"operation": op, "service": map[string]any{"name": e.Product}}
		switch e.EventType {
		case schema.EventToolCall, schema.EventAgentSpawn:
			activityID, activityName = 1, "Create"
		case schema.EventToolResult, schema.EventHumanPrompt, schema.EventModelResponse:
			activityID, activityName = 2, "Read"
		}
	}

	obj["class_uid"] = classUID
	obj["category_uid"] = categoryUID
	obj["activity_id"] = activityID
	obj["activity_name"] = activityName
	obj["type_uid"] = classUID*100 + activityID
	obj["severity_id"] = 1 // Informational — events are facts, findings carry severity
	obj["time"] = ocsfTime(e.Timestamp)
	obj["message"] = e.Summary
	obj["metadata"] = ocsfMetadata(e.EventID, e.SourcePath)
	if e.Host != "" {
		obj["device"] = map[string]any{"hostname": e.Host, "type_id": 0}
	}
	actor := map[string]any{"app_name": e.Product}
	if e.User != "" {
		actor["user"] = map[string]any{"name": e.User}
	}
	obj["actor"] = actor

	var observables []map[string]any
	if e.NetworkDest != "" {
		host := netdest.Host(e.NetworkDest)
		typeID := 1 // Hostname
		if isIPv4(host) {
			typeID = 2 // IP Address
		}
		obj["dst_endpoint"] = map[string]any{"hostname": host}
		observables = append(observables, map[string]any{"name": "dst_endpoint.hostname", "type_id": typeID, "value": host})
	}
	if e.Command != "" {
		observables = append(observables, map[string]any{"name": "process.cmd_line", "type_id": 13, "value": e.Command})
	}
	if e.File != "" {
		observables = append(observables, map[string]any{"name": "file.path", "type_id": 26, "value": e.File})
	}
	if len(observables) > 0 {
		obj["observables"] = observables
	}

	obj["unmapped"] = map[string]any{
		"agentdfir.event_type":          e.EventType,
		"agentdfir.actor_type":          e.ActorType,
		"agentdfir.corroboration_state": e.Corroboration,
		"agentdfir.session_id":          e.SessionID,
		"agentdfir.agent_id":            e.AgentID,
		"agentdfir.parent_agent_id":     e.ParentAgentID,
		"agentdfir.task_id":             e.TaskID,
		"agentdfir.vendor":              e.Vendor,
		"agentdfir.product":             e.Product,
		"agentdfir.model":               e.Model,
		"agentdfir.tool":                e.Tool,
		"agentdfir.tool_call_id":        e.ToolCallID,
		"agentdfir.mcp_server":          e.MCPServer,
		"agentdfir.mcp_tool":            e.MCPTool,
		"agentdfir.action":              e.Action,
		"agentdfir.result":              e.Result,
		"agentdfir.source_artifact":     e.SourceArtifact,
		"agentdfir.source_line":         e.SourceLine,
		"agentdfir.source_offset":       e.SourceOffset,
		"agentdfir.case_id":             e.CaseID,
	}
	return obj
}

func fileActivity(action, tool string) (int, string) {
	s := strings.ToLower(action + " " + tool)
	switch {
	case strings.Contains(s, "delete") || strings.Contains(s, "remove"):
		return 4, "Delete"
	case strings.Contains(s, "write") || strings.Contains(s, "create"):
		return 1, "Create"
	case strings.Contains(s, "edit") || strings.Contains(s, "update") || strings.Contains(s, "patch"):
		return 3, "Update"
	case strings.Contains(s, "read") || strings.Contains(s, "view") || strings.Contains(s, "cat"):
		return 2, "Read"
	default:
		return 99, "Other"
	}
}

// WriteOCSFFindings writes findings as OCSF Detection Finding JSON lines.
func WriteOCSFFindings(findings []schema.Finding, caseID, path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)
	now := time.Now().UTC().UnixMilli()
	for _, fd := range findings {
		if err := enc.Encode(OCSFFinding(fd, caseID, now)); err != nil {
			f.Close()
			return err
		}
	}
	if err := w.Flush(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// OCSFFinding maps one finding to an OCSF Detection Finding (2004).
// Findings carry no timestamp of their own; `time` is the export time and
// the evidence reference points at the timestamped events.
func OCSFFinding(fd schema.Finding, caseID string, nowMillis int64) map[string]any {
	uid := deterministicUUID("finding", caseID, fd.RuleID, fd.SessionID, fd.AgentID, strings.Join(fd.EvidenceRefs, "|"))
	info := map[string]any{
		"uid":   uid,
		"title": fd.Title,
		"desc":  fd.Description,
		"analytic": map[string]any{
			"name":    fd.RuleID,
			"type_id": 1, // Rule
			"type":    "Rule",
		},
		"types": []string{"Agent Activity"},
	}
	var attacks []map[string]any
	if fd.MitreATTACK != "" {
		attacks = append(attacks, map[string]any{
			"technique": map[string]any{"uid": fd.MitreATTACK},
			"version":   "ATT&CK",
		})
	}
	if fd.MitreATLAS != "" {
		attacks = append(attacks, map[string]any{
			"technique": map[string]any{"uid": fd.MitreATLAS},
			"version":   "ATLAS",
		})
	}
	if len(attacks) > 0 {
		info["attacks"] = attacks
	}
	sevID, sevName := ocsfSeverity(fd.Severity)
	confID, confName := ocsfConfidence(fd.Status)
	obj := map[string]any{
		"class_uid":     2004,
		"category_uid":  2,
		"activity_id":   1,
		"activity_name": "Create",
		"type_uid":      200401,
		"severity_id":   sevID,
		"severity":      sevName,
		"confidence_id": confID,
		"confidence":    confName,
		"status_id":     1,
		"status":        "New",
		"time":          nowMillis,
		"message":       fd.Title,
		"finding_info":  info,
		"metadata":      ocsfMetadata(uid, "agentdfir.findings"),
		"evidences":     ocsfEvidences(fd),
		"unmapped": map[string]any{
			"agentdfir.rule_id":                fd.RuleID,
			"agentdfir.session_id":             fd.SessionID,
			"agentdfir.agent_id":               fd.AgentID,
			"agentdfir.parent_agent_id":        fd.ParentAgentID,
			"agentdfir.corroboration_state":    fd.Status,
			"agentdfir.endpoint_corroboration": fd.Endpoint,
			"agentdfir.related":                fd.Related,
			"agentdfir.false_positive_notes":   fd.FalsePositive,
			"agentdfir.case_id":                caseID,
		},
	}
	return obj
}

func ocsfEvidences(fd schema.Finding) []map[string]any {
	var out []map[string]any
	for _, ref := range fd.EvidenceRefs {
		path, line := splitEvidenceRef(ref)
		ev := map[string]any{"data": map[string]any{"reference": ref}}
		if path != "" {
			ev["file"] = map[string]any{"path": path, "name": baseName(path), "type_id": 1}
		}
		if line > 0 {
			ev["data"].(map[string]any)["line"] = line
		}
		out = append(out, ev)
	}
	return out
}

func ocsfSeverity(s string) (int, string) {
	switch s {
	case "INFO":
		return 1, "Informational"
	case "LOW":
		return 2, "Low"
	case "MEDIUM":
		return 3, "Medium"
	case "HIGH":
		return 4, "High"
	case "CRITICAL":
		return 5, "Critical"
	default:
		return 0, "Unknown"
	}
}

func ocsfConfidence(state string) (int, string) {
	switch state {
	case schema.StateCorroborated:
		return 3, "High"
	case schema.StateObserved, schema.StatePartial:
		return 2, "Medium"
	case schema.StateReported, schema.StateRequested:
		return 1, "Low"
	default:
		return 0, "Unknown"
	}
}

func isIPv4(h string) bool {
	parts := strings.Split(h, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return false
			}
		}
	}
	return true
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}
