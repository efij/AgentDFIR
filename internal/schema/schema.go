// Package schema defines the unified, vendor-neutral agent forensic
// schema: normalized events, entities and relationships. Large or
// sensitive content (prompt bodies, tool outputs) is never duplicated
// here — events reference raw evidence by artifact, offset and hash.
package schema

// Corroboration states (evidence vs claims, plan §12). Aggregate
// precedence: CONTRADICTED > CORROBORATED > PARTIALLY_CORROBORATED >
// OBSERVED > REPORTED > REQUESTED > UNKNOWN.
const (
	StateRequested    = "REQUESTED"
	StateReported     = "REPORTED"
	StateObserved     = "OBSERVED"
	StateCorroborated = "CORROBORATED"
	StatePartial      = "PARTIALLY_CORROBORATED"
	StateContradicted = "CONTRADICTED"
	StateUnknown      = "UNKNOWN"
)

// Event types (controlled vocabulary v0.1).
const (
	EventHumanPrompt   = "human_prompt"
	EventModelResponse = "model_response"
	EventToolCall      = "tool_call"
	EventToolResult    = "tool_result"
	EventAgentSpawn    = "agent_spawn"
	EventAgentMessage  = "agent_message"
	EventSessionMeta   = "session_meta"
	EventTraceGap      = "trace_gap"
)

// Actor types.
const (
	ActorHuman  = "human"
	ActorModel  = "model"
	ActorAgent  = "agent"
	ActorSystem = "system"
)

// Event is one normalized forensic event.
type Event struct {
	EventID        string `json:"event_id"`
	CaseID         string `json:"case_id"`
	SchemaVersion  string `json:"schema_version"`
	Sequence       int    `json:"sequence"`
	Timestamp      string `json:"timestamp,omitempty"`
	TimestampSrc   string `json:"timestamp_source,omitempty"`
	Host           string `json:"host,omitempty"`
	User           string `json:"user,omitempty"`
	Vendor         string `json:"vendor,omitempty"`
	Product        string `json:"product,omitempty"`
	ProductVersion string `json:"product_version,omitempty"`
	SessionID      string `json:"session_id,omitempty"`
	AgentID        string `json:"agent_id,omitempty"`
	ParentAgentID  string `json:"parent_agent_id,omitempty"`
	TaskID         string `json:"task_id,omitempty"`
	ActorType      string `json:"actor_type,omitempty"`
	EventType      string `json:"event_type"`
	Model          string `json:"model,omitempty"`
	Tool           string `json:"tool,omitempty"`
	ToolCallID     string `json:"tool_call_id,omitempty"`
	MCPServer      string `json:"mcp_server,omitempty"`
	MCPTool        string `json:"mcp_tool,omitempty"`
	Command        string `json:"command,omitempty"`
	Cwd            string `json:"cwd,omitempty"` // working directory the tool ran in, when the transcript records it
	File           string `json:"file,omitempty"`
	NetworkDest    string `json:"network_destination,omitempty"`
	Action         string `json:"action,omitempty"`
	Result         string `json:"result,omitempty"`
	Summary        string `json:"summary,omitempty"` // short, sanitized extract
	SourceArtifact string `json:"source_artifact"`   // artifact_id in the sealed zone
	SourcePath     string `json:"source_logical_path,omitempty"`
	SourceOffset   int64  `json:"source_offset"` // byte offset of the source line
	SourceLine     int    `json:"source_line"`
	Corroboration  string `json:"corroboration_state"`
	// WitnessNote names the independent source that confirmed or disproved
	// this event, in a sentence an analyst can read. Empty when nothing
	// outside the transcript was consulted.
	WitnessNote string `json:"witness_note,omitempty"`
}

// Entity is one node in the agent relationship graph.
type Entity struct {
	EntityID   string            `json:"entity_id"` // e.g. session:<id>, agent:<id>, tool:Bash
	Kind       string            `json:"kind"`      // user|session|agent|tool|mcp_server|process|file|network
	Label      string            `json:"label"`
	Product    string            `json:"product,omitempty"`
	Attributes map[string]string `json:"attributes,omitempty"`
}

// Relationship is one evidence-backed edge. DerivedFrom MUST reference
// the event(s) proving the edge; edges without evidence are forbidden.
type Relationship struct {
	From          string   `json:"from"`
	To            string   `json:"to"`
	Type          string   `json:"type"` // spawned|sent_message|invoked|belongs_to|resumed
	DerivedFrom   []string `json:"derived_from"`
	Corroboration string   `json:"corroboration_state"`
}

// Finding is one detection result.
type Finding struct {
	RuleID        string   `json:"rule_id"`
	Severity      string   `json:"severity"` // INFO|LOW|MEDIUM|HIGH|CRITICAL
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	SessionID     string   `json:"session_id,omitempty"`
	AgentID       string   `json:"agent_id,omitempty"`
	ParentAgentID string   `json:"parent_agent_id,omitempty"` // "UNKNOWN" when unverified
	Related       []string `json:"related,omitempty"`
	EvidenceRefs  []string `json:"evidence_refs"` // logical_path:line (artifact <id>)
	Status        string   `json:"status"`        // corroboration state of the underlying events
	Endpoint      string   `json:"endpoint_corroboration"`
	MitreATLAS    string   `json:"mitre_atlas,omitempty"` // omitted when no valid technique exists
	MitreATTACK   string   `json:"mitre_attack,omitempty"`

	// Confidence is how likely it is that this finding is real. It is
	// deliberately separate from Severity, which is how bad it would be if
	// it were. Collapsing the two is how tools end up unable to explain
	// either: a scratch-directory deletion is low confidence and low impact,
	// a disproved credential exfiltration is high confidence and high
	// impact, and one number cannot say both.
	Confidence string `json:"confidence,omitempty"` // HIGH|MEDIUM|LOW
	// Reasons are plain sentences explaining how Confidence was reached, in
	// the order the verifiers ran.
	Reasons []string `json:"confidence_reasons,omitempty"`
	// Timestamp is when the evidence this finding cites happened. Findings
	// had none, which made them impossible to filter or plot by time.
	Timestamp string `json:"timestamp,omitempty"`
	// Class separates alerts from context; see internal/catalog.
	Class         string      `json:"class,omitempty"`
	FalsePositive string      `json:"false_positive_notes,omitempty"`
	ChainSteps    []ChainStep `json:"chain_steps,omitempty"` // set only by attack-chain findings: the ordered steps that matched
}

// ChainStep is one matched step of an attack chain: which named step, which
// event proved it, when, and the evidence reference of that event.
type ChainStep struct {
	Step      string `json:"step"`
	EventID   string `json:"event_id"`
	Timestamp string `json:"timestamp,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	Summary   string `json:"summary,omitempty"`
	Evidence  string `json:"evidence"`
}

// Normalized is the merged output of all parsers for one package.
type Normalized struct {
	Events        []Event
	Entities      []Entity
	Relationships []Relationship
}

// SpawnEvidence maps agent IDs to the event that evidences their spawn
// (a Task spawn event or a spawn-linking tool result).
func (n *Normalized) SpawnEvidence() map[string]string {
	out := map[string]string{}
	for _, ev := range n.Events {
		if ev.EventType == EventAgentSpawn && ev.TaskID != "" {
			out[ev.TaskID] = ev.EventID
		}
	}
	return out
}
