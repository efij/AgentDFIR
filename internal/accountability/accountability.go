// Package accountability answers, for every consequential thing an agent
// did in a case, four questions in one row: who asked (instruction), what
// was allowed (authority), what the agent did (action), and whether the
// action went beyond the instruction (gap).
//
// Everything in the report is already in the case. The instruction is the
// provenance trigger — the nearest preceding human prompt or tool result
// in the same session. The authority is the permission state the
// collection captured: settings files, bypass flags, hooks, MCP servers,
// and the permission mode the transcript itself recorded for the session.
// The action is the event and the findings on it, with its evidence state
// and whatever witness confirmed or disproved it. The gap is rule-based
// and deterministic: a short code and a sentence, or NONE_DETECTED. The
// report never upgrades an evidence state and never calls anything
// "authorized": it shows what was asked, what was allowed and what
// happened, and leaves the judgement to the person reading it.
//
// Not legal advice. The report preserves and presents evidence; a
// qualified person decides what it supports.
package accountability

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/accounts"
	"github.com/efij/AgentDFIR/v3/internal/analysis"
	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/catalog"
	"github.com/efij/AgentDFIR/v3/internal/chain"
	"github.com/efij/AgentDFIR/v3/internal/custody"
	"github.com/efij/AgentDFIR/v3/internal/provenance"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/seal"
	"github.com/efij/AgentDFIR/v3/internal/store"
	"github.com/efij/AgentDFIR/v3/internal/version"
	"github.com/efij/AgentDFIR/v3/internal/witness"
)

// Schema identifies the JSON document this package writes.
const Schema = "agentdfir.accountability/1"

// Options select what the report covers.
type Options struct {
	SessionID string // one session only
	Since     string // RFC 3339; actions before it are left out
	Until     string // RFC 3339; actions after it are left out
	Finding   string // one rule id, or a rule id prefix
}

// Report is the whole document.
type Report struct {
	Schema       string   `json:"schema"`
	GeneratedUTC string   `json:"generated_utc"`
	ToolVersion  string   `json:"tool_version"`
	Case         Header   `json:"case"`
	Filter       Options  `json:"filter"`
	Rows         []Row    `json:"actions"`
	Summary      Summary  `json:"summary"`
	Limits       []string `json:"limits"`
}

// Header identifies the case and the evidence the report was made from.
type Header struct {
	CaseID           string        `json:"case_id"`
	Host             string        `json:"host"`
	OS               string        `json:"os"`
	OperatorOSUser   string        `json:"operator_os_user,omitempty"`
	OperatorAsserted string        `json:"operator_asserted,omitempty"`
	CreatedUTC       string        `json:"created_utc"`
	SealDigest       string        `json:"seal_digest"`
	Signed           bool          `json:"signed"`
	SignatureValid   bool          `json:"signature_valid"`
	SignerKey        string        `json:"signer_key,omitempty"`
	SignerFingerprnt string        `json:"signer_fingerprint,omitempty"`
	Anchored         bool          `json:"anchored"`
	Verify           VerifySummary `json:"verify"`
	Rounds           []RoundInfo   `json:"rounds"`
	Authorization    Authorization `json:"authorization"`
	Accounts         []AccountInfo `json:"accounts"`
	Simulated        bool          `json:"simulated"`
	Events           int           `json:"events"`
	Findings         int           `json:"findings"`
}

// VerifySummary is the outcome of verifying the package for this report.
type VerifySummary struct {
	Depth    string   `json:"depth"`
	Result   string   `json:"result"` // VERIFIED | FAILED | ERROR
	Problems []string `json:"problems,omitempty"`
}

// RoundInfo is one collection round.
type RoundInfo struct {
	Round            int    `json:"round"`
	StartedUTC       string `json:"started_utc"`
	CompletedUTC     string `json:"completed_utc,omitempty"`
	CollectorVersion string `json:"collector_version"`
	Signer           string `json:"signer_fingerprint,omitempty"`
	PriorIntegrity   string `json:"prior_integrity,omitempty"`
}

// Authorization is what the case records about who allowed the
// acquisition: the reference given at collection time and any
// authorization recorded afterwards with `agentdfir case authorize`.
type Authorization struct {
	Reference string       `json:"reference,omitempty"`
	Records   []AuthRecord `json:"records,omitempty"`
}

// AuthRecord is one `case authorize` entry.
type AuthRecord struct {
	By         string `json:"by"`
	Basis      string `json:"basis"`
	Reference  string `json:"reference,omitempty"`
	RecordedBy string `json:"recorded_by"`
	TS         string `json:"ts_utc"`
	SealDigest string `json:"seal_digest,omitempty"`
}

// AccountInfo is one AI login seen in the case.
type AccountInfo struct {
	Key     string `json:"key"`
	Label   string `json:"label"`
	Product string `json:"product"`
	Email   string `json:"email,omitempty"`
	Org     string `json:"org,omitempty"`
	Known   bool   `json:"known"`
	Actions int    `json:"actions"`
}

// Row is one consequential action.
type Row struct {
	Index       int          `json:"index"`
	SessionID   string       `json:"session_id"`
	AgentID     string       `json:"agent_id,omitempty"`
	Product     string       `json:"product,omitempty"`
	Account     string       `json:"account"`
	Class       string       `json:"class"` // destructive | cloud_destructive | exfiltration | credential | config_change | execution | other
	Findings    []FindingRef `json:"findings"`
	Instruction Instruction  `json:"instruction"`
	Authority   Authority    `json:"authority"`
	Action      Action       `json:"action"`
	Gaps        []Gap        `json:"gaps"`
}

// FindingRef names a finding on the action.
type FindingRef struct {
	RuleID   string `json:"rule_id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Chain    bool   `json:"chain,omitempty"`
}

// Instruction is who asked.
type Instruction struct {
	Trigger       string `json:"trigger"` // human_prompt | tool_result | unknown
	TriggerRef    string `json:"trigger_ref,omitempty"`
	TriggerDetail string `json:"trigger_detail,omitempty"`
	Prompt        string `json:"prompt,omitempty"`
	PromptRef     string `json:"prompt_ref,omitempty"`
	PromptTime    string `json:"prompt_time,omitempty"`
	Statement     string `json:"statement"` // the sentence a reader gets
}

// Authority is what was allowed when the action ran, as far as the case
// shows it.
type Authority struct {
	SessionPermissionMode string         `json:"session_permission_mode,omitempty"` // from the transcript's own init record
	HeadlessLaunch        *Indicator     `json:"headless_launch,omitempty"`         // this session was started with permissions bypassed
	Configs               []ConfigState  `json:"configs"`
	Changed               []ConfigChange `json:"changed_between_rounds,omitempty"`
	AgentWrites           []Indicator    `json:"agent_writes_to_permissions,omitempty"` // earlier in this session
	Indicators            []Indicator    `json:"case_indicators,omitempty"`             // case-wide bypass findings
	MCPServers            []string       `json:"mcp_servers,omitempty"`
	Statement             string         `json:"statement"`
}

// ConfigState is one permission-bearing configuration file as captured.
type ConfigState struct {
	Path                  string   `json:"path"`
	Product               string   `json:"product,omitempty"`
	ArtifactID            string   `json:"artifact_id"`
	Round                 int      `json:"round"`
	CollectedUTC          string   `json:"collected_utc"`
	DefaultMode           string   `json:"default_mode,omitempty"`
	Allow                 []string `json:"allow,omitempty"`
	Deny                  []string `json:"deny,omitempty"`
	Ask                   []string `json:"ask,omitempty"`
	DisableBypassMode     string   `json:"disable_bypass_permissions_mode,omitempty"`
	Hooks                 []string `json:"hooks,omitempty"`
	BypassMarkers         []string `json:"bypass_markers,omitempty"`
	EnableAllProjectMCP   bool     `json:"enable_all_project_mcp_servers,omitempty"`
	EnabledProjectServers []string `json:"enabled_mcpjson_servers,omitempty"`
	Note                  string   `json:"note,omitempty"`
}

// ConfigChange is the same path captured with different content in two
// rounds.
type ConfigChange struct {
	Path   string      `json:"path"`
	Before ConfigState `json:"before"`
	After  ConfigState `json:"after"`
}

// Indicator is one evidence-backed fact about authority.
type Indicator struct {
	RuleID    string `json:"rule_id,omitempty"`
	Text      string `json:"text"`
	Evidence  string `json:"evidence,omitempty"`
	SessionID string `json:"session_id,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

// Action is what the agent did.
type Action struct {
	EventID     string             `json:"event_id"`
	Timestamp   string             `json:"timestamp,omitempty"`
	Tool        string             `json:"tool,omitempty"`
	MCPServer   string             `json:"mcp_server,omitempty"`
	Command     string             `json:"command,omitempty"` // secrets masked
	File        string             `json:"file,omitempty"`
	NetworkDest string             `json:"network_destination,omitempty"`
	Target      string             `json:"target,omitempty"`
	Summary     string             `json:"summary,omitempty"`
	State       string             `json:"state"` // corroboration state, never upgraded here
	StateLabel  string             `json:"state_label"`
	Witness     string             `json:"witness,omitempty"`
	Evidence    string             `json:"evidence"`
	ChainSteps  []schema.ChainStep `json:"chain_steps,omitempty"`
	Narrative   string             `json:"narrative_after,omitempty"` // what the model said next
}

// Gap is one reason the action may have gone beyond the instruction.
type Gap struct {
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

// Summary counts the report.
type Summary struct {
	Actions   int            `json:"actions"`
	Sessions  int            `json:"sessions"`
	WithGaps  int            `json:"actions_with_gaps"`
	ByGap     map[string]int `json:"by_gap"`
	ByTrigger map[string]int `json:"by_trigger"`
	ByClass   map[string]int `json:"by_class"`
}

// Build computes the report from an analyzed package. The analysis must
// already be current (analysis.Ensure); Build reads, it never re-runs it.
func Build(pkg string, opts Options) (*Report, error) {
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		return nil, err
	}
	ci, err := casepkg.ReadCaseInfo(pkg)
	if err != nil {
		return nil, err
	}
	events := analysis.LoadEvents(pkg)
	findings := analysis.LoadFindings(pkg)
	st := casepkg.NewStore(pkg, man)

	rep := &Report{Schema: Schema, GeneratedUTC: time.Now().UTC().Format(time.RFC3339), ToolVersion: version.Version, Filter: opts}
	rep.Case = header(pkg, man, ci, len(events), len(findings))

	// Accounts: the login each profile ran under.
	accts, uuids := accounts.Identities(st, man.Current())

	// Session index, chronological within each session (overlay order).
	bySession := map[string][]int{}
	for i, ev := range events {
		bySession[ev.SessionID] = append(bySession[ev.SessionID], i)
	}
	byID := make(map[string]int, len(events))
	for i, ev := range events {
		byID[ev.EventID] = i
	}
	refIdx := chain.RefIndex(events)

	auth := caseAuthority(pkg, man, st, events, findings)

	// Group the consequential findings by the event they cite.
	type rowSeed struct {
		idx      int
		findings []FindingRef
		steps    []schema.ChainStep
		class    string
	}
	seeds := map[int]*rowSeed{}
	var order []int
	for _, f := range findings {
		cls, ok := consequential(f)
		if !ok {
			continue
		}
		if opts.Finding != "" && !strings.HasPrefix(f.RuleID, opts.Finding) {
			continue
		}
		idx := -1
		var steps []schema.ChainStep
		if len(f.ChainSteps) > 0 {
			// The consequence is the last step; the chain is kept on the row.
			last := f.ChainSteps[len(f.ChainSteps)-1]
			if i, ok := byID[last.EventID]; ok {
				idx, steps = i, f.ChainSteps
			}
		}
		if idx < 0 {
			for _, r := range f.EvidenceRefs {
				if id := chain.EventForRef(refIdx, r); id != "" {
					if i, ok := byID[id]; ok {
						idx = i
						break
					}
				}
			}
		}
		if idx < 0 {
			continue // a configuration or artifact finding, not an action
		}
		ev := events[idx]
		if !isAction(ev) {
			continue
		}
		if opts.SessionID != "" && ev.SessionID != opts.SessionID {
			continue
		}
		if !within(ev.Timestamp, opts.Since, opts.Until) {
			continue
		}
		s := seeds[idx]
		if s == nil {
			s = &rowSeed{idx: idx, class: cls}
			seeds[idx] = s
			order = append(order, idx)
		}
		s.findings = append(s.findings, FindingRef{RuleID: f.RuleID, Severity: f.Severity, Title: f.Title, Chain: len(f.ChainSteps) > 0})
		if len(steps) > 0 && len(s.steps) == 0 {
			s.steps = steps
		}
		if classRank[cls] > classRank[s.class] {
			s.class = cls
		}
	}
	sort.Slice(order, func(i, j int) bool {
		a, b := events[order[i]], events[order[j]]
		if a.Timestamp != b.Timestamp {
			return a.Timestamp < b.Timestamp
		}
		return order[i] < order[j]
	})

	rep.Summary = Summary{ByGap: map[string]int{}, ByTrigger: map[string]int{}, ByClass: map[string]int{}}
	sessions := map[string]bool{}
	actionsByAcct := map[string]int{}
	for n, idx := range order {
		s := seeds[idx]
		ev := events[idx]
		sort.Slice(s.findings, func(i, j int) bool {
			if sevRank[s.findings[i].Severity] != sevRank[s.findings[j].Severity] {
				return sevRank[s.findings[i].Severity] > sevRank[s.findings[j].Severity]
			}
			return s.findings[i].RuleID < s.findings[j].RuleID
		})
		acc := accounts.Resolve(accts, uuids, ev.SourcePath, ev.Product)
		actionsByAcct[acc.Key]++
		row := Row{Index: n + 1, SessionID: ev.SessionID, AgentID: ev.AgentID, Product: ev.Product, Account: acc.Label, Class: s.class, Findings: s.findings}
		trig := provenance.TriggerFor(events, bySession[ev.SessionID], idx)
		row.Instruction = instruction(st, events, trig)
		row.Action = action(events, bySession[ev.SessionID], idx, s.steps)
		row.Authority = sessionAuthority(auth, events, bySession[ev.SessionID], idx, trig)
		row.Gaps = gaps(row, events, bySession[ev.SessionID], idx, trig)
		rep.Rows = append(rep.Rows, row)
		sessions[ev.SessionID] = true
		rep.Summary.ByTrigger[row.Instruction.Trigger]++
		rep.Summary.ByClass[row.Class]++
		if len(row.Gaps) == 1 && row.Gaps[0].Code == GapNone {
			rep.Summary.ByGap[GapNone]++
		} else {
			rep.Summary.WithGaps++
			for _, g := range row.Gaps {
				rep.Summary.ByGap[g.Code]++
			}
		}
	}
	rep.Summary.Actions = len(rep.Rows)
	rep.Summary.Sessions = len(sessions)
	for _, acc := range accts {
		rep.Case.Accounts = append(rep.Case.Accounts, AccountInfo{Key: acc.Key, Label: acc.Label, Product: acc.Product,
			Email: acc.Email, Org: acc.Org, Known: acc.Known, Actions: actionsByAcct[acc.Key]})
	}
	sort.Slice(rep.Case.Accounts, func(i, j int) bool { return rep.Case.Accounts[i].Key < rep.Case.Accounts[j].Key })
	rep.Limits = limits(pkg, man, ci, findings, auth, rep)
	return rep, nil
}

func header(pkg string, man *casepkg.Manifest, ci *casepkg.CaseInfo, events, findings int) Header {
	h := Header{CaseID: man.CaseID, Host: man.Host, OS: man.OS + "/" + man.Arch, CreatedUTC: man.CreatedUTC,
		OperatorOSUser: ci.OperatorOSUser, OperatorAsserted: ci.OperatorAsserted,
		SealDigest: custody.SealDigest(pkg), Simulated: analysis.IsSimulated(man), Events: events, Findings: findings}
	if vres, err := casepkg.Verify(pkg); err != nil {
		h.Verify = VerifySummary{Result: "ERROR", Problems: []string{err.Error()}}
	} else {
		h.Verify = VerifySummary{Depth: vres.Depth, Result: "VERIFIED", Problems: vres.Problems}
		if len(vres.Problems) > 0 {
			h.Verify.Result = "FAILED"
		}
	}
	if sig, err := seal.Verify(pkg, ""); err == nil && sig.Present {
		h.Signed = true
		h.SignatureValid = sig.Valid
		h.SignerKey = sig.PublicKey
		h.SignerFingerprnt = seal.Fingerprint(sig.PublicKey)
		if !sig.Valid {
			h.Verify.Problems = append(h.Verify.Problems, "SEAL.sig: "+sig.Reason)
			h.Verify.Result = "FAILED"
		}
	}
	if abs, err := filepath.Abs(pkg); err == nil {
		if a, err := store.LatestAnchor(man.CaseID, abs); err == nil && a != nil && a.SealsDigest == h.SealDigest {
			h.Anchored = true
		}
	}
	for _, r := range ci.Rounds {
		ri := RoundInfo{Round: r.Round, StartedUTC: r.StartedUTC, CompletedUTC: r.CompletedUTC, CollectorVersion: r.CollectorVersion, PriorIntegrity: r.PriorIntegrity}
		if r.Signer != "" {
			ri.Signer = seal.Fingerprint(r.Signer)
		}
		h.Rounds = append(h.Rounds, ri)
	}
	if len(h.Rounds) == 0 {
		h.Rounds = []RoundInfo{{Round: 1, StartedUTC: man.CreatedUTC, CollectorVersion: man.CollectorVersion}}
	}
	h.Authorization.Reference = ci.Authorization
	if recs, _, err := custody.Read(pkg); err == nil {
		for _, r := range custody.Authorizations(recs) {
			h.Authorization.Records = append(h.Authorization.Records, AuthRecord{
				By: r.FieldString("by"), Basis: r.FieldString("basis"), Reference: r.FieldString("reference"),
				RecordedBy: r.OSUser + "@" + r.Host, TS: r.TS, SealDigest: r.SealDigest})
		}
	}
	return h
}

// ---- which findings count ----

var classRank = map[string]int{"other": 0, "execution": 1, "config_change": 2, "credential": 3, "exfiltration": 4, "destructive": 5, "cloud_destructive": 6}
var sevRank = map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

// consequentialRules are the rules whose findings are always an action
// worth a row, whatever their severity; the value is the action class.
var consequentialRules = map[string]string{
	"DESTRUCTIVE_COMMAND": "destructive", "DISK_WIPE": "destructive", "LOG_DELETION": "destructive", "HISTORY_CLEARING": "destructive",
	"OS_LOG_TAMPER": "destructive", "BULK_FILE_ENCRYPTION": "destructive", "TIMESTOMP_COMMAND": "destructive", "SESSION_TAMPERING": "destructive",
	"CHAIN_ACTION_THEN_LOG_TAMPER": "destructive", "CHAIN_MCP_RESULT_TO_DESTRUCTIVE": "destructive",
	"CLOUD_DATA_DESTRUCTION": "cloud_destructive", "CLOUD_RESOURCE_DELETION": "cloud_destructive", "CLOUD_RECOVERY_PROTECTION_REMOVED": "cloud_destructive",
	"CLOUD_DESTRUCTIVE_BURST": "cloud_destructive", "CLOUD_LOGGING_DISABLE": "cloud_destructive",
	"POTENTIAL_DATA_EXFILTRATION": "exfiltration", "EGRESS_VIA_TRUSTED_SERVICE": "exfiltration", "GITHUB_EXFIL_REPO_CREATE": "exfiltration",
	"CURL_FILE_UPLOAD": "exfiltration", "CLOUD_STORAGE_UPLOAD": "exfiltration", "REMOTE_COPY_TO_HOST": "exfiltration", "GIT_PUSH_TO_URL": "exfiltration",
	"WEBHOOK_C2_EXFIL": "exfiltration", "DNS_EXFIL_LABELS": "exfiltration", "ENV_DUMP_TO_NETWORK": "exfiltration", "PASTE_SITE_DESTINATION": "exfiltration",
	"UNEXPECTED_NETWORK_DESTINATION": "exfiltration", "PACKAGE_PUBLISH": "exfiltration", "DNS_TUNNEL_TOOL": "exfiltration",
	"CHAIN_SECRET_TO_EXFIL": "exfiltration", "CHAIN_SUBAGENT_CROSS_TALK_EXFIL": "exfiltration", "CHAIN_INJECTION_TO_PUSH": "exfiltration",
	"SECRET_ACCESS": "credential", "SENSITIVE_FILE_READ": "credential", "POTENTIAL_SECRET_EXPOSURE": "credential", "HEADLESS_AGENT_SECRET_HUNT": "credential",
	"CLOUD_CREDENTIAL_EXPORT": "credential", "CLOUD_METADATA_ACCESS": "credential", "SSH_PRIVATE_KEY_READ": "credential", "GIT_CREDENTIAL_EXPOSURE": "credential",
	"KUBE_SECRET_DUMP": "credential", "CREDENTIAL_DIR_ARCHIVE": "credential", "BROWSER_CREDENTIAL_ACCESS": "credential", "SHADOW_FILE_ACCESS": "credential",
	"MEMORY_CREDENTIAL_DUMP": "credential", "LSASS_CREDENTIAL_DUMP": "credential", "TERRAFORM_STATE_ACCESS": "credential",
	"AGENT_CREDENTIAL_STORE_ACCESS": "credential", "TOOLCHAIN_CREDENTIAL_FILE_ACCESS": "credential", "ENV_SECRET_ECHO": "credential",
	"AGENT_SELF_MODIFICATION": "config_change", "INSTRUCTION_FILE_WRITTEN_BY_AGENT": "config_change", "INSTRUCTION_FROM_TOOL_RESULT": "config_change",
	"INSTRUCTION_INJECTION_PHRASE": "config_change", "INSTRUCTION_WRITTEN_BY_SUBAGENT": "config_change", "AGENT_CONFIG_SHELL_WRITE": "config_change",
	"AGENT_ADDS_MCP_SERVER": "config_change", "CONFIG_HOOK_REMOTE_FETCH": "config_change", "GIT_HOOK_INSTALL": "config_change", "SSH_KEY_WRITE": "config_change",
	"SHELL_RC_PERSISTENCE": "config_change", "CRON_PERSISTENCE": "config_change", "SERVICE_PERSISTENCE": "config_change", "PERMISSION_ESCALATION": "config_change",
	"NESTED_AGENT_PERMISSION_BYPASS": "config_change", "CHAIN_CONTEXT_POISON_TO_EXEC": "config_change", "CHAIN_ORPHAN_PERSISTENCE": "config_change",
	"CURL_PIPE_SHELL": "execution", "BASE64_PIPE_SHELL": "execution", "DOWNLOAD_THEN_EXECUTE": "execution", "ENCODED_PAYLOAD_EXECUTED": "execution",
	"REVERSE_SHELL": "execution", "CHAIN_DOWNLOAD_AND_EXECUTE": "execution",
}

// consequential reports whether a finding describes an action the report
// should carry, and the class of that action.
func consequential(f schema.Finding) (string, bool) {
	if f.Class == catalog.ClassBuildingBlock || catalog.IsBuildingBlock(f.RuleID) {
		return "", false
	}
	if cls, ok := consequentialRules[f.RuleID]; ok {
		return cls, true
	}
	if sevRank[f.Severity] >= sevRank["HIGH"] {
		return classFromRuleID(f.RuleID), true
	}
	return "", false
}

func classFromRuleID(id string) string {
	switch {
	case containsAny(id, "WIPE", "DESTR", "DELET", "TAMPER", "ENCRYPT"):
		return "destructive"
	case containsAny(id, "EXFIL", "UPLOAD", "NETWORK", "PUSH", "EGRESS", "C2"):
		return "exfiltration"
	case containsAny(id, "SECRET", "CREDENTIAL", "KEY", "TOKEN", "PASSWORD"):
		return "credential"
	case containsAny(id, "CONFIG", "HOOK", "MCP", "INSTRUCTION", "PERMISSION", "PERSIST"):
		return "config_change"
	case containsAny(id, "EXEC", "SHELL", "PAYLOAD"):
		return "execution"
	}
	return "other"
}

func containsAny(s string, subs ...string) bool {
	for _, x := range subs {
		if strings.Contains(s, x) {
			return true
		}
	}
	return false
}

// isAction: the row's event has to be something the agent did, not a
// prompt or a system record.
func isAction(ev schema.Event) bool {
	switch ev.EventType {
	case schema.EventToolCall, schema.EventAgentSpawn, schema.EventAgentMessage, schema.EventModelResponse:
		return true
	}
	return false
}

func within(ts, since, until string) bool {
	if ts == "" {
		return since == "" && until == ""
	}
	if since != "" && ts < since {
		return false
	}
	if until != "" && ts > until {
		return false
	}
	return true
}

// ---- instruction ----

func instruction(st *casepkg.Store, events []schema.Event, t provenance.Trigger) Instruction {
	in := Instruction{Trigger: t.Kind, TriggerRef: t.Ref, TriggerDetail: t.Detail, Prompt: t.Prompt, PromptRef: t.PromptRef, PromptTime: t.PromptTime}
	if t.PromptIdx >= 0 {
		// The overlay keeps a 200-character excerpt; the sealed line has
		// the whole prompt, and the gap rules want all of it.
		if full := fullPrompt(st, events[t.PromptIdx]); full != "" {
			in.Prompt = full
		}
	}
	switch t.Kind {
	case "human_prompt":
		in.Statement = "A person asked, in this session: " + quote(in.Prompt, 160)
	case "tool_result":
		if OutsideContent(t.Detail) {
			in.Statement = "No human asked for this; it followed content that came back from " + t.Detail + "."
			if in.Prompt != "" {
				in.Statement += " The nearest earlier request from a person was: " + quote(in.Prompt, 120)
			}
		} else if in.Prompt != "" {
			in.Statement = "A person asked, in this session: " + quote(in.Prompt, 160) + " — the input right before this action was the output of the agent's own earlier " + t.Detail + " step, not a new request."
		} else {
			in.Statement = "No human prompt precedes this action in the session's evidence; the input before it was output from " + t.Detail + "."
		}
	default:
		in.Statement = "No preceding human prompt or tool result is in the evidence for this session (the transcript may start after the request, or the agent was started without one)."
	}
	return in
}

// fullPrompt reads the whole prompt text out of the sealed transcript line
// behind a human_prompt event. Shapes handled: a JSON record whose
// message.content is a string or an array of text parts (Claude Code),
// or a payload/content/text field (Codex and generic). Anything else
// falls back to the overlay's excerpt.
func fullPrompt(st *casepkg.Store, ev schema.Event) string {
	if ev.SourceArtifact == "" || ev.SourceArtifact == "live" {
		return ""
	}
	f, err := st.OpenAt(ev.SourceArtifact, ev.SourceOffset)
	if err != nil {
		return ""
	}
	defer f.Close()
	line, err := bufio.NewReaderSize(f, 1<<20).ReadString('\n')
	if err != nil && line == "" {
		return ""
	}
	var v map[string]any
	if json.Unmarshal([]byte(strings.TrimSpace(line)), &v) != nil {
		return ""
	}
	for _, key := range []string{"message", "payload"} {
		if m, ok := v[key].(map[string]any); ok {
			if t := textOf(m["content"]); t != "" {
				return t
			}
		}
	}
	if t := textOf(v["content"]); t != "" {
		return t
	}
	return textOf(v["text"])
}

func textOf(c any) string {
	switch t := c.(type) {
	case string:
		return strings.TrimSpace(t)
	case []any:
		var parts []string
		for _, p := range t {
			if m, ok := p.(map[string]any); ok {
				if s, ok := m["text"].(string); ok && (m["type"] == "text" || m["type"] == "input_text" || m["type"] == nil) {
					parts = append(parts, strings.TrimSpace(s))
				}
			}
		}
		return strings.Join(parts, "\n")
	}
	return ""
}

// ---- action ----

func action(events []schema.Event, idxs []int, at int, steps []schema.ChainStep) Action {
	ev := events[at]
	a := Action{EventID: ev.EventID, Timestamp: ev.Timestamp, Tool: ev.Tool, MCPServer: ev.MCPServer, File: ev.File,
		NetworkDest: ev.NetworkDest, Summary: ev.Summary, State: ev.Corroboration, StateLabel: schema.Label(ev.Corroboration),
		Witness: ev.WitnessNote, Evidence: provenance.EvidenceRef(ev), ChainSteps: steps}
	if ev.MCPTool != "" {
		a.Tool = "mcp:" + ev.MCPServer + "/" + ev.MCPTool
	}
	if ev.Command != "" {
		a.Command = maskSecrets(ev.Command)
	}
	a.Target = target(ev)
	// What the model said next, when the action was consequential: a claim
	// made after a deletion is part of the record of that deletion.
	pos := sort.SearchInts(idxs, at)
	for k := pos + 1; k < len(idxs) && k <= pos+40; k++ {
		n := events[idxs[k]]
		if n.EventType == schema.EventHumanPrompt {
			break
		}
		if n.EventType == schema.EventModelResponse && n.Summary != "" && n.Tool == "" {
			a.Narrative = n.Summary
			break
		}
	}
	return a
}

// target names what the action touched: a path, a host, a database.
func target(ev schema.Event) string {
	if ev.File != "" {
		return ev.File
	}
	if ev.NetworkDest != "" {
		return ev.NetworkDest
	}
	cmd := ev.FullCommand()
	if cmd == "" {
		return ""
	}
	if t := dbTarget(cmd); t != "" {
		return t
	}
	for _, pat := range []string{"rm -rf ", "rm -fr ", "rm -r ", "rm -f ", "rm "} {
		if i := strings.Index(cmd, pat); i >= 0 {
			rest := strings.Fields(cmd[i+len(pat):])
			var paths []string
			for _, r := range rest {
				if strings.HasPrefix(r, "-") {
					continue
				}
				if strings.ContainsAny(r, ";|&") {
					break
				}
				paths = append(paths, r)
			}
			if len(paths) > 0 {
				return strings.Join(paths, " ")
			}
		}
	}
	return ""
}

// dbTarget: "DROP DATABASE production" → "production".
func dbTarget(cmd string) string {
	up := strings.ToUpper(cmd)
	for _, kw := range []string{"DROP DATABASE ", "DROP TABLE ", "DROP SCHEMA ", "TRUNCATE TABLE ", "TRUNCATE ", "DELETE FROM "} {
		if i := strings.Index(up, kw); i >= 0 {
			rest := strings.TrimLeft(cmd[i+len(kw):], " ")
			rest = strings.TrimPrefix(strings.TrimPrefix(rest, "IF EXISTS "), "if exists ")
			name := strings.FieldsFunc(rest, func(r rune) bool { return r == ';' || r == ' ' || r == '\'' || r == '"' || r == ')' })
			if len(name) > 0 {
				return name[0]
			}
		}
	}
	return ""
}

// maskSecrets hides credential-looking values in a command line. The
// report leaves the case, the command may carry the key it leaked.
func maskSecrets(cmd string) string {
	words := strings.Fields(cmd)
	for i, w := range words {
		lw := strings.ToLower(w)
		switch {
		case strings.HasPrefix(lw, "bearer") && i+1 < len(words):
			words[i+1] = mask(words[i+1])
		case strings.Contains(lw, "token=") || strings.Contains(lw, "secret=") || strings.Contains(lw, "password=") || strings.Contains(lw, "api_key=") || strings.Contains(lw, "apikey="):
			if j := strings.Index(w, "="); j > 0 {
				words[i] = w[:j+1] + mask(w[j+1:])
			}
		case strings.HasPrefix(w, "AKIA") && len(w) == 20, strings.HasPrefix(w, "ASIA") && len(w) == 20,
			strings.HasPrefix(w, "sk-") && len(w) > 20, strings.HasPrefix(w, "ghp_"), strings.HasPrefix(w, "xox"):
			words[i] = mask(w)
		}
	}
	return strings.Join(words, " ")
}

func mask(s string) string {
	lead := len(s) - len(strings.TrimLeft(s, `"'`))
	trail := len(s) - len(strings.TrimRight(s, `"'`))
	q1, q2 := s[:lead], s[len(s)-trail:]
	v := s[lead : len(s)-trail]
	switch {
	case strings.HasPrefix(v, "$"):
		return s // a variable reference, not a value
	case len(v) <= 6:
		v = "***"
	default:
		v = v[:3] + "…(masked)"
	}
	return q1 + v + q2
}

func quote(s string, n int) string {
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > n {
		s = string(r[:n]) + "…"
	}
	return `"` + s + `"`
}

// ---- limits ----

func limits(pkg string, man *casepkg.Manifest, ci *casepkg.CaseInfo, findings []schema.Finding, auth *caseAuth, rep *Report) []string {
	var out []string
	if rep.Case.Simulated {
		out = append(out, "This case was collected from a profile written by `agentdfir simulate`; it is synthetic and not evidence of a real incident.")
	}
	if _, err := os.Stat(filepath.Join(pkg, "detections", "corroboration.json")); err != nil {
		out = append(out, "No OS telemetry (auditd, Sysmon, EDR) or cloud audit log was imported: actions are OBSERVED in the agent's own transcript, not CORROBORATED by a second witness, unless the host witness says otherwise.")
	}
	if _, err := witness.Load(pkg); err != nil {
		out = append(out, "No host witness record (witness.json) is in the package: whether the files the agent claimed to write exist was not asked at acquisition time.")
	}
	gaps := map[string]bool{}
	for _, f := range findings {
		switch f.RuleID {
		case "TRANSCRIPT_DELETED", "TRANSCRIPT_TRUNCATED", "TRANSCRIPT_REWRITTEN", "TRANSCRIPT_REPLACED", "TRACE_GAP", "SESSION_TAMPERING", "LOG_DELETION":
			gaps[f.RuleID] = true
		}
	}
	if len(gaps) > 0 {
		var ids []string
		for id := range gaps {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		out = append(out, "Transcripts were deleted, truncated or rewritten before or during collection ("+strings.Join(ids, ", ")+"): actions in the missing parts are not in this report.")
	}
	out = append(out, "Vendor-side records (the agent provider's API and console logs) were not imported; this report covers what the machine kept.")
	if len(auth.configs) == 0 {
		out = append(out, "No permission-bearing configuration file was collected; the authority column relies on the transcript's own permission record and case-wide findings only.")
	} else {
		last := auth.configs[len(auth.configs)-1]
		out = append(out, fmt.Sprintf("Permission state is as captured at collection time (round %d, %s), which is after the actions; a setting changed between an action and the collection is only visible where a transcript recorded the change.", last.Round, last.CollectedUTC))
	}
	unknown := 0
	for _, a := range rep.Case.Accounts {
		if !a.Known && a.Actions > 0 {
			unknown++
		}
	}
	if unknown > 0 {
		out = append(out, fmt.Sprintf("%d profile(s) with actions have no login file in the collection; their account is named by profile directory only.", unknown))
	}
	out = append(out, "Timestamps of actions are the agent product's own (transcript time); only round start/end times were taken by the collector's clock ("+ci.Timezone+").")
	out = append(out, "The instruction is the nearest preceding human prompt or tool result in the same session; a request made in another session, by voice, or outside the agent is not visible here.")
	return out
}
