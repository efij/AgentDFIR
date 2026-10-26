// Package aiexport normalizes AI-service account data exports — the
// archive a user downloads from ChatGPT, Claude.ai, DeepSeek or Google
// Takeout (Gemini Apps) — into the unified schema, so the same rules and
// the same explorer work on a provider's record of a conversation as on
// an agent transcript collected from an endpoint.
//
// Evidence class. An export is the provider's record, produced on the
// provider's side, not endpoint telemetry. The evidence states say so:
//
//   - user turns are human_prompt events in state REQUESTED (ASKED);
//   - assistant text is model_response in state REPORTED (CLAIMED);
//   - a tool call (code interpreter, browsing, search, Claude tool_use) is
//     a tool_call in state OBSERVED (RECORDED) only when the export itself
//     records the call. Such events never carry Command, File or
//     NetworkDest: the tool ran in the provider's sandbox, and leaving
//     those fields empty keeps endpoint and cloud correlation from ever
//     "confirming" it against activity on the examined machine.
//
// Every event's timestamp source starts with "provider_export" (followed
// by the original field and value when the export recorded one). The
// per-artifact integrity rules key on that prefix: one export file holds
// every conversation of an account, so "many sessions in one file" and
// "timestamps run backwards" are its normal shape, not splicing.
//
// Every file is classified by its structure (see Sniff), never its name.
// A file named like an export file whose structure is not a known schema
// becomes one trace_gap event with result "unsupported" naming the file
// and the keys that were expected; nothing is guessed from it.
//
// Large files are streamed: the top-level array is walked one element at
// a time (jsonwalk.go) and every event records the byte offset, line and
// RFC 6901 JSON Pointer of the value it was read from.
package aiexport

import (
	"fmt"
	"io"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/parsers/segment"
	"github.com/efij/AgentDFIR/v4/internal/schema"
	"github.com/efij/AgentDFIR/v4/internal/version"
)

// Collector rules for export artifacts. The parser reads RuleConversations
// and RuleMetadata; the rest are sealed and preserved unparsed.
const (
	RuleConversations = "aiexport.conversations" // conversations, projects, activity
	RuleMetadata      = "aiexport.metadata"      // account, feedback, shared links
	RuleFile          = "aiexport.file"          // any other file of an export (HTML view, images, attachments)
	RuleUFDRReport    = "ufdr.report"            // Cellebrite UFDR report.xml, read generically by internal/parsers/suite
	RuleUFDRFile      = "ufdr.file"              // a file of a UFDR file tree
)

// Artifact types for export artifacts. Conversation files are
// agent_session so the content rules (credential exposure, injection
// phrases, invisible Unicode, honeytokens) scan them like any transcript.
const (
	TypeConversations = "agent_session"
	TypeMetadata      = "ai_export_metadata"
	TypeFile          = "ai_export_file"
	TypeUFDRReport    = "ufdr_report"
	TypeUFDRFile      = "ufdr_file"
)

// IDFormat renders an event id from its sequence number; the incremental
// overlay needs it to renumber a cached artifact's events.
const IDFormat = "evt-ax-%06d"

// Bounds for hostile input.
const (
	MaxElementBytes = 64 << 20 // one conversation (one top-level array element)
	maxNodes        = 200000   // mapping nodes per conversation
	maxMessages     = 200000   // chat_messages per conversation
	maxBlocks       = 4096     // content blocks / parts per message
	maxAttachments  = 256      // attachments listed per message
)

// Results that mark where an event sits in a conversation.
const (
	resultActive     = "export"                   // on the active branch, or a linear conversation
	resultAlternate  = "export:alternate-branch"  // a regenerated/edited branch the user moved away from
	resultUnresolved = "export:branch-unresolved" // a fork in an export that does not say which branch is current
	resultAttachment = "export:attachment"
	resultUnsup      = "unsupported" // trace_gap: a known export file in an unknown schema
	resultUnparsed   = "unparsed"    // trace_gap: malformed/truncated region
)

const (
	evidenceClass  = "provider_export" // entity attribute and timestamp source prefix
	actionProvider = "provider_tool"   // tool calls executed on the provider side
	maxSummary     = 200
	maxToolSummary = 300
)

// ParsePackage parses every export artifact in a sealed package.
func ParsePackage(pkgDir string) (*schema.Normalized, error) { return parseWith(pkgDir, nil, nil) }

// StreamPackage parses and emits every event to sink instead of
// accumulating them, returning only entities/relationships.
func StreamPackage(pkgDir string, sink func(schema.Event)) (*schema.Normalized, error) {
	return parseWith(pkgDir, sink, nil)
}

// StreamPackageCached is StreamPackage with an overlay cache: artifacts the
// cache already holds are replayed instead of re-read.
func StreamPackageCached(pkgDir string, sink func(schema.Event), cache segment.Cache) (*schema.Normalized, error) {
	return parseWith(pkgDir, sink, cache)
}

// Parses reports whether an artifact is one this parser reads.
func Parses(a casepkg.ArtifactRecord) bool {
	return a.Status == casepkg.StatusOK && (a.CollectorRule == RuleConversations || a.CollectorRule == RuleMetadata)
}

func parseWith(pkgDir string, sink func(schema.Event), cache segment.Cache) (*schema.Normalized, error) {
	man, err := casepkg.ReadManifest(pkgDir)
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	store := casepkg.NewStore(pkgDir, man)
	p := &parser{res: &schema.Normalized{}, sink: sink, caseID: man.CaseID, host: man.Host,
		entities: map[string]schema.Entity{}, relSeen: map[string]bool{}}
	for _, a := range man.Current() {
		if !Parses(a) {
			continue
		}
		base := p.seq
		if cache != nil {
			rp, err := cache.Begin(a, base)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
			}
			if rp != nil {
				p.seq = base + rp.Events
				for _, e := range rp.Entities {
					p.addEntity(e)
				}
				for _, r := range rp.Relationships {
					p.addRel(r)
				}
				continue
			}
			p.rec = &segment.Recorder{}
		}
		if err := p.parseArtifact(store, a); err != nil {
			return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
		}
		if cache != nil {
			if err := cache.End(a, base, p.seq-base, p.rec.Entities, p.rec.Relationships); err != nil {
				return nil, fmt.Errorf("%s: %w", a.LogicalPath, err)
			}
			p.rec = nil
		}
	}
	p.finishEntities()
	return p.res, nil
}

type parser struct {
	sink     func(schema.Event)
	res      *schema.Normalized
	caseID   string
	host     string
	seq      int
	entities map[string]schema.Entity
	relSeen  map[string]bool
	rec      *segment.Recorder

	// per artifact
	art casepkg.ArtifactRecord
	det Detection
}

// parseArtifact sniffs the artifact's head and dispatches on structure.
func (p *parser) parseArtifact(store *casepkg.Store, art casepkg.ArtifactRecord) error {
	p.art = art
	rc, err := store.Open(art.ArtifactID)
	if err != nil {
		return err
	}
	head := make([]byte, SniffBytes)
	n, _ := io.ReadFull(rc, head)
	rc.Close()
	det, ok := Sniff(head[:n], art.LogicalPath)
	if !ok {
		det = Detection{Service: unknownService, Kind: KindUnsupported, Reason: "structure not recognized as an AI-service export file"}
	}
	p.det = det
	if det.Kind == KindUnsupported {
		p.unsupported(det)
		return nil
	}
	rc, err = store.Open(art.ArtifactID)
	if err != nil {
		return err
	}
	defer rc.Close()
	switch det.Kind {
	case KindConversations:
		switch det.Service {
		case ServiceChatGPT, ServiceDeepSeek:
			return p.parseMappingConversations(rc)
		case ServiceClaudeAI:
			return p.parseClaudeConversations(rc)
		}
	case KindProjects:
		return p.parseClaudeProjects(rc)
	case KindAccount:
		return p.parseAccount(rc)
	case KindFeedback:
		return p.parseFeedback(rc)
	case KindShared:
		return p.parseShared(rc)
	case KindActivity:
		return p.parseGeminiActivity(rc)
	case KindActivityHTML:
		p.unsupported(Detection{Service: ServiceGemini, Kind: KindUnsupported,
			Reason: "Takeout My Activity exported as HTML only; request the export again with the JSON format to have prompts and responses parsed"})
		return nil
	}
	p.unsupported(Detection{Service: det.Service, Kind: KindUnsupported, Reason: "no reader for " + det.String()})
	return nil
}

// ---- events ----

// base starts an event in a conversation session.
func (p *parser) base(sessionID string) schema.Event {
	ev := schema.Event{
		TimestampSrc: evidenceClass,
		SessionID:    sessionID,
		Vendor:       p.det.Vendor(),
		Product:      p.det.Product(),
	}
	if sessionID != "" {
		ev.AgentID = "main:" + sessionID
	}
	return ev
}

// at sets the event's source location.
func at(ev *schema.Event, off int64, line int, ptr string) {
	ev.SourceOffset, ev.SourceLine, ev.SourceJSONPath = off, line, ptr
}

func (p *parser) emit(ev schema.Event) {
	ev.EventID = fmt.Sprintf(IDFormat, p.seq)
	ev.CaseID = p.caseID
	ev.SchemaVersion = version.SchemaVersion
	ev.Sequence = p.seq
	ev.Host = p.host
	ev.User = p.art.User
	ev.SourceArtifact = p.art.ArtifactID
	ev.SourcePath = p.art.LogicalPath
	if ev.Corroboration == "" {
		ev.Corroboration = schema.StateUnknown
	}
	if ev.SessionID != "" {
		p.touchSession(ev.SessionID)
	}
	p.seq++
	if p.sink != nil {
		p.sink(ev)
	} else {
		p.res.Events = append(p.res.Events, ev)
	}
	if ev.EventType == schema.EventToolCall && ev.Tool != "" {
		p.addEntity(schema.Entity{EntityID: "tool:" + ev.Tool, Kind: "tool", Label: ev.Tool})
		p.addRel(schema.Relationship{From: "agent:" + ev.AgentID, To: "tool:" + ev.Tool,
			Type: "invoked", DerivedFrom: []string{ev.EventID}, Corroboration: ev.Corroboration})
	}
}

// prompt, reply, toolCall, toolResult and meta build the event kinds with
// the evidence states this package's doc comment sets out.
func (p *parser) prompt(ev schema.Event, text string) {
	ev.EventType, ev.ActorType, ev.Corroboration = schema.EventHumanPrompt, schema.ActorHuman, schema.StateRequested
	ev.Summary = trim(text, maxSummary)
	p.emit(ev)
}

func (p *parser) reply(ev schema.Event, text string) {
	ev.EventType, ev.ActorType, ev.Corroboration = schema.EventModelResponse, schema.ActorModel, schema.StateReported
	ev.Summary = trim(text, maxSummary)
	p.emit(ev)
}

func (p *parser) toolCall(ev schema.Event, tool, callID, detail string) {
	ev.EventType, ev.ActorType, ev.Corroboration = schema.EventToolCall, schema.ActorAgent, schema.StateObserved
	ev.Tool, ev.ToolCallID, ev.Action = trim(tool, 80), callID, actionProvider
	ev.Summary = trim(detail, maxToolSummary)
	p.emit(ev)
}

func (p *parser) toolResult(ev schema.Event, tool, callID, detail string) {
	ev.EventType, ev.ActorType, ev.Corroboration = schema.EventToolResult, schema.ActorAgent, schema.StateObserved
	ev.Tool, ev.ToolCallID = trim(tool, 80), callID
	ev.Summary = trim(detail, maxToolSummary)
	p.emit(ev)
}

func (p *parser) meta(ev schema.Event, result, summary string) {
	ev.EventType, ev.ActorType, ev.Corroboration = schema.EventSessionMeta, schema.ActorSystem, schema.StateObserved
	if result != "" {
		ev.Result = result
	}
	ev.Summary = trim(summary, maxSummary)
	p.emit(ev)
}

// gap records a malformed or truncated region of a known schema.
func (p *parser) gap(sessionID string, off int64, line int, ptr, why string) {
	ev := p.base(sessionID)
	ev.EventType, ev.ActorType, ev.Corroboration = schema.EventTraceGap, schema.ActorSystem, schema.StateObserved
	ev.Result = resultUnparsed
	ev.Summary = trim(why, 400)
	at(&ev, off, line, ptr)
	p.emit(ev)
}

// unsupported records that a file is not in a schema this package reads.
func (p *parser) unsupported(d Detection) {
	ev := p.base("")
	ev.EventType, ev.ActorType, ev.Corroboration = schema.EventTraceGap, schema.ActorSystem, schema.StateObserved
	ev.Result = resultUnsup
	why := fmt.Sprintf("UNSUPPORTED %s (%s): %s", p.art.LogicalPath, d.Service, d.Reason)
	if len(d.Missing) > 0 {
		why += "; expected keys missing: " + strings.Join(d.Missing, ", ")
	}
	ev.Summary = trim(why, 600)
	at(&ev, 0, 1, "")
	p.emit(ev)
}

// attachment lists one attachment by name/id only; its content, when the
// export embeds it, stays in the sealed artifact.
func (p *parser) attachment(ev schema.Event, name, id, kind string) {
	s := "attachment: " + name
	if name == "" {
		s = "attachment"
	}
	if id != "" {
		s += " (id " + id + ")"
	}
	if kind != "" {
		s += " [" + kind + "]"
	}
	ev.Model = ""
	p.meta(ev, resultAttachment, s)
}

// ---- graph ----

func (p *parser) touchSession(sessionID string) {
	p.addEntity(schema.Entity{EntityID: "session:" + sessionID, Kind: "session",
		Label: sessionID, Product: p.det.Product()})
	p.addEntity(schema.Entity{EntityID: "agent:main:" + sessionID, Kind: "agent",
		Label: "main:" + sessionID, Product: p.det.Product()})
	p.addRel(schema.Relationship{From: "agent:main:" + sessionID, To: "session:" + sessionID,
		Type: "belongs_to", Corroboration: schema.StateObserved})
}

// describeSession attaches conversation metadata (title, service, schema
// variant) to the session entity.
func (p *parser) describeSession(sessionID string, attrs map[string]string) {
	if sessionID == "" {
		return
	}
	a := map[string]string{"evidence_class": evidenceClass, "service": p.det.Service, "schema_variant": p.det.Variant}
	for k, v := range attrs {
		if v != "" {
			a[k] = trim(v, 200)
		}
	}
	label := sessionID
	if t := a["title"]; t != "" {
		label = t
	}
	p.addEntity(schema.Entity{EntityID: "session:" + sessionID, Kind: "session",
		Label: label, Product: p.det.Product(), Attributes: a})
}

// addEntity keeps the richest record per id: a later record that carries
// attributes replaces a bare one, so a title found on a conversation wins
// over the bare session touched by its first event.
func (p *parser) addEntity(e schema.Entity) {
	if p.rec != nil {
		p.rec.Entity(e)
	}
	prev, ok := p.entities[e.EntityID]
	if !ok || (len(prev.Attributes) == 0 && len(e.Attributes) > 0) {
		p.entities[e.EntityID] = e
	}
}

func (p *parser) addRel(r schema.Relationship) {
	if p.rec != nil {
		p.rec.Rel(r)
	}
	k := r.From + "\x00" + r.To + "\x00" + r.Type
	if p.relSeen[k] {
		return
	}
	p.relSeen[k] = true
	p.res.Relationships = append(p.res.Relationships, r)
}

func (p *parser) finishEntities() {
	keys := make([]string, 0, len(p.entities))
	for k := range p.entities {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p.res.Entities = append(p.res.Entities, p.entities[k])
	}
}

// ---- helpers ----

// epochTime converts a provider epoch (seconds, fractional) to UTC and
// names the original value in the timestamp source.
func epochTime(ev *schema.Event, field string, v float64) {
	if v <= 0 || v > 1e11 {
		return
	}
	// A float64 epoch near 1.8e9 carries about microsecond precision;
	// anything finer is representation noise, so round to the microsecond.
	sec := int64(v)
	usec := int64(math.Round((v - float64(sec)) * 1e6))
	if usec >= 1e6 {
		sec, usec = sec+1, usec-1e6
	}
	ev.Timestamp = time.Unix(sec, usec*1e3).UTC().Format(time.RFC3339Nano)
	ev.TimestampSrc = fmt.Sprintf("%s:%s=%s", evidenceClass, field, trimFloat(v))
}

// isoTime normalizes an RFC 3339 timestamp to UTC and keeps the original
// text (with its offset) in the timestamp source.
func isoTime(ev *schema.Event, field, v string) {
	v = strings.TrimSpace(v)
	if v == "" {
		return
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999", "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05"} {
		if t, err := time.Parse(layout, v); err == nil {
			ev.Timestamp = t.UTC().Format(time.RFC3339Nano)
			ev.TimestampSrc = fmt.Sprintf("%s:%s=%s", evidenceClass, field, trim(v, 40))
			return
		}
	}
	ev.TimestampSrc = fmt.Sprintf("%s:%s=%s (unparsed)", evidenceClass, field, trim(v, 40))
}

func trimFloat(v float64) string {
	s := fmt.Sprintf("%.6f", v)
	s = strings.TrimRight(s, "0")
	return strings.TrimSuffix(s, ".")
}

func trim(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + "…"
}
