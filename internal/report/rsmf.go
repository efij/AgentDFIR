package report

// RSMF export: each agent session becomes one Relativity Short Message
// Format 2.0 file — an RFC 5322 message whose headers summarize the
// conversation, a text/plain body a person can read, and an rsmf.zip
// attachment holding rsmf_manifest.json (participants, conversations,
// events) plus any attachment files.
//
// The output is built from the published RSMF 2.0 manifest structure and
// checked by ValidateRSMF; it has not been loaded into a review platform
// here, and nothing about it is a claim of admissibility. Everything
// AgentDFIR knows that RSMF has no field for — evidence state, the source
// artifact and line an event came from, tool names, finding ids — goes in
// the spec's custom name/value fields, so a reviewer can always walk from
// a message back to the sealed byte range it was read from.

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"mime"
	"mime/quotedprintable"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/efij/AgentDFIR/v3/internal/products"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/version"
)

// RSMFVersion is the manifest/header version this writer emits.
const RSMFVersion = "2.0.0"

// rsmfBodyMax caps a command's length in an event body; longer commands
// travel whole as an attachment file and the body says so.
const rsmfBodyMax = 2048

// RSMFManifest is rsmf_manifest.json.
type RSMFManifest struct {
	Version       string             `json:"version"`
	Participants  []RSMFParticipant  `json:"participants"`
	Conversations []RSMFConversation `json:"conversations"`
	Events        []RSMFEvent        `json:"events"`
}

// RSMFParticipant is one person or agent in the manifest.
type RSMFParticipant struct {
	ID        string       `json:"id"`
	Display   string       `json:"display"`
	Email     string       `json:"email,omitempty"`
	AccountID string       `json:"account_id,omitempty"`
	Custom    []RSMFCustom `json:"custom,omitempty"`
}

// RSMFConversation is one conversation (an agent session).
type RSMFConversation struct {
	ID           string       `json:"id"`
	Display      string       `json:"display"`
	Platform     string       `json:"platform"`
	Type         string       `json:"type"`
	Participants []string     `json:"participants"`
	Custodian    string       `json:"custodian,omitempty"`
	Custom       []RSMFCustom `json:"custom,omitempty"`
}

// RSMFEvent is one message, join or notice.
type RSMFEvent struct {
	ID           string           `json:"id"`
	Type         string           `json:"type"`
	Conversation string           `json:"conversation"`
	Participant  string           `json:"participant,omitempty"`
	Timestamp    string           `json:"timestamp"`
	Body         string           `json:"body,omitempty"`
	Parent       string           `json:"parent,omitempty"`
	Attachments  []RSMFAttachment `json:"attachments,omitempty"`
	Deleted      bool             `json:"deleted,omitempty"`
	Edited       bool             `json:"edited,omitempty"`
	Custom       []RSMFCustom     `json:"custom,omitempty"`
}

// RSMFAttachment names a file inside rsmf.zip.
type RSMFAttachment struct {
	ID      string `json:"id"`
	Display string `json:"display"`
	Size    int64  `json:"size"`
}

// RSMFCustom is the spec's extension mechanism: a name/value pair.
type RSMFCustom struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// RSMFOptions selects what is exported.
type RSMFOptions struct {
	// Sessions limits the export to these session ids (all when empty).
	Sessions []string
}

// RSMFTrace ties one exported RSMF event to the evidence it came from.
type RSMFTrace struct {
	EventID     string
	ArtifactID  string
	LogicalPath string
	Line        int
	Offset      int64
}

// RSMFOmission is an event that could not be represented, and why.
type RSMFOmission struct {
	EventID     string
	ArtifactID  string
	LogicalPath string
	Line        int
	Reason      string
}

// RSMFFile is one generated .rsmf message.
type RSMFFile struct {
	Name         string // file name, e.g. session-5f0c9c1e….rsmf
	Conversation string // RSMF conversation id
	SessionID    string
	Data         []byte
	Manifest     RSMFManifest
	Trace        []RSMFTrace
	Omitted      []RSMFOmission
}

// conversation accumulates one session's events before rendering.
type rsmfConv struct {
	session string
	product string
	events  []schema.Event
}

// BuildRSMF renders one RSMF file per session in c. Events without a
// usable timestamp cannot be placed in an RSMF conversation (the spec
// requires one); they are returned as omissions, never given a made-up
// time. A session with no dated event at all produces no file; its events
// are all in the omissions.
func BuildRSMF(c *Case, opts RSMFOptions) ([]RSMFFile, []RSMFOmission, error) {
	want := map[string]bool{}
	for _, s := range opts.Sessions {
		want[s] = true
	}
	convs := map[string]*rsmfConv{}
	var order []string
	for _, e := range sortedEvents(c.Events) {
		if len(want) > 0 && !want[e.SessionID] {
			continue
		}
		cv := convs[e.SessionID]
		if cv == nil {
			cv = &rsmfConv{session: e.SessionID, product: e.Product}
			convs[e.SessionID] = cv
			order = append(order, e.SessionID)
		}
		if cv.product == "" {
			cv.product = e.Product
		}
		cv.events = append(cv.events, e)
	}
	sort.Strings(order)
	sidechain := map[string]bool{}
	for _, en := range c.Entities {
		if en.Kind == "agent" && en.Attributes["sidechain"] == "true" {
			sidechain[strings.TrimPrefix(en.EntityID, "agent:")] = true
		}
	}
	findingsByRef := findingIndex(c.Findings)

	var out []RSMFFile
	var omitted []RSMFOmission
	used := map[string]bool{}
	for _, sid := range order {
		f, err := buildConversation(convs[sid], sidechain, findingsByRef)
		if err != nil {
			return nil, nil, err
		}
		omitted = append(omitted, f.Omitted...)
		if len(f.Manifest.Events) == 0 {
			continue
		}
		f.Name = uniqueName(used, "session-"+safeFileName(sid, "unattributed"), ".rsmf")
		out = append(out, f)
	}
	return out, omitted, nil
}

// WriteRSMF builds the RSMF files into dir and validates every one before
// returning; a file that fails its own validator is an error, not a
// warning.
func WriteRSMF(c *Case, dir string, opts RSMFOptions) ([]RSMFFile, []RSMFOmission, error) {
	files, omitted, err := BuildRSMF(c, opts)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, nil, err
	}
	for _, f := range files {
		if probs := ValidateRSMF(f.Data); len(probs) > 0 {
			return nil, nil, fmt.Errorf("rsmf %s failed validation: %s", f.Name, strings.Join(probs, "; "))
		}
		if err := os.WriteFile(filepath.Join(dir, f.Name), f.Data, 0o600); err != nil {
			return nil, nil, err
		}
	}
	return files, omitted, nil
}

func buildConversation(cv *rsmfConv, sidechain map[string]bool, findings map[string][]string) (RSMFFile, error) {
	convID := "session:" + cv.session
	if cv.session == "" {
		convID = "session:unattributed"
	}
	productName := productDisplay(cv.product)
	f := RSMFFile{Conversation: convID, SessionID: cv.session}
	m := RSMFManifest{Version: RSMFVersion}

	parts := map[string]*RSMFParticipant{}
	var partOrder []string
	addPart := func(p RSMFParticipant) string {
		if _, ok := parts[p.ID]; !ok {
			pp := p
			parts[p.ID] = &pp
			partOrder = append(partOrder, p.ID)
		}
		return p.ID
	}
	agentPart := func(id, product string) RSMFParticipant {
		name := productDisplay(product)
		short := shortAgent(id)
		role := "agent"
		if sidechain[id] || (id != "" && !strings.HasPrefix(id, "main:")) {
			role = "subagent"
		}
		disp := name + " " + role + " " + short
		if id == "" {
			disp = name + " agent (id not recorded)"
			id = "unknown:" + cv.session
		}
		return RSMFParticipant{ID: "agent:" + id, Display: disp,
			Custom: customs("agentdfir_actor", role, "agentdfir_agent_id", id, "agentdfir_product", product)}
	}

	callEvent := map[string]string{} // tool_call_id → RSMF event id of the call
	attach := map[string][]byte{}
	var humans []string
	var minTS, maxTS time.Time
	for _, e := range cv.events {
		ts, ok := parseEventTime(e.Timestamp)
		if !ok {
			reason := "no timestamp recorded"
			if e.Timestamp != "" {
				reason = "unparseable timestamp"
			}
			f.Omitted = append(f.Omitted, RSMFOmission{EventID: e.EventID, ArtifactID: e.SourceArtifact,
				LogicalPath: e.SourcePath, Line: e.SourceLine, Reason: reason})
			continue
		}
		ts = ts.UTC()
		if minTS.IsZero() || ts.Before(minTS) {
			minTS = ts
		}
		if ts.After(maxTS) {
			maxTS = ts
		}
		ev := RSMFEvent{ID: e.EventID, Type: "message", Conversation: convID, Timestamp: rsmfTime(ts)}
		switch e.ActorType {
		case schema.ActorHuman:
			user := e.User
			p := RSMFParticipant{ID: "human:" + user, Display: "User " + user, AccountID: user,
				Custom: customs("agentdfir_actor", "human")}
			if user == "" {
				p.ID, p.Display = "human:unknown", "User (account not recorded)"
			}
			if _, seen := parts[p.ID]; !seen {
				humans = append(humans, p.Display)
			}
			ev.Participant = addPart(p)
		case schema.ActorModel, schema.ActorAgent:
			ev.Participant = addPart(agentPart(e.AgentID, e.Product))
		default:
			ev.Participant = addPart(RSMFParticipant{ID: "system:agentdfir", Display: "AgentDFIR (parser notice)",
				Custom: customs("agentdfir_actor", "system")})
		}
		body := e.Summary
		switch e.EventType {
		case schema.EventToolCall:
			name := e.Tool
			if e.MCPServer != "" {
				name = e.MCPServer + "/" + e.MCPTool
			}
			detail := e.FullCommand()
			if detail == "" {
				detail = firstNonEmpty(e.Summary, e.File)
			}
			if len(detail) > rsmfBodyMax {
				aid := "att-" + e.EventID + "-command"
				attach[aid] = []byte(detail)
				ev.Attachments = append(ev.Attachments, RSMFAttachment{ID: aid, Display: "command-" + e.EventID + ".txt", Size: int64(len(detail))})
				detail = truncUTF8(detail, rsmfBodyMax) + "… [full text in attachment " + aid + "]"
			}
			body = "Tool call " + name + ": " + detail
			if e.ToolCallID != "" {
				callEvent[e.ToolCallID] = e.EventID
			}
		case schema.EventToolResult:
			body = "Tool result"
			if e.Result != "" {
				body += " (" + e.Result + ")"
			}
			body += ": " + e.Summary
			if p, ok := callEvent[e.ToolCallID]; ok && e.ToolCallID != "" {
				ev.Parent = p
			}
		case schema.EventAgentSpawn:
			if e.TaskID != "" {
				ev.Type = "join"
				ev.Participant = addPart(agentPart(e.TaskID, e.Product))
			}
		case schema.EventTraceGap:
			ev.Type = "disclaimer"
			body = "Transcript gap: " + firstNonEmpty(e.Summary, e.Result, "unreadable region")
		case schema.EventSessionMeta:
			ev.Type = "disclaimer"
		case schema.EventHumanPrompt, schema.EventModelResponse, schema.EventAgentMessage:
		default:
			ev.Type = "unknown"
		}
		ev.Body = body
		ev.Custom = eventCustom(e, findings)
		m.Events = append(m.Events, ev)
		f.Trace = append(f.Trace, RSMFTrace{EventID: e.EventID, ArtifactID: e.SourceArtifact,
			LogicalPath: e.SourcePath, Line: e.SourceLine, Offset: e.SourceOffset})
	}
	for _, id := range partOrder {
		m.Participants = append(m.Participants, *parts[id])
	}
	conv := RSMFConversation{ID: convID, Platform: productName, Participants: partOrder,
		Display: productName + " session " + shortAgent(cv.session),
		Custom:  customs("agentdfir_session_id", cv.session, "agentdfir_product", cv.product)}
	if cv.session == "" {
		conv.Display = productName + " events without a session id"
	}
	conv.Type = "direct"
	if len(partOrder) > 2 {
		conv.Type = "channel"
	}
	if len(humans) == 1 {
		conv.Custodian = humans[0]
	}
	if conv.Participants == nil {
		conv.Participants = []string{}
	}
	if m.Participants == nil {
		m.Participants = []RSMFParticipant{}
	}
	if m.Events == nil {
		m.Events = []RSMFEvent{}
	}
	m.Conversations = []RSMFConversation{conv}
	f.Manifest = m

	data, err := renderRSMF(m, conv, attach, minTS, maxTS)
	if err != nil {
		return f, err
	}
	f.Data = data
	return f, nil
}

// eventCustom carries the AgentDFIR facts RSMF has no field for, in a
// fixed order, empty values left out.
func eventCustom(e schema.Event, findings map[string][]string) []RSMFCustom {
	ids := findings[e.SourcePath+":"+strconv.Itoa(e.SourceLine)]
	ids = append(ids, findings["event:"+e.EventID]...)
	ids = dedupSorted(ids)
	return customs(
		"agentdfir_event_id", e.EventID,
		"agentdfir_event_type", e.EventType,
		"agentdfir_actor_type", e.ActorType,
		"agentdfir_agent_id", e.AgentID,
		"agentdfir_parent_agent_id", e.ParentAgentID,
		"evidence_state", schema.Label(e.Corroboration),
		"evidence_state_code", e.Corroboration,
		"source_artifact_id", e.SourceArtifact,
		"source_logical_path", e.SourcePath,
		"source_line", strconv.Itoa(e.SourceLine),
		"source_offset", strconv.FormatInt(e.SourceOffset, 10),
		"timestamp_source", e.TimestampSrc,
		"tool", e.Tool,
		"tool_call_id", e.ToolCallID,
		"mcp_server", e.MCPServer,
		"mcp_tool", e.MCPTool,
		"model", e.Model,
		"cwd", e.Cwd,
		"file", e.File,
		"network_destination", e.NetworkDest,
		"result", e.Result,
		"witness_note", e.WitnessNote,
		"finding_ids", strings.Join(ids, ","),
	)
}

// findingIndex maps "logical_path:line" and "event:<id>" to the rule ids
// of findings that cite them. Findings cite evidence by source line, so a
// finding id lands on every event read from that line.
func findingIndex(fs []schema.Finding) map[string][]string {
	out := map[string][]string{}
	for _, f := range fs {
		for _, ref := range f.EvidenceRefs {
			key := ref
			if i := strings.Index(ref, " ("); i >= 0 {
				key = ref[:i]
			}
			out[key] = append(out[key], f.RuleID)
		}
		for _, st := range f.ChainSteps {
			if st.EventID != "" {
				out["event:"+st.EventID] = append(out["event:"+st.EventID], f.RuleID)
			}
		}
	}
	return out
}

func dedupSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

func customs(kv ...string) []RSMFCustom {
	var out []RSMFCustom
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			out = append(out, RSMFCustom{Name: kv[i], Value: kv[i+1]})
		}
	}
	return out
}

func firstNonEmpty(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// productDisplay names a product from its id via the product registry;
// an unknown id is shown as recorded rather than guessed at.
func productDisplay(id string) string {
	if id == "" {
		return "Unknown product"
	}
	if p, err := products.ByID(id); err == nil && p.Name != "" {
		return p.Name
	}
	return id
}

func shortAgent(id string) string {
	id = strings.TrimPrefix(id, "main:")
	if len(id) > 8 {
		return id[:8]
	}
	if id == "" {
		return "(unattributed)"
	}
	return id
}

func rsmfTime(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// safeFileName keeps [A-Za-z0-9_-] (everything else, dots included,
// becomes '_'), at most 80 characters.
func safeFileName(s, empty string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 80 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return empty
	}
	return b.String()
}

func uniqueName(used map[string]bool, base, ext string) string {
	name := base + ext
	for i := 2; used[strings.ToLower(name)]; i++ {
		name = fmt.Sprintf("%s-%d%s", base, i, ext)
	}
	used[strings.ToLower(name)] = true
	return name
}

// renderRSMF writes the RFC 5322 message. Everything that varies is
// derived from the content (dates from the events, boundary and
// Message-ID from a digest), so the same input gives the same bytes.
func renderRSMF(m RSMFManifest, conv RSMFConversation, attach map[string][]byte, begin, end time.Time) ([]byte, error) {
	man, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	zipModTime := end
	if zipModTime.Year() < 1980 {
		zipModTime = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
	}
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	names := []string{"rsmf_manifest.json"}
	files := map[string][]byte{"rsmf_manifest.json": append(man, '\n')}
	ids := make([]string, 0, len(attach))
	for id := range attach {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		names = append(names, id)
		files[id] = attach[id]
	}
	for _, n := range names {
		w, err := zw.CreateHeader(&zip.FileHeader{Name: n, Method: zip.Deflate, Modified: zipModTime})
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(files[n]); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	// Human-readable body.
	disp := map[string]string{}
	for _, p := range m.Participants {
		disp[p.ID] = p.Display
	}
	var tb strings.Builder
	fmt.Fprintf(&tb, "%s\r\n", sanitize.Terminal(conv.Display))
	fmt.Fprintf(&tb, "Exported by AgentDFIR %s in RSMF %s. Evidence strength per event: ASKED / CLAIMED / RECORDED / PARTLY CONFIRMED / CONFIRMED / DISPROVED / UNKNOWN. Model text (CLAIMED) is not proof that anything ran.\r\n", version.Version, RSMFVersion)
	fmt.Fprintf(&tb, "Each event's source artifact and line are in rsmf_manifest.json (custom fields source_artifact_id, source_line).\r\n\r\n")
	for _, ev := range m.Events {
		who := disp[ev.Participant]
		if who == "" {
			who = "notice"
		}
		state := ""
		for _, c := range ev.Custom {
			if c.Name == "evidence_state" {
				state = c.Value
			}
		}
		body := strings.ReplaceAll(sanitize.Terminal(ev.Body), "\n", "\r\n    ")
		fmt.Fprintf(&tb, "[%s] %s (%s, %s): %s\r\n", ev.Timestamp, sanitize.Terminal(who), ev.Type, state, body)
	}
	var qp bytes.Buffer
	qw := quotedprintable.NewWriter(&qp)
	if _, err := qw.Write([]byte(tb.String())); err != nil {
		return nil, err
	}
	if err := qw.Close(); err != nil {
		return nil, err
	}

	digest := sha256.New()
	digest.Write(qp.Bytes())
	digest.Write(zb.Bytes())
	sum := hex.EncodeToString(digest.Sum(nil))
	// "=_" cannot occur in quoted-printable or base64 text, so the
	// boundary can never collide with the parts it separates.
	boundary := "=_rsmf_" + sum[:32]

	var out bytes.Buffer
	h := func(k, v string) { out.WriteString(k + ": " + v + "\r\n") }
	dateOf := rsmfTime
	h("From", "AgentDFIR <rsmf@agentdfir.invalid>")
	h("Subject", headerText(conv.Display))
	h("Date", end.UTC().Format(time.RFC1123Z))
	h("Message-ID", "<"+sum[:40]+"@agentdfir.invalid>")
	h("MIME-Version", "1.0")
	h("X-RSMF-Version", RSMFVersion)
	h("X-RSMF-Generator", "AgentDFIR "+version.Version)
	h("X-RSMF-Application", headerText(conv.Platform))
	h("X-RSMF-BeginDate", dateOf(begin))
	h("X-RSMF-EndDate", dateOf(end))
	h("X-RSMF-EventCount", strconv.Itoa(len(m.Events)))
	h("X-RSMF-AttachmentCount", strconv.Itoa(len(attach)))
	if conv.Custodian != "" {
		h("X-RSMF-Custodian", headerText(conv.Custodian))
	}
	var pd []string
	for _, p := range m.Participants {
		pd = append(pd, headerText(p.Display))
	}
	if len(pd) > 0 {
		h("X-RSMF-Participants", strings.Join(pd, ";\r\n "))
	}
	h("Content-Type", `multipart/mixed; boundary="`+boundary+`"`)
	out.WriteString("\r\n")
	out.WriteString("This is a multi-part message in RSMF format.\r\n")
	out.WriteString("--" + boundary + "\r\n")
	out.WriteString("Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\n")
	out.Write(qp.Bytes())
	out.WriteString("\r\n--" + boundary + "\r\n")
	out.WriteString("Content-Type: application/zip; name=\"rsmf.zip\"\r\nContent-Disposition: attachment; filename=\"rsmf.zip\"\r\nContent-Transfer-Encoding: base64\r\n\r\n")
	b64 := base64.StdEncoding.EncodeToString(zb.Bytes())
	for len(b64) > 76 {
		out.WriteString(b64[:76] + "\r\n")
		b64 = b64[76:]
	}
	if b64 != "" {
		out.WriteString(b64 + "\r\n")
	}
	out.WriteString("--" + boundary + "--\r\n")
	return out.Bytes(), nil
}

// headerText makes a value safe for one header line: control characters
// dropped, non-ASCII RFC 2047-encoded, length bounded.
func headerText(s string) string {
	s = sanitize.Terminal(s)
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	return mime.QEncoding.Encode("utf-8", truncUTF8(s, 200))
}

// truncUTF8 cuts s to at most n bytes without splitting a character.
func truncUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
