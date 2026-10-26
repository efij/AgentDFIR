package report

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/redact"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

func rsmfCase() *Case {
	ev := func(id, ts, actor, typ string, mod func(*schema.Event)) schema.Event {
		e := schema.Event{EventID: id, CaseID: "C", Timestamp: ts, User: "dev", Product: "claude-code",
			SessionID: "5f0c9c1e-1111", AgentID: "main:5f0c9c1e-1111", ActorType: actor, EventType: typ,
			Corroboration: schema.StateObserved, SourceArtifact: "art1", SourcePath: ".claude/projects/p/s.jsonl"}
		if mod != nil {
			mod(&e)
		}
		return e
	}
	return &Case{
		Entities: []schema.Entity{{EntityID: "agent:adad4e2c", Kind: "agent", Attributes: map[string]string{"sidechain": "true"}}},
		Events: []schema.Event{
			ev("e1", "2026-08-30T14:00:00Z", schema.ActorHuman, schema.EventHumanPrompt, func(e *schema.Event) {
				e.Summary, e.SourceLine = "summarize auth; mail me at dev@corp.example", 1
			}),
			ev("e2", "2026-08-30T14:00:05Z", schema.ActorModel, schema.EventModelResponse, func(e *schema.Event) {
				e.Summary, e.SourceLine, e.Corroboration = "I ran the tests and they pass.", 2, schema.StateReported
			}),
			ev("e3", "2026-08-30T14:00:06Z", schema.ActorAgent, schema.EventToolCall, func(e *schema.Event) {
				e.Tool, e.ToolCallID, e.Command, e.SourceLine = "Bash", "t1", "cat /Users/dev/.aws/credentials", 3
				e.CommandFull = "cat /Users/dev/.aws/credentials " + strings.Repeat("x", 3000)
			}),
			ev("e4", "2026-08-30T14:00:07Z", schema.ActorAgent, schema.EventToolResult, func(e *schema.Event) {
				e.ToolCallID, e.Result, e.Summary, e.SourceLine = "t1", "ok", "key AKIAQ3EGRZJ7LMN2PX4T", 4
			}),
			ev("e5", "2026-08-30T14:00:08Z", schema.ActorAgent, schema.EventAgentSpawn, func(e *schema.Event) {
				e.TaskID, e.Summary, e.SourceLine = "adad4e2c", "spawn", 5
			}),
			ev("e6", "2026-08-30T14:00:09Z", schema.ActorAgent, schema.EventAgentMessage, func(e *schema.Event) {
				e.AgentID, e.Summary, e.SourceLine = "adad4e2c", "subagent says hi\x1b[31m", 1
			}),
			ev("e7", "", schema.ActorSystem, schema.EventTraceGap, func(e *schema.Event) { e.Summary, e.SourceLine = "malformed", 9 }),
			ev("e8", "2026-08-30T15:00:00Z", schema.ActorHuman, schema.EventHumanPrompt, func(e *schema.Event) {
				e.SessionID, e.Summary, e.SourceLine, e.SourceArtifact = "other/../session", "second", 1, "art2"
			}),
		},
		Findings: []schema.Finding{{RuleID: "SECRET_IN_TRANSCRIPT", EvidenceRefs: []string{".claude/projects/p/s.jsonl:4 (artifact art1, offset 0)"}}},
	}
}

func TestRSMFStructureAndTraceability(t *testing.T) {
	files, omitted, err := BuildRSMF(rsmfCase(), RSMFOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("got %d files, want one per session (2)", len(files))
	}
	if len(omitted) != 1 || omitted[0].EventID != "e7" || omitted[0].Line != 9 {
		t.Errorf("undated event must be reported as omitted with its source line: %+v", omitted)
	}
	for _, f := range files {
		if probs := ValidateRSMF(f.Data); len(probs) > 0 {
			t.Fatalf("%s invalid: %v", f.Name, probs)
		}
		if strings.ContainsAny(f.Name, "/\\") || strings.Contains(f.Name, "..") {
			t.Errorf("unsafe file name %q", f.Name)
		}
		if len(f.Trace) != len(f.Manifest.Events) {
			t.Errorf("%s: %d trace rows for %d events", f.Name, len(f.Trace), len(f.Manifest.Events))
		}
		for _, ev := range f.Manifest.Events {
			cf := map[string]string{}
			for _, c := range ev.Custom {
				cf[c.Name] = c.Value
			}
			if cf["source_artifact_id"] == "" || cf["source_line"] == "" || cf["evidence_state"] == "" {
				t.Errorf("event %s lacks traceability custom fields: %v", ev.ID, cf)
			}
		}
	}
	m := files[0].Manifest
	byID := map[string]RSMFEvent{}
	for _, e := range m.Events {
		byID[e.ID] = e
	}
	state := func(id string) string {
		for _, c := range byID[id].Custom {
			if c.Name == "evidence_state" {
				return c.Value
			}
		}
		return ""
	}
	if state("e2") != "CLAIMED" || state("e3") != "RECORDED" {
		t.Errorf("evidence state not preserved: e2=%s e3=%s", state("e2"), state("e3"))
	}
	if byID["e4"].Parent != "e3" {
		t.Errorf("tool result not threaded under its call: parent=%q", byID["e4"].Parent)
	}
	if byID["e5"].Type != "join" || byID["e5"].Participant != "agent:adad4e2c" {
		t.Errorf("spawn should be a join by the subagent: %+v", byID["e5"])
	}
	if len(byID["e3"].Attachments) != 1 {
		t.Errorf("long command should travel as an attachment")
	}
	var fids string
	for _, c := range byID["e4"].Custom {
		if c.Name == "finding_ids" {
			fids = c.Value
		}
	}
	if fids != "SECRET_IN_TRANSCRIPT" {
		t.Errorf("finding id not mapped to its evidence line: %q", fids)
	}
	disp := map[string]string{}
	for _, p := range m.Participants {
		disp[p.ID] = p.Display
	}
	if disp["agent:main:5f0c9c1e-1111"] != "Claude Code agent 5f0c9c1e" || disp["agent:adad4e2c"] != "Claude Code subagent adad4e2c" {
		t.Errorf("participant names: %v", disp)
	}
	if m.Conversations[0].Type != "channel" {
		t.Errorf("3+ participants should be a channel, got %s", m.Conversations[0].Type)
	}

	// The plain-text body is readable and terminal-safe.
	msg, _ := mail.ReadMessage(bytes.NewReader(files[0].Data))
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	part, _ := multipart.NewReader(msg.Body, params["boundary"]).NextPart()
	text, _ := io.ReadAll(part)
	if !strings.Contains(string(text), "I ran the tests and they pass.") || strings.Contains(string(text), "\x1b") {
		t.Errorf("text body wrong or unsanitized:\n%s", text)
	}
}

func TestRSMFDeterministicAndSessionFilter(t *testing.T) {
	a, _, _ := BuildRSMF(rsmfCase(), RSMFOptions{})
	b, _, _ := BuildRSMF(rsmfCase(), RSMFOptions{})
	for i := range a {
		if !bytes.Equal(a[i].Data, b[i].Data) {
			t.Fatalf("%s differs between identical runs", a[i].Name)
		}
	}
	only, _, _ := BuildRSMF(rsmfCase(), RSMFOptions{Sessions: []string{"other/../session"}})
	if len(only) != 1 || only[0].SessionID != "other/../session" {
		t.Fatalf("session filter: %+v", only)
	}
	none, _, err := BuildRSMF(&Case{}, RSMFOptions{})
	if err != nil || len(none) != 0 {
		t.Errorf("empty case: %v %d", err, len(none))
	}
}

func TestRSMFRedacted(t *testing.T) {
	r, _ := redact.Parse("secrets,emails,paths")
	c, err := RedactCase(rsmfCase(), r)
	if err != nil {
		t.Fatal(err)
	}
	files, _, _ := BuildRSMF(c, RSMFOptions{})
	for _, f := range files {
		raw := string(f.Data) + mustManifestJSON(t, f.Data)
		for _, leak := range []string{"AKIAQ3EGRZJ7LMN2PX4T", "dev@corp.example", "/Users/dev"} {
			if strings.Contains(raw, leak) {
				t.Errorf("%s leaks %q", f.Name, leak)
			}
		}
		if probs := ValidateRSMF(f.Data); len(probs) > 0 {
			t.Errorf("redacted file invalid: %v", probs)
		}
	}
	if orig := rsmfCase(); !strings.Contains(orig.Events[3].Summary, "AKIA") {
		t.Error("redaction mutated its input")
	}
}

func mustManifestJSON(t *testing.T, data []byte) string {
	t.Helper()
	msg, _ := mail.ReadMessage(bytes.NewReader(data))
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err != nil {
			t.Fatal("no zip part")
		}
		if p.FileName() == "rsmf.zip" {
			z, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, p))
			zr, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
			if err != nil {
				t.Fatal(err)
			}
			var all strings.Builder
			for _, f := range zr.File {
				rc, _ := f.Open()
				b, _ := io.ReadAll(rc)
				rc.Close()
				all.Write(b)
			}
			return all.String()
		}
	}
}

func TestValidatorCatchesBrokenManifests(t *testing.T) {
	good := func() *RSMFManifest {
		return &RSMFManifest{Version: RSMFVersion,
			Participants:  []RSMFParticipant{{ID: "p1", Display: "P"}},
			Conversations: []RSMFConversation{{ID: "c1", Display: "C", Type: "direct", Participants: []string{"p1"}}},
			Events: []RSMFEvent{{ID: "e1", Type: "message", Conversation: "c1", Participant: "p1", Timestamp: "2026-01-01T00:00:00Z",
				Attachments: []RSMFAttachment{{ID: "a1", Display: "a", Size: 3}}}}}
	}
	if p := ValidateRSMFManifest(good(), map[string]int64{"a1": 3}); len(p) != 0 {
		t.Fatalf("good manifest rejected: %v", p)
	}
	cases := map[string]func(m *RSMFManifest){
		"version":           func(m *RSMFManifest) { m.Version = "1.0" },
		"dup participant":   func(m *RSMFManifest) { m.Participants = append(m.Participants, m.Participants[0]) },
		"conv ref":          func(m *RSMFManifest) { m.Conversations[0].Participants = []string{"ghost"} },
		"event conv":        func(m *RSMFManifest) { m.Events[0].Conversation = "nope" },
		"event participant": func(m *RSMFManifest) { m.Events[0].Participant = "ghost" },
		"timestamp":         func(m *RSMFManifest) { m.Events[0].Timestamp = "yesterday" },
		"non-utc":           func(m *RSMFManifest) { m.Events[0].Timestamp = "2026-01-01T02:00:00+02:00" },
		"type":              func(m *RSMFManifest) { m.Events[0].Type = "shout" },
		"parent":            func(m *RSMFManifest) { m.Events[0].Parent = "e9" },
		"dup event": func(m *RSMFManifest) {
			m.Events = append(m.Events, RSMFEvent{ID: "e1", Type: "disclaimer", Conversation: "c1", Timestamp: "2026-01-01T00:00:00Z"})
		},
		"attachment size": func(m *RSMFManifest) { m.Events[0].Attachments[0].Size = 4 },
		"attachment gone": func(m *RSMFManifest) { m.Events[0].Attachments[0].ID = "a2" },
		"no display":      func(m *RSMFManifest) { m.Participants[0].Display = "" },
		"custom name":     func(m *RSMFManifest) { m.Events[0].Custom = []RSMFCustom{{Value: "v"}} },
	}
	for name, mutate := range cases {
		m := good()
		mutate(m)
		if p := ValidateRSMFManifest(m, map[string]int64{"a1": 3}); len(p) == 0 {
			t.Errorf("%s: broken manifest accepted", name)
		}
	}
}

func TestValidatorHostileFiles(t *testing.T) {
	files, _, _ := BuildRSMF(rsmfCase(), RSMFOptions{})
	data := files[0].Data
	for name, in := range map[string][]byte{
		"empty":       nil,
		"garbage":     []byte("\x00\x01not a message"),
		"truncated":   data[:len(data)/2],
		"no zip":      bytes.Replace(data, []byte(`filename="rsmf.zip"`), []byte(`filename="other.zip"`), 1),
		"bad version": bytes.Replace(data, []byte("X-RSMF-Version: 2.0.0"), []byte("X-RSMF-Version: 9"), 1),
		"bad count":   bytes.Replace(data, []byte("X-RSMF-EventCount: "), []byte("X-RSMF-EventCount: 9"), 1),
	} {
		if p := ValidateRSMF(in); len(p) == 0 {
			t.Errorf("%s: accepted", name)
		}
	}
}
