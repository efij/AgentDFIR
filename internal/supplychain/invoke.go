package supplychain

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/correlate"
	"github.com/efij/AgentDFIR/v4/internal/mcpaudit"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// maxRawLine bounds one re-read transcript line.
const maxRawLine = 1 << 20

// rawReader re-reads single transcript lines from the sealed store to
// recover what normalization does not keep: a Skill tool's input, a hook
// record's command, the tool list a session started with.
type rawReader struct {
	store   *casepkg.Store
	budget  int
	used    int
	skipped int
}

func (r *rawReader) line(ev schema.Event) []byte {
	if r == nil || r.store == nil || ev.SourceArtifact == "" {
		return nil
	}
	if r.used >= r.budget {
		r.skipped++
		return nil
	}
	r.used++
	rc, err := r.store.OpenAt(ev.SourceArtifact, ev.SourceOffset)
	if err != nil {
		return nil
	}
	defer rc.Close()
	br := bufio.NewReaderSize(io.LimitReader(rc, maxRawLine), 64<<10)
	var out []byte
	for {
		chunk, isPrefix, err := br.ReadLine()
		out = append(out, chunk...)
		if err != nil || !isPrefix {
			break
		}
	}
	return out
}

// invocation is one recorded use of a component.
type invocation struct {
	comp  string
	class string
	basis string
	kind  string // mcp_tool_call | skill | slash_command | hook
	ev    schema.Event
	t     time.Time
	hasT  bool
	label string
}

type toolSnap struct {
	tools []string
	ev    schema.Event
}

var commandNameRe = regexp.MustCompile(`<command-name>\s*/?([^<\s]+)\s*</command-name>`)

func (b *builder) invocations() {
	ev := b.in.Events
	b.evByID = make(map[string]int, len(ev))
	for i := range ev {
		b.evByID[ev[i].EventID] = i
	}
	if b.in.Store != nil {
		b.raw = &rawReader{store: b.in.Store, budget: b.o.MaxRawReads}
	} else {
		b.note("evidence store not available: Skill tool inputs and hook records were not re-read from the transcripts")
	}
	b.initTools = map[string][]toolSnap{}
	byName := map[string][]string{} // invocation name → skill/command/subagent ids
	mcpByName := map[string][]string{}
	hookByCmd := map[string][]string{}
	hookByEvent := map[string][]string{}
	for _, c := range b.rep.Components {
		switch c.Kind {
		case KindSkill, KindCommand, KindSubagent:
			byName[c.Name] = append(byName[c.Name], c.ID)
		case KindMCP:
			mcpByName[c.Name] = append(mcpByName[c.Name], c.ID)
		case KindHook:
			hookByCmd[c.cmd] = append(hookByCmd[c.cmd], c.ID)
			hookByEvent[c.event] = append(hookByEvent[c.event], c.ID)
		}
	}
	seenHook := map[string]bool{}
	for _, e := range ev {
		switch e.EventType {
		case schema.EventToolCall:
			switch {
			case e.MCPServer != "":
				ids := b.filterHost(mcpByName[e.MCPServer], e.Product)
				if len(ids) == 0 {
					ids = []string{b.observed(KindMCP, e.MCPServer, e.Product, "server named by a recorded tool call; no configuration for it was collected")}
					mcpByName[e.MCPServer] = ids
				}
				b.invoke(ids, "mcp_tool_call", e, fmt.Sprintf("tool call %s names server %s (tool %s)", e.ToolCallID, e.MCPServer, e.MCPTool), e.MCPServer+"/"+e.MCPTool)
			case e.Tool == "Skill" || e.Tool == "SlashCommand":
				name := b.skillInput(e)
				if name == "" {
					continue
				}
				ids := b.filterHost(byName[name], e.Product)
				if len(ids) == 0 {
					kind := KindSkill
					if e.Tool == "SlashCommand" {
						kind = KindCommand
					}
					ids = []string{b.observed(kind, name, e.Product, "named by a recorded "+e.Tool+" tool call; its definition was not collected")}
					byName[name] = ids
				}
				b.invoke(ids, map[bool]string{true: "slash_command", false: "skill"}[e.Tool == "SlashCommand"], e,
					fmt.Sprintf("%s tool call %s names %q", e.Tool, e.ToolCallID, name), name)
			}
		case schema.EventHumanPrompt:
			if !strings.Contains(e.Summary, "<command-") {
				continue
			}
			m := commandNameRe.FindStringSubmatch(e.Summary)
			if m == nil {
				m = commandNameRe.FindStringSubmatch(string(b.raw.line(e)))
			}
			if m == nil {
				continue
			}
			// Built-in commands (/clear, /model …) have no component and are
			// not invented one.
			if ids := b.filterHost(byName[m[1]], e.Product); len(ids) > 0 {
				b.invoke(ids, "slash_command", e, fmt.Sprintf("the prompt record names command /%s", m[1]), "/"+m[1])
			}
		case schema.EventSessionMeta:
			r := e.Result
			if r != "unknown_type:attachment" && r != "system:init" && r != "system:stop_hook_summary" && !strings.HasPrefix(r, "progress") {
				continue
			}
			line := b.raw.line(e)
			if len(line) == 0 {
				continue
			}
			if r == "system:init" {
				b.sessionInit(e, line)
				continue
			}
			for _, h := range hookRecords(line) {
				key := e.SessionID + "\x00" + h.event + "\x00" + h.command + "\x00" + h.toolUseID
				if seenHook[key] {
					continue
				}
				seenHook[key] = true
				b.hookExecution(e, h, hookByCmd, hookByEvent)
			}
		}
	}
	b.sessionInitDrift()
	b.followOns()
}

// filterHost keeps the components the event's product loads, when any do.
func (b *builder) filterHost(ids []string, product string) []string {
	if len(ids) < 2 || product == "" {
		return ids
	}
	var keep []string
	for _, id := range ids {
		if c := b.comp(id); c != nil && c.Host == product {
			keep = append(keep, id)
		}
	}
	if len(keep) == 0 {
		return ids
	}
	return keep
}

// observed adds a component known only from the transcripts.
func (b *builder) observed(kind, name, host, why string) string {
	id := kind + ":observed:" + name
	if b.comp(id) == nil {
		b.add(Component{ID: id, Kind: kind, Name: name, Host: host, Observed: true,
			Origin: Origin{Type: "unknown", Trust: "unknown", Basis: why}})
	}
	return id
}

// invoke records one invocation against its candidate components:
// verified when exactly one component carries the name, inferred for each
// when several do.
func (b *builder) invoke(ids []string, kind string, e schema.Event, basis, label string) {
	class := Verified
	if len(ids) > 1 {
		class = Inferred
		basis += fmt.Sprintf("; %d components share the name, so which one ran is a name match only", len(ids))
	}
	t, ok := parseTS(e.Timestamp)
	for _, id := range ids {
		c := b.comp(id)
		if c == nil {
			continue
		}
		inv := invocation{comp: id, class: class, basis: basis, kind: kind, ev: e, t: t, hasT: ok, label: label}
		b.invs = append(b.invs, inv)
		if class == Verified {
			c.Invocations++
			if e.SessionID != "" {
				c.Sessions = appendUniq(c.Sessions, e.SessionID)
			}
			if ok {
				st := &Stamp{Time: rfc(t), Source: TimeLog, Detail: "invocation recorded in a transcript", Ref: refString(eventRef(e))}
				c.seen(st, false)
				st2 := *st
				c.seen(&st2, true)
			}
		}
		b.relate(Relation{From: id, To: "event:" + e.EventID, Type: "invoked", Class: class, Basis: basis, Time: e.Timestamp,
			Session: e.SessionID, Label: label, Refs: []Ref{eventRef(e)}})
		b.timeline(TimelineEntry{Time: e.Timestamp, TimeSource: TimeLog, Kind: "invocation", Component: id, Class: class, Session: e.SessionID,
			Text: fmt.Sprintf("%s invoked (%s)", label, kind), Ref: refString(eventRef(e))})
	}
}

// skillInput reads the skill or command a Skill / SlashCommand tool call
// named from its raw transcript line.
func (b *builder) skillInput(e schema.Event) string {
	line := b.raw.line(e)
	if len(line) == 0 {
		return ""
	}
	var rec struct {
		Message struct {
			Content json.RawMessage `json:"content"`
		} `json:"message"`
	}
	if json.Unmarshal(line, &rec) != nil {
		return ""
	}
	var items []struct {
		Type  string `json:"type"`
		ID    string `json:"id"`
		Name  string `json:"name"`
		Input struct {
			Skill   string `json:"skill"`
			Command string `json:"command"`
		} `json:"input"`
	}
	if json.Unmarshal(rec.Message.Content, &items) != nil {
		return ""
	}
	for _, it := range items {
		if it.Type != "tool_use" || (e.ToolCallID != "" && it.ID != e.ToolCallID) {
			continue
		}
		name := strings.TrimSpace(firstNonEmpty(it.Input.Skill, it.Input.Command))
		name = strings.TrimPrefix(name, "/")
		if i := strings.IndexAny(name, " \t\n"); i > 0 {
			name = name[:i]
		}
		return trim(name, 200)
	}
	return ""
}

// hookRecord is one hook execution a transcript line records.
type hookRecord struct {
	event, name, command, toolUseID string
}

// hookRecords reads the hook executions Claude Code writes into a
// transcript: attachment lines (hook_success, hook_error, …), progress
// lines (hook_progress) and stop_hook_summary system lines.
func hookRecords(line []byte) []hookRecord {
	var rec struct {
		Type       string `json:"type"`
		Subtype    string `json:"subtype"`
		ToolUseID  string `json:"toolUseID"`
		Attachment *struct {
			Type      string `json:"type"`
			HookName  string `json:"hookName"`
			HookEvent string `json:"hookEvent"`
			Command   string `json:"command"`
			ToolUseID string `json:"toolUseID"`
		} `json:"attachment"`
		Data *struct {
			Type      string `json:"type"`
			HookName  string `json:"hookName"`
			HookEvent string `json:"hookEvent"`
			Command   string `json:"command"`
		} `json:"data"`
		HookInfos []struct {
			Command string `json:"command"`
		} `json:"hookInfos"`
	}
	if json.Unmarshal(line, &rec) != nil {
		return nil
	}
	var out []hookRecord
	switch {
	case rec.Attachment != nil && strings.HasPrefix(rec.Attachment.Type, "hook_"):
		a := rec.Attachment
		out = append(out, hookRecord{event: firstNonEmpty(a.HookEvent, hookEventOf(a.HookName)), name: a.HookName, command: a.Command, toolUseID: a.ToolUseID})
	case rec.Data != nil && rec.Data.Type == "hook_progress":
		d := rec.Data
		out = append(out, hookRecord{event: firstNonEmpty(d.HookEvent, hookEventOf(d.HookName)), name: d.HookName, command: d.Command, toolUseID: rec.ToolUseID})
	case rec.Type == "system" && rec.Subtype == "stop_hook_summary":
		for i, h := range rec.HookInfos {
			if i >= 50 {
				break
			}
			out = append(out, hookRecord{event: "Stop", command: h.Command, toolUseID: rec.ToolUseID})
		}
	}
	return out
}

func hookEventOf(name string) string {
	if i := strings.Index(name, ":"); i > 0 {
		return name[:i]
	}
	return name
}

// hookExecution links one hook record to the hook it ran: verified when
// the record names a command identical to a declared one; inferred when
// only the lifecycle event matches a single declared hook.
func (b *builder) hookExecution(e schema.Event, h hookRecord, byCmd, byEvent map[string][]string) {
	var ids []string
	class, basis := Verified, ""
	switch {
	case h.command != "" && len(byCmd[h.command]) > 0:
		ids = byCmd[h.command]
		basis = "the hook record names a command identical to the declared hook command"
		if len(ids) > 1 {
			class = Inferred
			basis += fmt.Sprintf("; %d declarations carry it", len(ids))
		}
	case h.command == "" && h.event != "" && len(byEvent[h.event]) == 1:
		ids, class = byEvent[h.event], Inferred
		basis = "the hook record names only its event (" + h.event + "); one declared hook has that event"
	case h.command != "":
		ids = []string{b.observedHook(h, e.Product)}
		basis = "the hook record names this command; no declaration for it was collected"
	default:
		return
	}
	label := firstNonEmpty(h.name, h.event) + " hook"
	if h.command != "" {
		label += ": " + trim(h.command, 120)
	}
	t, ok := parseTS(e.Timestamp)
	for _, id := range ids {
		c := b.comp(id)
		if c == nil {
			continue
		}
		b.invs = append(b.invs, invocation{comp: id, class: class, basis: basis, kind: "hook", ev: e, t: t, hasT: ok, label: label})
		if class == Verified {
			c.Invocations++
			if e.SessionID != "" {
				c.Sessions = appendUniq(c.Sessions, e.SessionID)
			}
			if ok {
				c.seen(&Stamp{Time: rfc(t), Source: TimeLog, Detail: "hook execution recorded in a transcript", Ref: refString(eventRef(e))}, false)
				c.seen(&Stamp{Time: rfc(t), Source: TimeLog, Detail: "hook execution recorded in a transcript", Ref: refString(eventRef(e))}, true)
			}
		}
		b.relate(Relation{From: id, To: "event:" + e.EventID, Type: "hook_executed", Class: class, Basis: basis, Time: e.Timestamp,
			Session: e.SessionID, Label: label, Refs: []Ref{eventRef(e)}})
		b.timeline(TimelineEntry{Time: e.Timestamp, TimeSource: TimeLog, Kind: "hook_execution", Component: id, Class: class, Session: e.SessionID,
			Text: label, Ref: refString(eventRef(e))})
	}
	// A hook record that names the tool_use id of a tool call is an
	// explicit reference to it.
	if h.toolUseID != "" {
		if b.toolUse == nil {
			b.toolUse = map[string]int{}
			for i := range b.in.Events {
				if t := &b.in.Events[i]; t.EventType == schema.EventToolCall && t.ToolCallID != "" {
					b.toolUse[t.SessionID+"\x00"+t.ToolCallID] = i
				}
			}
		}
		if i, ok := b.toolUse[e.SessionID+"\x00"+h.toolUseID]; ok {
			t := b.in.Events[i]
			b.relate(Relation{From: "event:" + e.EventID, To: "event:" + t.EventID, Type: "hook_for_tool_call", Class: Verified,
				Basis: "the hook record names this tool call's tool_use id", Time: e.Timestamp, Session: e.SessionID,
				Label: trim(firstNonEmpty(t.Command, t.Tool), 160), Refs: []Ref{eventRef(e), eventRef(t)}})
		}
	}
}

func (b *builder) observedHook(h hookRecord, host string) string {
	id := "hook:observed:" + h.event + ":" + short(sha(h.command))
	if b.comp(id) == nil {
		b.add(Component{ID: id, Kind: KindHook, Name: firstNonEmpty(h.event, "unknown") + " hook", Host: host, Observed: true,
			SHA256: sha(h.command), HashBasis: "recorded command string", cmd: h.command, event: h.event,
			Origin: Origin{Type: "unknown", Trust: "unknown", Basis: "named by a hook record in a transcript; no declaration for it was collected"}})
	}
	return id
}

// sessionInit keeps the tool list a session's init record logged, per MCP
// server (tool names mcp__<server>__<tool>).
func (b *builder) sessionInit(e schema.Event, line []byte) {
	var rec struct {
		Tools []string `json:"tools"`
	}
	if json.Unmarshal(line, &rec) != nil {
		return
	}
	// Only servers that listed tools: a server that failed to connect lists
	// none, and comparing against that would read every tool as new.
	per := map[string][]string{}
	for i, t := range rec.Tools {
		if i >= 5000 {
			break
		}
		parts := strings.SplitN(t, "__", 3)
		if len(parts) == 3 && parts[0] == "mcp" {
			per[parts[1]] = append(per[parts[1]], parts[2])
		}
	}
	for srv, tools := range per {
		sort.Strings(tools)
		b.initTools[srv] = append(b.initTools[srv], toolSnap{tools: tools, ev: e})
	}
}

// sessionInitDrift compares the tool lists consecutive sessions started
// with, per server. Names only: an init record lists tool names, not
// definitions.
func (b *builder) sessionInitDrift() {
	for _, srv := range sortedKeys(b.initTools) {
		snaps := b.initTools[srv]
		sort.SliceStable(snaps, func(i, j int) bool {
			ti, _ := parseTS(snaps[i].ev.Timestamp)
			tj, _ := parseTS(snaps[j].ev.Timestamp)
			return ti.Before(tj)
		})
		cid := b.mcpByName(srv)
		if cid == "" && b.mcpCount(srv) == 0 {
			cid = b.observed(KindMCP, srv, snaps[0].ev.Product, "server listed in a session's init record; no configuration for it was collected")
		}
		for k := 1; k < len(snaps); k++ {
			prev, cur := snaps[k-1], snaps[k]
			if strings.Join(prev.tools, "\x00") == strings.Join(cur.tools, "\x00") {
				continue
			}
			d := compareServers(toolServer(srv, prev.tools), toolServer(srv, cur.tools))
			if d == nil {
				continue
			}
			d.Component, d.Subject, d.Class = cid, srv, Verified
			d.Basis = "both tool lists are logged session init records; tool names only (no definitions are logged there)"
			d.From = Snapshot{Label: "session " + prev.ev.SessionID + " init", Source: "session_init", Session: prev.ev.SessionID, Time: prev.ev.Timestamp, TimeSource: TimeLog, Ref: refString(eventRef(prev.ev))}
			d.To = Snapshot{Label: "session " + cur.ev.SessionID + " init", Source: "session_init", Session: cur.ev.SessionID, Time: cur.ev.Timestamp, TimeSource: TimeLog, Ref: refString(eventRef(cur.ev))}
			b.addDrift(*d)
		}
	}
}

func toolServer(name string, tools []string) mcpaudit.Server {
	s := mcpaudit.Server{Name: name}
	for _, t := range tools {
		s.Tools = append(s.Tools, mcpaudit.Tool{Name: t})
	}
	return s
}

// followOns lists, for every invocation, the commands and MCP calls that
// came after it in the same session inside the window — inferred, time
// proximity only — and what endpoint correlation tied those commands to.
func (b *builder) followOns() {
	type tev struct {
		i int
		t time.Time
	}
	bySession := map[string][]tev{}
	for i, e := range b.in.Events {
		if e.EventType != schema.EventToolCall || e.SessionID == "" || (e.Command == "" && e.MCPServer == "") {
			continue
		}
		if t, ok := parseTS(e.Timestamp); ok {
			bySession[e.SessionID] = append(bySession[e.SessionID], tev{i, t})
		}
	}
	for s := range bySession {
		l := bySession[s]
		sort.SliceStable(l, func(i, j int) bool { return l[i].t.Before(l[j].t) })
	}
	matches := map[string][]correlate.Match{}
	if b.in.Correlation != nil {
		for _, m := range b.in.Correlation.Matches {
			matches[m.EventID] = append(matches[m.EventID], m)
		}
	}
	done := map[string]bool{}
	b.followed = map[string]bool{}
	seenPair := map[string]bool{}
	for _, inv := range b.invs {
		if !inv.hasT || inv.ev.SessionID == "" {
			continue
		}
		n := 0
		for _, te := range bySession[inv.ev.SessionID] {
			if !te.t.After(inv.t) && !(te.t.Equal(inv.t) && b.in.Events[te.i].Sequence > inv.ev.Sequence) {
				continue
			}
			if te.t.Sub(inv.t) > b.o.Window || n >= b.o.MaxFollow {
				break
			}
			e := b.in.Events[te.i]
			if e.EventID == inv.ev.EventID {
				continue
			}
			pair := inv.comp + "\x00" + inv.ev.EventID + "\x00" + e.EventID
			if seenPair[pair] {
				continue
			}
			seenPair[pair] = true
			n++
			label := trim(e.Command, 160)
			if e.MCPServer != "" {
				label = "mcp " + e.MCPServer + "/" + e.MCPTool
			}
			b.relate(Relation{From: "event:" + inv.ev.EventID, To: "event:" + e.EventID, Type: "followed_by", Class: Inferred,
				Basis: fmt.Sprintf("time proximity only: %s after the %s invocation of %s, same session", te.t.Sub(inv.t).Round(time.Second), inv.kind, inv.comp),
				Time:  e.Timestamp, Session: e.SessionID, Label: label, Refs: []Ref{eventRef(inv.ev), eventRef(e)}})
			if !done[e.EventID] {
				done[e.EventID] = true
				b.followed[e.EventID] = true
				if e.Command != "" {
					b.timeline(TimelineEntry{Time: e.Timestamp, TimeSource: TimeLog, Kind: "command", Class: Inferred, Session: e.SessionID,
						Text: "command after " + inv.label + ": " + label, Ref: refString(eventRef(e))})
				}
				b.produced(e, matches[e.EventID])
			}
		}
	}
}

// produced adds what endpoint correlation tied a command to.
func (b *builder) produced(e schema.Event, ms []correlate.Match) {
	for _, m := range ms {
		pid := fmt.Sprintf("process:%s", firstNonEmpty(m.Record.Ref, fmt.Sprintf("pid %d @ %s", m.Record.PID, m.Record.Time.Format(time.RFC3339))))
		label := trim(firstNonEmpty(m.Record.Cmdline, m.Record.Exe, m.Record.DestHost, m.Record.FilePath, m.Record.Operation), 160)
		b.relate(Relation{From: "event:" + e.EventID, To: pid, Type: "produced", Class: Inferred, Confidence: m.Confidence,
			Basis: fmt.Sprintf("endpoint correlation (%s witness): %s within %d ms", m.Witness, m.Basis, m.WindowMS),
			Time:  m.Record.Time.UTC().Format(time.RFC3339), Session: e.SessionID, Label: label,
			Refs: []Ref{eventRef(e), {External: m.Record.Ref}}})
		for _, rel := range m.Related {
			to := fmt.Sprintf("record:%s", firstNonEmpty(rel.Record.Ref, rel.Record.Time.Format(time.RFC3339Nano)))
			b.relate(Relation{From: pid, To: to, Type: "related_record", Class: Verified,
				Basis: "telemetry ties the record to the matched process by " + rel.Basis,
				Time:  rel.Record.Time.UTC().Format(time.RFC3339), Label: trim(firstNonEmpty(rel.Record.Cmdline, rel.Record.DestHost, rel.Record.DestIP, rel.Record.FilePath), 160),
				Refs: []Ref{{External: rel.Record.Ref}}})
		}
	}
}
