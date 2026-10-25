package supplychain

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/chain"
	"github.com/efij/AgentDFIR/v4/internal/notes"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// maliciousRules are the findings that mark a component as carrying
// something hostile: hidden or overriding instructions, a loader, a
// download piped into a shell, a typosquatted package, a known indicator.
var maliciousRules = map[string]bool{
	"EXTENSION_INVISIBLE_CODE": true, "EXTENSION_OBFUSCATED_LOADER": true, "PLUGIN_HOOK_EXECUTES_REMOTE": true,
	"SKILL_HIDDEN_INSTRUCTIONS": true, "MCP_TOOL_DESCRIPTION_POISONING": true, "MCP_REMOTE_FETCH_COMMAND": true,
	"MCP_PACKAGE_TYPOSQUAT": true, "KNOWN_INCIDENT_IOC": true, "TOOL_POISONING_INDICATOR": true,
	"INVISIBLE_UNICODE_INSTRUCTION": true,
}

// flaggable kinds: a settings file holds many things, so a finding on it
// does not flag everything it declares.
var flaggable = map[string]bool{KindSkill: true, KindSubagent: true, KindCommand: true, KindPlugin: true, KindHook: true,
	KindMCP: true, KindExtension: true, KindInstruction: true}

// flags marks the components the malicious-indicating findings cite, by
// the file (or MCP server) the finding names.
func (b *builder) flags() {
	for _, f := range b.in.Findings {
		if !maliciousRules[f.RuleID] {
			continue
		}
		event := ""
		for _, r := range f.Related {
			if strings.HasPrefix(r, "event: ") {
				event = strings.TrimPrefix(r, "event: ")
			}
		}
		key := notes.FindingKey(f.RuleID, f.EvidenceRefs)
		for _, ref := range f.EvidenceRefs {
			p := refPath(ref)
			server := ""
			if i := strings.Index(ref, " (server "); i >= 0 {
				server = strings.TrimSuffix(strings.SplitN(ref[i+len(" (server "):], ",", 2)[0], ")")
			}
			for i := range b.rep.Components {
				c := &b.rep.Components[i]
				if !flaggable[c.Kind] || !c.cites(p) {
					continue
				}
				if c.Kind == KindMCP && server != "" && c.Name != server {
					continue
				}
				if c.Kind == KindHook && event != "" && c.event != event {
					continue
				}
				if contains(c.Flags, f.RuleID) {
					continue
				}
				c.Flags = append(c.Flags, f.RuleID)
				b.relate(Relation{From: c.ID, To: key, Type: "flagged_by", Class: Verified,
					Basis: "the finding cites this component's file" + map[bool]string{true: " and server name", false: ""}[server != ""],
					Label: f.Title, Refs: []Ref{{Path: p}}})
			}
		}
	}
}

// cites reports whether a logical path is one of the component's files,
// or inside its directory.
func (c *Component) cites(p string) bool {
	if p == "" {
		return false
	}
	if c.paths[p] {
		return true
	}
	if c.Kind == KindPlugin || c.Kind == KindExtension {
		for d := range c.paths {
			if strings.HasPrefix(p, d+"/") {
				return true
			}
		}
	}
	return false
}

func contains(l []string, v string) bool {
	for _, x := range l {
		if x == v {
			return true
		}
	}
	return false
}

// singleHash reports whether every round of the case held the component
// with one hash, and that hash.
func (c *Component) singleHash() (string, bool) {
	h := ""
	for _, v := range c.History {
		if v.Source != "round" {
			continue
		}
		if h != "" && v.SHA256 != h {
			return "", false
		}
		h = v.SHA256
	}
	if h == "" {
		return c.SHA256, c.SHA256 != ""
	}
	return h, true
}

// reuse lists components with logged invocations in two or more sessions.
func (b *builder) reuse() {
	for i := range b.rep.Components {
		c := &b.rep.Components[i]
		if len(c.Sessions) < 2 {
			continue
		}
		r := Reuse{Component: c.ID, Sessions: append([]string(nil), c.Sessions...), Flagged: c.Flags}
		sort.Strings(r.Sessions)
		h, one := c.singleHash()
		switch {
		case c.Observed:
			r.Class = Inferred
			r.Basis = fmt.Sprintf("logged invocations in %d sessions name it, but its definition was not collected: the same name, not a proven same hash", len(r.Sessions))
		case one:
			r.SHA256, r.Class = h, Verified
			r.Basis = fmt.Sprintf("logged invocations in %d sessions; every collected round holds it with one hash", len(r.Sessions))
		default:
			r.Class = Inferred
			r.Basis = fmt.Sprintf("logged invocations in %d sessions, but its hash changed between rounds: which version each session ran follows from collection times only", len(r.Sessions))
		}
		if len(b.rep.Reuse) >= 2000 {
			b.omitted["reuse"]++
			continue
		}
		b.rep.Reuse = append(b.rep.Reuse, r)
	}
}

func finding(id, sev, title, desc string, refs []string, atlas string, related ...string) schema.Finding {
	return schema.Finding{
		RuleID: id, Severity: sev, Title: title, Description: desc, EvidenceRefs: refs,
		Status: schema.StateObserved, Endpoint: schema.StateUnknown,
		MitreATTACK: "T1195.002", MitreATLAS: atlas, Related: related,
	}
}

// rules raises the three supply-chain findings.
func (b *builder) rules() {
	b.ruleDriftExpansion()
	b.ruleUntrustedBeforeHigh()
	b.ruleFlaggedReused()
}

// SUPPLY_MCP_TOOL_DRIFT_EXPANSION: the same MCP server, two snapshots, and
// the later one can do more.
func (b *builder) ruleDriftExpansion() {
	seen := map[string]bool{}
	for _, d := range b.rep.Drift {
		if (d.Kind != "mcp_tool_definition" && d.Kind != "mcp_server_definition") || len(d.Expansion) == 0 {
			continue
		}
		k := d.Component + "|" + d.Subject + "|" + d.From.Label + "|" + d.To.Label
		if seen[k] {
			continue
		}
		seen[k] = true
		sev := "HIGH"
		if d.To.Source == "session_init" && onlyNewTools(d.Expansion) {
			sev = "MEDIUM"
		}
		var refs []string
		for _, r := range []string{d.To.Ref, d.From.Ref} {
			if r != "" {
				refs = append(refs, r)
			}
		}
		f := finding("SUPPLY_MCP_TOOL_DRIFT_EXPANSION", sev, "MCP Server Gained Capabilities Between Snapshots",
			fmt.Sprintf("MCP server %s changed between %s and %s and can now do more: %s. %s",
				d.Subject, d.From.Label, d.To.Label, strings.Join(d.Expansion, "; "), d.Basis),
			refs, "AML.T0110", "server: "+d.Subject, "from: "+d.From.Label, "to: "+d.To.Label)
		f.SessionID = d.To.Session
		f.Timestamp = d.To.Time
		f.FalsePositive = "An owner adding a tool to their own server, or an upgrade they made, produces the same drift; check who changed the configuration and whether the new tools were expected."
		b.rep.Findings = append(b.rep.Findings, f)
	}
}

func onlyNewTools(exp []string) bool {
	for _, e := range exp {
		if !strings.HasPrefix(e, "new tool ") {
			return false
		}
	}
	return true
}

// highEvents maps each event cited by a HIGH or CRITICAL finding (other
// than this package's own) to those findings.
func (b *builder) highEvents() map[string][]int {
	out := map[string][]int{}
	var byRef map[string]string
	for i, f := range b.in.Findings {
		if (f.Severity != "HIGH" && f.Severity != "CRITICAL") || strings.HasPrefix(f.RuleID, "SUPPLY_") {
			continue
		}
		for _, st := range f.ChainSteps {
			if st.EventID != "" {
				out[st.EventID] = append(out[st.EventID], i)
			}
		}
		if len(f.EvidenceRefs) > 0 && byRef == nil {
			byRef = chain.RefIndex(b.in.Events)
		}
		for _, r := range f.EvidenceRefs {
			if id := chain.EventForRef(byRef, r); id != "" {
				out[id] = append(out[id], i)
			}
		}
	}
	return out
}

// SUPPLY_UNTRUSTED_COMPONENT_BEFORE_HIGH: a skill, command or plugin hook
// from an untrusted origin ran, and within the window a command in the
// same session drew a HIGH or CRITICAL finding.
func (b *builder) ruleUntrustedBeforeHigh() {
	high := b.highEvents()
	if len(high) == 0 {
		return
	}
	type tcmd struct {
		e schema.Event
		t time.Time
	}
	bySession := map[string][]tcmd{}
	for id := range high {
		i, ok := b.evByID[id]
		if !ok {
			continue
		}
		e := b.in.Events[i]
		if e.EventType != schema.EventToolCall || e.FullCommand() == "" || e.SessionID == "" {
			continue
		}
		if t, ok := parseTS(e.Timestamp); ok {
			bySession[e.SessionID] = append(bySession[e.SessionID], tcmd{e, t})
		}
	}
	for s := range bySession {
		l := bySession[s]
		sort.SliceStable(l, func(i, j int) bool { return l[i].t.Before(l[j].t) })
	}
	for id := range b.followed {
		for _, fi := range high[id] {
			f := b.in.Findings[fi]
			if i, ok := b.evByID[id]; ok {
				e := b.in.Events[i]
				b.timeline(TimelineEntry{Time: e.Timestamp, TimeSource: TimeLog, Kind: "finding", Session: e.SessionID,
					Text: fmt.Sprintf("%s %s on a command that followed a component invocation", f.Severity, f.RuleID), Ref: refString(eventRef(e))})
			}
		}
	}
	seen := map[string]bool{}
	for _, inv := range b.invs {
		if inv.class != Verified || !inv.hasT {
			continue
		}
		c := b.comp(inv.comp)
		if c == nil {
			continue
		}
		origin := c.Origin
		switch c.Kind {
		case KindSkill, KindCommand, KindSubagent:
		case KindHook:
			if c.Parent == "" || !strings.HasPrefix(c.Parent, "plugin:") {
				continue
			}
		default:
			continue
		}
		if !origin.Untrusted() {
			continue
		}
		for _, cm := range bySession[inv.ev.SessionID] {
			dt := cm.t.Sub(inv.t)
			if dt <= 0 || dt > b.o.Window {
				continue
			}
			for _, fi := range high[cm.e.EventID] {
				hf := b.in.Findings[fi]
				k := c.ID + "|" + cm.e.EventID + "|" + hf.RuleID
				if seen[k] {
					continue
				}
				seen[k] = true
				f := finding("SUPPLY_UNTRUSTED_COMPONENT_BEFORE_HIGH", "HIGH", "Untrusted Agent Component Ran Shortly Before a High-Severity Command",
					fmt.Sprintf("%s %s (origin: %s, trust %s; %s) was invoked at %s — verified: %s. %s later in the same session the command `%s` drew %s %s (%s). The link between the two is time proximity only (inferred); the invocation and the finding are each verified on their own.",
						c.Kind, c.Name, originText(origin), origin.Trust, origin.Basis, rfc(inv.t), inv.basis, dt.Round(time.Second),
						trim(cm.e.Command, 160), hf.Severity, hf.RuleID, hf.Title),
					[]string{refString(eventRef(inv.ev)), refString(eventRef(cm.e))}, "AML.T0010.005",
					"component: "+c.ID, "finding: "+hf.RuleID, fmt.Sprintf("window: %s", b.o.Window))
				f.SessionID = inv.ev.SessionID
				f.AgentID = cm.e.AgentID
				f.Timestamp = cm.e.Timestamp
				f.FalsePositive = "A third-party skill used for routine work can precede an unrelated risky command; read what the skill instructs and whether the command follows from it."
				b.rep.Findings = append(b.rep.Findings, f)
			}
		}
	}
}

func originText(o Origin) string {
	parts := []string{o.Type}
	for _, v := range []string{o.Marketplace, o.Location, o.Package, o.GitRemote, o.URL} {
		if v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " ")
}

// SUPPLY_FLAGGED_COMPONENT_REUSED: a component a malicious-indicating
// finding cites was used in two or more sessions.
func (b *builder) ruleFlaggedReused() {
	for _, r := range b.rep.Reuse {
		c := b.comp(r.Component)
		if c == nil || len(c.Flags) == 0 || len(r.Sessions) < 2 {
			continue
		}
		var refs []string
		perSession := map[string]bool{}
		for _, inv := range b.invs {
			if inv.comp == c.ID && inv.class == Verified && !perSession[inv.ev.SessionID] && len(refs) < 6 {
				perSession[inv.ev.SessionID] = true
				refs = append(refs, refString(eventRef(inv.ev)))
			}
		}
		if len(c.Paths) > 0 {
			refs = append(refs, c.Paths[0])
		}
		f := finding("SUPPLY_FLAGGED_COMPONENT_REUSED", "HIGH", "Component Flagged as Malicious Was Used in Several Sessions",
			fmt.Sprintf("%s %s is cited by %s and ran in %d sessions (%s). Reuse is %s: %s.",
				c.Kind, c.Name, strings.Join(c.Flags, ", "), len(r.Sessions), strings.Join(firstN(r.Sessions, 5), ", "), r.Class, r.Basis),
			refs, "AML.T0010.005", "component: "+c.ID, "sessions: "+fmt.Sprint(len(r.Sessions)))
		if c.LastSeen != nil {
			f.Timestamp = c.LastSeen.Time
		}
		f.FalsePositive = "The flagging finding is a heuristic; if it is a false positive, so is this. Confirm the flag first."
		b.rep.Findings = append(b.rep.Findings, f)
	}
}

func firstN(l []string, n int) []string {
	if len(l) > n {
		return l[:n]
	}
	return l
}
