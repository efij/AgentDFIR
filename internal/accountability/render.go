package accountability

import (
	"encoding/json"
	"fmt"
	"html"
	"os"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/report"
	"github.com/efij/AgentDFIR/v5/internal/sanitize"
)

// WriteJSON writes the report as one JSON document (docs/schema/accountability.schema.json).
func WriteJSON(r *Report, path string) error {
	data, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

// WriteMarkdown writes the report as Markdown.
func WriteMarkdown(r *Report, path string) error {
	return os.WriteFile(path, []byte(Markdown(r)), 0o600)
}

// WriteHTML writes the report as a self-contained, network-silent page.
func WriteHTML(r *Report, path string) error {
	return os.WriteFile(path, []byte(HTML(r)), 0o600)
}

func s(v string) string { return sanitize.Terminal(v) }

func sortedKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Markdown renders the report.
func Markdown(r *Report) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	h := r.Case
	w("# Accountability report — case %s\n\n", s(h.CaseID))
	w("Who asked, what was allowed, what the agent did, and whether it went beyond the request — for every consequential action in the case. ")
	w("Evidence states are the case's own and are never upgraded here. **Not legal advice.**\n\n")
	if h.Simulated {
		w("> **Synthetic case.** This profile was written by `agentdfir simulate`; nothing in it happened on a real machine.\n\n")
	}
	w("## Case\n\n")
	w("| | |\n|---|---|\n")
	w("| Case | `%s` on `%s` (%s) |\n", s(h.CaseID), s(h.Host), s(h.OS))
	w("| Collected by | OS user `%s`", s(h.OperatorOSUser))
	if h.OperatorAsserted != "" {
		w(", asserted `%s`", s(h.OperatorAsserted))
	}
	w(" |\n")
	w("| Seal digest | `%s` |\n", h.SealDigest)
	switch {
	case h.Signed && h.SignatureValid:
		w("| Signature | VALID (ed25519, key fingerprint `%s`) |\n", h.SignerFingerprnt)
	case h.Signed:
		w("| Signature | INVALID |\n")
	default:
		w("| Signature | none (package is unsigned) |\n")
	}
	w("| Anchored | %v (anchor log on this machine matches the seal) |\n", h.Anchored)
	w("| Verify | %s (%s", h.Verify.Result, h.Verify.Depth)
	if len(h.Verify.Problems) > 0 {
		w("; %d problem(s)", len(h.Verify.Problems))
	}
	w(") |\n")
	for _, rd := range h.Rounds {
		line := fmt.Sprintf("round %d: %s → %s, collector %s", rd.Round, rd.StartedUTC, rd.CompletedUTC, rd.CollectorVersion)
		if rd.Signer != "" {
			line += ", signed " + rd.Signer
		}
		if rd.PriorIntegrity != "" {
			line += ", earlier rounds " + rd.PriorIntegrity
		}
		w("| Collection | %s |\n", s(line))
	}
	if h.Authorization.Reference != "" {
		w("| Authorization reference | `%s` (given at collection) |\n", s(h.Authorization.Reference))
	}
	for _, a := range h.Authorization.Records {
		w("| Authorization recorded | by **%s** — %s", s(a.By), s(a.Basis))
		if a.Reference != "" {
			w(" (ref `%s`)", s(a.Reference))
		}
		w("; recorded %s by `%s` against seal `%.16s…` |\n", a.TS, s(a.RecordedBy), a.SealDigest)
	}
	if len(h.Authorization.Records) == 0 && h.Authorization.Reference == "" {
		w("| Authorization | none recorded (`agentdfir case authorize --by … --basis …`) |\n")
	}
	for _, a := range h.Accounts {
		w("| Account | %s — %d action(s) |\n", s(a.Label), a.Actions)
	}
	w("| Evidence | %d events, %d findings |\n\n", h.Events, h.Findings)
	for _, p := range h.Verify.Problems {
		w("- integrity problem: `%s`\n", s(p))
	}
	if len(h.Verify.Problems) > 0 {
		w("\n")
	}

	w("## Summary\n\n")
	w("%d consequential action(s) in %d session(s); %d with a gap.\n\n", r.Summary.Actions, r.Summary.Sessions, r.Summary.WithGaps)
	if len(r.Summary.ByGap) > 0 {
		w("| Gap code | Actions |\n|---|---|\n")
		for _, k := range sortedKeys(r.Summary.ByGap) {
			w("| `%s` | %d |\n", k, r.Summary.ByGap[k])
		}
		w("\n")
	}
	if len(r.Summary.ByTrigger) > 0 {
		w("| Instruction trigger | Actions |\n|---|---|\n")
		for _, k := range sortedKeys(r.Summary.ByTrigger) {
			w("| `%s` | %d |\n", k, r.Summary.ByTrigger[k])
		}
		w("\n")
	}

	w("## Actions\n\n")
	if len(r.Rows) == 0 {
		w("No consequential action matched the filter.\n\n")
	}
	for _, row := range r.Rows {
		w("### %d. %s — %s\n\n", row.Index, strings.ReplaceAll(row.Class, "_", " "), s(row.Action.Timestamp))
		w("- **Session** `%s`", s(row.SessionID))
		if row.AgentID != "" {
			w(" · agent `%s`", s(row.AgentID))
		}
		w(" · account %s\n", s(row.Account))
		for _, f := range row.Findings {
			tag := ""
			if f.Chain {
				tag = " (attack chain)"
			}
			w("- **Finding** %s `%s` — %s%s\n", f.Severity, f.RuleID, s(f.Title), tag)
		}
		w("\n**Instruction — who asked.** %s\n", s(row.Instruction.Statement))
		if row.Instruction.PromptRef != "" {
			w("  Prompt evidence: `%s` at %s\n", s(row.Instruction.PromptRef), s(row.Instruction.PromptTime))
		}
		if row.Instruction.Trigger == "tool_result" && row.Instruction.TriggerRef != "" {
			w("  Trigger evidence: `%s`\n", s(row.Instruction.TriggerRef))
		}
		w("\n**Authority — what was allowed.** %s\n", s(row.Authority.Statement))
		if row.Authority.HeadlessLaunch != nil {
			w("  - %s", s(row.Authority.HeadlessLaunch.Text))
			if row.Authority.HeadlessLaunch.Evidence != "" {
				w(" — `%s`", s(row.Authority.HeadlessLaunch.Evidence))
			}
			w("\n")
		}
		for _, c := range row.Authority.Configs {
			w("  - `%s` (round %d, captured %s, artifact `%.12s`)", s(c.Path), c.Round, c.CollectedUTC, c.ArtifactID)
			var bits []string
			if c.DefaultMode != "" {
				bits = append(bits, "defaultMode="+c.DefaultMode)
			}
			if len(c.Allow) > 0 {
				bits = append(bits, fmt.Sprintf("allow=%v", c.Allow))
			}
			if len(c.Deny) > 0 {
				bits = append(bits, fmt.Sprintf("deny=%v", c.Deny))
			}
			if len(c.Ask) > 0 {
				bits = append(bits, fmt.Sprintf("ask=%v", c.Ask))
			}
			if c.DisableBypassMode != "" {
				bits = append(bits, "disableBypassPermissionsMode="+c.DisableBypassMode)
			}
			if len(c.BypassMarkers) > 0 {
				bits = append(bits, "bypass markers: "+strings.Join(c.BypassMarkers, " | "))
			}
			if len(c.Hooks) > 0 {
				bits = append(bits, fmt.Sprintf("hooks: %s", strings.Join(c.Hooks, "; ")))
			}
			if c.EnableAllProjectMCP {
				bits = append(bits, "enableAllProjectMcpServers=true")
			}
			if c.Note != "" {
				bits = append(bits, c.Note)
			}
			if len(bits) > 0 {
				w(": %s", s(strings.Join(bits, "; ")))
			}
			w("\n")
		}
		for _, ch := range row.Authority.Changed {
			w("  - `%s` changed between round %d and round %d (artifact `%.12s` → `%.12s`)\n", s(ch.Path), ch.Before.Round, ch.After.Round, ch.Before.ArtifactID, ch.After.ArtifactID)
		}
		for _, in := range row.Authority.AgentWrites {
			w("  - %s — `%s`\n", s(in.Text), s(in.Evidence))
		}
		for _, in := range row.Authority.Indicators {
			w("  - case-wide `%s`: %s — `%s`\n", in.RuleID, s(trimTo(in.Text, 160)), s(in.Evidence))
		}
		if len(row.Authority.MCPServers) > 0 {
			w("  - MCP servers configured: %s\n", s(strings.Join(row.Authority.MCPServers, ", ")))
		}
		w("\n**Action — what the agent did.** ")
		if row.Action.Command != "" {
			w("`%s` ran `%s`", s(row.Action.Tool), s(row.Action.Command))
		} else if row.Action.File != "" {
			w("`%s` on `%s`", s(row.Action.Tool), s(row.Action.File))
		} else {
			w("%s %s", s(row.Action.Tool), s(row.Action.Summary))
		}
		if row.Action.Target != "" {
			w(" — target `%s`", s(row.Action.Target))
		}
		if row.Action.NetworkDest != "" {
			w(" — destination `%s`", s(row.Action.NetworkDest))
		}
		w("\n  Evidence state: **%s**", row.Action.StateLabel)
		if row.Action.Witness != "" {
			w(" — %s", s(row.Action.Witness))
		}
		w("\n  Evidence: `%s`\n", s(row.Action.Evidence))
		for _, st := range row.Action.ChainSteps {
			w("  - chain step %s at %s: %s — `%s`\n", s(st.Step), st.Timestamp, s(st.Summary), s(st.Evidence))
		}
		if row.Action.Narrative != "" {
			w("  The agent then said: %s\n", s(quote(row.Action.Narrative, 200)))
		}
		w("\n**Gap — beyond the instruction?**\n")
		for _, g := range row.Gaps {
			w("  - `%s` — %s\n", g.Code, s(g.Reason))
		}
		w("\n")
	}

	w("## Limits — what this evidence cannot show\n\n")
	for _, l := range r.Limits {
		w("- %s\n", s(l))
	}
	w("\n## Gap codes\n\n")
	for _, g := range GapCodes {
		w("- `%s` — %s\n", g.Code, g.Meaning)
	}
	w("\nGenerated by AgentDFIR %s at %s. Derived from the sealed case; the case itself is unchanged. Not legal advice.\n", r.ToolVersion, r.GeneratedUTC)
	return b.String()
}

func esc(v string) string { return html.EscapeString(sanitize.Terminal(v)) }

// HTML renders the report as a page that loads nothing from anywhere.
func HTML(r *Report) string {
	var b strings.Builder
	w := func(v string) { b.WriteString(v) }
	h := r.Case
	w(`<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">`)
	w(`<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:">`)
	w(`<meta name="viewport" content="width=device-width, initial-scale=1">`)
	w(`<title>AgentDFIR Accountability — ` + esc(h.CaseID) + `</title>`)
	w(`<style>` + report.BaseCSS + accountabilityCSS + `</style></head><body>`)
	w(`<header><h1>AgentDFIR Accountability Report</h1><p class="sub">Case ` + esc(h.CaseID) + ` · who asked · what was allowed · what happened · gap</p></header><main>`)
	if h.Simulated {
		w(`<p class="warn">Synthetic case written by <code>agentdfir simulate</code>; nothing in it happened on a real machine.</p>`)
	}
	w(`<section><h2>Summary</h2><div class="cards">`)
	w(card("Actions", fmt.Sprint(r.Summary.Actions)))
	w(card("Sessions", fmt.Sprint(r.Summary.Sessions)))
	cls := "ok"
	if r.Summary.WithGaps > 0 {
		cls = "bad"
	}
	w(card("With a gap", fmt.Sprint(r.Summary.WithGaps), cls))
	w(card("Integrity", h.Verify.Result, map[bool]string{true: "ok", false: "bad"}[h.Verify.Result == "VERIFIED"]))
	w(`</div></section>`)

	w(`<section><h2>Case</h2><table class="kv">`)
	w(kv("Case", h.CaseID+" on "+h.Host+" ("+h.OS+")"))
	w(kv("Collected by", h.OperatorOSUser+" "+h.OperatorAsserted))
	w(kv("Seal digest", h.SealDigest))
	sig := "none (package is unsigned)"
	if h.Signed && h.SignatureValid {
		sig = "VALID (ed25519, key fingerprint " + h.SignerFingerprnt + ")"
	} else if h.Signed {
		sig = "INVALID"
	}
	w(kv("Signature", sig))
	w(kv("Anchored", fmt.Sprint(h.Anchored)))
	for _, rd := range h.Rounds {
		w(kv(fmt.Sprintf("Round %d", rd.Round), fmt.Sprintf("%s → %s, collector %s %s %s", rd.StartedUTC, rd.CompletedUTC, rd.CollectorVersion, rd.Signer, rd.PriorIntegrity)))
	}
	if h.Authorization.Reference != "" {
		w(kv("Authorization reference", h.Authorization.Reference))
	}
	for _, a := range h.Authorization.Records {
		w(kv("Authorization recorded", fmt.Sprintf("by %s — %s %s (recorded %s by %s)", a.By, a.Basis, a.Reference, a.TS, a.RecordedBy)))
	}
	for _, a := range h.Accounts {
		w(kv("Account", fmt.Sprintf("%s — %d action(s)", a.Label, a.Actions)))
	}
	w(kv("Evidence", fmt.Sprintf("%d events, %d findings", h.Events, h.Findings)))
	w(`</table>`)
	for _, p := range h.Verify.Problems {
		w(`<p class="bad mono">` + esc(p) + `</p>`)
	}
	w(`</section>`)

	w(`<section><h2>Actions</h2>`)
	if len(r.Rows) == 0 {
		w(`<p class="muted">No consequential action matched the filter.</p>`)
	}
	for _, row := range r.Rows {
		sev := "info"
		if len(row.Findings) > 0 {
			sev = map[string]string{"CRITICAL": "crit", "HIGH": "high", "MEDIUM": "med", "LOW": "low", "INFO": "info"}[row.Findings[0].Severity]
		}
		w(`<div class="finding ` + sev + `"><div class="fhead"><span class="badge ` + sev + `">` + esc(strings.ReplaceAll(row.Class, "_", " ")) + `</span> <strong>` + esc(row.Action.Timestamp) + `</strong> <span class="rule">` + esc(row.SessionID) + `</span></div>`)
		w(`<table class="kv">`)
		w(kv("Account", row.Account))
		for _, f := range row.Findings {
			w(kv("Finding", f.Severity+" "+f.RuleID+" — "+f.Title))
		}
		w(`</table><div class="four">`)
		w(`<div><h3>Instruction</h3><p>` + esc(row.Instruction.Statement) + `</p>`)
		if row.Instruction.PromptRef != "" {
			w(`<p class="mono ev">` + esc(row.Instruction.PromptRef) + ` · ` + esc(row.Instruction.PromptTime) + `</p>`)
		}
		if row.Instruction.Trigger == "tool_result" && row.Instruction.TriggerRef != "" {
			w(`<p class="mono ev">trigger: ` + esc(row.Instruction.TriggerRef) + `</p>`)
		}
		w(`</div><div><h3>Authority</h3><p>` + esc(row.Authority.Statement) + `</p><ul>`)
		if hl := row.Authority.HeadlessLaunch; hl != nil {
			w(`<li>` + esc(hl.Text) + ` <span class="mono ev">` + esc(hl.Evidence) + `</span></li>`)
		}
		for _, c := range row.Authority.Configs {
			line := fmt.Sprintf("%s (round %d, %s)", c.Path, c.Round, c.CollectedUTC)
			if c.DefaultMode != "" {
				line += " defaultMode=" + c.DefaultMode
			}
			if len(c.Allow) > 0 {
				line += fmt.Sprintf(" allow=%v", c.Allow)
			}
			if len(c.Deny) > 0 {
				line += fmt.Sprintf(" deny=%v", c.Deny)
			}
			if len(c.BypassMarkers) > 0 {
				line += " bypass: " + strings.Join(c.BypassMarkers, " | ")
			}
			if len(c.Hooks) > 0 {
				line += " hooks: " + strings.Join(c.Hooks, "; ")
			}
			w(`<li class="mono">` + esc(line) + `</li>`)
		}
		for _, ch := range row.Authority.Changed {
			w(`<li>` + esc(fmt.Sprintf("%s changed between round %d and %d", ch.Path, ch.Before.Round, ch.After.Round)) + `</li>`)
		}
		for _, in := range row.Authority.AgentWrites {
			w(`<li>` + esc(in.Text) + ` <span class="mono ev">` + esc(in.Evidence) + `</span></li>`)
		}
		for _, in := range row.Authority.Indicators {
			w(`<li>` + esc(in.RuleID+": "+trimTo(in.Text, 160)) + ` <span class="mono ev">` + esc(in.Evidence) + `</span></li>`)
		}
		if len(row.Authority.MCPServers) > 0 {
			w(`<li>MCP servers: ` + esc(strings.Join(row.Authority.MCPServers, ", ")) + `</li>`)
		}
		w(`</ul></div><div><h3>Action</h3>`)
		detail := row.Action.Summary
		if row.Action.Command != "" {
			detail = "$ " + row.Action.Command
		} else if row.Action.File != "" {
			detail = row.Action.Tool + " " + row.Action.File
		}
		w(`<p class="mono">` + esc(detail) + `</p>`)
		if row.Action.Target != "" {
			w(`<p>target: <span class="mono">` + esc(row.Action.Target) + `</span></p>`)
		}
		w(`<p>state: <span class="st st-` + esc(row.Action.State) + `">` + esc(row.Action.StateLabel) + `</span>`)
		if row.Action.Witness != "" {
			w(` — ` + esc(row.Action.Witness))
		}
		w(`</p><p class="mono ev">` + esc(row.Action.Evidence) + `</p>`)
		if len(row.Action.ChainSteps) > 0 {
			w(`<ol class="chain">`)
			for _, st := range row.Action.ChainSteps {
				w(`<li><span class="mono">` + esc(st.Timestamp) + `</span> <strong>` + esc(st.Step) + `</strong>: ` + esc(st.Summary) + ` <span class="mono ev">` + esc(st.Evidence) + `</span></li>`)
			}
			w(`</ol>`)
		}
		if row.Action.Narrative != "" {
			w(`<p class="muted">The agent then said: ` + esc(quote(row.Action.Narrative, 200)) + `</p>`)
		}
		w(`</div><div><h3>Gap</h3><ul>`)
		for _, g := range row.Gaps {
			c := "gap"
			if g.Code == GapNone {
				c = "nogap"
			}
			w(`<li class="` + c + `"><span class="mono">` + esc(g.Code) + `</span> — ` + esc(g.Reason) + `</li>`)
		}
		w(`</ul></div></div></div>`)
	}
	w(`</section>`)
	w(`<section><h2>Limits — what this evidence cannot show</h2><ul>`)
	for _, l := range r.Limits {
		w(`<li>` + esc(l) + `</li>`)
	}
	w(`</ul></section><section><h2>Gap codes</h2><table class="kv">`)
	for _, g := range GapCodes {
		w(kv(g.Code, g.Meaning))
	}
	w(`</table></section>`)
	w(`<footer>Generated by AgentDFIR ` + esc(r.ToolVersion) + ` at ` + esc(r.GeneratedUTC) + ` · derived from the sealed case, which is unchanged · loads no external resources · evidence states are never upgraded · not legal advice.</footer>`)
	w(`</main></body></html>`)
	return b.String()
}

func card(label, value string, class ...string) string {
	c := ""
	if len(class) > 0 {
		c = " " + class[0]
	}
	return `<div class="metric` + c + `"><div class="mv">` + esc(value) + `</div><div class="ml">` + esc(label) + `</div></div>`
}

func kv(k, v string) string {
	if strings.TrimSpace(v) == "" {
		v = "—"
	}
	return `<tr><th>` + esc(k) + `</th><td>` + esc(v) + `</td></tr>`
}

const accountabilityCSS = `
.four{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:10px}
.four h3{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:0 0 6px}
.four ul{padding-left:16px;margin:4px 0;font-size:13px}.four p{margin:4px 0;font-size:13.5px}
li.gap{color:#fca5a5}li.nogap{color:var(--muted)}
.warn{background:rgba(245,158,11,.15);border:1px solid var(--amber);border-radius:8px;padding:10px 14px}
@media(max-width:900px){.four{grid-template-columns:1fr}}
`
