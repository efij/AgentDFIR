package reconstruct

import (
	"fmt"
	"io"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/detect"
	"github.com/efij/AgentDFIR/v4/internal/sanitize"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// textTimelineMax bounds the timeline section of the text report; the JSON
// carries every kept entry.
const textTimelineMax = 400

func t(s string) string { return sanitize.Terminal(detect.MaskSecrets(s)) }

// WriteText prints the report in the fixed section order: Summary,
// Timeline, Delegation, Hand-offs, Cross-host links, Attack stages,
// Missing evidence.
func WriteText(w io.Writer, r *Report) {
	s := r.Summary
	fmt.Fprintln(w, "INCIDENT RECONSTRUCTION (deterministic correlation; no narrative)")
	if r.Unverified {
		fmt.Fprintln(w, "WARNING: includes a case whose seal did not verify; every result is marked by it.")
	}
	fmt.Fprintln(w, "\n== Summary")
	fmt.Fprintf(w, "%d case(s), %d host entit(ies), %d session(s), %d agent(s), %d segment(s)\n", s.Cases, s.Hosts, s.Sessions, s.Agents, s.Segments)
	fmt.Fprintf(w, "%d timeline entr(ies) · %d delegation(s) · %d hand-off(s) · %d cross-host link(s)\n", s.TimelineEntries, s.Delegations, s.Handoffs, s.Links)
	fmt.Fprintf(w, "%d stage item(s) · %d verified / %d inferred stage edge(s) · %d missing-evidence item(s)\n", s.StageItems, s.VerifiedEdges, s.InferredEdges, s.Missing)
	for _, c := range r.Cases {
		tel := "no second witness"
		if len(c.Telemetry) > 0 {
			tel = strings.Join(c.Telemetry, ", ")
		}
		fmt.Fprintf(w, "  %s  host %s · package %s · %s · %d events, %d findings · %s\n", c.Label, t(c.Host), t(c.PackageID), c.Integrity, c.Events, c.Findings, t(tel))
	}
	for _, n := range r.Identities.Notes {
		fmt.Fprintf(w, "  identity: %s\n", t(n))
	}
	for _, l := range r.Identities.Links {
		fmt.Fprintf(w, "  identity link (%s %s): %s\n", t(l.Identifier), t(l.Value), t(strings.Join(l.Entities, " = ")))
	}

	fmt.Fprintln(w, "\n== Timeline")
	if len(r.Timeline) == 0 {
		fmt.Fprintln(w, "  (no timed agent activity)")
	}
	for i, e := range r.Timeline {
		if i == textTimelineMax {
			fmt.Fprintf(w, "  … %d more entr(ies) in the JSON output\n", len(r.Timeline)-textTimelineMax)
			break
		}
		when := e.Time
		if when == "" {
			when = "(untimed)"
		}
		what := e.Kind
		if e.Kind == "finding" {
			what = e.Severity + " " + e.RuleID
		}
		fmt.Fprintf(w, "  %4d %s  %s %s  %s  %s: %s\n", e.Seq, when, e.Case, t(e.Host), t(e.Segment), what, t(e.Summary))
	}
	if n := r.Omitted["timeline"]; n > 0 {
		fmt.Fprintf(w, "  TRUNCATED: %d entr(ies) past the bound left out\n", n)
	}

	fmt.Fprintln(w, "\n== Delegation")
	if len(r.Delegations) == 0 {
		fmt.Fprintln(w, "  (none recorded)")
	}
	for _, d := range r.Delegations {
		fmt.Fprintf(w, "  [%s] %s %s → %s (%s)\n", strings.ToUpper(d.Link), d.Case, t(d.Parent), t(orDash(d.Child)), d.Kind)
		fmt.Fprintf(w, "      %s\n", t(d.Basis))
		for _, ref := range d.Refs {
			fmt.Fprintf(w, "      Evidence: %s\n", t(ref))
		}
	}

	fmt.Fprintln(w, "\n== Hand-offs")
	if len(r.Handoffs) == 0 {
		fmt.Fprintln(w, "  (none found)")
	}
	for _, h := range r.Handoffs {
		fmt.Fprintf(w, "  [%s] %s %s: %s → %s %s\n", strings.ToUpper(h.Link), h.Kind, t(h.Key), t(h.From), t(orDash(h.To)), h.Relation)
		fmt.Fprintf(w, "      %s\n", t(h.Basis))
		for _, ref := range h.Refs {
			fmt.Fprintf(w, "      Evidence: %s\n", t(ref))
		}
	}

	fmt.Fprintln(w, "\n== Cross-host links")
	if len(r.Links) == 0 {
		fmt.Fprintln(w, "  (none: one case, or nothing shared)")
	}
	for _, l := range r.Links {
		fmt.Fprintf(w, "  [%s] %s: %s · cases %s\n", strings.ToUpper(l.Class), l.Kind, t(l.Display), strings.Join(l.Cases, ", "))
		if len(l.Segments) > 0 {
			fmt.Fprintf(w, "      segments: %s\n", t(strings.Join(l.Segments, ", ")))
		}
		if l.Note != "" {
			fmt.Fprintf(w, "      %s\n", t(l.Note))
		}
	}

	fmt.Fprintln(w, "\n== Attack stages")
	if len(r.StageItems) == 0 {
		fmt.Fprintln(w, "  (no attack-chain finding and no HIGH/CRITICAL finding with a mapped ATT&CK technique)")
	}
	items := map[string]StageItem{}
	for _, it := range r.StageItems {
		items[it.ID] = it
	}
	for _, st := range r.Stages {
		fmt.Fprintf(w, "  %d. %s\n", st.Order, strings.ToUpper(strings.ReplaceAll(st.Stage, "_", " ")))
		for _, id := range st.Items {
			it := items[id]
			step := ""
			if it.Step != "" {
				step = " · step \"" + it.Step + "\""
			}
			fmt.Fprintf(w, "     %s %s %s %s%s · %s %s · %s\n", it.ID, orDash(it.Time), it.Case, it.RuleID, t(step), t(orDash(it.Segment)), schema.Label(orUnknown(it.State)), t(it.Title))
		}
	}
	if len(r.StageEdges) > 0 {
		fmt.Fprintln(w, "  Edges (verified and inferred are kept apart):")
		for _, link := range []string{Verified, Inferred} {
			for _, e := range r.StageEdges {
				if e.Link != link {
					continue
				}
				x := ""
				if e.CrossHost {
					x = " cross-host"
				}
				fmt.Fprintf(w, "     [%s%s] %s → %s: %s\n", strings.ToUpper(e.Link), x, e.From, e.To, t(e.Basis))
			}
		}
	}

	fmt.Fprintln(w, "\n== Missing evidence")
	if len(r.Missing) == 0 {
		fmt.Fprintln(w, "  (nothing listed)")
	}
	for _, m := range r.Missing {
		fmt.Fprintf(w, "  [%s] %s %s: %s\n", strings.ToUpper(strings.ReplaceAll(m.Status, "_", " ")), m.Scope, t(m.Target), t(m.Text))
		if m.Collect != "" {
			fmt.Fprintf(w, "      Collect: %s\n", t(m.Collect))
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "note: %s\n", t(n))
	}
	for _, k := range sortedKeys(r.Omitted) {
		if k != "timeline" {
			fmt.Fprintf(w, "TRUNCATED: %d %s left out (bound)\n", r.Omitted[k], strings.ReplaceAll(k, "_", " "))
		}
	}
}

// WriteMermaid renders hosts as subgraphs of segments, with delegation,
// hand-off, cross-host and stage edges. Verified edges are solid, inferred
// ones dashed.
func WriteMermaid(w io.Writer, r *Report) {
	fmt.Fprintln(w, "flowchart LR")
	ids := map[string]string{}
	for i, s := range r.Segments {
		ids[s.ID] = fmt.Sprintf("g%d", i)
	}
	for _, c := range r.Cases {
		fmt.Fprintf(w, "  subgraph %s[\"%s\"]\n", c.Label, mText(c.Label+" host "+c.Host))
		for _, s := range r.Segments {
			if s.Case == c.Label {
				fmt.Fprintf(w, "    %s[\"%s\"]\n", ids[s.ID], mText(segLabel(s)))
			}
		}
		fmt.Fprintln(w, "  end")
	}
	arrow := func(link string) string {
		if link == Verified {
			return "-->"
		}
		return "-.->"
	}
	for _, d := range r.Delegations {
		if ids[d.ParentSegment] != "" && ids[d.ChildSegment] != "" {
			fmt.Fprintf(w, "  %s %s|\"%s\"| %s\n", ids[d.ParentSegment], arrow(d.Link), mText("delegated · "+d.Link), ids[d.ChildSegment])
		}
	}
	for _, h := range r.Handoffs {
		if ids[h.From] != "" && ids[h.To] != "" && h.From != h.To {
			fmt.Fprintf(w, "  %s %s|\"%s\"| %s\n", ids[h.From], arrow(h.Link), mText(h.Kind+" · "+h.Link), ids[h.To])
		}
	}
	for _, l := range r.Links {
		for i := 1; i < len(l.Segments); i++ {
			if ids[l.Segments[0]] != "" && ids[l.Segments[i]] != "" && segCase(r, l.Segments[0]) != segCase(r, l.Segments[i]) {
				fmt.Fprintf(w, "  %s -.-|\"%s\"| %s\n", ids[l.Segments[0]], mText("shared "+l.Display), ids[l.Segments[i]])
			}
		}
	}
	if len(r.StageItems) > 0 {
		fmt.Fprintln(w, "  subgraph stages[\"attack stages\"]")
		for _, it := range r.StageItems {
			fmt.Fprintf(w, "    %s{{\"%s\"}}\n", it.ID, mText(it.ID+" "+it.Stage+" · "+it.Case+" · "+it.RuleID))
		}
		fmt.Fprintln(w, "  end")
		for _, e := range r.StageEdges {
			fmt.Fprintf(w, "  %s %s|\"%s\"| %s\n", e.From, arrow(e.Link), e.Link, e.To)
		}
	}
}

// WriteDOT renders the same picture as Graphviz DOT.
func WriteDOT(w io.Writer, r *Report) {
	fmt.Fprintln(w, "digraph reconstruct {")
	fmt.Fprintln(w, "  rankdir=LR;")
	fmt.Fprintln(w, "  node [fontname=\"Helvetica\", fontsize=10];")
	ids := map[string]string{}
	for i, s := range r.Segments {
		ids[s.ID] = fmt.Sprintf("g%d", i)
	}
	for _, c := range r.Cases {
		fmt.Fprintf(w, "  subgraph cluster_%s {\n    label=\"%s\";\n", c.Label, dText(c.Label+" host "+c.Host))
		for _, s := range r.Segments {
			if s.Case == c.Label {
				fmt.Fprintf(w, "    %s [label=\"%s\", shape=box];\n", ids[s.ID], dText(segLabel(s)))
			}
		}
		fmt.Fprintln(w, "  }")
	}
	style := func(link string) string {
		if link == Verified {
			return "solid"
		}
		return "dashed"
	}
	for _, d := range r.Delegations {
		if ids[d.ParentSegment] != "" && ids[d.ChildSegment] != "" {
			fmt.Fprintf(w, "  %s -> %s [label=\"%s\", style=%s];\n", ids[d.ParentSegment], ids[d.ChildSegment], dText("delegated · "+d.Link), style(d.Link))
		}
	}
	for _, h := range r.Handoffs {
		if ids[h.From] != "" && ids[h.To] != "" && h.From != h.To {
			fmt.Fprintf(w, "  %s -> %s [label=\"%s\", style=%s];\n", ids[h.From], ids[h.To], dText(h.Kind+" · "+h.Link), style(h.Link))
		}
	}
	for _, l := range r.Links {
		for i := 1; i < len(l.Segments); i++ {
			if ids[l.Segments[0]] != "" && ids[l.Segments[i]] != "" && segCase(r, l.Segments[0]) != segCase(r, l.Segments[i]) {
				fmt.Fprintf(w, "  %s -> %s [label=\"%s\", style=dotted, dir=none];\n", ids[l.Segments[0]], ids[l.Segments[i]], dText("shared "+l.Display))
			}
		}
	}
	for _, it := range r.StageItems {
		fmt.Fprintf(w, "  %s [label=\"%s\", shape=hexagon];\n", it.ID, dText(it.ID+" "+it.Stage+" · "+it.Case+" · "+it.RuleID))
	}
	for _, e := range r.StageEdges {
		fmt.Fprintf(w, "  %s -> %s [label=\"%s\", style=%s];\n", e.From, e.To, e.Link, style(e.Link))
	}
	fmt.Fprintln(w, "}")
}

func segLabel(s Segment) string {
	l := s.ID
	if s.Product != "" {
		l += " · " + s.Product
	}
	if s.Start != "" {
		l += " · " + s.Start
	}
	return l
}

func segCase(_ *Report, id string) string {
	if i := strings.IndexByte(id, '/'); i > 0 {
		return id[:i]
	}
	return id
}

func mText(s string) string {
	s = detect.MaskTruncate(sanitize.Terminal(s), 90)
	return strings.NewReplacer("#", "#35;", "\"", "#quot;", "\n", " ", "\r", " ", "|", "#124;", "<", "#lt;", ">", "#gt;", "`", "'").Replace(s)
}

func dText(s string) string {
	s = detect.MaskTruncate(sanitize.Terminal(s), 90)
	return strings.NewReplacer("\\", "\\\\", "\"", "\\\"", "\n", " ", "\r", " ").Replace(s)
}
