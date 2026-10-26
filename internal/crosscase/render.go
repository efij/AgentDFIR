package crosscase

import (
	"fmt"
	"io"
	"strings"

	"github.com/efij/AgentDFIR/v5/internal/sanitize"
)

// WriteText prints the comparison for a terminal.
func WriteText(w io.Writer, r *Report) {
	fmt.Fprintf(w, "Cross-case comparison of %d case(s)\n", len(r.Cases))
	if r.Unverified {
		fmt.Fprintln(w, "WARNING: includes a case whose seal did NOT verify; results from it are marked UNVERIFIED.")
	}
	for _, c := range r.Cases {
		users := strings.Join(c.OSUsers, ",")
		if users == "" {
			users = "-"
		}
		mark := ""
		if c.Integrity.Result != "VERIFIED" {
			mark = " [UNVERIFIED: " + sanitize.Terminal(strings.Join(c.Integrity.Problems, "; ")) + "]"
		}
		fmt.Fprintf(w, "  %s  %s  case %s · host %s · users %s · %d events, %d findings · seal %s, signature %s%s\n",
			c.Label, sanitize.Terminal(c.Path), sanitize.Terminal(c.CaseID), sanitize.Terminal(c.Host),
			sanitize.Terminal(users), c.Events, c.Findings, c.Integrity.Result, c.Integrity.Signature, mark)
	}
	if len(r.Shared) == 0 {
		fmt.Fprintln(w, "\nNothing in common.")
	}
	kind := ""
	for _, s := range r.Shared {
		if s.Kind != kind {
			kind = s.Kind
			fmt.Fprintf(w, "\n%s\n", strings.ToUpper(strings.ReplaceAll(kind, "_", " ")))
		}
		fmt.Fprintf(w, "  %s\n", sanitize.Terminal(s.Display))
		if s.Note != "" {
			fmt.Fprintf(w, "    note: %s\n", s.Note)
		}
		for _, o := range s.Cases {
			when := ""
			if o.FirstSeen != "" {
				when = fmt.Sprintf(" · %s → %s (%s)", o.FirstSeen, o.LastSeen, o.TimeSource)
			}
			un := ""
			if o.Unverified {
				un = " · UNVERIFIED"
			}
			fmt.Fprintf(w, "    %s ×%d%s%s\n", o.Case, o.Count, when, un)
			for _, wh := range o.Where {
				fmt.Fprintf(w, "       in: %s\n", sanitize.Terminal(wh))
			}
			for _, ref := range o.Refs {
				fmt.Fprintf(w, "       evidence: %s\n", sanitize.Terminal(ref))
			}
		}
	}
	if len(r.Links) > 0 {
		fmt.Fprintln(w, "\nIDENTITY LINKS (exact identifiers only)")
		for _, l := range r.Links {
			fmt.Fprintf(w, "  %s %s links: %s\n", l.Identifier, sanitize.Terminal(l.Value), sanitize.Terminal(strings.Join(l.Entities, " | ")))
		}
	}
	if len(r.Timeline) > 0 {
		fmt.Fprintln(w, "\nTIMELINE OF SHARED ITEMS")
		for _, t := range r.Timeline {
			fmt.Fprintf(w, "  %s  %s  %-10s %s  %s (%s)\n", t.Time, t.Case, t.Event, t.Kind, sanitize.Terminal(t.Display), t.TimeSource)
		}
	}
	for _, n := range r.Notes {
		fmt.Fprintf(w, "note: %s\n", sanitize.Terminal(n))
	}
	if n := r.Omitted["timeline"]; n > 0 {
		fmt.Fprintf(w, "note: %d timeline entries not shown (bound)\n", n)
	}
}

// maxTextJoins bounds the join edges the text summary lists.
const maxTextJoins = 60

// WriteGraphText prints the activity graph's summary: what it holds, the
// cross-case joins (strong first) and the cross-case findings.
func WriteGraphText(w io.Writer, g *Graph) {
	if g == nil {
		return
	}
	fmt.Fprintln(w, "\nACTIVITY GRAPH")
	if g.Unverified {
		fmt.Fprintln(w, "  WARNING: includes a case whose seal did NOT verify; its nodes, edges and findings are marked UNVERIFIED.")
	}
	var kinds []string
	for _, k := range []string{NodeCase, NodeHost, NodeExecEnv, NodeSession, NodeAgent, NodeMCPTool, NodePrincipal, NodeResource, NodeCommit, NodeFile, NodeDestination} {
		if n := g.Summary.Nodes[k]; n > 0 {
			kinds = append(kinds, fmt.Sprintf("%d %s", n, k))
		}
	}
	fmt.Fprintf(w, "  %d node(s): %s\n", len(g.Nodes), strings.Join(kinds, ", "))
	fmt.Fprintf(w, "  joins: %d strong, %d moderate, %d weak · %d context edge(s)\n",
		g.Summary.JoinEdges[Strong], g.Summary.JoinEdges[Moderate], g.Summary.JoinEdges[Weak], g.Summary.ContextEdges)
	shown := 0
	for _, e := range g.Edges {
		if e.JoinKey == "" {
			continue
		}
		if shown++; shown > maxTextJoins {
			continue
		}
		rel := e.Time.Relation
		if e.Time.FromTime != "" || e.Time.ToTime != "" {
			rel += fmt.Sprintf(" (%s → %s)", orDash(e.Time.FromTime), orDash(e.Time.ToTime))
		}
		un := ""
		if e.Unverified {
			un = " · UNVERIFIED"
		}
		fmt.Fprintf(w, "  [%s] %s %s: %s → %s · %s%s\n", strings.ToUpper(e.Confidence), e.JoinKey, sanitize.Terminal(e.JoinValue),
			sanitize.Terminal(e.From), sanitize.Terminal(e.To), rel, un)
		fmt.Fprintf(w, "       why: %s\n", sanitize.Terminal(e.Reason))
		for _, r := range e.Evidence {
			fmt.Fprintf(w, "       evidence: %s\n", sanitize.Terminal(r.String()))
		}
	}
	if shown > maxTextJoins {
		fmt.Fprintf(w, "  … %d more join(s) in --json\n", shown-maxTextJoins)
	}
	if len(g.Findings) == 0 {
		fmt.Fprintln(w, "\n  No cross-case findings. (Weak joins alone never raise one.)")
	}
	for _, f := range g.Findings {
		un := ""
		if f.Unverified {
			un = " · UNVERIFIED"
		}
		fmt.Fprintf(w, "\n  %s  %s  %s (cases %s · ATLAS %s%s · evidence %s · confidence %s%s)\n", f.Severity, f.RuleID, f.Title,
			strings.Join(f.Cases, ","), f.MitreATLAS, prefixed(" · ATT&CK ", f.MitreATTACK), f.Status, f.Confidence, un)
		fmt.Fprintf(w, "    %s\n", sanitize.Terminal(f.Description))
		for _, s := range f.ChainSteps {
			fmt.Fprintf(w, "    step: %s · %s · %s\n", s.Step, orDash(s.Timestamp), sanitize.Terminal(s.Evidence))
		}
		for _, j := range f.Joins {
			fmt.Fprintf(w, "    join: [%s] %s %s (%s → %s, %s)\n", strings.ToUpper(j.Confidence), j.JoinKey, sanitize.Terminal(j.JoinValue),
				sanitize.Terminal(j.From), sanitize.Terminal(j.To), j.Relation)
		}
		for _, l := range f.Limits {
			fmt.Fprintf(w, "    limit: %s\n", l)
		}
	}
	for _, n := range g.Notes {
		fmt.Fprintf(w, "  note: %s\n", sanitize.Terminal(n))
	}
	for _, k := range sortedKeys(g.Omitted) {
		fmt.Fprintf(w, "  note: %d %s not shown (bound)\n", g.Omitted[k], strings.ReplaceAll(k, "_", " "))
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func prefixed(p, s string) string {
	if s == "" {
		return ""
	}
	return p + s
}
