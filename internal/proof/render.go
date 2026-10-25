package proof

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/sanitize"
)

// WriteText prints the report for a terminal. Evidence text goes through
// sanitize.Terminal like every other terminal view.
func WriteText(w io.Writer, r *Report) {
	t := sanitize.Terminal
	p := func(format string, a ...any) { fmt.Fprintf(w, format+"\n", a...) }
	p("Action proof for case %s (%s)", t(r.CaseID), r.Schema)
	if r.Scope.SessionID != "" {
		p("Session %s", t(r.Scope.SessionID))
	}
	p("%d tool call(s); match window ±%s", r.Scope.ToolCalls, time.Duration(r.Scope.WindowMS)*time.Millisecond)

	p("")
	p("TELEMETRY COVERAGE & HEALTH")
	if r.Telemetry.Note != "" {
		p("  %s", t(r.Telemetry.Note))
	}
	for _, s := range r.Telemetry.Sources {
		span := ""
		if !s.First.IsZero() {
			span = fmt.Sprintf(", %s → %s", clock(s.First), clock(s.Last))
		}
		p("  %s  %s  %d record(s)%s", s.Verdict, t(s.File), s.Records, span)
		if s.SHA256 != "" {
			p("      sha256 %s", s.SHA256)
		}
		if len(s.Hosts) > 0 {
			p("      host(s): %s", t(strings.Join(s.Hosts, ", ")))
		}
		for _, d := range s.Domains {
			line := fmt.Sprintf("      sequence %s: %d event(s), %d..%d", t(d.Domain), d.Events, d.FirstSeq, d.LastSeq)
			if d.Gaps > 0 {
				line += fmt.Sprintf(", %d gap(s), %d missing", d.Gaps, d.Missing)
			}
			if d.Overflow {
				line += ", too fragmented to check"
			}
			p("%s", line)
			for _, g := range d.GapRanges {
				what := fmt.Sprintf("%d missing after %d", g.Missing, g.After)
				if g.Restart {
					what = fmt.Sprintf("restarted after %d", g.After)
				}
				p("        gap: %s (%s)", what, spanOf(g.Start, g.End))
			}
		}
		for _, d := range s.Drops {
			p("      drop: %s: %s (%s)%s", d.Signal, t(d.Detail), spanOf(d.Start, d.End), refSuffix(t(d.Ref)))
		}
		if s.DropsOmitted > 0 {
			p("      %d more drop signal(s) not kept", s.DropsOmitted)
		}
		if s.Note != "" {
			p("      %s", t(s.Note))
		}
	}
	if len(r.Telemetry.Coverage) > 0 {
		p("  Coverage per host and kind:")
		for _, c := range r.Telemetry.Coverage {
			host := c.Host
			if host == "" {
				host = "(any host)"
			}
			role := "disproves on absence"
			if !c.CountsAsCoverage {
				role = "corroborates only"
			}
			p("    %-16s %-14s %-8s %s → %s  %d record(s), %s", t(host), t(c.Kind), c.Health, clock(c.Start), clock(c.End), c.Records, role)
			for _, iv := range c.Partial {
				p("      partial: %s (%s, %s)", t(iv.Reason), t(iv.Source), spanOf(iv.Start, iv.End))
			}
			if c.PartialOmitted > 0 {
				p("      %d more partial interval(s)", c.PartialOmitted)
			}
		}
	}
	p("")
	p("SUMMARY")
	p("  states:   %s", countList(r.Summary.States))
	if len(r.Summary.Coverage) > 0 {
		p("  coverage: %s", countList(r.Summary.Coverage))
	}

	for i, a := range r.Actions {
		p("")
		p("[%d] %s  %s  %s", i+1, a.Timestamp, t(a.Tool), a.StateLabel)
		p("    claim:      %s", t(a.Claim))
		p("    confidence: %s", a.Confidence)
		for _, f := range a.Coverage {
			need := ""
			if f.Needed {
				need = " (needed)"
			}
			p("    coverage:   %s%s %s: %s", f.Kind, need, f.Coverage, t(f.Reason))
		}
		p("    chain:")
		for _, s := range a.Chain {
			head := fmt.Sprintf("      %s %s", s.Role, t(s.Label))
			if s.Relation != "" {
				head = fmt.Sprintf("      ─%s→ %s %s", s.Relation, s.Role, t(s.Label))
			}
			attrs := []string{}
			if s.State != "" {
				attrs = append(attrs, s.State)
			}
			if s.Assurance != "" {
				attrs = append(attrs, s.Assurance)
			}
			if s.Correlation != "" {
				attrs = append(attrs, "correlation "+s.Correlation)
			}
			if len(attrs) > 0 {
				head += "  [" + strings.Join(attrs, ", ") + "]"
			}
			p("%s", head)
			for _, ref := range s.Refs {
				p("          ref %s", t(refText(ref)))
			}
		}
		if a.Truncated {
			p("      (chain cut at %d steps)", maxChain)
		}
		for _, l := range a.Limitations {
			p("    limitation: %s", t(l))
		}
	}
	if r.Omitted > 0 {
		p("")
		p("%d more tool call(s) not listed.", r.Omitted)
	}
	if len(r.Notes) > 0 {
		p("")
		p("NOTES")
		for _, n := range r.Notes {
			p("  - %s", t(n))
		}
	}
	p("")
	p("CHECKING THIS REPORT")
	p("  --json prints the same report with every reference resolvable: %d sealed artifact(s), %d derived file(s).", len(r.Artifacts), len(r.Derived))
	for _, d := range r.Derived {
		p("  %s sha256 %s", d.Path, d.SHA256)
	}
}

func refText(r SourceRef) string {
	if r.Telemetry != "" {
		s := "telemetry " + r.Telemetry
		if r.TelemetryFile != "" {
			s += " [" + r.TelemetryFile
			if r.TelemetrySHA256 != "" {
				s += " sha256 " + r.TelemetrySHA256[:16] + "…"
			}
			s += "]"
		}
		return s
	}
	id := r.ArtifactID
	if len(id) > 16 {
		id = id[:16] + "…"
	}
	return fmt.Sprintf("%s:%d (artifact %s, offset %d)", r.LogicalPath, r.Line, id, r.Offset)
}

func refSuffix(ref string) string {
	if ref == "" {
		return ""
	}
	return " [" + ref + "]"
}

func clock(t time.Time) string {
	if t.IsZero() {
		return "?"
	}
	return t.UTC().Format("2006-01-02 15:04:05Z")
}

func spanOf(a, b time.Time) string {
	switch {
	case a.IsZero() && b.IsZero():
		return "time not placed: whole window"
	case a.IsZero():
		return "until " + clock(b)
	case b.IsZero():
		return "from " + clock(a)
	}
	return clock(a) + " – " + clock(b)
}

func countList(m map[string]int) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s %d", k, m[k]))
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ", ")
}
