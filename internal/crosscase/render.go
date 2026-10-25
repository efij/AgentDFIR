package crosscase

import (
	"fmt"
	"io"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/sanitize"
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
