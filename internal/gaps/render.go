package gaps

import (
	"fmt"
	"io"

	"github.com/efij/AgentDFIR/v5/internal/sanitize"
)

// WriteText prints the report for a terminal: the summary line, then the
// known / unknown / verify-next items, then the limits. Evidence text is
// passed through sanitize.Terminal like every other terminal view.
func WriteText(w io.Writer, r *Report) {
	host := ""
	if r.Host != "" {
		host = " (host " + sanitize.Terminal(r.Host) + ")"
	}
	fmt.Fprintf(w, "Coverage for case %s%s\n", sanitize.Terminal(r.CaseID), host)
	s := r.Summary
	partly := ""
	if s.Partial > 0 {
		partly = fmt.Sprintf(" (%d only partly)", s.Partial)
	}
	fmt.Fprintf(w, "  %d session(s) · %d tool call(s): %d confirmed%s, %d disproved, %d unverified · %d time gap(s)\n",
		s.Sessions, s.ToolCalls, s.Verified, partly, s.Disproved, s.Unverified, s.TimeGaps)
	sections := []struct{ status, title string }{
		{Known, "KNOWN"}, {Unknown, "UNKNOWN"}, {VerifyNext, "VERIFY NEXT — what to collect"},
	}
	for _, sec := range sections {
		n := 0
		for _, it := range r.Items {
			if it.Status != sec.status {
				continue
			}
			if n == 0 {
				fmt.Fprintf(w, "\n%s\n", sec.title)
			}
			n++
			fmt.Fprintf(w, "  - [%s] %s\n", it.Category, sanitize.Terminal(it.Text))
			if it.Collect != "" {
				fmt.Fprintf(w, "      Collect: %s\n", sanitize.Terminal(it.Collect))
			}
			for _, ref := range it.Refs {
				fmt.Fprintf(w, "      Evidence: %s\n", sanitize.Terminal(ref))
			}
		}
	}
	if r.Truncated {
		fmt.Fprintln(w, "\nSome lists were cut at their bound; --json prints the full structured report.")
	}
	fmt.Fprintln(w, "\nLimits")
	for _, l := range r.Limits {
		fmt.Fprintf(w, "  - %s\n", l)
	}
}
