package supplychain

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/sanitize"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// textRelations bounds each relationship section of the text report; the
// JSON carries all of them.
const textRelations = 200

// WriteText renders the report for a terminal: inventory, drift, the
// chronological timeline, then verified and inferred relationships in
// separate sections.
func WriteText(w io.Writer, r *Report) {
	p := func(format string, args ...any) { fmt.Fprintf(w, format, args...) }
	s := sanitize.Terminal
	p("Supply chain — case %s", s(r.CaseID))
	if r.Host != "" {
		p(" (host %s)", s(r.Host))
	}
	p("\n")
	if r.Since != "" {
		p("Since %s\n", s(r.Since))
	}
	if len(r.Rounds) > 0 {
		var rs []string
		for _, x := range r.Rounds {
			rs = append(rs, fmt.Sprintf("%d (%s)", x.Round, x.Started))
		}
		p("Rounds: %s\n", s(strings.Join(rs, ", ")))
	}
	p("Inference window: %s\n", s(r.Window))

	p("\nCOMPONENTS (%d)\n", len(r.Components))
	for _, c := range r.Components {
		p("  [%s] %s", s(c.Kind), s(c.Name))
		if c.Host != "" {
			p("  (%s)", s(c.Host))
		}
		if c.Observed {
			p("  observed only")
		}
		p("\n    origin: %s, trust %s — %s\n", s(originText(c.Origin)), s(c.Origin.Trust), s(c.Origin.Basis))
		if c.Origin.Version != "" || c.Origin.GitCommit != "" {
			p("    version %s  commit %s\n", s(c.Origin.Version), s(c.Origin.GitCommit))
		}
		if c.SHA256 != "" {
			p("    sha256 %s (%s)\n", s(short(c.SHA256)), s(c.HashBasis))
		}
		if c.FirstSeen != nil || c.LastSeen != nil {
			p("    first seen %s · last seen %s\n", s(stamp(c.FirstSeen)), s(stamp(c.LastSeen)))
		}
		if len(c.History) > 1 {
			var hs []string
			for _, v := range c.History {
				hs = append(hs, fmt.Sprintf("%s %s", s(v.Label), s(short(v.SHA256))))
			}
			p("    hash history: %s\n", strings.Join(hs, " · "))
		}
		if c.Invocations > 0 {
			p("    invocations: %d in %d session(s)\n", c.Invocations, len(c.Sessions))
		}
		if len(c.Flags) > 0 {
			p("    flagged by: %s\n", s(strings.Join(c.Flags, ", ")))
		}
	}

	p("\nDRIFT (%d)\n", len(r.Drift))
	for _, d := range r.Drift {
		p("  %s  %s: %s → %s  [%s]\n", s(d.Kind), s(d.Subject), s(d.From.Label), s(d.To.Label), s(d.Class))
		for _, x := range d.Added {
			p("    + %s\n", s(x))
		}
		for _, x := range d.Removed {
			p("    - %s\n", s(x))
		}
		for _, x := range d.Changed {
			p("    ~ %s\n", s(x))
		}
		if len(d.Expansion) > 0 {
			p("    PERMISSION EXPANSION: %s\n", s(strings.Join(d.Expansion, "; ")))
		}
	}

	p("\nTIMELINE (chronological, %d)\n", len(r.Timeline))
	for _, t := range r.Timeline {
		class := t.Class
		if class == "" {
			class = "-"
		}
		p("  %s  %-16s %-8s %-14s %s\n", s(t.Time), s(t.TimeSource), s(class), s(t.Kind), s(t.Text))
	}

	relations := func(title string, rs []Relation) {
		p("\n%s (%d)\n", title, len(rs))
		for i, x := range rs {
			if i >= textRelations {
				p("  … %d more (see --json)\n", len(rs)-textRelations)
				break
			}
			p("  %s  -[%s]->  %s", s(x.From), s(x.Type), s(x.To))
			if x.Label != "" {
				p("  %s", s(trim(x.Label, 100)))
			}
			if x.Confidence != "" {
				p("  confidence %s", s(x.Confidence))
			}
			p("\n    basis: %s\n", s(x.Basis))
		}
	}
	relations("VERIFIED RELATIONSHIPS — hash-identical artifacts, logged invocations, explicit references", r.Relations.Verified)
	relations("INFERRED RELATIONSHIPS — time proximity or name match only; not evidence on their own", r.Relations.Inferred)

	p("\nREUSE (%d)\n", len(r.Reuse))
	for _, x := range r.Reuse {
		p("  %s  [%s]", s(x.Component), s(x.Class))
		if len(x.Sessions) > 0 {
			p("  %d session(s)", len(x.Sessions))
		}
		for _, c := range x.Cases {
			p("  %s:%s", s(c.Label), s(c.Host))
		}
		p("\n    %s\n", s(x.Basis))
	}

	p("\nFINDINGS (%d)\n", len(r.Findings))
	for _, f := range r.Findings {
		p("  %s %s — %s\n    %s\n", s(f.Severity), s(f.RuleID), s(f.Title), s(f.Description))
	}
	if len(r.Unsupported) > 0 {
		p("\nUNSUPPORTED\n")
		for _, u := range r.Unsupported {
			p("  - %s\n", s(u))
		}
	}
	if len(r.Notes) > 0 {
		p("\nNOTES\n")
		for _, n := range r.Notes {
			p("  - %s\n", s(n))
		}
	}
	if len(r.Omitted) > 0 {
		p("\nOMITTED (bounds): %s\n", s(fmt.Sprint(r.Omitted)))
	}
	p("\nLIMITS\n")
	for _, l := range r.Limits {
		p("  - %s\n", s(l))
	}
}

func stamp(st *Stamp) string {
	if st == nil {
		return "unknown"
	}
	return st.Time + " (" + st.Source + ")"
}

// Since returns a copy of the report restricted to activity at or after t:
// timeline entries, dated relationships, drift whose later side is in
// range, findings, and the components seen in range. Undated structure
// (a plugin contains a skill) is kept.
func Since(r *Report, t time.Time) *Report {
	out := *r
	out.Since = rfc(t)
	in := func(s string) bool {
		x, ok := parseTS(s)
		return !ok || !x.Before(t)
	}
	inStrict := func(s string) bool {
		x, ok := parseTS(s)
		return ok && !x.Before(t)
	}
	out.Components = nil
	for _, c := range r.Components {
		if c.LastSeen == nil || inStrict(c.LastSeen.Time) {
			out.Components = append(out.Components, c)
		}
	}
	out.Timeline = nil
	for _, e := range r.Timeline {
		if inStrict(e.Time) {
			out.Timeline = append(out.Timeline, e)
		}
	}
	out.Drift = nil
	for _, d := range r.Drift {
		if in(d.To.Time) {
			out.Drift = append(out.Drift, d)
		}
	}
	filter := func(rs []Relation) []Relation {
		res := []Relation{}
		for _, x := range rs {
			if in(x.Time) {
				res = append(res, x)
			}
		}
		return res
	}
	out.Relations = Relations{Verified: filter(r.Relations.Verified), Inferred: filter(r.Relations.Inferred)}
	out.Findings = []schema.Finding{}
	for _, f := range r.Findings {
		if in(f.Timestamp) {
			out.Findings = append(out.Findings, f)
		}
	}
	if out.Components == nil {
		out.Components = []Component{}
	}
	if out.Timeline == nil {
		out.Timeline = []TimelineEntry{}
	}
	if out.Drift == nil {
		out.Drift = []Drift{}
	}
	return &out
}

// Peer is another case's stored report, for cross-case reuse.
type Peer struct {
	Label      string
	CaseID     string
	Host       string
	Report     *Report
	Unverified bool
}

// CrossCase adds the components whose hash also appears in other cases
// (another host, or another collection of the same one), and raises
// SUPPLY_FLAGGED_COMPONENT_REUSED when such a component is flagged in any
// of them. Hash-identical components are verified reuse; nothing is
// matched by name across cases.
func CrossCase(r *Report, peers []Peer) {
	type hit struct {
		peer Peer
		c    Component
	}
	byHash := map[string][]hit{}
	for _, pr := range peers {
		if pr.Report == nil {
			continue
		}
		for _, c := range pr.Report.Components {
			if c.SHA256 == "" || c.Kind == KindAgentSetting || c.Kind == KindMarketplace {
				continue
			}
			byHash[c.SHA256] = append(byHash[c.SHA256], hit{pr, c})
		}
	}
	for _, c := range r.Components {
		hits := byHash[c.SHA256]
		if c.SHA256 == "" || len(hits) == 0 || c.Kind == KindAgentSetting || c.Kind == KindMarketplace {
			continue
		}
		ru := Reuse{Component: c.ID, SHA256: c.SHA256, Class: Verified, Flagged: append([]string(nil), c.Flags...)}
		hosts := map[string]bool{}
		for _, h := range hits {
			ru.Cases = append(ru.Cases, CaseSeen{Label: h.peer.Label, CaseID: h.peer.CaseID, Host: h.peer.Host, Component: h.c.ID, Unverified: h.peer.Unverified})
			hosts[h.peer.Host] = true
			for _, f := range h.c.Flags {
				ru.Flagged = appendUniq(ru.Flagged, f)
			}
		}
		sort.Strings(ru.Flagged)
		ru.Basis = fmt.Sprintf("hash-identical component (%s) in %d other case(s), %d host name(s)", c.HashBasis, len(hits), len(hosts))
		r.Reuse = append(r.Reuse, ru)
		if len(ru.Flagged) > 0 {
			var where []string
			for _, cs := range ru.Cases {
				where = append(where, cs.Label+" "+cs.Host)
			}
			f := finding("SUPPLY_FLAGGED_COMPONENT_REUSED", "HIGH", "Component Flagged as Malicious Was Used in Several Sessions",
				fmt.Sprintf("%s %s (sha256 %s) is flagged by %s and the identical component is present in %s as well as this case. Reuse across cases is verified by hash; whether it ran there is shown by that case's own report.",
					c.Kind, c.Name, short(c.SHA256), strings.Join(ru.Flagged, ", "), strings.Join(where, ", ")),
				append([]string{}, c.Paths...), "AML.T0010.005", "component: "+c.ID, fmt.Sprintf("cases: %d", len(hits)+1))
			f.FalsePositive = "The flagging finding is a heuristic; if it is a false positive, so is this. Confirm the flag first."
			r.Findings = append(r.Findings, f)
		}
	}
}
