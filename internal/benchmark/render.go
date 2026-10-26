package benchmark

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// WriteJSON writes the report as indented JSON.
func (r *Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

func pct(v *float64) string {
	if v == nil {
		return "n/a"
	}
	return fmt.Sprintf("%.1f%%", *v*100)
}

func mdEscape(s string) string { return strings.ReplaceAll(s, "|", `\|`) }

// WriteMarkdown writes the report as a Markdown document.
func (r *Report) WriteMarkdown(w io.Writer) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format+"\n", a...) }
	verdict := "PASS"
	if !r.Passed() {
		verdict = fmt.Sprintf("FAIL (%d)", len(r.Failures))
	}
	p("# AgentDFIR benchmark — SYNTHETIC")
	p("")
	p("> **%s.** Every number below comes from fixtures written for this purpose. They reproduce real shapes, but a score on them says how the tool behaves on those shapes, not how accurate it is on real evidence.", r.Label)
	p("")
	sub := ""
	if r.Quick {
		sub = " (quick subset)"
	}
	p("agentdfir %s%s · verdict: **%s**", r.Version, sub, verdict)
	p("")
	p("| Section | Result |")
	p("|---|---|")
	d := r.Detection
	p("| Detection (synthetic) | precision %s, recall %s over %d attack cases, %d scenarios, %d benign cases |", pct(d.Precision), pct(d.Recall), d.AttackCases, d.Scenarios, d.BenignCases)
	p("| Rule coverage (synthetic) | %d of %d alert rules have an attack fixture; %d building blocks |", d.RuleUniverse-d.BuildingBlocks-len(d.Uncovered), d.RuleUniverse-d.BuildingBlocks, d.BuildingBlocks)
	p("| Evidence states | %d/%d labeled checks, %d contract violations over %d events |", r.Evidence.Passed, r.Evidence.Total, len(r.Evidence.ContractViolations), r.Evidence.Events)
	p("| Provenance | %d dangling of %d events and %d finding references |", r.Provenance.Dangling(), r.Provenance.Events, r.Provenance.Refs)
	p("| Integrity mutations | %d/%d detected |", r.Integrity.Detected, r.Integrity.Total)
	p("| Compatibility | %d/%d historical packages verify and analyze |", r.Compat.OK, r.Compat.Total)
	p("| Robustness | %d/%d hostile-input cases |", r.Robustness.Passed, r.Robustness.Total)
	if r.Performance != nil {
		m := r.Performance.Measured
		p("| Performance | analyze %d ms, peak heap %.1f MiB on %d events (baseline %d ms, %.1f MiB) |", m.AnalyzeMS, m.PeakHeapMB, m.Events, r.Performance.Baseline.AnalyzeMS, r.Performance.Baseline.PeakHeapMB)
	}
	r.suiteRows(p)
	p("")
	if len(r.Failures) > 0 {
		p("## Failures")
		p("")
		for _, f := range r.Failures {
			p("- %s", f)
		}
		p("")
	}
	if len(r.Warnings) > 0 {
		p("## Warnings")
		p("")
		for _, f := range r.Warnings {
			p("- %s", f)
		}
		p("")
	}

	p("## Detection (synthetic)")
	p("")
	p("Labels come from `internal/corpus/testdata` (attack cases name the rules they must produce, benign cases the rules they may) and from each `simulate` scenario's expected rules. A firing on an attack fixture that its label does not mention is not scored.")
	p("")
	p("| Rule | TP | FP | FN | Precision | Recall |")
	p("|---|---:|---:|---:|---:|---:|")
	for _, s := range d.Rules {
		p("| %s | %d | %d | %d | %s | %s |", s.Rule, s.TP, s.FP, s.FN, pct(s.Precision), pct(s.Recall))
	}
	p("| **all** | **%d** | **%d** | **%d** | **%s** | **%s** |", d.TP, d.FP, d.FN, pct(d.Precision), pct(d.Recall))
	p("")
	list := func(title string, items []string) {
		p("**%s** (%d)", title, len(items))
		p("")
		if len(items) == 0 {
			p("none")
		} else {
			p("%s", "`"+strings.Join(items, "`, `")+"`")
		}
		p("")
	}
	list("Fired on benign fixtures", d.BenignFirings)
	list("Lost detections", d.Missed)
	list("Unlabeled firings on attack fixtures", d.Unlabeled)
	list("Coverage gaps: alert rules with no attack fixture", d.Uncovered)

	p("## Evidence states")
	p("")
	p("| Scenario | Second witness | Event | Want | Got |")
	p("|---|---|---|---|---|")
	for _, c := range r.Evidence.Checks {
		got := c.Got
		if !c.OK {
			got = "**" + got + "**"
		}
		p("| %s | %s | %s | %s | %s |", c.Scenario, mdEscape(c.Witness), mdEscape(c.Event), c.Want, got)
	}
	p("")
	var states []string
	for _, s := range r.Evidence.States {
		states = append(states, fmt.Sprintf("%s %d", s.Label, s.Count))
	}
	p("Every event of every scenario held to the contract (CONFIRMED only with a second-witness record, DISPROVED only on endpoint or host-witness evidence, narrative never promoted): %d events, %d violations. States: %s.", r.Evidence.Events, len(r.Evidence.ContractViolations), strings.Join(states, ", "))
	p("")

	pr := r.Provenance
	p("## Provenance")
	p("")
	p("| Measure | Count |")
	p("|---|---:|")
	p("| packages checked | %d |", pr.Packages)
	p("| events resolved to artifact, line and line-start offset | %d of %d |", pr.EventsResolved, pr.Events)
	p("| events describing a whole artifact (line 0) | %d |", pr.EventsWholeArtifact)
	p("| events citing a missing artifact | %d |", pr.EventsDanglingArtifact)
	p("| events citing a line past the end | %d |", pr.EventsLineOutOfRange)
	p("| events whose offset is not the start of their line | %d |", pr.EventsOffsetMismatch)
	p("| finding references resolved | %d of %d |", pr.RefsResolved, pr.Refs)
	p("| finding references to external witness logs (not sealed, by design) | %d |", pr.RefsExternal)
	p("| finding references dangling | %d |", pr.RefsDangling)
	p("| findings citing nothing | %d |", pr.FindingsUnreferenced)
	p("| chain steps citing a missing event | %d |", pr.ChainStepsDangling)
	p("")
	for _, e := range pr.Examples {
		p("- %s", mdEscape(e))
	}
	if len(pr.Examples) > 0 {
		p("")
	}

	p("## Integrity mutation suite")
	p("")
	p("Reference package: %s. Each mutation is applied to a fresh copy and checked with `agentdfir verify` (mode `pinned`: `verify --pubkey <recorded signer>`).", r.Integrity.Reference)
	p("")
	p("| Mutation | What | Mode | Detected | First problem reported |")
	p("|---|---|---|---|---|")
	for _, m := range r.Integrity.Mutations {
		det := "yes"
		if !m.Detected {
			det = "**NO**"
		}
		p("| %s | %s | %s | %s | %s |", m.ID, mdEscape(m.What), m.Mode, det, mdEscape(truncate(m.Problem, 110)))
	}
	p("")

	p("## Compatibility")
	p("")
	p("| Produced by | Verified | Signature | Analyzed | Events | Findings |")
	p("|---|---|---|---|---:|---:|")
	for _, c := range r.Compat.Packages {
		p("| %s | %t | %s | %t | %d | %d |", c.Version, c.Verified, c.Signature, c.Analyzed, c.Events, c.Findings)
	}
	p("")

	p("## Robustness")
	p("")
	p("| Case | Input | Crashed | Events | Result |")
	p("|---|---|---|---:|---|")
	for _, c := range r.Robustness.Cases {
		res := "ok"
		if !c.OK {
			res = "**" + mdEscape(strings.Join(append(append([]string{c.Error}, c.Problems...), prefixAll("missing ", c.Missing)...), "; ")) + "**"
		}
		p("| %s | %s | %t | %d | %s |", c.Name, mdEscape(c.What), c.Crashed, c.Events, res)
	}
	p("")

	if pf := r.Performance; pf != nil {
		m, bl := pf.Measured, pf.Baseline
		p("## Performance")
		p("")
		p("Generated case: %d sessions, %d tool calls, %d bytes of transcript. Warn-only, tolerance %.0f%%; numbers depend on the machine.", m.Sessions, m.ToolCalls, m.InputBytes, RegressionTolerance*100)
		p("")
		p("| | Measured | Baseline |")
		p("|---|---:|---:|")
		p("| events | %d | %d |", m.Events, bl.Events)
		p("| collect | %d ms | %d ms |", m.CollectMS, bl.CollectMS)
		p("| analyze | %d ms | %d ms |", m.AnalyzeMS, bl.AnalyzeMS)
		p("| peak heap | %.1f MiB | %.1f MiB |", m.PeakHeapMB, bl.PeakHeapMB)
		p("| allocated | %.1f MiB | %.1f MiB |", m.AllocMB, bl.AllocMB)
		p("| platform | %s, %d CPUs, %s | %s, %d CPUs, %s |", m.Platform, m.CPUs, m.GoVersion, bl.Platform, bl.CPUs, bl.GoVersion)
		p("")
	}
	r.writeSuites(p)
	_, err := io.WriteString(w, b.String())
	return err
}

func prefixAll(prefix string, items []string) []string {
	out := make([]string, len(items))
	for i, s := range items {
		out[i] = prefix + s
	}
	return out
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
