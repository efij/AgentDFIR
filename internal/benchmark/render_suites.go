package benchmark

import (
	"fmt"
	"strings"
)

// suiteRows adds one summary-table row per cross-platform suite.
func (r *Report) suiteRows(p func(string, ...any)) {
	for _, s := range r.Suites {
		res := s.Status + ": " + s.Summary
		if s.Status == SuiteSkip {
			res = "SKIP: " + s.Reason
		}
		if n := len(s.ExpectedFailures); n > 0 {
			res += fmt.Sprintf(" (%d expected failure(s), listed below)", n)
		}
		p("| %s (%s) | %s |", strings.ToUpper(s.Name[:1])+s.Name[1:], "synthetic/tool-generated", mdEscape(res))
	}
}

func checkTable(p func(string, ...any), checks []Check) {
	p("| Check | Want | Got | Status |")
	p("|---|---|---|---|")
	for _, c := range checks {
		st := c.Status
		if st != SuitePass {
			st = "**" + st + "**"
		}
		got := c.Got
		if c.ExpectedFail != "" && c.Status == CheckXFail {
			got += " — expected failure: " + c.ExpectedFail
		}
		p("| %s | %s | %s | %s |", mdEscape(c.Name), mdEscape(c.Want), mdEscape(truncate(got, 300)), st)
	}
	p("")
}

// writeSuites renders the cross-platform suites.
func (r *Report) writeSuites(p func(string, ...any)) {
	if len(r.Suites) == 0 {
		return
	}
	p("## Cross-platform suites")
	p("")
	p("> %s. Each suite reports PASS / FAIL / SKIP on its own; a SKIP says why.", SuiteLabel)
	p("")
	p("| Suite | Status | Measured |")
	p("|---|---|---|")
	for _, s := range r.Suites {
		m := s.Summary
		if s.Status == SuiteSkip {
			m = s.Reason
		}
		p("| %s | %s | %s |", s.Name, s.Status, mdEscape(m))
	}
	p("")
	for _, s := range r.Suites {
		for _, x := range s.ExpectedFailures {
			p("- expected failure (%s): %s", s.Name, mdEscape(x))
		}
	}
	p("")

	if a := r.Acquisition; a != nil {
		p("### Acquisition (disk images)")
		p("")
		if a.Skipped != "" {
			p("SKIP: %s", a.Skipped)
			p("")
		} else {
			p("Each fixture is decompressed to a scratch directory (sparse), opened read-only with the `collect --image` reader, every volume enumerated and every regular file read, then compared with the fixture's manifest (coreutils listing or `shasum` made from the source tree) or with the reference image its container wraps. The fixture and every segment file are hashed before and after: \"source unchanged\" is that proof. %d fixtures in %.1f s.", a.Totals.Fixtures, a.Seconds)
			p("")
			p("| Fixture | Made by | Container | Volumes | Files read / enumerated | Compared with | Manifest files recovered | Hash matches | UNSUPPORTED reported | Source unchanged | Result |")
			p("|---|---|---|---|---:|---|---:|---:|---|---|---|")
			for _, f := range a.Fixtures {
				var vols []string
				for _, v := range f.Volumes {
					vs := v.Type + " " + v.Status
					if v.Name != "" {
						vs = v.Name + ": " + vs
					}
					vols = append(vols, vs)
				}
				if f.OpenError != "" {
					vols = []string{"open refused"}
				}
				man, hm := "-", "-"
				if f.Expected > 0 {
					man = fmt.Sprintf("%d/%d", f.Recovered, f.Expected)
					hm = fmt.Sprintf("%d/%d", f.HashMatch, f.Expected)
					if f.ManifestUnsupported > 0 {
						hm += fmt.Sprintf(" (+%d UNSUPPORTED)", f.ManifestUnsupported)
					}
				}
				cmp := f.Comparison
				if f.LogicalMatch != nil && !*f.LogicalMatch {
					cmp += " (**differs**)"
				}
				uns := "none"
				if len(f.Unsupported) > 0 {
					uns = fmt.Sprintf("%d: %s", len(f.Unsupported), truncate(f.Unsupported[0], 90))
				}
				res := "ok"
				if !f.OK {
					res = "**" + truncate(strings.Join(f.Problems, "; "), 200) + "**"
				}
				p("| %s | %s | %s | %s | %d / %d | %s | %s | %s | %s | %t | %s |", mdEscape(f.Name), mdEscape(f.Origin), f.Container, mdEscape(strings.Join(vols, ", ")),
					f.FilesRead, f.FilesFound, mdEscape(cmp), man, hm, mdEscape(uns), f.SourceUnchanged, mdEscape(res))
			}
			p("")
		}
	}

	if pl := r.Platforms; pl != nil {
		p("### Per-OS corroboration")
		p("")
		p("Generated sessions analyzed with one platform's OS telemetry (synthetic records in each source's documented shape), then the labeled corpus cases that carry endpoint telemetry.")
		p("")
		p("| Platform | Scenario | Telemetry | Tool calls | CORROBORATED (want) | DISPROVED | Outside coverage | Contract violations |")
		p("|---|---|---|---:|---|---:|---:|---:|")
		for _, s := range pl.Scenarios {
			want := "unlabeled"
			if s.WantCorr >= 0 {
				want = fmt.Sprint(s.WantCorr)
			}
			p("| %s | %s | %s | %d | %d (%s) | %d | %d | %d |", s.Platform, s.Name, mdEscape(s.Telemetry), s.ToolCalls, s.Corroborated, want, s.Contradicted, s.Outside, s.Contract)
		}
		p("")
		p("| Platform | Corpus case | Telemetry | Tool calls | CORROBORATED | DISPROVED | Outside coverage | Expected rules fired | Contract violations |")
		p("|---|---|---|---:|---:|---:|---:|---|---:|")
		for _, c := range pl.Corpus {
			p("| %s | %s | %s | %d | %d | %d | %d | %d/%d | %d |", c.Platform, c.Case, mdEscape(c.Telemetry), c.ToolCalls, c.Corroborated, c.Contradicted, c.Outside, c.Fired, c.Expected, c.Contract)
		}
		p("")
		checkTable(p, pl.Checks)
	}

	if in := r.Interop; in != nil {
		p("### Forensic interop")
		p("")
		if in.Skipped != "" {
			p("SKIP: %s", in.Skipped)
			p("")
		} else {
			p("Hand-made exports in each tool's documented layout (none produced by the tool), sealed as `collect --suite-export` seals them and analyzed.")
			p("")
			p("| Export | Imitates | Suite events | Records (want) | UNSUPPORTED (want) | Unparsed (want) | Originals sealed byte-identical | Result |")
			p("|---|---|---:|---|---|---|---|---|")
			for _, f := range in.Fixtures {
				res := "ok"
				if !f.OK {
					res = "**" + mdEscape(f.Problem) + "**"
				}
				extra := ""
				if f.CaseDB {
					extra = " (AXIOM_CASE_DB_UNSUPPORTED finding)"
				}
				p("| %s | %s | %d | %d (%d) | %d (%d)%s | %d (%d) | %d/%d | %s |", f.Name, mdEscape(f.Imitates), f.SuiteEvents, f.Records, f.WantRecords, f.Unsupported, f.WantUnsup, extra, f.Unparsed, f.WantUnparse, f.Identical, f.Files, res)
			}
			p("")
		}
	}

	if len(r.Detection.Platforms) > 0 {
		p("### Detection by platform")
		p("")
		p("| Platform | Attack fixtures | Benign fixtures | TP | FP | FN | Precision | Recall | Rules expected |")
		p("|---|---:|---:|---:|---:|---:|---:|---:|---|")
		for _, ps := range r.Detection.Platforms {
			p("| %s | %d | %d | %d | %d | %d | %s | %s | %s |", ps.Platform, ps.AttackCases, ps.BenignCases, ps.TP, ps.FP, ps.FN, pct(ps.Precision), pct(ps.Recall), mdEscape(strings.Join(ps.Rules, ", ")))
		}
		p("")
	}

	if ei := r.IntegritySet; ei != nil {
		p("### Evidence integrity")
		p("")
		p("%s; %s.", ei.Mutations, ei.Compat)
		p("")
		v := ei.Verifier
		if v.Status == SuiteSkip {
			p("Python verifier: SKIP (%s).", v.Reason)
		} else {
			p("Python verifier (`%s`, %s), packages this run built and the historical ones:", v.Script, v.Python)
			p("")
			p("| Package | Verdict |")
			p("|---|---|")
			for _, pk := range v.Packages {
				p("| %s | %s |", mdEscape(pk.Package), pk.Verdict)
			}
		}
		p("")
	}
}
