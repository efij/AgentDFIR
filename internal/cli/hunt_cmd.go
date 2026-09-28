package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/analysis"
	"github.com/efij/AgentDFIR/v3/internal/ioc"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
)

// cmdHunt answers "was this machine hit by X?" for the embedded incident
// packs and any STIX/MISP feed. Exit 1 when an incident's indicators are
// present, 0 otherwise.
func cmdHunt(args []string) int {
	fs := flag.NewFlagSet("hunt", flag.ContinueOnError)
	incident := fs.String("incident", "all", "incident id(s), comma-separated, or all")
	var iocs multiFlag
	fs.Var(&iocs, "iocs", "extra IOC feed: agentdfir incident pack, STIX 2.1 bundle or MISP event JSON (repeatable)")
	dir := fs.String("path", "", "also walk this directory for lockfiles, installed files and shell rc files (a project, or your home)")
	list := fs.Bool("list", false, "list the incidents and their sources")
	asJSON := fs.Bool("json", false, "machine-readable verdicts")
	noRaw := fs.Bool("no-transcripts", false, "skip the raw transcript byte scan (faster on very large cases)")
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil {
		return 2
	}
	if pkg == "" && fs.NArg() == 1 {
		pkg = fs.Arg(0)
	}
	ids := []string{}
	if *incident != "" && *incident != "all" {
		ids = strings.Split(*incident, ",")
	}
	if *list {
		return huntList(iocs)
	}
	if pkg == "" {
		pkg = defaultCase()
	}
	var verdicts []ioc.Verdict
	var notes []string
	if pkg == "" {
		if *dir == "" {
			fmt.Fprintln(os.Stderr, "usage: agentdfir hunt [<case.adfir>] [--incident id,…] [--iocs feed.json] [--path dir] [--json]   (no case on this machine yet: run agentdfir run, or pass --path)")
			return 2
		}
		incs, err := loadIncidents(iocs, ids)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
		verdicts = ioc.Hunt(incs, ioc.Inputs{Path: *dir})
	} else {
		if _, err := analysis.Ensure(pkg, io.Discard); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		var err error
		verdicts, notes, err = analysis.HuntCase(pkg, nil, analysis.HuntOptions{Incidents: ids, IOCFiles: iocs, RawTranscripts: !*noRaw, Path: *dir})
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
	}
	hit := false
	for _, v := range verdicts {
		hit = hit || v.Status == "HIT"
	}
	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(map[string]any{"case": pkg, "path": *dir, "verdicts": verdicts, "notes": notes})
	} else {
		printHunt(pkg, verdicts, notes)
	}
	if hit {
		return 1
	}
	return 0
}

func loadIncidents(files []string, ids []string) ([]ioc.Incident, error) {
	incs, err := ioc.Embedded()
	if err != nil {
		return nil, err
	}
	for _, f := range files {
		extra, _, err := ioc.LoadFile(f)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", f, err)
		}
		incs = append(incs, extra...)
	}
	return ioc.Select(incs, ids)
}

func huntList(files []string) int {
	incs, err := loadIncidents(files, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	for _, i := range incs {
		fmt.Printf("%-18s %s  (%s..%s, %d indicators)\n", i.ID, sanitize.Terminal(i.Title), i.FirstSeen, i.LastSeen, len(i.Indicators))
		for _, s := range i.Sources {
			fmt.Printf("%-18s   %s\n", "", sanitize.Terminal(s))
		}
	}
	return 0
}

func printHunt(pkg string, vs []ioc.Verdict, notes []string) {
	win := ""
	if len(vs) > 0 && vs[0].Window != "" {
		win = " — agent activity in the evidence: " + vs[0].Window
	}
	if pkg != "" {
		fmt.Printf("Incident hunt: %s%s\n", sanitize.Terminal(pkg), win)
	} else {
		fmt.Println("Incident hunt (directory only)")
	}
	if len(vs) > 0 {
		fmt.Println("Searched: " + strings.Join(vs[0].Surfaces, "; "))
	}
	fmt.Println()
	for _, v := range vs {
		label := strings.ReplaceAll(v.Status, "_", " ")
		fmt.Printf("  %-13s %-17s %s (%s..%s)\n", label, v.Incident.ID, sanitize.Terminal(v.Incident.Title), v.Incident.FirstSeen, v.Incident.LastSeen)
		if v.Status != "NO_EVIDENCE" && v.Reason != "" && len(v.Hits) == 0 {
			fmt.Printf("  %-13s %s\n", "", sanitize.Terminal(v.Reason))
		}
		for _, h := range v.Hits {
			when := ""
			if h.FirstSeen != "" {
				when = " first " + h.FirstSeen
				if h.TimeSrc != "" {
					when += " (" + h.TimeSrc + ")"
				}
			}
			fmt.Printf("  %-13s   %-8s %-14s %s ×%d%s\n", "", h.Indicator.Severity(h.Where), h.Where, sanitize.Terminal(h.Indicator.Label()), h.Count, when)
			fmt.Printf("  %-13s     %s\n", "", sanitize.Terminal(h.Evidence))
		}
		for _, h := range v.Context {
			fmt.Printf("  %-13s   context: %s seen (%s) — shared infrastructure, not evidence on its own\n", "", sanitize.Terminal(h.Indicator.Label()), sanitize.Terminal(h.Evidence))
		}
		if len(v.Mentions) > 0 {
			fmt.Printf("  %-13s   (%d mention(s) in conversation text — context, not evidence of compromise)\n", "", len(v.Mentions))
		}
	}
	seen := map[string]bool{}
	for _, v := range vs {
		for _, n := range v.Notes {
			if !seen[n] {
				seen[n] = true
				fmt.Println("note:", sanitize.Terminal(n))
			}
		}
	}
	for _, n := range notes {
		fmt.Println("note:", sanitize.Terminal(n))
	}
	fmt.Println("\nNO EVIDENCE covers only the surfaces searched. Add --path ~ to check lockfiles and installed files on disk.")
}
