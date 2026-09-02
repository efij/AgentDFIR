package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/efij/AgentDFIR/internal/provenance"
	"github.com/efij/AgentDFIR/internal/sanitize"
)

const provenanceUsage = `usage: agentdfir provenance <package-dir> [file] [--json] [--all-lines]

For every line of an agent instruction / memory / config file: who wrote it
(session, agent, tool, time) and what triggered the write — a human request,
or content that came back from a tool (the injection → persistence path).
[file] filters by logical path (e.g. CLAUDE.md, .cursorrules, settings.json).
Writes to instruction-like paths whose file was not collected are listed too.
Results: <pkg>/detections/provenance.json
`

func cmdProvenance(args []string) int {
	fs := flag.NewFlagSet("provenance", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "machine-readable output")
	allLines := fs.Bool("all-lines", false, "print unattributed lines too (default: attributed only)")
	var positional []string
	rest := args
	for len(rest) > 0 && len(rest[0]) > 0 && rest[0][0] != '-' {
		positional = append(positional, rest[0])
		rest = rest[1:]
	}
	if err := fs.Parse(rest); err != nil {
		fmt.Fprint(os.Stderr, provenanceUsage)
		return 2
	}
	positional = append(positional, fs.Args()...)
	if len(positional) < 1 || len(positional) > 2 {
		fmt.Fprint(os.Stderr, provenanceUsage)
		return 2
	}
	pkg := positional[0]
	filter := ""
	if len(positional) == 2 {
		filter = positional[1]
	}
	dir := filepath.Join(pkg, "normalized")
	if _, err := os.Stat(filepath.Join(dir, "events.jsonl")); err != nil {
		fmt.Println("Package not normalized yet — normalizing first.")
		if rc := cmdNormalize([]string{pkg}); rc != 0 {
			return rc
		}
	}
	events := loadEvents(dir)
	rep, err := provenance.Run(pkg, events, filter)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	detDir := filepath.Join(pkg, "detections")
	_ = os.MkdirAll(detDir, 0o700)
	data, _ := json.MarshalIndent(rep, "", "  ")
	_ = os.WriteFile(filepath.Join(detDir, "provenance.json"), append(data, '\n'), 0o600)
	if *asJSON {
		fmt.Println(string(data))
		return exitFor(rep.Findings)
	}
	for _, fr := range rep.Files {
		fmt.Printf("%s  (%s)\n", sanitize.Terminal(fr.LogicalPath), fr.Product)
		fmt.Printf("  %d write event(s); %d line(s) attributed to agent writes, %d unattributed (pre-existing or edited outside the evidence)\n", fr.Writes, fr.Attributed, fr.Unattributed)
		for _, la := range fr.Lines {
			if !la.Written && !*allLines {
				continue
			}
			if !la.Written {
				if la.Text != "" {
					fmt.Printf("  L%-4d %-28s %s\n", la.Line, "(unattributed)", sanitize.Terminal(trimTo(la.Text, 90)))
				}
				continue
			}
			trig := la.Trigger
			if la.TrigInfo != "" && la.Trigger == "tool_result" {
				trig += "(" + la.TrigInfo + ")"
			}
			fmt.Printf("  L%-4d %-28s %s\n", la.Line, sanitize.Terminal(trimTo(la.Text, 90)), "")
			fmt.Printf("        <- %s via %s  %s  session %s  trigger=%s\n", sanitize.Terminal(la.AgentID), la.Tool, la.Timestamp, sanitize.Terminal(shortStr(la.SessionID, 12)), sanitize.Terminal(trig))
			if la.Prompt != "" {
				fmt.Printf("           after prompt: %s\n", sanitize.Terminal(la.Prompt))
			}
		}
		fmt.Println()
	}
	if len(rep.OtherWrite) > 0 {
		fmt.Printf("Writes to instruction-like paths (file not in this collection):\n")
		for _, w := range rep.OtherWrite {
			fmt.Printf("  %s  <- %s via %s  %s  trigger=%s\n", sanitize.Terminal(w.Path), sanitize.Terminal(w.Event.AgentID), w.Event.Tool, w.Event.Timestamp, w.Trigger+infoSuffix(w))
			fmt.Printf("     %s\n", sanitize.Terminal(w.Snippet))
		}
		fmt.Println()
	}
	if len(rep.Files) == 0 && len(rep.OtherWrite) == 0 {
		fmt.Println("No instruction/memory/config files or agent writes to them found in this package.")
	}
	printFindings(rep.Findings)
	fmt.Printf("\nreport written to %s\n", filepath.Join(detDir, "provenance.json"))
	return exitFor(rep.Findings)
}

func infoSuffix(w provenance.Write) string {
	if w.Trigger == "tool_result" && w.TrigInfo != "" {
		return "(" + w.TrigInfo + ")"
	}
	return ""
}

func shortStr(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
