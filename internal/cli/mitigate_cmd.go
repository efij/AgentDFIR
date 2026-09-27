package cli

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v2/internal/analysis"
	"github.com/efij/AgentDFIR/v2/internal/mitigate"
	"github.com/efij/AgentDFIR/v2/internal/notes"
	"github.com/efij/AgentDFIR/v2/internal/report"
	"github.com/efij/AgentDFIR/v2/internal/sanitize"
	"github.com/efij/AgentDFIR/v2/internal/schema"
	"github.com/efij/AgentDFIR/v2/internal/store"
)

const mitigateUsage = `usage: agentdfir mitigate [flags]

Turns what a case found into guardrails in the AI agents' own settings, so it
cannot happen again, and fixes config that is unsafe right now. This is the
only command that changes files outside a case: it always shows the plan
first, backs every file up, records every change in a hash-chained ledger and
can put everything back.

  agentdfir mitigate                              what it would change (writes nothing)
  agentdfir mitigate --apply                      apply the default packs and the fixes, asking per file
  agentdfir mitigate --select all --apply --yes   every pack, no questions (scripts)
  agentdfir mitigate --select secret-paths,outbound-upload --deny outbound-upload --apply
  agentdfir mitigate --status                     every change made, and whether it is still in place
  agentdfir mitigate --revert <id> | --revert-all put files back exactly as they were
  agentdfir mitigate --export managed             JSON for an administrator's managed-settings.json

Packs (--select, comma separated; "default" = the ones marked *, "all", "fix"):
%s
Flags:
`

func cmdMitigate(args []string) int {
	fs := flag.NewFlagSet("mitigate", flag.ContinueOnError)
	casePath := fs.String("case", "", "case whose findings to mitigate (default: this machine's case from `agentdfir run`)")
	selectF := fs.String("select", "default,fix", "packs to apply: ids, default, all, fix")
	denyF := fs.String("deny", "", "ask-level packs to raise to deny (comma separated)")
	apply := fs.Bool("apply", false, "make the changes (asks per file unless --yes)")
	yes := fs.Bool("yes", false, "with --apply: do not ask")
	status := fs.Bool("status", false, "show every applied change and verify it is still in place")
	revert := fs.String("revert", "", "undo one applied change by its id")
	revertAll := fs.Bool("revert-all", false, "undo every applied change, newest first")
	force := fs.Bool("force", false, "with --revert: restore the backup even if the file changed since")
	export := fs.String("export", "", "managed: print a managed-settings.json fragment for the selected packs")
	showDiff := fs.Bool("diff", false, "print the full diff of every file")
	asJSON := fs.Bool("json", false, "machine-readable plan / status")
	homeF := fs.String("home", "", "profile root to protect (default: your home directory)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, mitigateUsage, packHelp())
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fs.Usage()
		return 2
	}
	env, err := mitigateEnv(*homeF)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	switch {
	case *status:
		return mitigateStatus(env, *asJSON)
	case *revert != "":
		if err := mitigate.Revert(env, *revert, *force); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("Reverted %s: the file is back exactly as it was before agentdfir changed it.\n", sanitize.Terminal(*revert))
		return 0
	case *revertAll:
		n, errs := mitigate.RevertAll(env, *force)
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, "error:", e)
		}
		fmt.Printf("Reverted %d change(s).\n", n)
		if len(errs) > 0 {
			return 1
		}
		return 0
	}

	sel, err := parseSelection(*selectF, *denyF)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if *export != "" {
		if *export != "managed" {
			fmt.Fprintln(os.Stderr, "error: --export supports only: managed")
			return 2
		}
		return exportManaged(sel)
	}

	pl, err := mitigate.BuildPlan(env, sel)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	pl.Recommend = append(pl.Recommend, mitigate.MCPRecommendations(env)...)
	pkg := *casePath
	if pkg == "" {
		pkg = defaultCase()
	}
	var assess *mitigate.Assessment
	if pkg != "" {
		if a, aErr := assessCase(env, pkg); aErr == nil {
			assess = a
		} else if *casePath != "" {
			fmt.Fprintln(os.Stderr, "error:", aErr)
			return 1
		}
	}
	if *asJSON {
		out := map[string]any{"plan": pl, "selection": sel}
		if assess != nil {
			out["assessment"] = assess
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(out)
		if *apply {
			fmt.Fprintln(os.Stderr, "--json prints the plan only; run again without --json to apply")
		}
		if len(pl.Changes) > 0 {
			return 3
		}
		return 0
	}
	if assess != nil {
		printAssessment(pkg, assess)
	}
	printPlan(pl, sel, *showDiff)
	if len(pl.Changes) == 0 {
		fmt.Println("\nNothing to change: every selected guardrail is already in place.")
		return 0
	}
	if !*apply {
		fmt.Printf("\nNothing was changed. To make these changes:  agentdfir mitigate --select %s --apply\n", selectionString(sel))
		return 3
	}
	in := bufio.NewReader(os.Stdin)
	var chosen []*mitigate.Change
	for _, c := range pl.Changes {
		if *yes {
			chosen = append(chosen, c)
			continue
		}
		fmt.Printf("\nChange %s? [y/N] ", sanitize.Terminal(c.Target))
		line, _ := in.ReadString('\n')
		if a := strings.ToLower(strings.TrimSpace(line)); a == "y" || a == "yes" {
			chosen = append(chosen, c)
		}
	}
	pl.Changes = chosen
	failed := 0
	fmt.Println()
	for _, r := range mitigate.Apply(env, pl) {
		switch {
		case r.Err != nil:
			failed++
			fmt.Printf("  FAILED   %s: %v\n", sanitize.Terminal(r.Target), r.Err)
		case r.ID == "":
			fmt.Printf("  skipped  %s (%s)\n", sanitize.Terminal(r.Target), r.Note)
		default:
			fmt.Printf("  applied  %s   id %s\n", sanitize.Terminal(r.Target), r.ID)
			if r.Note != "" {
				fmt.Printf("           %s\n", r.Note)
			}
		}
	}
	fmt.Printf("\nLedger: %s\nCheck them any time: agentdfir mitigate --status · undo: agentdfir mitigate --revert <id> | --revert-all\n", filepath.Join(env.StateDir, "ledger.jsonl"))
	fmt.Println("Restart running agents so they read the new settings.")
	if failed > 0 {
		return 1
	}
	return 0
}

// cmdGuard is the hook entry point: `agentdfir guard log` reads one Claude
// Code PreToolUse payload on stdin.
func cmdGuard(args []string) int {
	if len(args) != 1 || args[0] != "log" {
		fmt.Fprintln(os.Stderr, "usage: agentdfir guard log   (reads a Claude Code PreToolUse payload on stdin; installed by agentdfir mitigate)")
		return 2
	}
	return mitigate.RunGuard(os.Stdin, os.Stderr)
}

func mitigateEnv(home string) (mitigate.Env, error) {
	if home == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return mitigate.Env{}, err
		}
		home = h
	}
	ah, err := store.Home()
	if err != nil {
		return mitigate.Env{}, err
	}
	return mitigate.Env{Home: home, StateDir: filepath.Join(ah, "mitigations"), GuardCommand: guardCommand()}, nil
}

// guardCommand is the hook command line. The binary on PATH is preferred
// over this process's path: a package manager's symlink survives upgrades,
// a Cellar path does not.
func guardCommand() string {
	p, err := exec.LookPath("agentdfir")
	if err != nil || p == "" {
		p, err = os.Executable()
		if err != nil {
			return ""
		}
	}
	if abs, err := filepath.Abs(p); err == nil {
		p = abs
	}
	if strings.ContainsAny(p, " \t'\"") {
		p = `"` + strings.ReplaceAll(p, `"`, `\"`) + `"`
	}
	return p + " guard log"
}

func parseSelection(sel, deny string) (mitigate.Selection, error) {
	s := mitigate.Selection{Deny: map[string]bool{}}
	seen := map[string]bool{}
	addPack := func(id string) {
		if !seen[id] {
			seen[id] = true
			s.Packs = append(s.Packs, id)
		}
	}
	for _, t := range strings.Split(sel, ",") {
		switch t = strings.TrimSpace(t); t {
		case "":
		case "fix":
			s.Fix = true
		case "default":
			for _, id := range mitigate.DefaultPacks() {
				addPack(id)
			}
		case "all":
			s.Fix = true
			for _, id := range mitigate.PackIDs() {
				addPack(id)
			}
		default:
			if _, ok := mitigate.PackByID(t); !ok {
				return s, fmt.Errorf("unknown pack %q (known: %s, plus default, all, fix)", t, strings.Join(mitigate.PackIDs(), ", "))
			}
			addPack(t)
		}
	}
	for _, t := range strings.Split(deny, ",") {
		if t = strings.TrimSpace(t); t != "" {
			if _, ok := mitigate.PackByID(t); !ok {
				return s, fmt.Errorf("--deny: unknown pack %q", t)
			}
			s.Deny[t] = true
		}
	}
	return s, nil
}

func selectionString(s mitigate.Selection) string {
	parts := append([]string{}, s.Packs...)
	if s.Fix {
		parts = append(parts, "fix")
	}
	out := strings.Join(parts, ",")
	var d []string
	for k := range s.Deny {
		d = append(d, k)
	}
	sort.Strings(d)
	if len(d) > 0 {
		out += " --deny " + strings.Join(d, ",")
	}
	return out
}

func packHelp() string {
	var b strings.Builder
	for _, p := range mitigate.Packs {
		mark := " "
		if p.DefaultOn {
			mark = "*"
		}
		fmt.Fprintf(&b, "  %s %-16s %-5s friction %d  %s\n", mark, p.ID, p.Level, p.Friction, p.Title)
	}
	return b.String()
}

// defaultCase is this machine's case from `agentdfir run`, when there is one.
func defaultCase() string {
	host, _ := os.Hostname()
	u := ""
	if cu, err := user.Current(); err == nil {
		u = cu.Username
	}
	d, err := store.CaseDir(host, u)
	if err != nil {
		return ""
	}
	if _, err := os.Stat(filepath.Join(d, "manifest.jsonl")); err != nil {
		return ""
	}
	return d
}

// assessCase reads a case's findings and the analyst's verdicts. It never
// re-runs analysis: that is `analyze`'s job, and a plan should be instant.
func assessCase(env mitigate.Env, pkg string) (*mitigate.Assessment, error) {
	if _, err := report.ReadManifest(pkg); err != nil {
		return nil, fmt.Errorf("%s is not an evidence package: %v", pkg, err)
	}
	fs := analysis.LoadFindings(pkg)
	if len(fs) == 0 {
		return nil, fmt.Errorf("%s has no findings yet — run agentdfir analyze %s first", pkg, pkg)
	}
	st, _ := notes.Open(pkg).Load()
	cleared := func(f schema.Finding) bool {
		v := st.Verdicts[notes.FindingKey(f.RuleID, f.EvidenceRefs)].Verdict
		return v == "benign" || v == "false_positive"
	}
	var states []mitigate.State
	if sameMachine(pkg) {
		states, _ = mitigate.Status(env)
	}
	a := mitigate.Assess(fs, cleared, states)
	return &a, nil
}

// sameMachine reports whether a case was collected on this host by this
// user: only then do this machine's guardrails say anything about it.
func sameMachine(pkg string) bool {
	info, err := report.ReadCaseInfo(pkg)
	if err != nil {
		return false
	}
	host, _ := os.Hostname()
	u := ""
	if cu, err := user.Current(); err == nil {
		u = cu.Username
	}
	return info.Host == host && (info.OperatorOSUser == "" || info.OperatorOSUser == u)
}

func printAssessment(pkg string, a *mitigate.Assessment) {
	counts := map[mitigate.Mode]int{}
	for _, r := range a.Rules {
		counts[r.Mode] += r.Total
	}
	fmt.Printf("Case %s\n", sanitize.Terminal(pkg))
	fmt.Printf("  fix now %d · prevent %d · needs a person %d · not fixable by config %d  (findings, analyst-cleared ones excluded)\n",
		counts[mitigate.Fix], counts[mitigate.Prevent], counts[mitigate.Manual], counts[mitigate.None])
	shown := 0
	for _, r := range a.Rules {
		if r.Total == 0 || (r.Severity != "CRITICAL" && r.Severity != "HIGH") || shown >= 12 {
			continue
		}
		shown++
		how := string(r.Mode)
		switch r.Mode {
		case mitigate.Prevent:
			how = "prevent: " + strings.Join(r.Packs, ", ")
		case mitigate.Fix:
			how = "fix: " + r.Control
		case mitigate.Manual:
			how = "you: " + r.Steps[0]
		case mitigate.None:
			how = "evidence: " + r.Steps[0]
		}
		since := ""
		if r.Since != nil {
			since = fmt.Sprintf("  (%d since %s)", *r.Since, r.SinceTS[:10])
		}
		fmt.Printf("  %-8s %4d  %-34s %s%s\n", r.Severity, r.Total, r.Rule, sanitize.Terminal(how), since)
	}
	fmt.Println()
	fmt.Println("Packs          level  friction  findings  state")
	for _, p := range a.Packs {
		mark := " "
		if p.DefaultOn {
			mark = "*"
		}
		fmt.Printf("%s %-14s %-5s  %d         %-8d  %s\n", mark, p.ID, p.Level, p.Friction, p.Findings, strings.ReplaceAll(p.State, "_", " "))
	}
	fmt.Println()
}

func printPlan(pl *mitigate.Plan, sel mitigate.Selection, full bool) {
	fmt.Printf("Plan for --select %s\n", selectionString(sel))
	for _, c := range pl.Changes {
		verb := "edit  "
		if !c.Existed {
			verb = "create"
		}
		fmt.Printf("\n  %s %s  (%s)\n", verb, sanitize.Terminal(c.Target), c.Product)
		max := len(c.Summary)
		if !full && max > 8 {
			max = 8
		}
		for _, s := range c.Summary[:max] {
			fmt.Printf("         %s\n", sanitize.Terminal(s))
		}
		if len(c.Summary) > max {
			fmt.Printf("         … %d more (--diff shows everything)\n", len(c.Summary)-max)
		}
		if full {
			fmt.Println(sanitize.Terminal(c.Diff))
		}
	}
	for _, t := range pl.InPlace {
		fmt.Printf("\n  in place %s\n", sanitize.Terminal(t))
	}
	for _, r := range pl.Refused {
		fmt.Printf("\n  refused  %s\n", sanitize.Terminal(r))
	}
	if len(pl.Recommend) > 0 {
		fmt.Println("\nBy hand (agentdfir does not change these):")
		for _, r := range pl.Recommend {
			fmt.Printf("  - %s\n", sanitize.Terminal(r))
		}
	}
}

// exportManaged prints the selected packs as a managed-settings.json
// fragment. Managed settings are root-owned and win over the user's, so
// they are the one layer an agent cannot edit away; installing them is an
// administrator's change, which is why this only prints.
func exportManaged(sel mitigate.Selection) int {
	deny, ask := []string{}, []string{}
	perms := map[string]any{}
	for _, id := range sel.Packs {
		p, _ := mitigate.PackByID(id)
		lvl := p.Level
		if sel.Deny[id] {
			lvl = mitigate.Deny
		}
		if lvl == mitigate.Deny {
			deny = append(deny, p.Claude...)
		} else {
			ask = append(ask, p.Claude...)
		}
		if p.Setting != nil && len(p.Setting.Path) == 2 && p.Setting.Path[0] == "permissions" {
			perms[p.Setting.Path[1]] = p.Setting.Value
		}
	}
	perms["deny"] = deny
	if len(ask) > 0 {
		perms["ask"] = ask
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	enc.Encode(map[string]any{"permissions": perms})
	fmt.Fprintln(os.Stderr, "Install as an administrator: /Library/Application Support/ClaudeCode/managed-settings.json (macOS), /etc/claude-code/managed-settings.json (Linux), C:\\ProgramData\\ClaudeCode\\managed-settings.json (Windows).")
	return 0
}

func mitigateStatus(env mitigate.Env, asJSON bool) int {
	st, err := mitigate.Status(env)
	if asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		enc.Encode(map[string]any{"changes": st, "ledger": filepath.Join(env.StateDir, "ledger.jsonl"), "error": errString(err)})
		if err != nil {
			return 1
		}
		return 0
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "WARNING:", err)
	}
	if len(st) == 0 {
		fmt.Println("No mitigations applied on this machine yet. See the plan: agentdfir mitigate")
		return 0
	}
	drift := 0
	for _, s := range st {
		mark := map[string]string{"in_place": "in place", "drifted": "DRIFTED", "missing": "FILE GONE", "reverted": "reverted"}[s.State]
		what := strings.Join(s.Record.Packs, ",")
		if what == "" {
			what = "fix"
		}
		fmt.Printf("%-12s %-9s %s  %s  %s\n", s.Record.ID, mark, s.Record.TS[:19], sanitize.Terminal(s.Record.Target), what)
		if s.State == "drifted" {
			drift++
			for i, m := range s.Missing {
				if i == 5 {
					fmt.Printf("               … %d more removed\n", len(s.Missing)-5)
					break
				}
				fmt.Printf("               removed since: %s\n", sanitize.Terminal(m))
			}
		}
	}
	if drift > 0 {
		fmt.Printf("\n%d change(s) drifted: something removed guardrails after they were applied. Re-apply with agentdfir mitigate --apply, and check the case for AGENT_SELF_MODIFICATION.\n", drift)
		return 1
	}
	return 0
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
