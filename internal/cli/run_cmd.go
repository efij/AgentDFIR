package cli

import (
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/efij/AgentDFIR/internal/analysis"
	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/products"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/schema"
	"github.com/efij/AgentDFIR/internal/seal"
	"github.com/efij/AgentDFIR/internal/serve"
	"github.com/efij/AgentDFIR/internal/store"
)

// cmdRun is the whole workflow in one command for the common case — this
// machine, this user: detect every AI agent, collect all of them into one
// sealed package, analyze it, open the case explorer. Each step calls the
// same code the individual commands use; nothing is skipped or approximated.
// `detect`, `collect`, `analyze` and `serve` remain for every other case.
func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	product := fs.String("product", "", "collect only this product (default: every detected agent)")
	out := fs.String("out", "", "package directory (default: the case for this host/user under $AGENTDFIR_HOME)")
	caseID := fs.String("case-id", "", "case identifier")
	operator := fs.String("operator", "", "asserted operator name")
	authz := fs.String("authorization", "", "authorization reference")
	maxFileMB := fs.Int64("max-file-mb", 0, "per-artifact size bound (MiB)")
	jobs := fs.Int("jobs", 0, "parallel acquisition workers (default: CPUs, max 8)")
	newCase := fs.Bool("new", false, "start a fresh case instead of adding a round to the existing one")
	recollect := fs.Bool("recollect", false, "re-read every file, even one an earlier round already preserved")
	noShare := fs.Bool("no-share", false, "do not share identical blobs with other cases on this machine")
	fullPlugins := fs.Bool("full-plugins", false, "also collect node_modules/.git subtrees (large, third-party)")
	signKey := fs.String("sign", "", "sign the sealed package with this ed25519 private key")
	var endpointLogs multiFlag
	fs.Var(&endpointLogs, "endpoint", "OS telemetry log (auditd, Sysmon XML, JSONL/CSV export); repeatable")
	gwLog := fs.String("gateway-log", "", "MCP gateway log (JSONL) to check MCP calls against")
	port := fs.Int("port", 0, "TCP port on 127.0.0.1 (default: ephemeral)")
	noOpen := fs.Bool("no-open", false, "print the URL but do not open the browser")
	noServe := fs.Bool("no-serve", false, "stop after analysis and print the findings (scripts, CI)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir run [--product <p>] [--out <dir>] [--endpoint <os-log>]... [--new] [--jobs N] [--no-open] [--no-serve]")
		return 2
	}

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	// 1. detect
	fmt.Println("Step 1/4  Detect — which AI agents are on this machine (none is executed)")
	var targets []string
	if *product != "" {
		targets = []string{canonicalProductID(*product)}
		fmt.Printf("  %s (requested)\n", targets[0])
	} else {
		dets, err := products.DetectAll(home)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		for _, d := range dets {
			if !d.Detected {
				continue
			}
			man, mErr := products.Manifest(d.Product.ID)
			if mErr != nil || man == nil {
				fmt.Printf("  %-16s detected (no collector yet — skipped)\n", d.Product.Name)
				continue
			}
			fmt.Printf("  %-16s detected\n", d.Product.Name)
			targets = append(targets, d.Product.ID)
		}
	}
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "no AI agents found for this user. Evidence somewhere else? agentdfir collect --path <copied home> | --import <tree> | --docker <container> | --archive <zip>")
		return 1
	}

	// 2. collect
	id := *caseID
	if id == "" {
		id = generateCaseID()
	}
	host, _ := os.Hostname()
	osUser := ""
	if u, err := user.Current(); err == nil {
		osUser = u.Username
	}
	// One case per host/user at a predictable path, so running from a
	// different directory adds a round to the same case instead of copying
	// every byte of evidence again.
	dest := *out
	if dest == "" {
		d, err := store.CaseDir(host, osUser)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		dest = d
		if *newCase {
			dest = filepath.Join(filepath.Dir(d), id+".adfir")
		}
	}
	info := casepkg.CaseInfo{
		OperatorOSUser: osUser, OperatorAsserted: *operator, Authorization: *authz,
		CollectionArgs: append([]string{"run"}, args...),
		Notes:          map[string]string{"mode": "current-user", "run": "detect+collect+analyze"},
	}
	b, reopened, err := openPackage(dest, id, info, !*noShare)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	defer b.Close()
	if reopened {
		fmt.Printf("\nStep 2/4  Collect — round %d of existing case %s\n", b.Round(), sanitize.Terminal(dest))
		fmt.Println("  Unchanged files are carried forward, not re-read; files that only grew store just the new tail.")
	} else {
		fmt.Printf("\nStep 2/4  Collect — sealed evidence package %s\n", sanitize.Terminal(dest))
	}
	var total collector.Stats
	var collectErr error
	prog := newProgress()
	for _, pid := range targets {
		prog.Start(fmt.Sprintf("  %-16s collecting", pid))
		st, err := collectCurrentUser(b, pid, home, host, osUser, collectTuning{
			MaxFileMB: *maxFileMB, Jobs: *jobs, Recollect: *recollect, FullContent: *fullPlugins,
		}, func(s collector.Stats) {
			prog.Set(fmt.Sprintf("%d new · %d carried · %s", s.Acquired, s.Carried, humanBytes(s.TotalBytes)))
		})
		prog.Stop()
		total.Acquired += st.Acquired
		total.Carried += st.Carried
		total.Symlinks += st.Symlinks
		total.Skipped += st.Skipped
		total.Failed += st.Failed
		total.TotalBytes += st.TotalBytes
		if err != nil {
			fmt.Fprintf(os.Stderr, "  %s: %v (continuing)\n", sanitize.Terminal(pid), err)
			if collectErr == nil {
				collectErr = err
			}
			continue
		}
		if st.Carried > 0 {
			fmt.Printf("  %-16s %d new · %d carried forward · %s\n", pid, st.Acquired, st.Carried, humanBytes(st.TotalBytes))
		} else {
			fmt.Printf("  %-16s %d artifacts · %s\n", pid, st.Acquired, humanBytes(st.TotalBytes))
		}
	}
	if *signKey != "" {
		if err := seal.Sign(dest, *signKey); err != nil {
			fmt.Fprintln(os.Stderr, "sign error:", err)
			return 1
		}
	}
	prog.Start("  sealing")
	roundStats := b.Stats()
	sealErr := b.Seal()
	prog.Stop()
	if sealErr != nil {
		fmt.Fprintln(os.Stderr, "seal error:", sealErr)
		return 1
	}
	fmt.Printf("  Sealed round %d: %d artifacts (%s evidence, %s added to disk), SHA256SUMS written",
		b.Round(), total.Acquired+total.Carried, humanBytes(total.TotalBytes), humanBytes(roundStats.StoredBytes))
	if collectErr != nil {
		fmt.Print(" — partial evidence, see errors above")
	}
	fmt.Println()

	// 3. analyze
	fmt.Println("\nStep 3/4  Analyze — detections, MCP audit, provenance")
	prog.Start("  analyzing")
	res, err := analysis.Run(dest, analysis.Options{EndpointLogs: endpointLogs, GatewayLog: *gwLog, Log: prog})
	prog.Stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	for _, n := range res.StageNotes {
		fmt.Fprintln(os.Stderr, "note:", n)
	}
	fmt.Printf("  %s\n", severitySummary(res.Findings))
	if *noServe {
		printTriageFindings(res.Findings)
		fmt.Printf("\nPackage: %s   (open it later: agentdfir serve %s)\n", dest, dest)
		return exitFor(res.Findings)
	}

	// 4. serve
	fmt.Println("\nStep 4/4  Look — case explorer in your browser")
	prog.Start("  loading the explorer")
	s, err := serve.Load(dest, serve.Options{Port: *port})
	prog.Stop()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	ln, url, err := s.Listen(*port)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("  Open %s   (127.0.0.1 only · read-only · Ctrl+C to stop)\n", url)
	fmt.Printf("  Package: %s   (later: agentdfir serve %s)\n", dest, dest)
	if !*noOpen {
		openBrowser(url)
	}
	if err := s.Serve(ln); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return 1
	}
	return 0
}

// collectTuning carries the acquisition knobs from the command line.
type collectTuning struct {
	MaxFileMB   int64
	Jobs        int
	Recollect   bool
	FullContent bool
}

// collectCurrentUser acquires one product from the current user's home into
// an open package, exactly as `collect --product` does for the live host.
func collectCurrentUser(b *casepkg.Builder, productID, home, host, osUser string, tune collectTuning, progress func(collector.Stats)) (*collector.Stats, error) {
	man, err := products.Manifest(productID)
	if err != nil {
		return &collector.Stats{}, err
	}
	if man == nil {
		return &collector.Stats{}, fmt.Errorf("no collector implemented yet for product %q", productID)
	}
	if override, _, oErr := products.LoadOverride(productID, seal.VerifyFileSig); oErr == nil && override != nil {
		man = override
	}
	prodDef, err := products.ByID(productID)
	if err != nil {
		return &collector.Stats{}, err
	}
	configRoot := filepath.Join(home, prodDef.ConfigDirs[0])
	if prodDef.ConfigEnv != "" {
		if v := os.Getenv(prodDef.ConfigEnv); v != "" {
			configRoot = v
		}
	}
	opts := collector.Options{
		ProfileRoot: home, ConfigRoot: configRoot, SystemRoot: "/", Host: host, User: osUser,
		Product: productID, Progress: progress,
		Jobs: tune.Jobs, Recollect: tune.Recollect, FullContent: tune.FullContent,
	}
	if tune.MaxFileMB > 0 {
		opts.MaxFileBytes = tune.MaxFileMB << 20
	}
	start := time.Now()
	_ = b.Log("collection_run_started", map[string]any{"product": productID, "profile_root": home, "config_root": configRoot})
	st, runErr := collector.Run(b, man, opts)
	_ = b.Log("collection_run_finished", map[string]any{
		"product": productID, "acquired": st.Acquired, "carried_forward": st.Carried,
		"symlinks": st.Symlinks, "skipped": st.Skipped,
		"failed": st.Failed, "bytes": st.TotalBytes, "duration_ms": time.Since(start).Milliseconds(),
	})
	return st, runErr
}

// canonicalProductID maps the short names users type to product IDs.
func canonicalProductID(name string) string {
	switch name {
	case "claude":
		return "claude-code"
	case "codex":
		return "codex-cli"
	case "cursor":
		return "cursor-cli"
	case "gemini":
		return "gemini-cli"
	case "copilot":
		return "copilot-cli"
	case "roo":
		return "roo-code"
	case "copilot-chat":
		return "copilot-chat-vscode"
	}
	return name
}

// severitySummary is the one-line verdict a non-specialist reads first.
func severitySummary(f []schema.Finding) string {
	if len(f) == 0 {
		return "0 findings"
	}
	counts := map[string]int{}
	for _, x := range f {
		counts[x.Severity]++
	}
	s := fmt.Sprintf("%d finding(s):", len(f))
	for _, sev := range []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"} {
		if counts[sev] > 0 {
			s += fmt.Sprintf(" %d %s", counts[sev], sev)
		}
	}
	return s
}
