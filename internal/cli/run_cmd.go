package cli

import (
	"flag"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/analysis"
	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/collector"
	"github.com/efij/AgentDFIR/v3/internal/gentle"
	"github.com/efij/AgentDFIR/v3/internal/integrity"
	"github.com/efij/AgentDFIR/v3/internal/normalize"
	"github.com/efij/AgentDFIR/v3/internal/products"
	"github.com/efij/AgentDFIR/v3/internal/progress"
	"github.com/efij/AgentDFIR/v3/internal/sanitize"
	"github.com/efij/AgentDFIR/v3/internal/schema"
	"github.com/efij/AgentDFIR/v3/internal/seal"
	"github.com/efij/AgentDFIR/v3/internal/serve"
	"github.com/efij/AgentDFIR/v3/internal/store"
	"github.com/efij/AgentDFIR/v3/internal/witness"
)

// cmdRun is the whole workflow in one command for the common case — this
// machine, this user: detect every AI agent, collect all of them into one
// sealed package, analyze it, open the case explorer. Each step calls the
// same code the individual commands use; nothing is skipped or approximated.
// `detect`, `collect`, `analyze` and `serve` remain for every other case.
//
// A repeat run is a delta: earlier rounds are proven intact, unchanged
// files are carried forward, only changed transcripts are parsed, and when
// neither the evidence nor the analysis code changed the stored results
// are reused outright. It is gentle on the machine by default — lowered
// priority, capped workers and heap, paced reads, a pause while the host is
// busy, and a free-disk floor it never crosses.
func cmdRun(args []string) int {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	product := fs.String("product", "", "collect only this product (default: every detected agent)")
	out := fs.String("out", "", "package directory (default: the case for this host/user under $AGENTDFIR_HOME)")
	caseID := fs.String("case-id", "", "case identifier")
	operator := fs.String("operator", "", "asserted operator name")
	authz := fs.String("authorization", "", "authorization reference")
	maxFileMB := fs.Int64("max-file-mb", 0, "per-artifact size bound (MiB)")
	jobs := fs.Int("jobs", 0, "parallel acquisition workers (default: half the CPUs, max 4; --priority normal: CPUs, max 8)")
	newCase := fs.Bool("new", false, "start a fresh case instead of adding a round to the existing one")
	recollect := fs.Bool("recollect", false, "re-read every file, even one an earlier round already preserved")
	noWitness := fs.Bool("no-witness", false, "do not ask the host whether the files the agent claimed to write exist")
	noShare := fs.Bool("no-share", false, "do not share identical blobs with other cases on this machine")
	fullPlugins := fs.Bool("full-plugins", false, "also collect node_modules/.git subtrees (large, third-party)")
	signKey := fs.String("sign", "", "sign the sealed round with this ed25519 private key (default: this machine's key)")
	noSign := fs.Bool("no-sign", false, "do not sign the sealed round")
	verifyPrior := fs.String("verify-prior", "quick", "before adding a round, check earlier rounds: quick | full (re-hash every blob)")
	priority := fs.String("priority", "gentle", "how much to yield to the rest of the machine: gentle | background | normal")
	maxMemMB := fs.Int64("max-memory-mb", 0, "soft heap limit in MiB (default: gentle/background 25% of RAM, 512 MiB–4 GiB)")
	readMBps := fs.Int("max-read-mbps", -1, "cap acquisition reads (MB/s; default gentle 200, background 50, normal unlimited; 0 = unlimited)")
	minFreeGB := fs.Int("min-free-gb", envInt("AGENTDFIR_MIN_FREE_GB"), "never leave less free disk than this on the evidence volume (default: 2 GB, or 1% of the volume up to 5 GB; env AGENTDFIR_MIN_FREE_GB)")
	noGovernor := fs.Bool("no-governor", false, "do not pause acquisition while the machine is busy")
	reanalyze := fs.Bool("reanalyze", false, "re-run the analysis even when the stored results are current")
	var endpointLogs multiFlag
	fs.Var(&endpointLogs, "endpoint", "OS telemetry log (auditd, Sysmon XML, JSONL/CSV export); repeatable")
	gwLog := fs.String("gateway-log", "", "MCP gateway log (JSONL) to check MCP calls against")
	rulesDir := fs.String("rules", "", "directory of extra JSON rule packs (added to the packs shipped in the binary)")
	noPacks := fs.Bool("no-builtin-packs", false, "skip the rule packs shipped in the binary; run built-in Go rules only")
	port := fs.Int("port", 0, "TCP port on 127.0.0.1 (default: ephemeral)")
	noOpen := fs.Bool("no-open", false, "print the URL but do not open the browser")
	noServe := fs.Bool("no-serve", false, "stop after analysis and print the findings (scripts, CI)")
	if err := fs.Parse(args); err != nil || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir run [--product <p>] [--out <dir>] [--endpoint <os-log>]... [--new] [--priority gentle|background|normal] [--no-open] [--no-serve]")
		return 2
	}
	mode, err := gentle.ParseMode(*priority)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	if *verifyPrior != "quick" && *verifyPrior != "full" {
		fmt.Fprintln(os.Stderr, "error: --verify-prior must be quick or full")
		return 2
	}
	settings := gentle.Apply(mode, *jobs, *maxMemMB<<20)

	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	// Where the case lives: one per host/user at a predictable path, so
	// running from a different directory adds a round to the same case
	// instead of copying every byte of evidence again.
	id := *caseID
	if id == "" {
		id = generateCaseID()
	}
	host, _ := os.Hostname()
	osUser := ""
	if u, err := user.Current(); err == nil {
		osUser = u.Username
	}
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
	if *newCase {
		if _, err := os.Stat(dest); err == nil {
			fmt.Fprintf(os.Stderr, "error: --new was given but %s already exists; remove it or choose another --out\n", sanitize.Terminal(dest))
			return 1
		}
	}
	_, statErr := os.Stat(dest)
	reopening := statErr == nil

	// One display for the whole run, sized from how long each step took on
	// this machine before.
	perfPath := ""
	if h, err := store.Home(); err == nil {
		perfPath = filepath.Join(h, "perf.jsonl")
	}
	prevEvents := 0
	if reopening {
		prevEvents = analysis.PreviousEvents(dest)
	}
	steps := []progress.Step{
		{Name: "detect", Label: "Detect — which AI agents are on this machine", Rate: 0.5},
		{Name: "verify-prior", Label: "Verify — earlier rounds of this case", Rate: 2},
		{Name: "survey", Label: "Collect — sizing the collection", Rate: 2},
		{Name: "collect", Label: "Collect — acquiring evidence", Units: 1, Rate: 1.0 / (120 << 20)},
		{Name: "witness", Label: "Collect — asking the host about the agent's claims", Units: 1, Rate: 1.0 / (40 << 20)},
		{Name: "seal", Label: "Collect — sealing and signing", Rate: 1},
		{Name: "analyze", Label: "Analyze — detections, MCP audit, provenance", Units: float64(max(prevEvents, 1)), Rate: 0.0008},
		{Name: "serve", Label: "Look — loading the case explorer", Rate: 3},
	}
	tr := progress.New(steps, progress.Options{Key: dest, Model: progress.LoadModel(perfPath)})
	if !reopening {
		tr.Skip("verify-prior")
	}
	if *noWitness {
		tr.Skip("witness")
	}
	if *noServe {
		tr.Skip("serve")
	}
	tr.Run()
	stopped := false
	stop := func() {
		if !stopped {
			stopped = true
			tr.Stop()
		}
	}
	defer stop()
	fail := func(code int, format string, a ...any) int {
		stop()
		fmt.Fprintf(os.Stderr, "error: "+format+"\n", a...)
		return code
	}
	w := io.Writer(tr)

	// 1. detect
	fmt.Fprintf(w, "Step 1/4  Detect — which AI agents are on this machine (none is executed)\n")
	fmt.Fprintf(w, "  Priority: %s · %d worker(s)\n", settings.Priority, settings.Workers)
	tr.Begin("detect")
	var targets []string
	if *product != "" {
		targets = []string{canonicalProductID(*product)}
		fmt.Fprintf(w, "  %s (requested)\n", targets[0])
	} else {
		dets, err := products.DetectAll(home)
		if err != nil {
			return fail(1, "%v", err)
		}
		for _, d := range dets {
			if !d.Detected {
				continue
			}
			man, mErr := products.Manifest(d.Product.ID)
			if mErr != nil || man == nil {
				fmt.Fprintf(w, "  %-16s detected (no collector yet — skipped)\n", d.Product.Name)
				continue
			}
			fmt.Fprintf(w, "  %-16s detected\n", d.Product.Name)
			targets = append(targets, d.Product.ID)
		}
	}
	tr.End()
	if len(targets) == 0 {
		return fail(1, "no AI agents found for this user. Evidence somewhere else? agentdfir collect --path <copied home> | --import <tree> | --docker <container> | --archive <zip>")
	}

	// 2. collect
	info := casepkg.CaseInfo{
		OperatorOSUser: osUser, OperatorAsserted: *operator, Authorization: *authz,
		CollectionArgs: append([]string{"run"}, args...),
		Notes:          map[string]string{"mode": "current-user", "run": "detect+collect+analyze"},
	}
	var prior integrity.Prior
	b, reopened, err := openPackage(dest, id, info, !*noShare, func() {
		fmt.Fprintf(w, "\nStep 2/4  Collect — adding a round to the existing case %s\n", sanitize.Terminal(dest))
		tr.Begin("verify-prior")
		prior = checkPrior(w, dest, *verifyPrior)
	})
	if err != nil {
		return fail(1, "%v", err)
	}
	defer b.Close()
	if reopened {
		prior.Apply(b)
		fmt.Fprintf(w, "  Round %d. Unchanged files are carried forward, not re-read; files that only grew store just the new tail.\n", b.Round())
	} else {
		fmt.Fprintf(w, "\nStep 2/4  Collect — sealed evidence package %s\n", sanitize.Terminal(dest))
	}

	// Metadata-only pre-walk: counts the bytes that will really be read —
	// files an earlier round already holds are not work — so the time
	// remaining is about this run, not about the size of the profile.
	tr.Begin("survey")
	tune := collectTuning{MaxFileMB: *maxFileMB, Jobs: settings.Workers, Recollect: *recollect, FullContent: *fullPlugins}
	var plan collector.Survey
	for _, pid := range targets {
		s, err := surveyCurrentUser(pid, home, host, osUser, tune, b)
		if err == nil {
			plan.Files += s.Files
			plan.Bytes += s.Bytes
			plan.Skipped += s.Skipped
			plan.Carried += s.Carried
			plan.ReadBytes += s.ReadBytes
		}
	}
	tr.End()
	if plan.Files > 0 {
		if plan.Carried > 0 {
			fmt.Fprintf(w, "  %d files · %s to read · %d unchanged since the last round\n", plan.Files-plan.Carried, humanBytes(plan.ReadBytes), plan.Carried)
		} else {
			fmt.Fprintf(w, "  %d files · %s to acquire\n", plan.Files, humanBytes(plan.ReadBytes))
		}
	}

	// Never take the last of the disk: refuse up front when the round
	// cannot fit above the floor, and stop cleanly if the floor is reached
	// anyway. Evidence compresses about 5x; the overlay needs headroom.
	volume := dest
	if !reopened {
		volume = filepath.Dir(dest)
	}
	floor := gentle.Floor(volume, *minFreeGB)
	if err := gentle.Preflight(volume, plan.ReadBytes/3+(256<<20), floor); err != nil {
		return fail(exitDiskFloor, "%v", err)
	}
	rate := *readMBps
	if rate < 0 {
		switch mode {
		case gentle.Gentle:
			rate = 200
		case gentle.Background:
			rate = 50
		default:
			rate = 0
		}
	}
	gov := gentle.NewGovernor(gentle.GovernorOptions{
		ReadMBps: rate, DiskPath: volume, FloorByte: floor,
		Adaptive: mode != gentle.Normal && !*noGovernor,
	})
	defer gov.Close()
	tune.Pace = gov.Pace

	// A carried-forward file costs a stat, not a read: count it as a small
	// fixed amount of work so progress moves through a round of unchanged
	// files without pretending they were gigabytes read.
	const statCost = 64 << 10
	tr.SetUnits("collect", float64(plan.ReadBytes+int64(plan.Files)*statCost))
	tr.Begin("collect")
	var total collector.Stats
	var collectErr error
	for _, pid := range targets {
		st, err := collectCurrentUser(b, pid, home, host, osUser, tune, func(s collector.Stats) {
			tr.Progress(float64(total.ReadBytes + s.ReadBytes + int64(total.Processed+s.Processed)*statCost))
			busy := ""
			if gov.Busy() {
				busy = " · paused while the machine is busy"
			}
			tr.Detail("%s · %s read · %d new · %d carried%s", pid, humanBytes(total.ReadBytes+s.ReadBytes), s.Acquired, s.Carried, busy)
		})
		total.Acquired += st.Acquired
		total.Carried += st.Carried
		total.Symlinks += st.Symlinks
		total.Skipped += st.Skipped
		total.Failed += st.Failed
		total.TotalBytes += st.TotalBytes
		total.ReadBytes += st.ReadBytes
		total.Processed += st.Processed
		if err != nil {
			fmt.Fprintf(w, "  %s: %v (continuing)\n", sanitize.Terminal(pid), err)
			if collectErr == nil {
				collectErr = err
			}
			continue
		}
		switch {
		case st.Acquired == 0 && st.Carried == 0:
			// Detected but empty. Printing a bare "0 artifacts" tells an
			// analyst nothing about whether the product stores nothing or
			// the collector is aimed at the wrong path.
			fmt.Fprintf(w, "  %-16s nothing collected — %d manifest path(s) checked, none present on this host\n", pid, st.NotPresent)
			fmt.Fprintf(w, "  %-16s   the paths are recorded as NOT_PRESENT in the manifest; `agentdfir inspect <pkg>` lists them\n", "")
		case st.Carried > 0:
			fmt.Fprintf(w, "  %-16s %d new · %d carried forward · %s\n", pid, st.Acquired, st.Carried, humanBytes(st.TotalBytes))
		default:
			fmt.Fprintf(w, "  %-16s %d artifacts · %s\n", pid, st.Acquired, humanBytes(st.TotalBytes))
		}
	}
	if pauses, paused := gov.Stats(); pauses > 0 {
		fmt.Fprintf(w, "  paused %d time(s), %s in all, while the machine was busy\n", pauses, elapsed(paused))
	}
	// The host witness is acquisition, not analysis: what the filesystem and
	// the repositories said at the moment the evidence was taken. Asking
	// later would describe a different host.
	events := 0
	if !*noWitness {
		tr.SetUnits("witness", float64(total.ReadBytes+(1<<20)))
		tr.Begin("witness")
		var gathered int
		gathered, events = gatherWitness(dest, b, host)
		if gathered > 0 {
			fmt.Fprintf(w, "  %d claimed write(s) checked against the filesystem\n", gathered)
		}
	}
	tr.Begin("seal")
	signing := prepareSigning(b, *signKey, *noSign)
	roundStats := b.Stats()
	if err := b.Seal(); err != nil {
		return fail(1, "seal: %v", err)
	}
	if _, err := finishSeal(w, dest, signing, b.CaseID(), b.Round(), true); err != nil {
		return fail(1, "%v", err)
	}
	tr.End()
	fmt.Fprintf(w, "  Sealed round %d: %d artifacts (%s evidence, %s added to disk), SHA256SUMS written",
		b.Round(), total.Acquired+total.Carried, humanBytes(total.TotalBytes), humanBytes(roundStats.StoredBytes))
	if collectErr != nil {
		fmt.Fprint(w, " — partial evidence, see errors above")
	}
	fmt.Fprintln(w)

	// 3. analyze — or reuse, when nothing it depends on changed.
	fmt.Fprintln(w, "\nStep 3/4  Analyze — detections, MCP audit, provenance")
	aopts := analysis.Options{
		EndpointLogs: endpointLogs, GatewayLog: *gwLog,
		RulesDir: *rulesDir, NoBuiltinPacks: *noPacks, Log: w,
		RetireExcluded: !*fullPlugins,
		Stage: func(n, total int, name string) {
			tr.Detail("stage %d/%d · %s", n, total, name)
		},
	}
	var findings []schema.Finding
	if current, _ := analysis.Current(dest, aopts); current && !*reanalyze {
		tr.Skip("analyze")
		findings = analysis.LoadFindings(dest)
		fmt.Fprintln(w, "  Results are current: no evidence, parser or rule changed since the last analysis — reused (--reanalyze to force)")
	} else {
		if events > 0 {
			tr.SetUnits("analyze", float64(events))
		}
		tr.Begin("analyze")
		res, err := analysis.Run(dest, aopts)
		if err != nil {
			return fail(1, "%v", err)
		}
		tr.End()
		for _, n := range res.StageNotes {
			fmt.Fprintln(w, "note:", n)
		}
		findings = res.Findings
	}
	fmt.Fprintf(w, "  %s\n", severitySummary(findings))
	exit := exitFor(findings)
	if prior.Status == integrity.Failed {
		exit = exitPriorFailed
	}
	if *noServe {
		stop()
		fmt.Printf("  Total %s (%s)\n", elapsed(tr.Elapsed()), tr.Summary())
		printTriageFindings(findings)
		fmt.Printf("\nPackage: %s   (open it later: agentdfir serve %s)\n", dest, dest)
		return exit
	}

	// 4. serve
	fmt.Fprintln(w, "\nStep 4/4  Look — case explorer in your browser")
	tr.Begin("serve")
	s, err := serve.Load(dest, serve.Options{Port: *port})
	if err != nil {
		return fail(1, "%v", err)
	}
	ln, url, err := s.Listen(*port)
	if err != nil {
		return fail(1, "%v", err)
	}
	stop()
	fmt.Printf("  Ready — total %s (%s)\n", elapsed(tr.Elapsed()), tr.Summary())
	fmt.Printf("  Open %s   (127.0.0.1 only · read-only · Ctrl+C to stop)\n", url)
	fmt.Printf("  Package: %s   (later: agentdfir serve %s)\n", dest, dest)
	if prior.Status == integrity.Failed {
		fmt.Fprintln(os.Stderr, "  WARNING: earlier rounds of this case failed their integrity check (see above).")
	}
	if !*noOpen {
		openBrowser(url)
	}
	if err := s.Serve(ln); err != nil {
		fmt.Fprintln(os.Stderr, "server:", err)
		return 1
	}
	return exit
}

// envInt reads a whole-number setting from the environment (0 when unset
// or not a number).
func envInt(name string) int {
	n, err := strconv.Atoi(os.Getenv(name))
	if err != nil {
		return 0
	}
	return n
}

// exitDiskFloor is the exit status when a run would have taken the
// evidence volume below its free-space floor.
const exitDiskFloor = 5

// collectTuning carries the acquisition knobs from the command line.
type collectTuning struct {
	MaxFileMB   int64
	Jobs        int
	Recollect   bool
	FullContent bool
	Pace        func(int64) error
}

// surveyCurrentUser measures what collectCurrentUser would acquire, using
// the same manifest, overrides and bounds, so the progress total matches
// the work that follows.
func surveyCurrentUser(productID, home, host, osUser string, tune collectTuning, b *casepkg.Builder) (collector.Survey, error) {
	man, opts, err := collectPlan(productID, home, host, osUser, tune)
	if err != nil {
		return collector.Survey{}, err
	}
	if b != nil {
		opts.Unchanged = func(path string, info os.FileInfo) bool {
			_, ok := b.Unchanged(path, info)
			return ok
		}
	}
	return collector.SurveyRun(man, opts), nil
}

// collectCurrentUser acquires one product from the current user's home into
// an open package, exactly as `collect --product` does for the live host.
// collectPlan resolves the manifest and options for one product. The
// survey and the acquisition share it so the progress total describes
// exactly the work that follows.
func collectPlan(productID, home, host, osUser string, tune collectTuning) (*products.CollectorManifest, collector.Options, error) {
	man, err := products.Manifest(productID)
	if err != nil {
		return nil, collector.Options{}, err
	}
	if man == nil {
		return nil, collector.Options{}, fmt.Errorf("no collector implemented yet for product %q", productID)
	}
	if override, _, oErr := products.LoadOverride(productID, seal.VerifyFileSig); oErr == nil && override != nil {
		man = override
	}
	prodDef, err := products.ByID(productID)
	if err != nil {
		return nil, collector.Options{}, err
	}
	configRoot := filepath.Join(home, prodDef.ConfigDirs[0])
	if prodDef.ConfigEnv != "" {
		if v := os.Getenv(prodDef.ConfigEnv); v != "" {
			configRoot = v
		}
	}
	opts := collector.Options{
		ProfileRoot: home, ConfigRoot: configRoot, SystemRoot: "/", Host: host, User: osUser,
		Product: productID,
		Jobs:    tune.Jobs, Recollect: tune.Recollect, FullContent: tune.FullContent,
		Pace: tune.Pace,
	}
	if tune.MaxFileMB > 0 {
		opts.MaxFileBytes = tune.MaxFileMB << 20
	}
	return man, opts, nil
}

func collectCurrentUser(b *casepkg.Builder, productID, home, host, osUser string, tune collectTuning, progress func(collector.Stats)) (*collector.Stats, error) {
	man, opts, err := collectPlan(productID, home, host, osUser, tune)
	if err != nil {
		return &collector.Stats{}, err
	}
	opts.Progress = progress
	configRoot := opts.ConfigRoot
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
	case "cowork":
		return "claude-cowork"
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

// gatherWitness asks the host about every file the agent claimed to write,
// and seals the answer into the package. It returns how many paths were
// checked and how many events the evidence holds.
//
// It reads the claims from the package's own evidence rather than from the
// live profile, so it inspects exactly what was preserved, and it runs
// before Seal so the record is covered by SHA256SUMS and the custody chain
// like anything else.
//
// The events come from the normalized overlay, refreshed here — only the
// transcripts this round added or changed are parsed — instead of a full
// parse of every transcript on every run. The analysis that follows finds
// the overlay current and parses nothing again.
func gatherWitness(pkg string, b *casepkg.Builder, host string) (checked, events int) {
	if !normalize.Status(pkg).Current {
		if _, err := normalize.Refresh(pkg, normalize.OverlayOptions{}); err != nil {
			fmt.Fprintln(os.Stderr, "note: host witness not gathered:", err)
			return 0, 0
		}
	}
	evs := analysis.LoadEvents(pkg)
	rec := witness.Gather(evs, host, b.Round(), witness.DefaultLimits)
	if len(rec.Files) == 0 && len(rec.Repos) == 0 {
		return 0, len(evs)
	}
	if err := witness.Write(b, rec); err != nil {
		fmt.Fprintln(os.Stderr, "note: host witness not recorded:", err)
		return 0, len(evs)
	}
	return len(rec.Files), len(evs)
}
