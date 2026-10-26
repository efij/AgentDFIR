package cli

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/analysis"
	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/export"
	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/repro"
	"github.com/efij/AgentDFIR/v5/internal/sanitize"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// sealedFiles are copied into a reproduction's work directory; raw/ is
// linked (or copied where links are not available). Nothing of the
// overlay is carried over except normalized/retired.json, which is an
// input to the scan set, not a result.
var sealedFiles = []string{"case.json", "manifest.jsonl", "manifest.json", "collection.jsonl", "chain-of-custody.jsonl", "SHA256SUMS", "SEAL.sig"}

// reproduceWorkdir builds a package that holds the sealed zone of pkg and
// no analysis results.
func reproduceWorkdir(pkg string) (string, error) {
	work, err := os.MkdirTemp("", "adfir-reproduce-")
	if err != nil {
		return "", err
	}
	dst := filepath.Join(work, "case.adfir")
	if err := os.MkdirAll(filepath.Join(dst, "normalized"), 0o700); err != nil {
		return work, err
	}
	cp := func(rel string) error {
		in, err := os.Open(filepath.Join(pkg, rel))
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		defer in.Close()
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dst, rel)), 0o700); err != nil {
			return err
		}
		out, err := os.OpenFile(filepath.Join(dst, rel), os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		if _, err := io.Copy(out, in); err != nil {
			out.Close()
			return err
		}
		return out.Close()
	}
	for _, f := range append(sealedFiles, filepath.Join("normalized", "retired.json")) {
		if err := cp(f); err != nil {
			return work, err
		}
	}
	if seals, err := os.ReadDir(filepath.Join(pkg, "seals")); err == nil {
		for _, e := range seals {
			if e.Type().IsRegular() {
				if err := cp(filepath.Join("seals", e.Name())); err != nil {
					return work, err
				}
			}
		}
	}
	rawSrc, err := filepath.Abs(filepath.Join(pkg, "raw"))
	if err != nil {
		return work, err
	}
	if err := os.Symlink(rawSrc, filepath.Join(dst, "raw")); err != nil {
		blobs, rerr := os.ReadDir(rawSrc)
		if rerr != nil {
			return work, rerr
		}
		for _, e := range blobs {
			if e.Type().IsRegular() {
				if err := cp(filepath.Join("raw", e.Name())); err != nil {
					return work, err
				}
			}
		}
	}
	return work, nil
}

// reproduceOptions rebuilds the analysis options a manifest recorded.
// Input files must still be where they were, with the same content; what
// is missing or different is returned as a reason not to run.
func reproduceOptions(m *repro.Manifest, honeyFile string) (analysis.Options, []string) {
	ro := m.Options
	var missing []string
	need := func(f *repro.FileRef) string {
		if f == nil {
			return ""
		}
		now := repro.HashFile(f.Path)
		switch {
		case now.Error != "":
			missing = append(missing, fmt.Sprintf("%s: %s (recorded sha256 %s)", f.Path, now.Error, f.SHA256))
		case f.SHA256 != "" && now.SHA256 != f.SHA256:
			missing = append(missing, fmt.Sprintf("%s: content changed since the analysis (recorded %s, now %s)", f.Path, f.SHA256, now.SHA256))
		}
		return f.Path
	}
	needAll := func(fs []repro.FileRef) []string {
		var out []string
		for i := range fs {
			out = append(out, need(&fs[i]))
		}
		return out
	}
	o := analysis.Options{
		EndpointLogs: needAll(ro.EndpointLogs), EndpointFormat: endpoint.Format(ro.EndpointFormat), Window: time.Duration(ro.WindowMS) * time.Millisecond,
		ShellHistory: need(ro.ShellHistory), GatewayLog: need(ro.GatewayLog), GatewayMap: need(ro.GatewayMap), GatewayServers: ro.GatewayServers,
		RulesDir: m.RuleSet.RulesDir, NoBuiltinPacks: ro.NoBuiltinPacks, SpawnThreshold: ro.SpawnThreshold, KnownDests: ro.KnownDests,
		IOCFiles: needAll(ro.IOCFiles), RetireExcluded: ro.RetireExcluded,
	}
	if ro.Honeytokens > 0 {
		if honeyFile == "" {
			missing = append(missing, fmt.Sprintf("the analysis used %d honeytoken(s); pass the same list with --honeytokens (the package records only their count)", ro.Honeytokens))
		} else if data, err := os.ReadFile(honeyFile); err != nil {
			missing = append(missing, "--honeytokens: "+err.Error())
		} else {
			o.Honeytokens = strings.Split(string(data), "\n")
		}
	} else if honeyFile != "" {
		missing = append(missing, "--honeytokens given, but the recorded analysis used none")
	}
	return o, missing
}

// cmdVerifyReproduce re-runs a recorded analysis from the sealed zone and
// compares findings fingerprints.
func cmdVerifyReproduce(pkg, manifestPath, honeyFile string, asJSON bool) int {
	if manifestPath == "" {
		manifestPath = repro.Path(pkg)
	}
	rec, err := repro.Read(manifestPath)
	if os.IsNotExist(err) {
		fmt.Fprintln(os.Stderr, "error:", repro.ErrNoManifest)
		return 1
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	opts, missing := reproduceOptions(rec, honeyFile)
	if len(missing) > 0 {
		fmt.Println("Result:             NOT REPRODUCIBLE — the analysis's inputs are not available as recorded:")
		for _, m := range missing {
			fmt.Printf("  - %s\n", sanitize.Terminal(m))
		}
		return 1
	}
	work, err := reproduceWorkdir(pkg)
	if work != "" {
		defer os.RemoveAll(work)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: preparing the reproduction:", err)
		return 1
	}
	wpkg := filepath.Join(work, "case.adfir")
	if !asJSON {
		fmt.Printf("Reproducing the analysis recorded %s by agentdfir %s, from the sealed evidence only…\n",
			sanitize.Terminal(rec.AnalyzedUTC), sanitize.Terminal(rec.Tool.Version))
	}
	if _, err := analysis.Run(wpkg, opts); err != nil {
		fmt.Fprintln(os.Stderr, "error: re-running the analysis:", err)
		return 1
	}
	now, err := repro.Read(repro.Path(wpkg))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	// The stored findings are compared one by one only if they are the
	// ones the manifest fingerprinted.
	var recFindings []schema.Finding
	if data, err := overlay.ReadFile(filepath.Join(pkg, filepath.FromSlash(repro.FindingsFile))); err == nil {
		if fp, _, err := repro.FingerprintJSON(data); err == nil && fp == rec.FindingsFingerprint {
			_ = json.Unmarshal(data, &recFindings)
			if recFindings == nil {
				recFindings = []schema.Finding{}
			}
		}
	}
	c := repro.Compare(rec, now, recFindings, analysis.LoadFindings(wpkg))
	if asJSON {
		data, _ := json.MarshalIndent(c, "", "  ")
		fmt.Println(string(data))
		if c.Reproduced {
			return 0
		}
		return 1
	}
	fmt.Printf("Recorded fingerprint:   %s (%d finding(s))\n", rec.FindingsFingerprint, rec.Findings.Count)
	fmt.Printf("Reproduced fingerprint: %s (%d finding(s))\n", now.FindingsFingerprint, now.Findings.Count)
	for _, d := range c.Differences {
		tag := "does not change findings"
		if d.Affects {
			tag = "can change findings"
		}
		fmt.Printf("  differs: %s (%s): recorded %q, now %q — %s\n", d.Field, tag, sanitize.Terminal(d.Recorded), sanitize.Terminal(d.Now), d.Explain)
	}
	for _, s := range c.OnlyRecorded {
		fmt.Printf("  only in the recorded findings: %s\n", sanitize.Terminal(s))
	}
	if c.OnlyRecordedCount > len(c.OnlyRecorded) {
		fmt.Printf("  … %d more only in the recorded findings\n", c.OnlyRecordedCount-len(c.OnlyRecorded))
	}
	for _, s := range c.OnlyNow {
		fmt.Printf("  only in the reproduction: %s\n", sanitize.Terminal(s))
	}
	if c.OnlyNowCount > len(c.OnlyNow) {
		fmt.Printf("  … %d more only in the reproduction\n", c.OnlyNowCount-len(c.OnlyNow))
	}
	for _, n := range c.Notes {
		fmt.Printf("  note: %s\n", n)
	}
	if c.Reproduced {
		fmt.Println("Result:             REPRODUCED — the same findings from the same sealed evidence")
		return 0
	}
	fmt.Println("Result:             NOT REPRODUCED — see the differences above")
	return 1
}

// printOverlayCheck reports the 0.2.2 analysis files of a package and
// returns how many problems it found.
func printOverlayCheck(pkg string) int {
	c := repro.CheckOverlay(pkg)
	if len(c.Checked) == 0 {
		return 0
	}
	state := "consistent"
	if len(c.Problems) > 0 {
		state = fmt.Sprintf("%d problem(s)", len(c.Problems))
	}
	fmt.Printf("Analysis overlay:   %s (%s; derived data, outside the seal)\n", state, strings.Join(c.Checked, ", "))
	for _, n := range c.Notes {
		fmt.Printf("  note: %s\n", sanitize.Terminal(n))
	}
	for _, p := range c.Problems {
		fmt.Printf("  - %s\n", sanitize.Terminal(p))
	}
	return len(c.Problems)
}

// cmdVerifyProduction checks a production set's files and signature.
func cmdVerifyProduction(dir, pubkey string) int {
	c, err := export.VerifyProduction(dir, pubkey)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Production set:     %s\n", sanitize.Terminal(dir))
	fmt.Printf("Files checked:      %d\n", c.Files)
	switch c.Signature {
	case "valid":
		fmt.Printf("Signature:          VALID (ed25519, key %.16s…)\n", c.Signer)
	case "INVALID":
		fmt.Println("Signature:          INVALID")
	default:
		fmt.Println("Signature:          none (production is unsigned)")
	}
	for _, n := range c.Notes {
		fmt.Printf("  note: %s\n", sanitize.Terminal(n))
	}
	if len(c.Problems) == 0 {
		fmt.Println("Result:             VERIFIED — every produced file matches the manifest")
		return 0
	}
	fmt.Printf("Result:             FAILED — %d problem(s):\n", len(c.Problems))
	for _, p := range c.Problems {
		fmt.Printf("  - %s\n", sanitize.Terminal(p))
	}
	return 1
}

// parseInterleaved parses flags that may come before, between or after
// positional arguments, and returns the positionals in order.
func parseInterleaved(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}
