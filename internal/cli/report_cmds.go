package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/detect"
	"github.com/efij/AgentDFIR/internal/encrypt"
	"github.com/efij/AgentDFIR/internal/export"
	"github.com/efij/AgentDFIR/internal/normalize"
	"github.com/efij/AgentDFIR/internal/report"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/seal"
	"github.com/efij/AgentDFIR/internal/supportpkg"
)

// cmdReport renders HTML/JSON/CSV/STIX/OTel outputs for a package.
func cmdReport(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	format := fs.String("format", "html", "html|json|csv|stix|otel|ocsf|sarif|timesketch|l2tcsv|all")
	outDir := fs.String("out", "", "output directory (default: <package>/reports)")
	// Accept the package either first or last: `report pkg --format x` is how
	// people type it; `report --format x pkg` is how flag parsing wants it.
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || (pkg == "" && fs.NArg() != 1) || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprintln(os.Stderr, "usage: agentdfir report <package-dir> [--format html|json|csv|stix|otel|ocsf|sarif|timesketch|l2tcsv|all] [--out dir]")
		return 2
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}
	switch *format {
	case "html", "json", "csv", "stix", "otel", "ocsf", "sarif", "timesketch", "l2tcsv", "all":
	default:
		fmt.Fprintf(os.Stderr, "unknown report format %q\n", sanitize.Terminal(*format))
		return 2
	}

	man, err := report.ReadManifest(pkg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	ci, _ := report.ReadCaseInfo(pkg)
	vres, _ := casepkg.Verify(pkg)
	res, err := normalize.ParsePackage(pkg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	findings := detect.RunPackage(res, pkg)

	c := &report.Case{
		Manifest: man, CaseInfo: ci, Verify: vres,
		Events: res.Events, Entities: res.Entities, Findings: findings,
	}

	dir := *outDir
	if dir == "" {
		dir = filepath.Join(pkg, "reports")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	var written []string
	do := func(name string, fn func() error) bool {
		if err := fn(); err != nil {
			fmt.Fprintln(os.Stderr, "error writing "+name+":", err)
			return false
		}
		written = append(written, filepath.Join(dir, name))
		return true
	}
	want := func(f string) bool { return *format == "all" || *format == f }

	ok := true
	undated := 0
	if want("html") {
		ok = do("report.html", func() error { return report.WriteHTML(c, filepath.Join(dir, "report.html")) }) && ok
	}
	if want("json") {
		ok = do("report.json", func() error { return report.WriteJSON(c, filepath.Join(dir, "report.json")) }) && ok
	}
	if want("csv") {
		ok = do("findings.csv", func() error { return report.WriteFindingsCSV(c, filepath.Join(dir, "findings.csv")) }) && ok
		ok = do("timeline.csv", func() error { return report.WriteTimelineCSV(c, filepath.Join(dir, "timeline.csv")) }) && ok
	}
	if want("stix") {
		ok = do("findings.stix.json", func() error { return export.WriteSTIX(findings, man.CaseID, filepath.Join(dir, "findings.stix.json")) }) && ok
	}
	if want("otel") {
		ok = do("events.otel.json", func() error { return export.WriteOTel(res.Events, filepath.Join(dir, "events.otel.json")) }) && ok
	}
	if want("ocsf") {
		ok = do("events.ocsf.jsonl", func() error { return export.WriteOCSFEvents(res.Events, filepath.Join(dir, "events.ocsf.jsonl")) }) && ok
		ok = do("findings.ocsf.jsonl", func() error {
			return export.WriteOCSFFindings(findings, man.CaseID, filepath.Join(dir, "findings.ocsf.jsonl"))
		}) && ok
	}
	if want("sarif") {
		ok = do("findings.sarif.json", func() error {
			return export.WriteSARIF(findings, man.CaseID, filepath.Join(dir, "findings.sarif.json"))
		}) && ok
	}
	if want("timesketch") {
		ok = do("timeline.timesketch.jsonl", func() error {
			st, err := report.WriteTimesketchJSONL(c, filepath.Join(dir, "timeline.timesketch.jsonl"))
			undated = st.Undated
			return err
		}) && ok
	}
	if want("l2tcsv") {
		ok = do("timeline.l2tcsv", func() error {
			_, err := report.WriteL2TCSV(c, filepath.Join(dir, "timeline.l2tcsv"))
			return err
		}) && ok
	}

	fmt.Printf("Report(s) written for case %s:\n", man.CaseID)
	for _, w := range written {
		fmt.Printf("  %s\n", w)
	}
	if undated > 0 {
		fmt.Printf("Note: %d event(s) without a timestamp were omitted from the Timesketch export (present in timeline.l2tcsv / timeline.csv).\n", undated)
	}
	if !ok {
		return 1
	}
	return 0
}

// cmdExport handles `export --support`.
func cmdExport(args []string) int {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	support := fs.Bool("support", false, "produce a redacted support package")
	out := fs.String("out", "", "output package path")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir export --support <package-dir> [--out support.adfir]")
		return 2
	}
	if !*support {
		fmt.Fprintln(os.Stderr, "export currently supports only --support")
		return 2
	}
	src := fs.Arg(0)
	dst := *out
	if dst == "" {
		dst = src + ".support"
	}
	rm, err := supportpkg.Export(src, dst)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	total := 0
	for _, e := range rm.RedactedEntries {
		for _, n := range e.Categories {
			total += n
		}
	}
	fmt.Printf("Support package written to %s\n", dst)
	fmt.Printf("Redacted %d secret/PII value(s) across %d artifact(s). Categories/counts recorded in redaction-manifest.json (no values stored).\n",
		total, len(rm.RedactedEntries))
	fmt.Println("Original forensic package is unmodified.")
	return 0
}

// cmdKeygen generates an ed25519 signing keypair.
func cmdKeygen(args []string) int {
	fs := flag.NewFlagSet("keygen", flag.ContinueOnError)
	priv := fs.String("priv", "agentdfir.key", "private key output path")
	pub := fs.String("pub", "agentdfir.pub", "public key output path")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if err := seal.GenerateKey(*priv, *pub); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Wrote private key %s and public key %s (ed25519).\n", *priv, *pub)
	return 0
}

// cmdSign signs a package's SHA256SUMS, or (with --file) writes a
// detached signature for an arbitrary file such as a knowledge pack.
func cmdSign(args []string) int {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	key := fs.String("key", "", "private key path")
	file := fs.Bool("file", false, "sign an arbitrary file (detached .sig) instead of a package")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 || *key == "" {
		fmt.Fprintln(os.Stderr, "usage: agentdfir sign --key <private-key> [--file] <package-dir|file>")
		return 2
	}
	if *file {
		sig := fs.Arg(0) + ".sig"
		if err := seal.SignFile(fs.Arg(0), *key, sig); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		fmt.Printf("Signed %s -> %s (ed25519 detached).\n", fs.Arg(0), sig)
		return 0
	}
	if err := seal.Sign(fs.Arg(0), *key); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Signed %s (SEAL.sig written).\n", fs.Arg(0))
	return 0
}

// cmdEncrypt encrypts a sealed package directory to a single file.
func cmdEncrypt(args []string) int {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	out := fs.String("out", "", "output .adfir.enc file")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir encrypt <package-dir> [--out file.adfir.enc]")
		return 2
	}
	pass := os.Getenv("AGENTDFIR_PASSPHRASE")
	if pass == "" {
		fmt.Fprintln(os.Stderr, "set AGENTDFIR_PASSPHRASE (passphrase is never taken as a CLI argument)")
		return 2
	}
	dst := *out
	if dst == "" {
		dst = fs.Arg(0) + ".enc"
	}
	if err := encrypt.Encrypt(fs.Arg(0), dst, pass); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Encrypted package written to %s (AES-256-GCM). Logical paths are not in the clear.\n", dst)
	return 0
}

// cmdDecrypt extracts an encrypted package.
func cmdDecrypt(args []string) int {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	out := fs.String("out", "", "output package directory")
	if err := fs.Parse(args); err != nil || fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir decrypt <file.adfir.enc> [--out dir]")
		return 2
	}
	pass := os.Getenv("AGENTDFIR_PASSPHRASE")
	if pass == "" {
		fmt.Fprintln(os.Stderr, "set AGENTDFIR_PASSPHRASE")
		return 2
	}
	dst := *out
	if dst == "" {
		dst = strings.TrimSuffix(fs.Arg(0), ".enc")
	}
	if err := encrypt.Decrypt(fs.Arg(0), dst, pass); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Decrypted package extracted to %s. Run `agentdfir verify %s` to confirm integrity.\n", dst, dst)
	return 0
}
