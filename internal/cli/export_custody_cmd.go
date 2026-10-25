package cli

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/accountability"
	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/custody"
	"github.com/efij/AgentDFIR/v4/internal/sanitize"
	"github.com/efij/AgentDFIR/v4/internal/seal"
	"github.com/efij/AgentDFIR/v4/internal/store"
)

const exportCustodyUsage = `usage: agentdfir export custody [<case.adfir>] --out <dir | file.zip>
                                [--certify --name <n> --title <t> --org <o>]

Produces a self-contained, human-readable chain-of-custody package beside the
case (derived data; the sealed case is not modified):
  custody.md / custody.json   every custody event in order, with actor, time,
                              action, round and digests; both hash chains and
                              their verified state
  seals/                      copies of SHA256SUMS*, SEAL.sig*, the signer's
                              public key, and the anchor records for this case
  verify.txt                  a full verify run at export time, and the exact
                              commands to re-run it with AgentDFIR and with
                              standard tools
  certification-902-14.md     the FRE 902(13)/902(14) template, pre-filled with
                              case facts; human fields left as [[ ]]. Never
                              signed by the tool.
  MANIFEST.sha256             sha256 of every file in the bundle
Default case: this machine's. Not legal advice.
`

func cmdExportCustody(args []string) int {
	fs := flag.NewFlagSet("export custody", flag.ContinueOnError)
	out := fs.String("out", "", "output directory or .zip file")
	certify := fs.Bool("certify", false, "include a pre-filled certification template")
	name := fs.String("name", "", "qualified person's name (with --certify)")
	title := fs.String("title", "", "qualified person's title (with --certify)")
	org := fs.String("org", "", "organization (with --certify)")
	pkg, rest := splitPositional(args)
	if err := fs.Parse(rest); err != nil || fs.NArg() > 1 || (pkg != "" && fs.NArg() != 0) {
		fmt.Fprint(os.Stderr, exportCustodyUsage)
		return 2
	}
	if pkg == "" {
		pkg = fs.Arg(0)
	}
	if pkg == "" {
		pkg = defaultCase()
	}
	if pkg == "" || *out == "" {
		fmt.Fprint(os.Stderr, exportCustodyUsage)
		return 2
	}
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	bundle := map[string][]byte{}
	// 1. custody.json / custody.md
	all, err := custody.Load(pkg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	cj, _ := json.MarshalIndent(map[string]any{
		"case_id": man.CaseID, "sealed_log": all.Sealed, "sealed_chain_ok": all.SealedChainErr == "",
		"sealed_chain_error": all.SealedChainErr, "activity_log": all.Activity,
		"activity_chain_ok": all.ActivityChainErr == "", "activity_chain_error": all.ActivityChainErr,
	}, "", "  ")
	bundle["custody.json"] = append(cj, '\n')
	bundle["custody.md"] = []byte(custodyMarkdown(man.CaseID, all))

	// 2. seals/
	for _, name := range []string{"SHA256SUMS", seal.SigFile} {
		if b, err := os.ReadFile(filepath.Join(pkg, name)); err == nil {
			bundle["seals/"+name] = b
		}
	}
	if ents, err := os.ReadDir(filepath.Join(pkg, "seals")); err == nil {
		for _, e := range ents {
			if b, err := os.ReadFile(filepath.Join(pkg, "seals", e.Name())); err == nil {
				bundle["seals/"+e.Name()] = b
			}
		}
	}
	if pub := store.PublicKeyPEM(); pub != nil {
		bundle["seals/signer.pub"] = pub
	}
	if abs, err := filepath.Abs(pkg); err == nil {
		if anchors, intact, err := store.AnchorsForCase(man.CaseID, abs); err == nil && len(anchors) > 0 {
			aj, _ := json.MarshalIndent(map[string]any{"anchor_log_chain_ok": intact, "anchors": anchors}, "", "  ")
			bundle["seals/anchors.json"] = append(aj, '\n')
		}
	}

	// 3. verify.txt — a full verify run plus the commands to reproduce it.
	bundle["verify.txt"] = []byte(verifyText(pkg, man.CaseID))

	// 4. certification template.
	if *certify || *name != "" || *title != "" || *org != "" {
		cert, err := accountability.Certification(pkg, accountability.CertFields{Name: *name, Title: *title, Org: *org})
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		bundle["certification-902-14.md"] = []byte(cert)
	}

	// 5. MANIFEST.sha256 over the bundle.
	bundle["MANIFEST.sha256"] = manifestSHA(bundle)

	n, err := writeBundle(*out, bundle)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	// Record the export in the case's custody activity log.
	if _, err := custody.Append(pkg, custody.EventCustodyExported, map[string]any{
		"out": *out, "files": n, "certified": *certify || *name != "",
	}); err != nil {
		fmt.Fprintln(os.Stderr, "warning: custody activity not recorded:", err)
	}
	fmt.Printf("Chain-of-custody package for case %s written to %s (%d file(s)).\n", sanitize.Terminal(man.CaseID), sanitize.Terminal(*out), n)
	fmt.Printf("Sealed custody chain: %s. Activity chain: %s.\n", okOr(all.SealedChainErr), okOr(all.ActivityChainErr))
	if _, ok := bundle["certification-902-14.md"]; ok {
		fmt.Println("A certification template is included; a qualified person completes the [[ ]] fields and signs it. Not legal advice.")
	}
	return 0
}

// custodyMarkdown renders both logs as a readable table.
func custodyMarkdown(caseID string, all *custody.All) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("# Chain of custody — case %s\n\n", sanitize.Terminal(caseID))
	w("Every recorded touch of this case, in order. The sealed log is inside the evidence seal; the activity log records what was done with the case after it was sealed (reports, exports, authorizations), as a hash chain outside the seal. Not legal advice.\n\n")
	w("## Sealed custody log (`chain-of-custody.jsonl`)\n\n")
	w("Hash chain: **%s**\n\n", okOr(all.SealedChainErr))
	w("| Seq | Time (UTC) | Event | Round | Detail |\n|---|---|---|---|---|\n")
	for _, r := range all.Sealed {
		w("| %d | %s | %s | %d | %s |\n", r.Seq, r.TS, r.Event, r.Round, sanitize.Terminal(custody.Describe(r)))
	}
	w("\n## Activity log (`custody/activity.jsonl`, outside the seal)\n\n")
	w("Hash chain: **%s**\n\n", okOr(all.ActivityChainErr))
	if len(all.Activity) == 0 {
		w("No post-seal activity recorded.\n")
	} else {
		w("| Seq | Time (UTC) | Event | Actor | Tool | Seal digest | Detail |\n|---|---|---|---|---|---|---|\n")
		for _, r := range all.Activity {
			w("| %d | %s | %s | %s@%s | %s | %.16s… | %s |\n", r.Seq, r.TS, r.Event, sanitize.Terminal(r.OSUser), sanitize.Terminal(r.Host), r.ToolVer, r.SealDigest, sanitize.Terminal(custody.Describe(r)))
		}
	}
	w("\nGenerated by AgentDFIR. Derived from the sealed case; the case itself is unchanged.\n")
	return b.String()
}

// verifyText runs a full verify and lists the commands to reproduce it.
func verifyText(pkg, caseID string) string {
	var b strings.Builder
	w := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	w("AgentDFIR verification of case %s at export time\n", caseID)
	w("================================================\n\n")
	res, err := casepkg.Verify(pkg)
	if err != nil {
		w("verify error: %v\n", err)
	} else {
		w("Depth:              %s\n", res.Depth)
		w("Rounds:             %d\n", res.Rounds)
		w("Files checked:      %d\n", res.FilesChecked)
		w("Artifacts OK:       %d (not acquired: %d)\n", res.ArtifactsOK, res.ArtifactsFailed)
		w("Collection records: %d (hash chain)\n", res.CollectionRecs)
		w("Custody records:    %d (hash chain)\n", res.CustodyRecs)
		if sr, serr := seal.Verify(pkg, ""); serr == nil {
			switch {
			case !sr.Present:
				w("Signature:          none (package is unsigned)\n")
			case sr.Valid:
				w("Signature:          VALID (ed25519, key %.16s…)\n", sr.PublicKey)
			default:
				w("Signature:          INVALID — %s\n", sr.Reason)
			}
		}
		if len(res.Problems) == 0 {
			w("Result:             VERIFIED — no modifications detected\n")
		} else {
			w("Result:             FAILED — %d problem(s):\n", len(res.Problems))
			for _, p := range res.Problems {
				w("  - %s\n", p)
			}
		}
	}
	w("\nReproduce this check\n--------------------\n\n")
	w("With AgentDFIR:\n")
	w("  agentdfir verify %s\n\n", filepath.Base(pkg))
	w("With standard tools, inside the package directory:\n")
	w("  # the sealed set is covered by SHA256SUMS; a changed byte breaks it\n")
	w("  sha256sum -c SHA256SUMS          # (macOS: shasum -a 256 -c SHA256SUMS)\n")
	w("  # the manifest digest the signature covers:\n")
	w("  sha256sum SHA256SUMS\n")
	w("  # if SEAL.sig is present, it is ed25519 over that digest; public_key is in SEAL.sig.\n")
	w("  # both logs are hash chains: each line's \"prev\" is the sha256 of the previous line.\n")
	w("  #   jq -c . chain-of-custody.jsonl | while read l; do printf '%%s' \"$l\" | sha256sum; done\n")
	return b.String()
}

func manifestSHA(bundle map[string][]byte) []byte {
	names := make([]string, 0, len(bundle))
	for n := range bundle {
		if n != "MANIFEST.sha256" {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	var b strings.Builder
	for _, n := range names {
		sum := sha256.Sum256(bundle[n])
		fmt.Fprintf(&b, "%s  %s\n", hex.EncodeToString(sum[:]), n)
	}
	return []byte(b.String())
}

// writeBundle writes the bundle to a directory or, when out ends in .zip,
// a zip file. Returns the number of files written.
func writeBundle(out string, bundle map[string][]byte) (int, error) {
	names := make([]string, 0, len(bundle))
	for n := range bundle {
		names = append(names, n)
	}
	sort.Strings(names)
	if strings.HasSuffix(strings.ToLower(out), ".zip") {
		f, err := os.OpenFile(out, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
		if err != nil {
			return 0, err
		}
		zw := zip.NewWriter(f)
		for _, n := range names {
			w, err := zw.Create(n)
			if err != nil {
				zw.Close()
				f.Close()
				return 0, err
			}
			if _, err := w.Write(bundle[n]); err != nil {
				zw.Close()
				f.Close()
				return 0, err
			}
		}
		if err := zw.Close(); err != nil {
			f.Close()
			return 0, err
		}
		return len(names), f.Close()
	}
	if err := os.MkdirAll(out, 0o700); err != nil {
		return 0, err
	}
	for _, n := range names {
		p := filepath.Join(out, filepath.FromSlash(n))
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			return 0, err
		}
		if err := os.WriteFile(p, bundle[n], 0o600); err != nil {
			return 0, err
		}
	}
	return len(names), nil
}
