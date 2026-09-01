// Package cli wires the agentdfir subcommands. Standard library only.
package cli

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/products"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/version"
)

const usage = `agentdfir — open-source DFIR for AI agents

Usage:
  agentdfir detect                      discover installed AI tooling
  agentdfir collect [flags]             forensic acquisition into an .adfir package
  agentdfir verify <package-dir>        verify a sealed evidence package
  agentdfir normalize <package-dir>     parse raw evidence into normalized events
  agentdfir timeline <package-dir>      print the unified, evidence-linked timeline
  agentdfir triage <package-dir>        normalize + run detections, print findings
  agentdfir simulate [flags]            generate a synthetic incident scenario
  agentdfir version                     print version

Collect flags:
  --product <id>       product to collect (default: claude)
  --out <dir>          output package directory (default: ./<case-id>.adfir)
  --case-id <id>       case identifier (default: generated)
  --operator <name>    asserted operator name for chain of custody
  --path <root>        offline profile root (mounted image / copied home)
  --authorization <r>  authorization reference (ticket / legal basis)
  --max-file-mb <n>    per-artifact size bound in MiB (default 512)

Detection never executes discovered binaries. Collection is always
lossless; nothing is redacted at acquisition time.
`

// Main dispatches and returns the process exit code.
func Main(args []string) int {
	if len(args) < 1 {
		fmt.Fprint(os.Stderr, usage)
		return 2
	}
	switch args[0] {
	case "detect":
		return cmdDetect()
	case "collect":
		return cmdCollect(args[1:])
	case "verify":
		return cmdVerify(args[1:])
	case "normalize":
		return cmdNormalize(args[1:])
	case "timeline":
		return cmdTimeline(args[1:])
	case "triage":
		return cmdTriage(args[1:])
	case "simulate":
		return cmdSimulate(args[1:])
	case "version", "--version", "-v":
		fmt.Printf("agentdfir %s (adfir format %s)\n", version.Version, version.ADFIRVersion)
		return 0
	case "help", "--help", "-h":
		fmt.Print(usage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n%s", sanitize.Terminal(args[0]), usage)
		return 2
	}
}

func cmdDetect() int {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	dets, err := products.DetectAll(home)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Println("Detected AI tooling")
	for _, d := range dets {
		status := "not detected"
		if d.Detected {
			status = "detected"
		}
		fmt.Printf("  %-16s %s\n", d.Product.Name, status)
		if d.Detected {
			for _, p := range d.ConfigPaths {
				fmt.Printf("    config:  %s\n", sanitize.Terminal(p))
			}
			if d.BinaryPath != "" {
				fmt.Printf("    binary:  %s\n", sanitize.Terminal(d.BinaryPath))
				fmt.Printf("    sha256:  %s\n", d.BinarySHA256)
				if d.InstallHint != "" {
					fmt.Printf("    install: %s\n", d.InstallHint)
				}
			}
		}
	}
	fmt.Println("\nNote: versions are not obtained by executing suspect binaries (by design).")
	return 0
}

func cmdCollect(args []string) int {
	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	product := fs.String("product", "claude", "product to collect (claude)")
	out := fs.String("out", "", "output package directory")
	caseID := fs.String("case-id", "", "case identifier")
	operator := fs.String("operator", "", "asserted operator name")
	offlineRoot := fs.String("path", "", "offline profile root")
	authz := fs.String("authorization", "", "authorization reference")
	maxFileMB := fs.Int64("max-file-mb", 0, "per-artifact size bound (MiB)")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	productID := *product
	switch productID {
	case "claude":
		productID = "claude-code"
	case "codex":
		productID = "codex-cli"
	}
	man, err := products.Manifest(productID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if man == nil {
		fmt.Fprintf(os.Stderr, "no collector implemented yet for product %q\n", sanitize.Terminal(productID))
		return 2
	}
	prodDef, err := products.ByID(productID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}

	// Resolve roots.
	var profileRoot, systemRoot string
	if *offlineRoot != "" {
		profileRoot = *offlineRoot
		systemRoot = *offlineRoot
	} else {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
		profileRoot = home
		systemRoot = "/"
	}
	configRoot := filepath.Join(profileRoot, prodDef.ConfigDirs[0])
	var envOverride string
	if *offlineRoot == "" && prodDef.ConfigEnv != "" {
		if v := os.Getenv(prodDef.ConfigEnv); v != "" {
			configRoot = v
			envOverride = v
		}
	}

	id := *caseID
	if id == "" {
		id = generateCaseID()
	}
	dest := *out
	if dest == "" {
		dest = id + ".adfir"
	}

	osUser := ""
	if u, err := user.Current(); err == nil {
		osUser = u.Username
	}
	info := casepkg.CaseInfo{
		OperatorOSUser:   osUser,
		OperatorAsserted: *operator,
		Authorization:    *authz,
		CollectionArgs:   args,
		Notes:            map[string]string{},
	}
	if *offlineRoot != "" {
		info.Notes["mode"] = "offline-path"
		info.Notes["offline_root"] = *offlineRoot
	} else {
		info.Notes["mode"] = "current-user"
		if envOverride != "" {
			info.Notes["config_dir_override"] = envOverride
		}
	}

	b, err := casepkg.New(dest, id, info)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	host, _ := os.Hostname()
	opts := collector.Options{
		ProfileRoot: profileRoot,
		ConfigRoot:  configRoot,
		SystemRoot:  systemRoot,
		Host:        host,
		User:        osUser,
		Product:     productID,
	}
	if *maxFileMB > 0 {
		opts.MaxFileBytes = *maxFileMB << 20
	}

	start := time.Now()
	_ = b.Log("collection_run_started", map[string]any{
		"product": productID, "profile_root": profileRoot, "config_root": configRoot,
	})
	st, runErr := collector.Run(b, man, opts)
	_ = b.Log("collection_run_finished", map[string]any{
		"acquired": st.Acquired, "symlinks": st.Symlinks, "skipped": st.Skipped,
		"failed": st.Failed, "bytes": st.TotalBytes,
		"duration_ms": time.Since(start).Milliseconds(),
	})
	if err := b.Seal(); err != nil {
		fmt.Fprintln(os.Stderr, "seal error:", err)
		return 1
	}
	if runErr != nil {
		fmt.Fprintln(os.Stderr, "collection error (package sealed with partial evidence):", runErr)
	}

	fmt.Printf("Case:      %s\n", id)
	fmt.Printf("Package:   %s\n", dest)
	fmt.Printf("Acquired:  %d artifacts (%d bytes)\n", st.Acquired, st.TotalBytes)
	fmt.Printf("Symlinks:  %d recorded (never followed)\n", st.Symlinks)
	fmt.Printf("Skipped:   %d   Failed: %d\n", st.Skipped, st.Failed)
	fmt.Println("Sealed:    SHA256SUMS written; run `agentdfir verify` to confirm integrity.")
	if runErr != nil {
		return 1
	}
	return 0
}

func cmdVerify(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: agentdfir verify <package-dir>")
		return 2
	}
	res, err := casepkg.Verify(args[0])
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Printf("Files checked:      %d\n", res.FilesChecked)
	fmt.Printf("Artifacts OK:       %d (not acquired: %d)\n", res.ArtifactsOK, res.ArtifactsFailed)
	fmt.Printf("Collection records: %d (hash chain)\n", res.CollectionRecs)
	fmt.Printf("Custody records:    %d (hash chain)\n", res.CustodyRecs)
	if len(res.Problems) == 0 {
		fmt.Println("Result:             VERIFIED — no modifications detected")
		return 0
	}
	fmt.Printf("Result:             FAILED — %d problem(s):\n", len(res.Problems))
	for _, p := range res.Problems {
		fmt.Printf("  - %s\n", sanitize.Terminal(p))
	}
	return 1
}

func generateCaseID() string {
	var b [4]byte
	_, _ = rand.Read(b[:])
	return "ADFIR-" + time.Now().UTC().Format("20060102-150405") + "-" + hex.EncodeToString(b[:])
}
