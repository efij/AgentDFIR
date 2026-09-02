package cli

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/products"
	"github.com/efij/AgentDFIR/internal/sanitize"
	"github.com/efij/AgentDFIR/internal/seal"
)

// importOpts carries the collect flags that apply to tree import.
type importOpts struct {
	tree, out, caseID, operator, authz, signKey string
	maxFileMB                                   int64
	args                                        []string
	notes                                       map[string]string // extra case notes (docker/archive provenance)
	fallback                                    bool              // archive mode: ingest loose session files when no profile is found
}

// collectImport acquires from a KAPE / Velociraptor / CyLR / image tree:
// it discovers every user profile that holds a known AI agent product and
// collects ALL products for ALL users into one sealed package. Manifests
// are applied for every platform because the tree may come from an OS
// other than the analysis host.
func collectImport(o importOpts) int {
	root, err := filepath.Abs(o.tree)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	if fi, err := os.Stat(root); err != nil || !fi.IsDir() {
		fmt.Fprintf(os.Stderr, "--import: %s is not a directory\n", sanitize.Terminal(root))
		return 2
	}
	prods, err := products.All()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	profiles := collector.DiscoverProfiles(root, prods, 12)
	if len(profiles) == 0 && !o.fallback {
		fmt.Fprintln(os.Stderr, "no user profiles with known AI agent products found under", sanitize.Terminal(root))
		return 1
	}

	id := o.caseID
	if id == "" {
		id = generateCaseID()
	}
	dest := o.out
	if dest == "" {
		dest = id + ".adfir"
	}
	osUser := ""
	if u, err := user.Current(); err == nil {
		osUser = u.Username
	}
	info := casepkg.CaseInfo{
		OperatorOSUser: osUser, OperatorAsserted: o.operator, Authorization: o.authz,
		CollectionArgs: o.args,
		Notes: map[string]string{
			"mode":        "import-tree",
			"import_root": root,
			"profiles":    fmt.Sprint(len(profiles)),
		},
	}
	for k, v := range o.notes {
		info.Notes[k] = v
	}
	b, err := casepkg.New(dest, id, info)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	host, _ := os.Hostname()
	start := time.Now()
	total := collector.Stats{}
	var firstErr error

	fmt.Printf("Import tree: %s\n", root)
	for _, pr := range profiles {
		rel, _ := filepath.Rel(root, pr.Path)
		fmt.Printf("  profile %-40s products: %v\n", sanitize.Terminal(rel), pr.Products)
		for _, pid := range pr.Products {
			man, err := products.ManifestAllPlatforms(pid)
			if err != nil || man == nil {
				continue
			}
			prod, err := products.ByID(pid)
			if err != nil {
				continue
			}
			configRoot := pr.Path
			if len(prod.ConfigDirs) > 0 {
				configRoot = filepath.Join(pr.Path, filepath.FromSlash(prod.ConfigDirs[0]))
			}
			opts := collector.Options{
				ProfileRoot: pr.Path, ConfigRoot: configRoot, SystemRoot: root,
				Host: host, User: pr.User, Product: pid,
			}
			if o.maxFileMB > 0 {
				opts.MaxFileBytes = o.maxFileMB << 20
			}
			_ = b.Log("collection_run_started", map[string]any{
				"product": pid, "profile_root": pr.Path, "config_root": configRoot, "profile_user": pr.User,
			})
			st, runErr := collector.Run(b, man, opts)
			_ = b.Log("collection_run_finished", map[string]any{
				"product": pid, "acquired": st.Acquired, "symlinks": st.Symlinks, "skipped": st.Skipped,
				"failed": st.Failed, "bytes": st.TotalBytes,
			})
			total.Acquired += st.Acquired
			total.Symlinks += st.Symlinks
			total.Skipped += st.Skipped
			total.Failed += st.Failed
			total.TotalBytes += st.TotalBytes
			if runErr != nil && firstErr == nil {
				firstErr = runErr
			}
		}
	}
	if len(profiles) == 0 && o.fallback {
		// Archive without a recognizable profile layout (CI artifact, support
		// bundle, vendor export): every JSON/JSONL file is preserved as an
		// archive.sessions artifact so the tolerant parser still yields events.
		st, err := collector.IngestLooseSessions(b, root, collector.Options{ProfileRoot: root, ConfigRoot: root, SystemRoot: root, Host: host, Product: "ci-archive"})
		if err != nil && firstErr == nil {
			firstErr = err
		}
		total.Acquired += st.Acquired
		total.Skipped += st.Skipped
		total.Failed += st.Failed
		total.TotalBytes += st.TotalBytes
		fmt.Printf("  no profile layout found — preserved %d loose JSON/JSONL file(s) as archive.sessions\n", st.Acquired)
	}
	_ = b.Log("import_finished", map[string]any{"duration_ms": time.Since(start).Milliseconds()})
	if err := b.Seal(); err != nil {
		fmt.Fprintln(os.Stderr, "seal error:", err)
		return 1
	}
	if o.signKey != "" {
		if err := seal.Sign(dest, o.signKey); err != nil {
			fmt.Fprintln(os.Stderr, "sign error:", err)
			return 1
		}
	}
	fmt.Printf("Case:      %s\n", id)
	fmt.Printf("Package:   %s\n", dest)
	fmt.Printf("Profiles:  %d\n", len(profiles))
	fmt.Printf("Acquired:  %d artifacts (%d bytes)\n", total.Acquired, total.TotalBytes)
	fmt.Printf("Symlinks:  %d recorded (never followed)\n", total.Symlinks)
	fmt.Printf("Skipped:   %d   Failed: %d\n", total.Skipped, total.Failed)
	if o.signKey != "" {
		fmt.Println("Signed:    SEAL.sig written (ed25519).")
	}
	fmt.Println("Sealed:    SHA256SUMS written; run `agentdfir verify` to confirm integrity.")
	if firstErr != nil {
		fmt.Fprintln(os.Stderr, "collection error (package sealed with partial evidence):", firstErr)
		return 1
	}
	return 0
}
