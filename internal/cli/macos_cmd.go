package cli

import (
	"fmt"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/collector"
	"github.com/efij/AgentDFIR/v5/internal/macoshost"
	"github.com/efij/AgentDFIR/v5/internal/products"
)

// macOS host state is opt-in evidence: collected only with
// --include-macos-host or `collect --product macos-host`. It is not agent
// data, so a default collection never takes it. TCC.db and login items
// are not secrets; keychains are only listed (lstat), never opened.

const macHostNote = "collected on request (--include-macos-host / --product macos-host): launchd plists, BTM store, login items, TCC.db; keychain files listed by metadata only, never opened"

// collectMacOSHost acquires the macos-host manifest and the keychain
// listing from the same roots as base into an open package. withManifest
// is false when the main run already was the macos-host manifest.
func collectMacOSHost(b *casepkg.Builder, base collector.Options, withManifest bool) (*collector.Stats, error) {
	st := &collector.Stats{}
	opts := base
	opts.Product = macoshost.Product
	opts.ConfigRoot = base.ProfileRoot
	start := time.Now()
	_ = b.Log("collection_run_started", map[string]any{"product": macoshost.Product, "profile_root": opts.ProfileRoot, "opt_in": true})
	var runErr error
	if withManifest {
		// Every platform's entries: the operator opted in by name, and a
		// macOS profile collected with --path from a Linux or Windows
		// workstation must not come back empty because the entries are
		// tagged darwin. On a non-macOS live host the paths are absent and
		// simply not found.
		man, err := products.ManifestAllPlatforms(macoshost.Product)
		if err != nil {
			return st, err
		}
		if man == nil {
			return st, fmt.Errorf("no macos-host collector")
		}
		st, runErr = collector.Run(b, man, opts)
	}
	if err := macoshost.CollectKeychainIndex(b, opts.ProfileRoot, opts.SystemRoot, opts.Host, opts.User); err != nil && runErr == nil {
		runErr = err
	}
	_ = b.Log("collection_run_finished", map[string]any{
		"product": macoshost.Product, "acquired": st.Acquired, "skipped": st.Skipped, "failed": st.Failed,
		"bytes": st.TotalBytes, "duration_ms": time.Since(start).Milliseconds(),
	})
	return st, runErr
}
