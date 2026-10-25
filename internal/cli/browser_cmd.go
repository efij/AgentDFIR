package cli

import (
	"fmt"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/collector"
	"github.com/efij/AgentDFIR/v3/internal/products"
)

// Browser history is opt-in evidence: it is collected only with
// --include-browser (collect, run) or `collect --product browser`, never by
// detection or a default run. History is broad personal data; the parser
// turns only AI-service visits into events and the rest of each database
// stays sealed, unread.

// browserProductID is the opt-in browser-history product.
const browserProductID = "browser"

// browserNote is recorded in the case notes whenever history was collected,
// so the package says who asked for it and what it was for.
const browserNote = "collected on request (--include-browser / --product browser); only AI-service visits are parsed, every other row stays sealed unread"

// collectBrowser acquires the browser-history manifest from the same
// profile as base into an open package.
func collectBrowser(b *casepkg.Builder, base collector.Options, allPlatforms bool) (*collector.Stats, error) {
	var man *products.CollectorManifest
	var err error
	if allPlatforms {
		man, err = products.ManifestAllPlatforms(browserProductID)
	} else {
		man, err = products.Manifest(browserProductID)
	}
	if err != nil {
		return &collector.Stats{}, err
	}
	if man == nil {
		return &collector.Stats{}, fmt.Errorf("no browser-history collector")
	}
	opts := base
	opts.Product = browserProductID
	opts.ConfigRoot = base.ProfileRoot
	start := time.Now()
	_ = b.Log("collection_run_started", map[string]any{"product": browserProductID, "profile_root": opts.ProfileRoot, "opt_in": true})
	st, runErr := collector.Run(b, man, opts)
	_ = b.Log("collection_run_finished", map[string]any{
		"product": browserProductID, "acquired": st.Acquired, "carried_forward": st.Carried,
		"symlinks": st.Symlinks, "skipped": st.Skipped, "failed": st.Failed, "bytes": st.TotalBytes,
		"duration_ms": time.Since(start).Milliseconds(),
	})
	return st, runErr
}

// addStats folds one collection's counters into another.
func addStats(dst, src *collector.Stats) {
	if dst == nil || src == nil {
		return
	}
	dst.Acquired += src.Acquired
	dst.Carried += src.Carried
	dst.Symlinks += src.Symlinks
	dst.Skipped += src.Skipped
	dst.Failed += src.Failed
	dst.NotPresent += src.NotPresent
	dst.TotalBytes += src.TotalBytes
	dst.ReadBytes += src.ReadBytes
	dst.Processed += src.Processed
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
