// Package collector implements manifest-driven forensic acquisition.
//
// Hardening rules (non-negotiable, see engineering standards):
//   - lstat before open; symlinks are never followed — recorded as metadata
//   - non-regular files (FIFOs, sockets, devices) are skipped and recorded
//   - per-artifact and total size bounds; over-bound files are recorded,
//     not silently dropped
//   - every failure is recorded in the manifest and collection log
package collector

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/products"
)

// Options controls one collection run.
type Options struct {
	ProfileRoot   string // user home or offline image home
	ConfigRoot    string // product config dir (e.g. ~/.claude); resolved by caller
	SystemRoot    string // "/" for live host, image mount for offline
	Host          string
	User          string
	Product       string
	MaxFileBytes  int64 // per-artifact bound; 0 = default
	MaxTotalBytes int64 // package bound; 0 = default
}

// Defaults for size bounds.
const (
	DefaultMaxFileBytes  = 512 << 20 // 512 MiB
	DefaultMaxTotalBytes = 8 << 30   // 8 GiB
)

// Stats summarizes a collection run.
type Stats struct {
	Acquired   int
	Symlinks   int
	Skipped    int
	Failed     int
	TotalBytes int64
}

// Run walks every manifest entry and ingests matches into the builder.
func Run(b *casepkg.Builder, man *products.CollectorManifest, opts Options) (*Stats, error) {
	if opts.MaxFileBytes == 0 {
		opts.MaxFileBytes = DefaultMaxFileBytes
	}
	if opts.MaxTotalBytes == 0 {
		opts.MaxTotalBytes = DefaultMaxTotalBytes
	}
	st := &Stats{}
	for _, entry := range man.Entries {
		for _, pattern := range entry.Paths {
			resolved := expand(pattern, opts)
			if resolved == "" {
				continue
			}
			if err := collectPattern(b, entry, resolved, opts, st); err != nil {
				return st, err
			}
		}
	}
	return st, nil
}

func expand(pattern string, opts Options) string {
	r := strings.NewReplacer(
		"${PROFILE_ROOT}", opts.ProfileRoot,
		"${CONFIG_ROOT}", opts.ConfigRoot,
		"${SYSTEM_ROOT}", strings.TrimSuffix(opts.SystemRoot, "/"),
	)
	out := r.Replace(pattern)
	if strings.Contains(out, "${") {
		return "" // unresolved variable: entry not applicable to this run
	}
	return filepath.FromSlash(out)
}

func collectPattern(b *casepkg.Builder, entry products.ManifestEntry, pattern string, opts Options, st *Stats) error {
	switch {
	case strings.HasSuffix(pattern, string(filepath.Separator)+"**") || strings.HasSuffix(pattern, "/**"):
		base := strings.TrimSuffix(strings.TrimSuffix(pattern, "**"), string(filepath.Separator))
		base = strings.TrimSuffix(base, "/")
		if strings.ContainsAny(base, "*?[") {
			// Glob directories mid-pattern (e.g. workspaceStorage/*/chatSessions/**).
			matches, err := filepath.Glob(base)
			if err != nil {
				return fmt.Errorf("glob %s: %w", base, err)
			}
			for _, m := range matches {
				if err := walkTree(b, entry, m, opts, st); err != nil {
					return err
				}
			}
			return nil
		}
		return walkTree(b, entry, base, opts, st)
	case strings.ContainsAny(pattern, "*?["):
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("glob %s: %w", pattern, err)
		}
		for _, m := range matches {
			if err := ingestPath(b, entry, m, opts, st); err != nil {
				return err
			}
		}
		return nil
	default:
		if _, err := os.Lstat(pattern); err != nil {
			if os.IsNotExist(err) {
				return nil // absent artifact: normal, not recorded as failure
			}
			return recordFailure(b, entry, pattern, err, opts, st)
		}
		return ingestPath(b, entry, pattern, opts, st)
	}
}

func walkTree(b *casepkg.Builder, entry products.ManifestEntry, base string, opts Options, st *Stats) error {
	if _, err := os.Lstat(base); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return recordFailure(b, entry, base, err, opts, st)
	}
	// WalkDir uses lstat semantics: symlinked directories are not descended.
	return filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			ferr := recordFailure(b, entry, path, err, opts, st)
			if ferr != nil {
				return ferr
			}
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			return nil
		}
		return ingestPath(b, entry, path, opts, st)
	})
}

func ingestPath(b *casepkg.Builder, entry products.ManifestEntry, path string, opts Options, st *Stats) error {
	info, err := os.Lstat(path)
	if err != nil {
		return recordFailure(b, entry, path, err, opts, st)
	}
	rec := baseRecord(entry, path, opts)
	rec.Size = info.Size()
	rec.Mode = info.Mode().String()
	rec.ModTimeUTC = info.ModTime().UTC().Format("2006-01-02T15:04:05.999999999Z07:00")

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, _ := os.Readlink(path)
		rec.Status = casepkg.StatusSymlink
		rec.SymlinkTarget = target
		st.Symlinks++
		return b.RecordNonFile(rec)
	case info.IsDir():
		return nil
	case !info.Mode().IsRegular():
		rec.Status = casepkg.StatusSkippedType
		st.Skipped++
		return b.RecordNonFile(rec)
	case info.Size() > opts.MaxFileBytes:
		rec.Status = casepkg.StatusSkippedBound
		rec.Error = fmt.Sprintf("size %d exceeds per-artifact bound %d", info.Size(), opts.MaxFileBytes)
		st.Skipped++
		return b.RecordNonFile(rec)
	case st.TotalBytes+info.Size() > opts.MaxTotalBytes:
		rec.Status = casepkg.StatusSkippedBound
		rec.Error = fmt.Sprintf("package bound %d would be exceeded", opts.MaxTotalBytes)
		st.Skipped++
		return b.RecordNonFile(rec)
	}

	if err := b.IngestFile(path, rec); err != nil {
		return err
	}
	// IngestFile records its own status; count from the source size.
	st.Acquired++
	st.TotalBytes += info.Size()
	return nil
}

func recordFailure(b *casepkg.Builder, entry products.ManifestEntry, path string, cause error, opts Options, st *Stats) error {
	rec := baseRecord(entry, path, opts)
	if os.IsPermission(cause) {
		rec.Status = casepkg.StatusAccessDenied
	} else {
		rec.Status = casepkg.StatusError
	}
	rec.Error = cause.Error()
	st.Failed++
	return b.RecordNonFile(rec)
}

func baseRecord(entry products.ManifestEntry, path string, opts Options) casepkg.ArtifactRecord {
	return casepkg.ArtifactRecord{
		SourcePath:    path,
		LogicalPath:   logicalPath(path, opts),
		Host:          opts.Host,
		User:          opts.User,
		Product:       opts.Product,
		CollectorRule: entry.ID,
		ArtifactType:  entry.Category,
		Sensitivity:   entry.Sensitivity,
	}
}

// logicalPath renders a stable, root-relative path for the manifest.
func logicalPath(path string, opts Options) string {
	for _, root := range []string{opts.ProfileRoot, strings.TrimSuffix(opts.SystemRoot, "/")} {
		if root != "" {
			if rel, err := filepath.Rel(root, path); err == nil && !strings.HasPrefix(rel, "..") {
				return filepath.ToSlash(rel)
			}
		}
	}
	return filepath.ToSlash(path)
}

// IngestLooseSessions preserves every *.json / *.jsonl file under root as
// an "archive.sessions" agent_session artifact. Used for archives (CI
// artifacts, support bundles, vendor exports) that carry agent transcripts
// without a recognizable user-profile layout.
func IngestLooseSessions(b *casepkg.Builder, root string, opts Options) (*Stats, error) {
	if opts.MaxFileBytes == 0 {
		opts.MaxFileBytes = DefaultMaxFileBytes
	}
	if opts.MaxTotalBytes == 0 {
		opts.MaxTotalBytes = DefaultMaxTotalBytes
	}
	st := &Stats{}
	entry := products.ManifestEntry{ID: "archive.sessions", Category: "agent_session", Sensitivity: "high"}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		low := strings.ToLower(path)
		if !strings.HasSuffix(low, ".json") && !strings.HasSuffix(low, ".jsonl") {
			return nil
		}
		return ingestPath(b, entry, path, opts, st)
	})
	return st, err
}
