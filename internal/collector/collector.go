// Package collector implements manifest-driven forensic acquisition.
//
// Hardening rules (non-negotiable, see engineering standards):
//   - lstat before open; symlinks are never followed — recorded as metadata
//   - non-regular files (FIFOs, sockets, devices) are skipped and recorded
//   - per-artifact and total size bounds; over-bound files are recorded,
//     not silently dropped
//   - every failure is recorded in the manifest and collection log
//
// Acquisition is parallel but deterministic. Discovery runs serially in
// manifest order and decides everything that affects *what* is collected —
// classification, size bounds, policy exclusions, and whether an earlier
// round's evidence still describes a file. Workers only do the I/O-bound
// part (read, hash, compress, write). Results are committed in discovery
// order through a reorder buffer, so the manifest, the collection log and
// the set of collected artifacts are identical whatever order the workers
// happen to finish in. A forensic tool must not collect different evidence
// because a disk was busy.
package collector

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/products"
)

// Options controls one collection run.
type Options struct {
	ProfileRoot   string // user home or offline image home
	ConfigRoot    string // product config dir (e.g. ~/.claude); resolved by caller
	SystemRoot    string // "/" for live host, image mount for offline
	Host          string
	User          string
	Product       string
	MaxFileBytes  int64       // per-artifact bound; 0 = default
	MaxTotalBytes int64       // package bound; 0 = default
	Jobs          int         // acquisition workers; 0 = min(NumCPU, 8)
	Recollect     bool        // re-read every file even when an earlier round already preserved it
	FullContent   bool        // collect dependency/VCS subtrees too (--full-plugins)
	Progress      func(Stats) // optional; called after every acquired artifact (UI status lines)
}

// Defaults for size bounds.
const (
	DefaultMaxFileBytes  = 512 << 20 // 512 MiB
	DefaultMaxTotalBytes = 8 << 30   // 8 GiB
	maxJobs              = 8
)

// excludedDirs are subtrees excluded by default from bulk agent-support
// directories: vendored dependencies and VCS object stores. They are
// hundreds of megabytes of third-party content that the agent did not
// author and that no detection reads.
//
// Deliberately NOT the whole .git tree. Excluding it wholesale — as this
// first did — also removes .git/hooks and .git/config, which are exactly
// the artifacts a hook-installation detection needs to check, and a
// poisoned plugin marketplace repo can ship a hook. Only the object stores
// go, because that is where the megabytes are.
//
// Excluded, not ignored: each excluded subtree gets a SKIPPED_BY_POLICY
// manifest record naming it with its file count and byte total, so the
// exclusion is visible in the evidence and reversible with --full-plugins.
// Evidence that was never collected cannot be examined later, so the
// decision has to be recorded where an analyst will see it.
var excludedDirs = map[string]bool{"node_modules": true}

// excludedPaths are excluded by their position rather than their name:
// git object storage, wherever it sits.
func isExcludedPath(path string) bool {
	p := filepath.ToSlash(path)
	for _, suffix := range []string{"/.git/objects", "/.git/lfs", "/.git/modules"} {
		if strings.HasSuffix(p, suffix) || strings.Contains(p, suffix+"/") {
			return true
		}
	}
	return false
}

// Stats summarizes a collection run.
type Stats struct {
	Acquired   int
	Carried    int
	Symlinks   int
	Skipped    int
	Failed     int
	NotPresent int   // manifest paths checked that do not exist on this host
	TotalBytes int64 // plaintext bytes the package now accounts for
}

// candidate is one discovered file awaiting acquisition.
type candidate struct {
	idx  int
	path string
	rec  casepkg.ArtifactRecord
	info os.FileInfo
}

// result is one acquired candidate, keyed by discovery order.
type result struct {
	idx     int
	pending *casepkg.Pending
	err     error
}

// Run walks every manifest entry and ingests matches into the builder.
func Run(b *casepkg.Builder, man *products.CollectorManifest, opts Options) (*Stats, error) {
	if opts.MaxFileBytes == 0 {
		opts.MaxFileBytes = DefaultMaxFileBytes
	}
	if opts.MaxTotalBytes == 0 {
		opts.MaxTotalBytes = DefaultMaxTotalBytes
	}
	if opts.Jobs <= 0 {
		opts.Jobs = runtime.NumCPU()
		if opts.Jobs > maxJobs {
			opts.Jobs = maxJobs
		}
	}
	st := &Stats{}
	r := newRunner(b, opts, st)
	for _, entry := range man.Entries {
		for _, pattern := range entry.Paths {
			resolved := expand(pattern, opts)
			if resolved == "" {
				continue
			}
			if err := r.collectPattern(entry, resolved); err != nil {
				r.stop()
				return st, err
			}
		}
	}
	return st, r.stop()
}

// runner owns the worker pool and the serial commit stage.
type runner struct {
	b    *casepkg.Builder
	opts Options
	st   *Stats

	jobs    chan candidate
	results chan result
	wg      sync.WaitGroup
	done    chan struct{}

	next    int // next discovery index to commit
	issued  int
	planned int64 // bytes discovery has committed to acquiring
	err     error
	mu      sync.Mutex
	stopped bool
}

func newRunner(b *casepkg.Builder, opts Options, st *Stats) *runner {
	r := &runner{
		b: b, opts: opts, st: st,
		jobs:    make(chan candidate, opts.Jobs*4),
		results: make(chan result, opts.Jobs*4),
		done:    make(chan struct{}),
	}
	for i := 0; i < opts.Jobs; i++ {
		r.wg.Add(1)
		go r.worker()
	}
	go r.committer()
	return r
}

// worker performs the I/O-bound part of acquisition. It never touches the
// builder's manifest or logs.
func (r *runner) worker() {
	defer r.wg.Done()
	for c := range r.jobs {
		p, err := r.b.PrepareFile(c.path, c.rec)
		r.results <- result{idx: c.idx, pending: p, err: err}
	}
}

// committer appends results in discovery order, buffering any that arrive
// early. Ordering is what makes a parallel run reproduce a serial one.
func (r *runner) committer() {
	defer close(r.done)
	buf := map[int]result{}
	for res := range r.results {
		buf[res.idx] = res
		for {
			cur, ok := buf[r.next]
			if !ok {
				break
			}
			delete(buf, r.next)
			r.next++
			r.commit(cur)
		}
	}
	// Drain anything left after an error closed the pipeline early.
	for _, res := range buf {
		res.pending.Discard()
	}
}

// commit appends one result and is the only place Stats is written. Every
// counter lives in this single goroutine, so the numbers a run reports are
// not a function of how the workers interleaved.
func (r *runner) commit(res result) {
	if res.err != nil {
		r.fail(res.err)
		res.pending.Discard()
		return
	}
	rec := res.pending.Record()
	carried := res.pending.Carried()
	if err := r.b.CommitPending(res.pending); err != nil {
		r.fail(err)
		return
	}
	switch {
	case carried:
		r.st.Carried++
		r.st.TotalBytes += rec.Size
	case rec.Status == casepkg.StatusOK:
		r.st.Acquired++
		r.st.TotalBytes += rec.Size
	case rec.Status == casepkg.StatusSymlink:
		r.st.Symlinks++
	case rec.Status == casepkg.StatusNotPresent:
		r.st.NotPresent++
	case rec.Status == casepkg.StatusSkippedType,
		rec.Status == casepkg.StatusSkippedBound,
		rec.Status == casepkg.StatusSkippedPolicy:
		r.st.Skipped++
	default:
		r.st.Failed++
	}
	if r.opts.Progress != nil {
		r.opts.Progress(*r.st)
	}
}

func (r *runner) fail(err error) {
	r.mu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.mu.Unlock()
}

// stop closes the pipeline and waits for every result to be committed.
func (r *runner) stop() error {
	if r.stopped {
		return r.err
	}
	r.stopped = true
	close(r.jobs)
	r.wg.Wait()
	close(r.results)
	<-r.done
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.err
}

// submit queues a discovered file for acquisition.
func (r *runner) submit(rec casepkg.ArtifactRecord, path string, info os.FileInfo) {
	r.jobs <- candidate{idx: r.issued, path: path, rec: rec, info: info}
	r.issued++
}

// record appends a metadata-only record in discovery order, by routing it
// through the same ordered pipeline the acquired files use.
func (r *runner) record(rec casepkg.ArtifactRecord) {
	p := r.b.PrepareRecord(rec)
	r.results <- result{idx: r.issued, pending: p}
	r.issued++
}

func expand(pattern string, opts Options) string {
	rep := strings.NewReplacer(
		"${PROFILE_ROOT}", opts.ProfileRoot,
		"${CONFIG_ROOT}", opts.ConfigRoot,
		"${SYSTEM_ROOT}", strings.TrimSuffix(opts.SystemRoot, "/"),
	)
	out := rep.Replace(pattern)
	if strings.Contains(out, "${") {
		return "" // unresolved variable: entry not applicable to this run
	}
	return filepath.FromSlash(out)
}

func (r *runner) collectPattern(entry products.ManifestEntry, pattern string) error {
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
				if err := r.walkTree(entry, m); err != nil {
					return err
				}
			}
			return nil
		}
		return r.walkTree(entry, base)
	case strings.ContainsAny(pattern, "*?["):
		matches, err := filepath.Glob(pattern)
		if err != nil {
			return fmt.Errorf("glob %s: %w", pattern, err)
		}
		for _, m := range matches {
			r.ingestPath(entry, m)
		}
		return nil
	default:
		if _, err := os.Lstat(pattern); err != nil {
			if os.IsNotExist(err) {
				// "We looked here and it was not there" is a finding about
				// the host, and the only thing that distinguishes a product
				// that stores nothing from a collector aimed at the wrong
				// path. Recorded, not discarded.
				r.recordAbsent(entry, pattern)
				return nil
			}
			r.recordFailure(entry, pattern, err)
			return nil
		}
		r.ingestPath(entry, pattern)
		return nil
	}
}

func (r *runner) walkTree(entry products.ManifestEntry, base string) error {
	if _, err := os.Lstat(base); err != nil {
		if os.IsNotExist(err) {
			r.recordAbsent(entry, base)
			return nil
		}
		r.recordFailure(entry, base, err)
		return nil
	}
	// WalkDir uses lstat semantics: symlinked directories are not descended.
	return filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			r.recordFailure(entry, path, err)
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if !r.opts.FullContent && path != base && (excludedDirs[d.Name()] || isExcludedPath(path)) {
				r.recordExcludedTree(entry, path)
				return fs.SkipDir
			}
			return nil
		}
		r.ingestPath(entry, path)
		return nil
	})
}

// recordExcludedTree documents a subtree the policy did not collect,
// with enough detail that an analyst can see exactly what was left out.
func (r *runner) recordExcludedTree(entry products.ManifestEntry, dir string) {
	var files int
	var bytes int64
	_ = filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		files++
		if info, err := d.Info(); err == nil {
			bytes += info.Size()
		}
		return nil
	})
	rec := r.baseRecord(entry, dir)
	rec.Status = casepkg.StatusSkippedPolicy
	rec.Size = bytes
	rec.Error = fmt.Sprintf("subtree excluded by default policy (%s): %d file(s), %d bytes not collected; use --full-plugins to include it",
		filepath.Base(dir), files, bytes)
	r.record(rec)
}

func (r *runner) ingestPath(entry products.ManifestEntry, path string) {
	info, err := os.Lstat(path)
	if err != nil {
		r.recordFailure(entry, path, err)
		return
	}
	rec := r.baseRecord(entry, path)
	rec.Size = info.Size()
	rec.Mode = info.Mode().String()
	rec.ModTimeUTC = info.ModTime().UTC().Format("2006-01-02T15:04:05.999999999Z07:00")

	switch {
	case info.Mode()&os.ModeSymlink != 0:
		target, _ := os.Readlink(path)
		rec.Status = casepkg.StatusSymlink
		rec.SymlinkTarget = target
		r.record(rec)
		return
	case info.IsDir():
		return
	case !info.Mode().IsRegular():
		rec.Status = casepkg.StatusSkippedType
		r.record(rec)
		return
	case info.Size() > r.opts.MaxFileBytes:
		rec.Status = casepkg.StatusSkippedBound
		rec.Error = fmt.Sprintf("size %d exceeds per-artifact bound %d", info.Size(), r.opts.MaxFileBytes)
		r.record(rec)
		return
	case r.planned+info.Size() > r.opts.MaxTotalBytes:
		// The bound is enforced here, in serial discovery order, and never
		// by a worker: which files a bound excludes must not depend on
		// which goroutine happened to get there first.
		rec.Status = casepkg.StatusSkippedBound
		rec.Error = fmt.Sprintf("package bound %d would be exceeded", r.opts.MaxTotalBytes)
		r.record(rec)
		return
	}
	r.planned += info.Size()

	// An earlier round may already hold exactly these bytes. Judged on
	// size, inode and ctime — never mtime alone, which any writer can set.
	if !r.opts.Recollect {
		if prev, ok := r.b.Unchanged(path, info); ok {
			r.recordCarried(prev, rec)
			return
		}
	}
	r.submit(rec, path, info)
}

func (r *runner) recordCarried(prev casepkg.ArtifactRecord, rec casepkg.ArtifactRecord) {
	r.results <- result{idx: r.issued, pending: r.b.PrepareCarryForward(prev, rec)}
	r.issued++
}

// recordAbsent notes a manifest path that does not exist on this host.
func (r *runner) recordAbsent(entry products.ManifestEntry, path string) {
	rec := r.baseRecord(entry, path)
	rec.Status = casepkg.StatusNotPresent
	rec.Method = casepkg.MethodMetadataOnly
	r.record(rec)
}

func (r *runner) recordFailure(entry products.ManifestEntry, path string, cause error) {
	rec := r.baseRecord(entry, path)
	if os.IsPermission(cause) {
		rec.Status = casepkg.StatusAccessDenied
	} else {
		rec.Status = casepkg.StatusError
	}
	rec.Error = cause.Error()
	r.record(rec)
}

func (r *runner) baseRecord(entry products.ManifestEntry, path string) casepkg.ArtifactRecord {
	return casepkg.ArtifactRecord{
		SourcePath:    path,
		LogicalPath:   logicalPath(path, r.opts),
		Host:          r.opts.Host,
		User:          r.opts.User,
		Product:       r.opts.Product,
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
	if opts.Jobs <= 0 {
		opts.Jobs = runtime.NumCPU()
		if opts.Jobs > maxJobs {
			opts.Jobs = maxJobs
		}
	}
	st := &Stats{}
	r := newRunner(b, opts, st)
	entry := products.ManifestEntry{ID: "archive.sessions", Category: "agent_session", Sensitivity: "high"}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		low := strings.ToLower(path)
		if !strings.HasSuffix(low, ".json") && !strings.HasSuffix(low, ".jsonl") {
			return nil
		}
		r.ingestPath(entry, path)
		return nil
	})
	if err != nil {
		r.stop()
		return st, err
	}
	return st, r.stop()
}

// Survey walks the same patterns Run would, using only lstat, and reports
// how much there is to acquire.
//
// It exists so `run` can show a real percentage and a real time remaining
// instead of a spinner. A metadata-only pass over ~22,000 files costs one
// or two seconds against the minutes the acquisition itself takes, and an
// honest ETA is worth that. Nothing is read, hashed or opened.
//
// The numbers describe what Run *would* acquire under the same options:
// symlinks, irregular files, over-bound files and policy-excluded subtrees
// are counted as skipped, not as work.
type Survey struct {
	Files   int   // regular files that would be read
	Bytes   int64 // their total size
	Skipped int   // symlinks, irregular, bound-exceeded, policy-excluded
}

// SurveyRun measures a collection without performing it.
func SurveyRun(man *products.CollectorManifest, opts Options) Survey {
	if opts.MaxFileBytes == 0 {
		opts.MaxFileBytes = DefaultMaxFileBytes
	}
	if opts.MaxTotalBytes == 0 {
		opts.MaxTotalBytes = DefaultMaxTotalBytes
	}
	s := &surveyor{opts: opts}
	for _, entry := range man.Entries {
		for _, pattern := range entry.Paths {
			resolved := expand(pattern, opts)
			if resolved == "" {
				continue
			}
			s.walk(resolved)
		}
	}
	return s.out
}

type surveyor struct {
	opts Options
	out  Survey
}

func (s *surveyor) walk(pattern string) {
	switch {
	case strings.HasSuffix(pattern, string(filepath.Separator)+"**") || strings.HasSuffix(pattern, "/**"):
		base := strings.TrimSuffix(strings.TrimSuffix(pattern, "**"), string(filepath.Separator))
		base = strings.TrimSuffix(base, "/")
		if strings.ContainsAny(base, "*?[") {
			matches, _ := filepath.Glob(base)
			for _, m := range matches {
				s.tree(m)
			}
			return
		}
		s.tree(base)
	case strings.ContainsAny(pattern, "*?["):
		matches, _ := filepath.Glob(pattern)
		for _, m := range matches {
			s.file(m)
		}
	default:
		s.file(pattern)
	}
}

func (s *surveyor) tree(base string) {
	_ = filepath.WalkDir(base, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			if !s.opts.FullContent && path != base && (excludedDirs[d.Name()] || isExcludedPath(path)) {
				return fs.SkipDir
			}
			return nil
		}
		s.file(path)
		return nil
	})
}

func (s *surveyor) file(path string) {
	info, err := os.Lstat(path)
	if err != nil {
		return
	}
	switch {
	case info.Mode()&os.ModeSymlink != 0, info.IsDir(), !info.Mode().IsRegular(),
		info.Size() > s.opts.MaxFileBytes,
		s.out.Bytes+info.Size() > s.opts.MaxTotalBytes:
		if !info.IsDir() {
			s.out.Skipped++
		}
		return
	}
	s.out.Files++
	s.out.Bytes += info.Size()
}
