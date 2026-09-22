// Package casepkg implements the sealed zone of the .adfir evidence
// package: content-addressed artifact storage, manifest, hash-chained
// collection and custody logs, and SHA256SUMS sealing/verification.
//
// Layout (sealed zone):
//
//	<pkg>/
//	├── raw/<sha256>[.gz]       content-addressed evidence bytes
//	├── manifest.jsonl          append-only artifact metadata (header + one record per line)
//	├── collection.jsonl        hash-chained collection log
//	├── chain-of-custody.jsonl  hash-chained custody log
//	├── case.json               case + operator + environment metadata, per-round summaries
//	├── seals/SHA256SUMS.<n>    the seal each earlier round was closed with
//	├── SHA256SUMS              covers the sealed zone exactly, as of the latest round
//	└── .lock                   held for a collect→seal cycle (not sealed, not evidence)
//
// The analysis overlay (normalized/, detections/, reports/, index/) is
// written by later phases and is excluded from SHA256SUMS by design.
//
// A package grows in rounds. A second collection against the same package
// appends: records carry their round, both hash chains continue unbroken
// from their previous last line, and the seal that closed the previous
// round is archived rather than discarded. Nothing already written is ever
// rewritten or removed.
//
// Packages written by earlier versions (manifest.json as a JSON array,
// uncompressed blobs at raw/<sha256>) stay readable and verifiable.
package casepkg

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v2/internal/hashchain"
	"github.com/efij/AgentDFIR/v2/internal/version"
)

// Artifact acquisition status values.
const (
	StatusOK            = "OK"
	StatusAccessDenied  = "ACCESS_DENIED"
	StatusSkippedBound  = "SKIPPED_BOUND_EXCEEDED"
	StatusSkippedType   = "SKIPPED_IRREGULAR_TYPE"
	StatusSkippedPolicy = "SKIPPED_BY_POLICY"
	// StatusNotPresent records a manifest path that was checked and did not
	// exist. Absence is evidence: it separates "this product stores nothing
	// here" from "the collector looked in the wrong place", and it is the
	// only way a detected-but-empty product can explain itself.
	StatusNotPresent = "NOT_PRESENT"
	StatusSymlink    = "SYMLINK_NOT_FOLLOWED"
	StatusError      = "ERROR"
)

// Collection methods recorded on a manifest record.
const (
	MethodFileCopy     = "file_copy"
	MethodMetadataOnly = "metadata_only"
	// MethodCarriedForward marks evidence that a later round did NOT
	// re-read: the source file was unchanged by size, ctime and inode.
	// It is a claim about evidence, so it is recorded as one and is never
	// rendered as freshly acquired.
	MethodCarriedForward = "carried_forward"
	// MethodAppended marks a file that grew by appending: the unchanged
	// prefix was proven to hash to the previously stored bytes and only
	// the new tail was stored.
	MethodAppended = "file_copy_appended"
)

// File names inside a package.
const (
	manifestJSONL = "manifest.jsonl"
	manifestJSON  = "manifest.json" // legacy array form; still read
	sumsFile      = "SHA256SUMS"
	sealsDir      = "seals"
	lockFile      = ".lock"
)

// Chunk is one stored unit of a chunked artifact. A file that grows by
// appending is stored as its original blob plus one tail blob per round;
// concatenating chunks in order reproduces the artifact's plaintext, whose
// SHA-256 is the artifact_id.
type Chunk struct {
	ID         string `json:"id"`   // sha256 of this chunk's plaintext
	Size       int64  `json:"size"` // plaintext size
	Codec      string `json:"codec,omitempty"`
	StoredSHA  string `json:"stored_sha256,omitempty"`
	StoredSize int64  `json:"stored_size,omitempty"`
	Round      int    `json:"round,omitempty"`
}

// ArtifactRecord is one manifest entry. Multiple records may reference
// the same content-addressed blob (dedupe by SHA-256).
type ArtifactRecord struct {
	ArtifactID     string `json:"artifact_id"` // sha256 hex of PLAINTEXT content; empty when no content acquired
	SourcePath     string `json:"source_path"`
	LogicalPath    string `json:"logical_path"`
	Host           string `json:"host"`
	User           string `json:"user"`
	Product        string `json:"product"`
	CollectorRule  string `json:"collector_rule"` // collector manifest entry id, e.g. claude.sessions
	ArtifactType   string `json:"artifact_type"`
	Sensitivity    string `json:"sensitivity"`
	Size           int64  `json:"size"` // plaintext size
	Mode           string `json:"mode"`
	ModTimeUTC     string `json:"mtime_utc"`
	CollectedUTC   string `json:"collection_timestamp_utc"`
	Method         string `json:"collection_method"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	SymlinkTarget  string `json:"symlink_target,omitempty"`
	FileWasGrowing bool   `json:"file_was_growing,omitempty"`

	// Storage representation. Absent on packages written before compression.
	Codec      string  `json:"codec,omitempty"`         // "", "none" or "gzip"
	StoredSHA  string  `json:"stored_sha256,omitempty"` // sha256 of the bytes on disk
	StoredSize int64   `json:"stored_size,omitempty"`   // bytes on disk
	Chunks     []Chunk `json:"chunks,omitempty"`        // set when the artifact is stored in parts

	// Incremental collection.
	Round      int    `json:"round,omitempty"`             // round that produced this record
	AcquiredIn int    `json:"acquired_in_round,omitempty"` // round whose bytes this record's content came from
	CTimeUTC   string `json:"ctime_utc,omitempty"`         // inode change time; not settable by an unprivileged writer
	Inode      uint64 `json:"inode,omitempty"`             // inode (unix) / file index (windows)
	TimeSkew   bool   `json:"mtime_before_ctime,omitempty"`
}

// Manifest is the manifest header plus, when read, every artifact record.
type Manifest struct {
	ADFIRVersion     string           `json:"adfir_version"`
	CaseID           string           `json:"case_id"`
	CreatedUTC       string           `json:"created_utc"`
	CollectorName    string           `json:"collector_name"`
	CollectorVersion string           `json:"collector_version"`
	CollectorBinary  string           `json:"collector_binary_sha256,omitempty"`
	Host             string           `json:"host"`
	OS               string           `json:"os"`
	Arch             string           `json:"arch"`
	Artifacts        []ArtifactRecord `json:"artifacts,omitempty"`

	// retired: source path → last round whose record the current policy
	// excludes from the scan set. In-memory only; see retire.go.
	retired map[string]int
}

// Round summarizes one collection round against a package.
type Round struct {
	Round            int      `json:"round"`
	StartedUTC       string   `json:"started_utc"`
	CompletedUTC     string   `json:"completed_utc,omitempty"`
	CollectorVersion string   `json:"collector_version"`
	CollectionArgs   []string `json:"collection_args,omitempty"`
	ArtifactsOK      int      `json:"artifacts_ok"`
	ArtifactsCarried int      `json:"artifacts_carried_forward"`
	ArtifactsFailed  int      `json:"artifacts_not_acquired"`
	StoredBytes      int64    `json:"stored_bytes"`
}

// CaseInfo is case.json.
type CaseInfo struct {
	CaseID           string            `json:"case_id"`
	CreatedUTC       string            `json:"created_utc"`
	OperatorOSUser   string            `json:"operator_os_user"`
	OperatorAsserted string            `json:"operator_asserted,omitempty"`
	Authorization    string            `json:"authorization_reference,omitempty"`
	Host             string            `json:"host"`
	OS               string            `json:"os"`
	LocalTime        string            `json:"local_time"`
	Timezone         string            `json:"timezone"`
	UTCOffsetSeconds int               `json:"utc_offset_seconds"`
	CollectionArgs   []string          `json:"collection_args,omitempty"`
	Notes            map[string]string `json:"notes,omitempty"`
	Rounds           []Round           `json:"rounds,omitempty"`
}

// Sharer optionally backs blob writes with a store shared between cases,
// so identical evidence occupies disk once per machine. Implemented by
// internal/store; nil means every package keeps its own bytes.
type Sharer interface {
	// Link places the already-written stored bytes at dst, reusing the
	// shared copy when one exists. It must verify the shared copy against
	// storedSHA before reusing it — a file name is never a content
	// assertion. Returns true when the shared copy was used.
	Link(storedSHA, dst string) (reused bool, err error)
	// Adopt offers a freshly written blob to the shared store.
	Adopt(storedSHA, src string) error
}

// Builder accumulates evidence into a package directory and seals it.
type Builder struct {
	Dir      string
	Shared   Sharer // optional cross-case blob sharing
	NoCodec  bool   // store plaintext (used by tests and --no-compress)
	manifest Manifest
	caseInfo CaseInfo
	coll     *hashchain.Writer // collection.jsonl
	custody  *hashchain.Writer // chain-of-custody.jsonl
	mf       *os.File          // manifest.jsonl, append mode
	lock     *lockHandle
	sealed   bool

	round   int
	started time.Time
	// sums maps a stored blob's file name to the SHA-256 of its bytes on
	// disk, computed once while writing. Sealing reuses these instead of
	// re-reading every blob.
	sums map[string]string
	// prev indexes the newest record per source path from earlier rounds,
	// for unchanged-file carry-forward and append detection.
	prev map[string]ArtifactRecord

	stats RoundStats
}

// RoundStats counts what one round did.
type RoundStats struct {
	OK          int
	Carried     int
	Failed      int
	StoredBytes int64
}

// New creates the package directory (must not already exist) and opens
// the hash-chained logs. This is round 1.
func New(dir, caseID string, info CaseInfo) (*Builder, error) {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create package dir: %w", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "raw"), 0o700); err != nil {
		return nil, err
	}
	host, _ := os.Hostname()
	now := time.Now()
	zone, offset := now.Zone()

	info.CaseID = caseID
	info.CreatedUTC = now.UTC().Format(time.RFC3339)
	info.Host = host
	info.OS = runtime.GOOS
	info.LocalTime = now.Format(time.RFC3339)
	info.Timezone = zone
	info.UTCOffsetSeconds = offset

	b := &Builder{
		Dir: dir,
		manifest: Manifest{
			ADFIRVersion:     version.ADFIRVersion,
			CaseID:           caseID,
			CreatedUTC:       info.CreatedUTC,
			CollectorName:    "agentdfir",
			CollectorVersion: version.Version,
			CollectorBinary:  selfHash(),
			Host:             host,
			OS:               runtime.GOOS,
			Arch:             runtime.GOARCH,
		},
		caseInfo: info,
		round:    1,
		started:  now,
		sums:     map[string]string{},
		prev:     map[string]ArtifactRecord{},
	}
	lk, err := acquireLock(dir)
	if err != nil {
		return nil, err
	}
	b.lock = lk
	// Every failure from here on goes through Close: it drops the lock and
	// closes whatever was already opened. Returning without it would leave
	// handles behind, which on Windows makes the package undeletable.
	fail := func(err error) (*Builder, error) {
		b.Close()
		return nil, err
	}
	if b.coll, err = hashchain.NewWriter(filepath.Join(dir, "collection.jsonl")); err != nil {
		return fail(err)
	}
	if b.custody, err = hashchain.NewWriter(filepath.Join(dir, "chain-of-custody.jsonl")); err != nil {
		return fail(err)
	}
	// The manifest header is written once, at creation.
	if b.mf, err = os.OpenFile(filepath.Join(dir, manifestJSONL), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600); err != nil {
		return fail(err)
	}
	header := b.manifest
	header.Artifacts = nil
	if err := b.writeManifestLine(header); err != nil {
		return fail(err)
	}
	if err := b.startRound(); err != nil {
		return fail(err)
	}
	return b, nil
}

// Reopen opens an already-sealed package for an additional collection
// round. Both hash chains are verified end to end before anything is
// appended: resuming a broken chain would hide the break behind a
// valid-looking tail.
func Reopen(dir string, info CaseInfo) (*Builder, error) {
	man, err := ReadManifest(dir)
	if err != nil {
		return nil, fmt.Errorf("reopen %s: %w", dir, err)
	}
	prevCase, err := ReadCaseInfo(dir)
	if err != nil {
		return nil, fmt.Errorf("reopen %s: %w", dir, err)
	}
	lk, err := acquireLock(dir)
	if err != nil {
		return nil, err
	}

	// Carry the operator's new assertions into the existing case record;
	// identity, creation time and host stay as first recorded.
	merged := *prevCase
	if info.OperatorAsserted != "" {
		merged.OperatorAsserted = info.OperatorAsserted
	}
	if info.Authorization != "" {
		merged.Authorization = info.Authorization
	}
	if len(info.CollectionArgs) > 0 {
		merged.CollectionArgs = info.CollectionArgs
	}
	for k, v := range info.Notes {
		if merged.Notes == nil {
			merged.Notes = map[string]string{}
		}
		merged.Notes[k] = v
	}

	round := 1
	for _, r := range merged.Rounds {
		if r.Round >= round {
			round = r.Round + 1
		}
	}
	if len(merged.Rounds) == 0 {
		// A package sealed before rounds existed is round 1 by definition.
		merged.Rounds = []Round{{
			Round: 1, StartedUTC: merged.CreatedUTC, CompletedUTC: merged.CreatedUTC,
			CollectorVersion: man.CollectorVersion, ArtifactsOK: countOK(man),
		}}
		round = 2
	}

	b := &Builder{
		Dir:      dir,
		manifest: *man,
		caseInfo: merged,
		round:    round,
		started:  time.Now(),
		sums:     map[string]string{},
		prev:     map[string]ArtifactRecord{},
		lock:     lk,
	}
	// As in New: any failure past this point releases the lock and closes
	// whatever is already open.
	fail := func(err error) (*Builder, error) {
		b.Close()
		return nil, err
	}
	b.manifest.CollectorVersion = version.Version
	b.manifest.CollectorBinary = selfHash()

	// Earlier rounds' blob hashes come from the seal they were closed
	// with, so sealing this round does not re-read them.
	if sums, err := readSums(filepath.Join(dir, sumsFile)); err == nil {
		for rel, h := range sums {
			if name, ok := strings.CutPrefix(rel, "raw/"); ok {
				b.sums[name] = h
			}
		}
	}
	for _, a := range man.Artifacts {
		if a.SourcePath != "" && a.Status == StatusOK {
			b.prev[a.SourcePath] = a
		}
	}

	if b.coll, err = hashchain.NewAppender(filepath.Join(dir, "collection.jsonl")); err != nil {
		return fail(fmt.Errorf("collection log: %w", err))
	}
	if b.custody, err = hashchain.NewAppender(filepath.Join(dir, "chain-of-custody.jsonl")); err != nil {
		return fail(fmt.Errorf("custody log: %w", err))
	}
	if b.mf, err = openManifestForAppend(dir, man); err != nil {
		return fail(err)
	}
	if err := b.startRound(); err != nil {
		return fail(err)
	}
	return b, nil
}

// openManifestForAppend returns an append handle on manifest.jsonl,
// migrating a legacy manifest.json array into the line form first. The
// legacy file is left in place: it was covered by the previous seal, which
// is archived, and removing sealed evidence is not this tool's business.
func openManifestForAppend(dir string, man *Manifest) (*os.File, error) {
	path := filepath.Join(dir, manifestJSONL)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
		if err != nil {
			return nil, err
		}
		header := *man
		header.Artifacts = nil
		if err := writeLine(f, header); err != nil {
			f.Close()
			return nil, err
		}
		for _, a := range man.Artifacts {
			if err := writeLine(f, a); err != nil {
				f.Close()
				return nil, err
			}
		}
		return f, nil
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
}

func countOK(m *Manifest) int {
	n := 0
	for _, a := range m.Artifacts {
		if a.Status == StatusOK {
			n++
		}
	}
	return n
}

// Round returns the round this builder is writing.
func (b *Builder) Round() int { return b.round }

// startRound records the opening custody event for this round.
func (b *Builder) startRound() error {
	return b.custody.Append(map[string]any{
		"event": "acquisition_started", "case_id": b.manifest.CaseID, "round": b.round,
		"operator_os_user": b.caseInfo.OperatorOSUser, "operator_asserted": b.caseInfo.OperatorAsserted,
		"authorization_reference": b.caseInfo.Authorization,
		"host":                    b.manifest.Host, "collector_version": version.Version,
		"collector_binary_sha256": b.manifest.CollectorBinary,
	})
}

// selfHash hashes the running collector binary (best effort).
func selfHash() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	h, _, err := hashFile(exe)
	if err != nil {
		return ""
	}
	return h
}

// Unchanged reports whether a source file is byte-identical to what an
// earlier round already stored, judged on size, inode and ctime — never on
// mtime alone, which an unprivileged writer can set at will. When it is,
// the caller can carry the record forward without reading the file.
func (b *Builder) Unchanged(srcPath string, info os.FileInfo) (ArtifactRecord, bool) {
	prev, ok := b.prev[srcPath]
	if !ok || prev.Status != StatusOK || prev.ArtifactID == "" {
		return ArtifactRecord{}, false
	}
	if prev.Size != info.Size() {
		return ArtifactRecord{}, false
	}
	sig, ok := statSignature(info)
	if !ok || prev.Inode == 0 || prev.CTimeUTC == "" {
		return ArtifactRecord{}, false // no trustworthy identity: re-read
	}
	if sig.inode != prev.Inode || sig.ctime.UTC().Format(time.RFC3339Nano) != prev.CTimeUTC {
		return ArtifactRecord{}, false
	}
	// The stored bytes must still be present and the right length.
	for _, name := range storedUnits(prev) {
		st, err := os.Stat(filepath.Join(b.Dir, "raw", name))
		if err != nil {
			return ArtifactRecord{}, false
		}
		if want := b.storedSizeOf(prev, name); want > 0 && st.Size() != want {
			return ArtifactRecord{}, false
		}
	}
	return prev, true
}

func (b *Builder) storedSizeOf(rec ArtifactRecord, name string) int64 {
	if len(rec.Chunks) == 0 {
		if blobName(rec.ArtifactID, rec.Codec) == name {
			return rec.StoredSize
		}
		return 0
	}
	for _, c := range rec.Chunks {
		if blobName(c.ID, c.Codec) == name {
			return c.StoredSize
		}
	}
	return 0
}

// PrepareRecord wraps a metadata-only record (symlink, skipped type,
// bound or policy exclusion, access denied) so it can flow through the
// same ordered commit path acquired files use.
func (b *Builder) PrepareRecord(rec ArtifactRecord) *Pending {
	if rec.CollectedUTC == "" {
		rec.CollectedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if rec.Method == "" {
		rec.Method = MethodMetadataOnly
	}
	if rec.Round == 0 {
		rec.Round = b.round
	}
	return &Pending{rec: rec}
}

// PrepareCarryForward builds the record for evidence an earlier round
// already preserved, for commit in discovery order.
func (b *Builder) PrepareCarryForward(prev ArtifactRecord, rec ArtifactRecord) *Pending {
	return &Pending{rec: b.carryRecord(prev, rec), carried: true}
}

// CarryForward records that an earlier round's evidence still describes
// the current file, without re-reading it. The record is explicitly marked
// so no consumer can mistake it for a fresh acquisition.
func (b *Builder) CarryForward(prev ArtifactRecord, rec ArtifactRecord) error {
	b.stats.Carried++
	return b.record(b.carryRecord(prev, rec))
}

func (b *Builder) carryRecord(prev ArtifactRecord, rec ArtifactRecord) ArtifactRecord {
	rec.ArtifactID = prev.ArtifactID
	rec.Size = prev.Size
	rec.Codec = prev.Codec
	rec.StoredSHA = prev.StoredSHA
	rec.StoredSize = prev.StoredSize
	rec.Chunks = prev.Chunks
	rec.Status = StatusOK
	rec.Method = MethodCarriedForward
	rec.CollectedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	rec.Round = b.round
	rec.AcquiredIn = prev.AcquiredIn
	if rec.AcquiredIn == 0 {
		rec.AcquiredIn = prev.Round
	}
	if rec.AcquiredIn == 0 {
		rec.AcquiredIn = 1
	}
	return rec
}

// Pending is a file that has been read, hashed and written to a temporary
// blob, but not yet committed to the package. Producing one touches no
// builder state, so collection can run many in parallel; committing one
// appends to the manifest and hash chain and must stay serial.
type Pending struct {
	rec      ArtifactRecord
	blob     *blobResult
	commitID string // content address the blob is stored under
	carried  bool   // evidence an earlier round preserved; nothing to store
}

// Record returns the manifest record this pending ingest will write.
func (p *Pending) Record() ArtifactRecord { return p.rec }

// Carried reports whether this record carries forward evidence an earlier
// round preserved, rather than newly acquired bytes.
func (p *Pending) Carried() bool { return p != nil && p.carried }

// Discard releases a prepared blob that will not be committed.
func (p *Pending) Discard() {
	if p != nil && p.blob != nil {
		os.Remove(p.blob.tmp)
	}
}

// IngestFile prepares and commits one file in the calling goroutine.
func (b *Builder) IngestFile(srcPath string, rec ArtifactRecord) error {
	p, err := b.PrepareFile(srcPath, rec)
	if err != nil {
		return err
	}
	return b.CommitPending(p)
}

// PrepareFile copies a regular file into a temporary blob (hash-while-copy,
// torn-read detection, symlink-race check) and returns the record it will
// produce. It is safe to call concurrently: it reads the builder's
// previous-round index, which is fixed for the life of a round, and
// otherwise touches only its own files. rec must have its descriptive
// fields set; content fields are filled in here.
func (b *Builder) PrepareFile(srcPath string, rec ArtifactRecord) (*Pending, error) {
	rec.CollectedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	rec.Method = MethodFileCopy
	rec.Round = b.round
	rec.AcquiredIn = b.round

	before, err := os.Lstat(srcPath)
	if err != nil {
		rec.Status = statusForErr(err)
		rec.Error = err.Error()
		return &Pending{rec: rec}, nil
	}
	rec.Size = before.Size()
	rec.Mode = before.Mode().String()
	rec.ModTimeUTC = before.ModTime().UTC().Format(time.RFC3339Nano)

	// Open without following symlinks and confirm the descriptor is the
	// same object Lstat classified. Evidence lives in directories the agent
	// (and anything that compromised it) can write, so the window between
	// classifying a path and opening it is attacker-reachable.
	f, err := openNoFollow(srcPath)
	if err != nil {
		rec.Status = statusForErr(err)
		rec.Error = err.Error()
		return &Pending{rec: rec}, nil
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		rec.Status = StatusError
		rec.Error = err.Error()
		return &Pending{rec: rec}, nil
	}
	if !sameFile(before, opened) {
		rec.Status = StatusError
		rec.Error = "source changed identity between lstat and open (symlink race): not ingested"
		return &Pending{rec: rec}, nil
	}
	if sig, ok := statSignature(opened); ok && !sig.ctime.IsZero() {
		rec.Inode = sig.inode
		rec.CTimeUTC = sig.ctime.UTC().Format(time.RFC3339Nano)
		// mtime later than ctime cannot happen through ordinary writes; it
		// means someone set the modification time explicitly. Recorded, not
		// judged.
		rec.TimeSkew = before.ModTime().After(sig.ctime.Add(time.Second))
	}

	// A file that only grew since an earlier round is stored as its proven
	// prefix plus the new tail. The prefix check costs nothing: the whole
	// file must be hashed anyway to compute the artifact_id.
	if prev, ok := b.prev[srcPath]; ok && prev.Status == StatusOK && prev.Size > 0 && prev.Size < before.Size() {
		p, err := b.prepareAppended(f, prev, rec, before)
		if err != nil {
			return nil, err
		}
		if p != nil {
			return p, nil
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			rec.Status = StatusError
			rec.Error = err.Error()
			return &Pending{rec: rec}, nil
		}
	}

	// Copy at most the size observed before opening: a live agent may be
	// appending; the hash must describe exactly the bytes preserved.
	res, err := b.writeBlob(io.LimitReader(f, before.Size()), before.Size())
	if err != nil {
		rec.Status = StatusError
		rec.Error = err.Error()
		return &Pending{rec: rec}, nil
	}
	rec.Size = res.plainSize
	rec.ArtifactID = res.plainSHA
	rec.Codec = res.codec
	rec.StoredSHA = res.storedSHA
	rec.StoredSize = res.storedSize

	if after, err := os.Lstat(srcPath); err == nil {
		if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			rec.FileWasGrowing = true
		}
	}
	rec.Status = StatusOK
	return &Pending{rec: rec, blob: res, commitID: rec.ArtifactID}, nil
}

// CommitPending places a prepared blob in the package and appends its
// manifest and collection-log records. It must be called from a single
// goroutine: both the manifest and the hash chain are strictly ordered.
func (b *Builder) CommitPending(p *Pending) error {
	if p == nil {
		return nil
	}
	if p.blob != nil {
		if err := b.commitBlob(p.blob, p.commitID); err != nil {
			return err
		}
	}
	switch {
	case p.carried:
		b.stats.Carried++
	case p.rec.Status == StatusOK:
		b.stats.OK++
	case p.rec.Status == StatusNotPresent, p.rec.Status == StatusSkippedPolicy,
		p.rec.Status == StatusSkippedBound, p.rec.Status == StatusSkippedType,
		p.rec.Status == StatusSymlink:
		// Recorded outcomes, not acquisition failures.
	default:
		b.stats.Failed++
	}
	return b.record(p.rec)
}

// prepareAppended stores only the tail of a file whose prefix is proven
// identical to what an earlier round preserved. It returns nil when the
// prefix does not match, in which case the caller stores the file whole.
//
// The prefix check is free: a changed file must be read in full anyway to
// compute its artifact_id, and this is that same read.
func (b *Builder) prepareAppended(f *os.File, prev ArtifactRecord, rec ArtifactRecord, info os.FileInfo) (*Pending, error) {
	h := sha256.New()
	if _, err := io.CopyN(h, f, prev.Size); err != nil {
		return nil, nil // short read: fall back to a whole-file copy
	}
	marshaler, ok := h.(interface {
		MarshalBinary() ([]byte, error)
	})
	if !ok {
		return nil, nil
	}
	state, err := marshaler.MarshalBinary()
	if err != nil {
		return nil, nil
	}
	if hex.EncodeToString(h.Sum(nil)) != prev.ArtifactID {
		return nil, nil // not an append: content before the old EOF changed
	}

	tailLen := info.Size() - prev.Size
	res, err := b.writeBlob(io.LimitReader(f, tailLen), tailLen)
	if err != nil {
		return nil, err
	}
	// Continue the full-file hash from the prefix state over the tail we
	// just stored, so artifact_id still addresses the whole plaintext.
	full := sha256.New()
	if u, ok := full.(interface{ UnmarshalBinary([]byte) error }); ok {
		if err := u.UnmarshalBinary(state); err != nil {
			os.Remove(res.tmp)
			return nil, nil
		}
	} else {
		os.Remove(res.tmp)
		return nil, nil
	}
	tf, err := os.Open(res.tmp)
	if err != nil {
		os.Remove(res.tmp)
		return nil, err
	}
	if res.codec == CodecGzip {
		rc, err := gzipReader(tf, tailLen)
		if err != nil {
			tf.Close()
			os.Remove(res.tmp)
			return nil, err
		}
		_, err = io.Copy(full, rc)
		rc.Close()
		if err != nil {
			tf.Close()
			os.Remove(res.tmp)
			return nil, err
		}
	} else if _, err := io.Copy(full, tf); err != nil {
		tf.Close()
		os.Remove(res.tmp)
		return nil, err
	}
	tf.Close()

	rec.ArtifactID = hex.EncodeToString(full.Sum(nil))
	rec.Size = info.Size()
	rec.Method = MethodAppended
	rec.Codec = ""
	rec.StoredSHA = ""
	rec.StoredSize = 0
	rec.Chunks = append(chunksOf(prev), Chunk{
		ID: res.plainSHA, Size: res.plainSize, Codec: res.codec,
		StoredSHA: res.storedSHA, StoredSize: res.storedSize, Round: b.round,
	})
	rec.Status = StatusOK
	return &Pending{rec: rec, blob: res, commitID: res.plainSHA}, nil
}

// chunksOf renders an earlier record as a chunk list.
func chunksOf(rec ArtifactRecord) []Chunk {
	if len(rec.Chunks) > 0 {
		out := make([]Chunk, len(rec.Chunks))
		copy(out, rec.Chunks)
		return out
	}
	return []Chunk{{
		ID: rec.ArtifactID, Size: rec.Size, Codec: rec.Codec,
		StoredSHA: rec.StoredSHA, StoredSize: rec.StoredSize, Round: rec.Round,
	}}
}

// blobResult describes a freshly written, not-yet-committed blob.
type blobResult struct {
	tmp        string
	plainSHA   string
	plainSize  int64
	storedSHA  string
	storedSize int64
	codec      string
}

// compressMin is the smallest artifact worth compressing, and the ratio
// below which compression is not worth the CPU on either side.
const (
	compressMin   = 4 << 10
	compressSniff = 256 << 10
	compressRatio = 1.15
)

// writeBlob streams src into a temporary file in raw/, hashing the
// plaintext (the content address) and the stored bytes (what the seal
// covers) in one pass, choosing a codec from a sample of the content.
func (b *Builder) writeBlob(src io.Reader, size int64) (*blobResult, error) {
	tmp, err := os.CreateTemp(filepath.Join(b.Dir, "raw"), ".tmp-*")
	if err != nil {
		return nil, err
	}
	res := &blobResult{tmp: tmp.Name(), codec: CodecNone}

	head := make([]byte, 0, compressSniff)
	if size > compressMin && !b.NoCodec {
		buf := make([]byte, compressSniff)
		n, err := io.ReadFull(src, buf)
		if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
			tmp.Close()
			os.Remove(res.tmp)
			return nil, err
		}
		head = buf[:n]
		if worthCompressing(head) {
			res.codec = CodecGzip
		}
	}

	plain := sha256.New()
	stored := sha256.New()
	counted := &countingWriter{w: io.MultiWriter(tmp, stored)}

	var sink io.Writer = counted
	var zw *gzip.Writer
	if res.codec == CodecGzip {
		zw = gzip.NewWriter(counted)
		sink = zw
	}
	n, err := io.Copy(io.MultiWriter(sink, plain), io.MultiReader(bytes.NewReader(head), src))
	if err == nil && zw != nil {
		err = zw.Close()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		os.Remove(res.tmp)
		return nil, err
	}
	res.plainSize = n
	res.plainSHA = hex.EncodeToString(plain.Sum(nil))
	res.storedSize = counted.n
	res.storedSHA = hex.EncodeToString(stored.Sum(nil))
	return res, nil
}

// commitBlob moves a written blob to its content-addressed name, dedupes
// against what the package already holds, and offers/consults the shared
// store. A blob already on disk is never trusted on its name alone.
func (b *Builder) commitBlob(res *blobResult, id string) error {
	name := blobName(id, res.codec)
	dst := filepath.Join(b.Dir, "raw", name)

	if _, err := os.Lstat(dst); err == nil {
		// Already in this package. Trust it only if the seal we are about
		// to write already accounts for exactly these bytes.
		if have, ok := b.sums[name]; ok && have == res.storedSHA {
			os.Remove(res.tmp)
			return nil
		}
		if h, _, err := hashFile(dst); err == nil && h == res.storedSHA {
			b.sums[name] = h
			b.stats.StoredBytes += res.storedSize
			os.Remove(res.tmp)
			return nil
		}
		// Present but not the expected bytes: replace with what we just
		// verified ourselves rather than seal someone else's file.
		_ = os.Chmod(dst, 0o600)
		_ = os.Remove(dst)
	}

	if b.Shared != nil {
		if reused, err := b.Shared.Link(res.storedSHA, dst); err == nil && reused {
			os.Remove(res.tmp)
			b.sums[name] = res.storedSHA
			b.stats.StoredBytes += res.storedSize
			return nil
		}
	}
	if err := os.Rename(res.tmp, dst); err != nil {
		os.Remove(res.tmp)
		return err
	}
	_ = os.Chmod(dst, 0o400)
	if b.Shared != nil {
		_ = b.Shared.Adopt(res.storedSHA, dst)
	}
	b.sums[name] = res.storedSHA
	b.stats.StoredBytes += res.storedSize
	return nil
}

// RecordNonFile appends a manifest entry that carries no content blob
// (symlinks, skipped irregular files, bound-exceeded, policy-excluded,
// access denied).
func (b *Builder) RecordNonFile(rec ArtifactRecord) error {
	if rec.CollectedUTC == "" {
		rec.CollectedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if rec.Method == "" {
		rec.Method = MethodMetadataOnly
	}
	if rec.Round == 0 {
		rec.Round = b.round
	}
	if rec.Status != StatusOK && rec.Status != StatusNotPresent {
		b.stats.Failed++
	}
	return b.record(rec)
}

func (b *Builder) record(rec ArtifactRecord) error {
	b.manifest.Artifacts = append(b.manifest.Artifacts, rec)
	if err := b.writeManifestLine(rec); err != nil {
		return err
	}
	return b.coll.Append(map[string]any{
		"event": "artifact", "status": rec.Status, "artifact_id": rec.ArtifactID,
		"source_path": rec.SourcePath, "size": rec.Size, "rule": rec.CollectorRule,
		"round": rec.Round, "method": rec.Method, "error": rec.Error,
	})
}

func (b *Builder) writeManifestLine(v any) error { return writeLine(b.mf, v) }

func writeLine(f *os.File, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	return err
}

// Log appends a free-form event to collection.jsonl.
func (b *Builder) Log(event string, fields map[string]any) error {
	m := map[string]any{"event": event, "round": b.round}
	for k, v := range fields {
		m[k] = v
	}
	return b.coll.Append(m)
}

// Stats returns what this round has done so far.
func (b *Builder) Stats() RoundStats { return b.stats }

// Seal finalizes the round: closes logs, writes case.json, archives the
// previous seal and writes SHA256SUMS over the sealed zone. Blob hashes
// computed during ingest are reused, so sealing never re-reads evidence.
func (b *Builder) Seal() error {
	if b.sealed {
		return fmt.Errorf("package already sealed")
	}
	ok, failed := 0, 0
	for _, a := range b.manifest.Artifacts {
		if a.Status == StatusOK {
			ok++
		} else {
			failed++
		}
	}
	if err := b.custody.Append(map[string]any{
		"event": "acquisition_completed", "case_id": b.manifest.CaseID, "round": b.round,
		"artifacts_ok": ok, "artifacts_not_acquired": failed,
		"round_ok": b.stats.OK, "round_carried_forward": b.stats.Carried,
		"round_not_acquired": b.stats.Failed, "round_stored_bytes": b.stats.StoredBytes,
	}); err != nil {
		return err
	}
	if err := b.custody.Append(map[string]any{
		"event": "package_sealed", "case_id": b.manifest.CaseID, "round": b.round,
	}); err != nil {
		return err
	}
	if err := b.coll.Close(); err != nil {
		return err
	}
	if err := b.custody.Close(); err != nil {
		return err
	}
	if err := b.mf.Close(); err != nil {
		return err
	}
	b.coll, b.custody, b.mf = nil, nil, nil

	b.caseInfo.Rounds = append(b.caseInfo.Rounds, Round{
		Round:            b.round,
		StartedUTC:       b.started.UTC().Format(time.RFC3339),
		CompletedUTC:     time.Now().UTC().Format(time.RFC3339),
		CollectorVersion: version.Version,
		CollectionArgs:   b.caseInfo.CollectionArgs,
		ArtifactsOK:      b.stats.OK,
		ArtifactsCarried: b.stats.Carried,
		ArtifactsFailed:  b.stats.Failed,
		StoredBytes:      b.stats.StoredBytes,
	})
	if err := writeJSON(filepath.Join(b.Dir, "case.json"), b.caseInfo); err != nil {
		return err
	}
	if err := b.archivePreviousSeal(); err != nil {
		return err
	}
	if err := b.writeSums(); err != nil {
		return err
	}
	b.sealed = true
	b.lock.release()
	return nil
}

// Close releases a builder that will not be sealed: it closes the manifest
// and both hash-chain files and drops the package lock. Safe to call after
// Seal, and safe to call twice.
//
// Closing the files matters beyond tidiness. A caller that hits an error
// mid-collection abandons the builder, and on Windows an open handle stops
// the package directory from being removed at all.
func (b *Builder) Close() {
	if b.sealed {
		if b.lock != nil {
			b.lock.release()
		}
		return
	}
	if b.coll != nil {
		_ = b.coll.Close()
		b.coll = nil
	}
	if b.custody != nil {
		_ = b.custody.Close()
		b.custody = nil
	}
	if b.mf != nil {
		_ = b.mf.Close()
		b.mf = nil
	}
	if b.lock != nil {
		b.lock.release()
	}
}

// archivePreviousSeal preserves the seal that closed the previous round.
// A round's sealed state must stay provable after the next round changes
// the current SHA256SUMS.
func (b *Builder) archivePreviousSeal() error {
	src := filepath.Join(b.Dir, sumsFile)
	data, err := os.ReadFile(src)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Join(b.Dir, sealsDir), 0o700); err != nil {
		return err
	}
	dst := filepath.Join(b.Dir, sealsDir, fmt.Sprintf("%s.%d", sumsFile, b.round-1))
	if _, err := os.Stat(dst); err == nil {
		return nil // already archived
	}
	return os.WriteFile(dst, data, 0o400)
}

// sealedFiles lists the non-raw files covered by SHA256SUMS. manifest.json
// is listed for packages that still carry the legacy array form.
var sealedFiles = []string{"case.json", manifestJSONL, manifestJSON, "collection.jsonl", "chain-of-custody.jsonl"}

func (b *Builder) writeSums() error {
	var lines []string
	for _, f := range sealedFiles {
		h, _, err := hashFile(filepath.Join(b.Dir, f))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) && (f == manifestJSON || f == manifestJSONL) {
				continue // only one manifest form is present
			}
			return err
		}
		lines = append(lines, h+"  "+f)
	}
	// Archived seals are themselves evidence of earlier state.
	if entries, err := os.ReadDir(filepath.Join(b.Dir, sealsDir)); err == nil {
		for _, e := range entries {
			rel := sealsDir + "/" + e.Name()
			h, _, err := hashFile(filepath.Join(b.Dir, filepath.FromSlash(rel)))
			if err != nil {
				return err
			}
			lines = append(lines, h+"  "+rel)
		}
	}
	// Blob hashes were computed while writing; earlier rounds' came from
	// the seal they were closed with. Anything still unknown (a package
	// built by an older version) is hashed once, here.
	entries, err := os.ReadDir(filepath.Join(b.Dir, "raw"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), ".tmp-") {
			continue
		}
		h, ok := b.sums[e.Name()]
		if !ok {
			if h, _, err = hashFile(filepath.Join(b.Dir, "raw", e.Name())); err != nil {
				return err
			}
			b.sums[e.Name()] = h
		}
		lines = append(lines, h+"  raw/"+e.Name())
	}
	sort.Strings(lines)
	return os.WriteFile(filepath.Join(b.Dir, sumsFile),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// VerifyResult reports the outcome of package verification.
type VerifyResult struct {
	FilesChecked    int
	CollectionRecs  int
	CustodyRecs     int
	ArtifactsOK     int
	ArtifactsFailed int
	NotPresent      int
	Carried         int
	Rounds          int
	Depth           string // "quick" or "full"
	Problems        []string
}

// Verify checks a sealed package in full: SHA256SUMS coverage and
// correctness over every file, content-address consistency (including
// chunked artifacts), and both hash chains.
func Verify(dir string) (*VerifyResult, error) { return verify(dir, true) }

// VerifyQuick checks everything Verify does except re-hashing evidence
// blobs: the small sealed files, both hash chains end to end, the manifest
// cross-check, and every blob's presence and recorded length. It is what
// interactive commands use so opening a case does not re-read gigabytes;
// `agentdfir verify` still runs the full check.
func VerifyQuick(dir string) (*VerifyResult, error) { return verify(dir, false) }

func verify(dir string, full bool) (*VerifyResult, error) {
	res := &VerifyResult{Depth: "quick"}
	if full {
		res.Depth = "full"
	}
	sums, err := os.ReadFile(filepath.Join(dir, sumsFile))
	if err != nil {
		return nil, fmt.Errorf("read SHA256SUMS: %w", err)
	}
	listed := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		parts := strings.SplitN(line, "  ", 2)
		if len(parts) != 2 {
			res.Problems = append(res.Problems, "SHA256SUMS: malformed line: "+line)
			continue
		}
		listed[parts[1]] = parts[0]
	}
	haveManifest := false
	for _, f := range sealedFiles {
		if _, ok := listed[f]; ok {
			if f == manifestJSON || f == manifestJSONL {
				haveManifest = true
			}
			continue
		}
		if f == manifestJSON || f == manifestJSONL {
			continue
		}
		res.Problems = append(res.Problems, "SHA256SUMS: required file not covered: "+f)
	}
	if !haveManifest {
		res.Problems = append(res.Problems, "SHA256SUMS: no manifest covered")
	}

	for rel, want := range listed {
		isBlob := strings.HasPrefix(rel, "raw/")
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if isBlob && !full {
			st, err := os.Stat(path)
			if err != nil {
				res.Problems = append(res.Problems, rel+": missing")
				continue
			}
			_ = st
			res.FilesChecked++
			continue
		}
		got, _, err := hashFile(path)
		if err != nil {
			res.Problems = append(res.Problems, rel+": unreadable: "+err.Error())
			continue
		}
		if got != want {
			res.Problems = append(res.Problems, rel+": hash mismatch (evidence modified)")
		}
		res.FilesChecked++
	}
	// Extra files in raw/ not covered by SHA256SUMS are a tamper signal.
	if entries, err := os.ReadDir(filepath.Join(dir, "raw")); err == nil {
		for _, e := range entries {
			rel := "raw/" + e.Name()
			if _, ok := listed[rel]; !ok {
				res.Problems = append(res.Problems, rel+": present but not covered by SHA256SUMS")
			}
		}
	}

	// Content-address consistency + manifest cross-check.
	man, err := ReadManifest(dir)
	if err != nil {
		res.Problems = append(res.Problems, "manifest: "+err.Error())
	} else {
		store := NewStore(dir, man)
		seen := map[string]bool{}
		for _, a := range man.Artifacts {
			switch a.Status {
			case StatusOK:
				res.ArtifactsOK++
				if a.Method == MethodCarriedForward {
					res.Carried++
				}
				for _, name := range storedUnits(a) {
					if _, err := os.Stat(filepath.Join(dir, "raw", name)); err != nil {
						res.Problems = append(res.Problems, a.LogicalPath+": blob missing: "+name)
					}
				}
				if !full || seen[a.ArtifactID] {
					continue
				}
				seen[a.ArtifactID] = true
				if err := verifyContentAddress(store, a); err != nil {
					res.Problems = append(res.Problems, a.LogicalPath+": "+err.Error())
				}
			case StatusNotPresent:
				res.NotPresent++
			default:
				res.ArtifactsFailed++
			}
		}
	}

	// Hash chains, always end to end: they are small and they are the
	// tamper-evidence the rest of the package leans on.
	n, err := hashchain.VerifyFile(filepath.Join(dir, "collection.jsonl"))
	res.CollectionRecs = n
	if err != nil {
		res.Problems = append(res.Problems, "collection.jsonl: "+err.Error())
	}
	n, err = hashchain.VerifyFile(filepath.Join(dir, "chain-of-custody.jsonl"))
	res.CustodyRecs = n
	if err != nil {
		res.Problems = append(res.Problems, "chain-of-custody.jsonl: "+err.Error())
	}
	if info, err := ReadCaseInfo(dir); err == nil {
		res.Rounds = len(info.Rounds)
		if res.Rounds == 0 {
			res.Rounds = 1
		}
	}
	return res, nil
}

// verifyContentAddress re-derives an artifact's plaintext hash from what
// is actually stored. For a chunked artifact the id is not the name of any
// file, so the chunks are streamed and hashed as one — without this, the
// strongest check would silently skip exactly the artifacts that grew.
func verifyContentAddress(s *Store, a ArtifactRecord) error {
	rc, err := s.Open(a.ArtifactID)
	if err != nil {
		return fmt.Errorf("unreadable: %w", err)
	}
	defer rc.Close()
	h := sha256.New()
	n, err := io.Copy(h, rc)
	if err != nil {
		return fmt.Errorf("unreadable: %w", err)
	}
	if hex.EncodeToString(h.Sum(nil)) != a.ArtifactID {
		return errors.New("content-address mismatch")
	}
	if a.Size > 0 && n != a.Size {
		return fmt.Errorf("size mismatch: recorded %d, stored %d", a.Size, n)
	}
	return nil
}

// ReadCaseInfo reads case.json.
func ReadCaseInfo(dir string) (*CaseInfo, error) {
	data, err := os.ReadFile(filepath.Join(dir, "case.json"))
	if err != nil {
		return nil, err
	}
	var c CaseInfo
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	return &c, nil
}

// readSums parses a SHA256SUMS file into path → hash.
func readSums(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	out := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if parts := strings.SplitN(line, "  ", 2); len(parts) == 2 {
			out[parts[1]] = parts[0]
		}
	}
	return out, nil
}

func statusForErr(err error) string {
	if os.IsPermission(err) {
		return StatusAccessDenied
	}
	return StatusError
}

func writeJSON(path string, v any) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0o600)
}

func hashFile(path string) (string, int64, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// countingWriter counts the stored bytes as they are written.
type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
