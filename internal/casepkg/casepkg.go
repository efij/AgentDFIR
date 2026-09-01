// Package casepkg implements the sealed zone of the .adfir evidence
// package: content-addressed artifact storage, manifest, hash-chained
// collection and custody logs, and SHA256SUMS sealing/verification.
//
// Layout (sealed zone):
//
//	<pkg>/
//	├── raw/<sha256>            content-addressed evidence bytes
//	├── manifest.json           artifact metadata (logical paths live here)
//	├── collection.jsonl        hash-chained collection log
//	├── chain-of-custody.jsonl  hash-chained custody log (ends at sealing)
//	├── case.json               case + operator + environment metadata
//	└── SHA256SUMS              covers the sealed zone exactly
//
// The analysis overlay (normalized/, detections/, reports/) is written by
// later phases and is excluded from SHA256SUMS by design.
package casepkg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/internal/hashchain"
	"github.com/efij/AgentDFIR/internal/version"
)

// Artifact acquisition status values.
const (
	StatusOK           = "OK"
	StatusAccessDenied = "ACCESS_DENIED"
	StatusSkippedBound = "SKIPPED_BOUND_EXCEEDED"
	StatusSkippedType  = "SKIPPED_IRREGULAR_TYPE"
	StatusSymlink      = "SYMLINK_NOT_FOLLOWED"
	StatusError        = "ERROR"
)

// ArtifactRecord is one manifest entry. Multiple records may reference
// the same content-addressed blob (dedupe by SHA-256).
type ArtifactRecord struct {
	ArtifactID     string `json:"artifact_id"` // sha256 hex of content; empty when no content acquired
	SourcePath     string `json:"source_path"`
	LogicalPath    string `json:"logical_path"`
	Host           string `json:"host"`
	User           string `json:"user"`
	Product        string `json:"product"`
	CollectorRule  string `json:"collector_rule"` // collector manifest entry id, e.g. claude.sessions
	ArtifactType   string `json:"artifact_type"`
	Sensitivity    string `json:"sensitivity"`
	Size           int64  `json:"size"`
	Mode           string `json:"mode"`
	ModTimeUTC     string `json:"mtime_utc"`
	CollectedUTC   string `json:"collection_timestamp_utc"`
	Method         string `json:"collection_method"`
	Status         string `json:"status"`
	Error          string `json:"error,omitempty"`
	SymlinkTarget  string `json:"symlink_target,omitempty"`
	FileWasGrowing bool   `json:"file_was_growing,omitempty"`
}

// Manifest is manifest.json.
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
	Artifacts        []ArtifactRecord `json:"artifacts"`
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
}

// Builder accumulates evidence into a package directory and seals it.
type Builder struct {
	Dir      string
	manifest Manifest
	caseInfo CaseInfo
	coll     *hashchain.Writer // collection.jsonl
	custody  *hashchain.Writer // chain-of-custody.jsonl
	sealed   bool
}

// New creates the package directory (must not already exist) and opens
// the hash-chained logs.
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
	}
	var err error
	if b.coll, err = hashchain.NewWriter(filepath.Join(dir, "collection.jsonl")); err != nil {
		return nil, err
	}
	if b.custody, err = hashchain.NewWriter(filepath.Join(dir, "chain-of-custody.jsonl")); err != nil {
		return nil, err
	}
	if err := b.custody.Append(map[string]any{
		"event": "acquisition_started", "case_id": caseID,
		"operator_os_user": info.OperatorOSUser, "operator_asserted": info.OperatorAsserted,
		"authorization_reference": info.Authorization,
		"host":                    host, "collector_version": version.Version,
		"collector_binary_sha256": b.manifest.CollectorBinary,
	}); err != nil {
		return nil, err
	}
	return b, nil
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

// IngestFile copies a regular file into raw/ (hash-while-copy, torn-read
// detection) and appends the manifest + collection records. rec must have
// its descriptive fields set; content fields are filled in here.
func (b *Builder) IngestFile(srcPath string, rec ArtifactRecord) error {
	rec.CollectedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	rec.Method = "file_copy"

	before, err := os.Lstat(srcPath)
	if err != nil {
		rec.Status = statusForErr(err)
		rec.Error = err.Error()
		return b.record(rec)
	}
	rec.Size = before.Size()
	rec.Mode = before.Mode().String()
	rec.ModTimeUTC = before.ModTime().UTC().Format(time.RFC3339Nano)

	f, err := os.Open(srcPath)
	if err != nil {
		rec.Status = statusForErr(err)
		rec.Error = err.Error()
		return b.record(rec)
	}
	defer f.Close()

	tmp, err := os.CreateTemp(filepath.Join(b.Dir, "raw"), ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	// Copy at most the size observed before opening: a live agent may be
	// appending; the hash must describe exactly the bytes preserved.
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(tmp, h), io.LimitReader(f, before.Size()))
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		if err == nil {
			err = closeErr
		}
		rec.Status = StatusError
		rec.Error = err.Error()
		return b.record(rec)
	}
	rec.Size = n
	rec.ArtifactID = hex.EncodeToString(h.Sum(nil))

	if after, err := os.Lstat(srcPath); err == nil {
		if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			rec.FileWasGrowing = true
		}
	}

	dst := filepath.Join(b.Dir, "raw", rec.ArtifactID)
	if _, err := os.Lstat(dst); err == nil {
		// Dedupe: identical content already stored.
	} else if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	rec.Status = StatusOK
	return b.record(rec)
}

// RecordNonFile appends a manifest entry that carries no content blob
// (symlinks, skipped irregular files, bound-exceeded, access denied).
func (b *Builder) RecordNonFile(rec ArtifactRecord) error {
	if rec.CollectedUTC == "" {
		rec.CollectedUTC = time.Now().UTC().Format(time.RFC3339Nano)
	}
	if rec.Method == "" {
		rec.Method = "metadata_only"
	}
	return b.record(rec)
}

func (b *Builder) record(rec ArtifactRecord) error {
	b.manifest.Artifacts = append(b.manifest.Artifacts, rec)
	return b.coll.Append(map[string]any{
		"event": "artifact", "status": rec.Status, "artifact_id": rec.ArtifactID,
		"source_path": rec.SourcePath, "size": rec.Size, "rule": rec.CollectorRule,
		"error": rec.Error,
	})
}

// Log appends a free-form event to collection.jsonl.
func (b *Builder) Log(event string, fields map[string]any) error {
	m := map[string]any{"event": event}
	for k, v := range fields {
		m[k] = v
	}
	return b.coll.Append(m)
}

// Seal finalizes the package: closes logs, writes manifest.json and
// case.json, then writes SHA256SUMS over the sealed zone.
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
		"event": "acquisition_completed", "case_id": b.manifest.CaseID,
		"artifacts_ok": ok, "artifacts_not_acquired": failed,
	}); err != nil {
		return err
	}
	if err := b.custody.Append(map[string]any{
		"event": "package_sealed", "case_id": b.manifest.CaseID,
	}); err != nil {
		return err
	}
	if err := b.coll.Close(); err != nil {
		return err
	}
	if err := b.custody.Close(); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(b.Dir, "manifest.json"), b.manifest); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(b.Dir, "case.json"), b.caseInfo); err != nil {
		return err
	}
	if err := b.writeSums(); err != nil {
		return err
	}
	b.sealed = true
	return nil
}

// sealedFiles lists the non-raw files covered by SHA256SUMS.
var sealedFiles = []string{"case.json", "manifest.json", "collection.jsonl", "chain-of-custody.jsonl"}

func (b *Builder) writeSums() error {
	var lines []string
	add := func(rel string) error {
		h, _, err := hashFile(filepath.Join(b.Dir, rel))
		if err != nil {
			return err
		}
		lines = append(lines, h+"  "+filepath.ToSlash(rel))
		return nil
	}
	for _, f := range sealedFiles {
		if err := add(f); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(filepath.Join(b.Dir, "raw"))
	if err != nil {
		return err
	}
	for _, e := range entries {
		if err := add(filepath.Join("raw", e.Name())); err != nil {
			return err
		}
	}
	sort.Strings(lines)
	return os.WriteFile(filepath.Join(b.Dir, "SHA256SUMS"),
		[]byte(strings.Join(lines, "\n")+"\n"), 0o600)
}

// VerifyResult reports the outcome of package verification.
type VerifyResult struct {
	FilesChecked    int
	CollectionRecs  int
	CustodyRecs     int
	ArtifactsOK     int
	ArtifactsFailed int
	Problems        []string
}

// Verify checks a sealed package: SHA256SUMS coverage and correctness,
// content-address consistency, and both hash chains.
func Verify(dir string) (*VerifyResult, error) {
	res := &VerifyResult{}
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
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
	for _, f := range sealedFiles {
		if _, ok := listed[f]; !ok {
			res.Problems = append(res.Problems, "SHA256SUMS: required file not covered: "+f)
		}
	}
	for rel, want := range listed {
		got, _, err := hashFile(filepath.Join(dir, filepath.FromSlash(rel)))
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
	var man Manifest
	if data, err := os.ReadFile(filepath.Join(dir, "manifest.json")); err != nil {
		res.Problems = append(res.Problems, "manifest.json: "+err.Error())
	} else if err := json.Unmarshal(data, &man); err != nil {
		res.Problems = append(res.Problems, "manifest.json: invalid JSON: "+err.Error())
	} else {
		for _, a := range man.Artifacts {
			switch a.Status {
			case StatusOK:
				res.ArtifactsOK++
				blob := filepath.Join(dir, "raw", a.ArtifactID)
				h, _, err := hashFile(blob)
				if err != nil {
					res.Problems = append(res.Problems, a.LogicalPath+": blob missing: "+a.ArtifactID)
				} else if h != a.ArtifactID {
					res.Problems = append(res.Problems, a.LogicalPath+": content-address mismatch")
				}
			default:
				res.ArtifactsFailed++
			}
		}
	}
	// Hash chains.
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
	return res, nil
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
