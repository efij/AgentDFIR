// Package repro makes an analysis reproducible and checkable by someone
// who does not trust the tool that produced it.
//
// Every analysis writes detections/analysis-manifest.json beside its
// findings: which binary ran (version, Go toolchain, OS/arch, and the
// fingerprint of the analysis code itself), which rule set decided (the
// built-in rules' code fingerprint and the SHA-256 of every rule pack and
// every file in --rules), which evidence it read (the seal digest, the
// manifest's SHA-256 and the analysis inputs digest), the options that
// change what is found (with the SHA-256 of every input file they name),
// and a findings_fingerprint: a hash over the findings in a canonical,
// order-independent form.
//
// The fingerprint covers what a finding asserts about the evidence — the
// rule, the severity, the two evidence states, the session and agent, and
// the evidence references — and nothing about the run: no analysis time,
// no titles or descriptions (those are prose and change with wording), no
// ordering. Two analyses of the same evidence by the same code with the
// same options have the same fingerprint; `agentdfir verify --reproduce`
// re-runs the analysis from the sealed zone and compares, and explains a
// mismatch by what differed. The algorithm is specified in
// docs/adfir-spec.md so a third party can recompute it from findings.json
// (tools/adfir-verify does, with the Python standard library).
//
// The manifest is overlay data: it is written next to the findings and is
// never part of the sealed zone, so writing it cannot change what
// `agentdfir verify` proves about the evidence.
package repro

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Identifiers written into the manifest.
const (
	ManifestSchema    = "agentdfir.analysis-manifest/1"
	FindingsAlgorithm = "adfir-findings-sha256/1"
	// Spec is the .adfir specification revision that defines the file.
	Spec = "0.2.2"
	// ManifestFile is the manifest's name under detections/.
	ManifestFile = "analysis-manifest.json"
	// FindingsFile is where the fingerprinted findings live, relative to
	// the package root (gzipped as findings.json.gz by current binaries).
	FindingsFile = "detections/findings.json"
)

// FingerprintFields names, in order, the finding fields the fingerprint
// covers. evidence_refs is a sorted list; the rest are strings.
var FingerprintFields = []string{"rule_id", "severity", "status", "endpoint_corroboration", "session_id", "agent_id", "evidence_refs"}

// Bounds on what a check reads: the manifest is small, findings and the
// graph are bounded by the overlay's own decompression limits.
const (
	maxManifestBytes = 16 << 20
	maxInputHash     = 4 << 30 // an input file larger than this is recorded by size only
)

// Manifest is detections/analysis-manifest.json.
type Manifest struct {
	Schema string `json:"schema"`
	Spec   string `json:"adfir_spec"`
	Tool   Tool   `json:"tool"`
	// RuleSet is what decided: the built-in rules (by code fingerprint) and
	// every pack, by content hash.
	RuleSet RuleSet `json:"rule_set"`
	Input   Input   `json:"input"`
	Options Options `json:"options"`
	// AnalyzedUTC is when the analysis ran. It is not part of the
	// fingerprint, and a reproduction never compares it.
	AnalyzedUTC         string          `json:"analyzed_utc"`
	Findings            FindingsSummary `json:"findings"`
	FindingsFingerprint string          `json:"findings_fingerprint"`
	Notes               []string        `json:"notes,omitempty"`
}

// Tool identifies the binary and the code that produced the findings.
type Tool struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	// AnalysisFingerprint is the hash of every in-module package analysis
	// depends on (internal/fingerprint): the code that turns evidence into
	// findings. Two binaries with the same value analyze identically.
	AnalysisFingerprint string `json:"analysis_fingerprint"`
	ParseFingerprint    string `json:"parse_fingerprint"`
}

// RuleSet identifies the rules that ran.
type RuleSet struct {
	// BuiltinFingerprint identifies the built-in Go rules and the packs
	// embedded in the binary (it is the analysis code fingerprint).
	BuiltinFingerprint string `json:"builtin_fingerprint"`
	BuiltinPacks       bool   `json:"builtin_packs"`
	Packs              []Pack `json:"packs"`
	// RulesDir and RulesDirFiles name an analyst-supplied --rules directory
	// and the SHA-256 of every .json file in it (rule packs and chain packs
	// are both read from there).
	RulesDir      string    `json:"rules_dir,omitempty"`
	RulesDirFiles []FileRef `json:"rules_dir_files,omitempty"`
}

// Pack is one loaded rule pack.
type Pack struct {
	Pack    string `json:"pack"`
	Version string `json:"version"`
	Rules   int    `json:"rules"`
	Origin  string `json:"origin"`
	SHA256  string `json:"sha256,omitempty"`
}

// FileRef names an input file by path and content.
type FileRef struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256,omitempty"`
	Size   int64  `json:"size"`
	Error  string `json:"error,omitempty"` // why it could not be hashed
}

// Input identifies the evidence the analysis read.
type Input struct {
	CaseID       string `json:"case_id,omitempty"`
	ADFIRVersion string `json:"adfir_version,omitempty"`
	// SealSHA256 is the SHA-256 of SHA256SUMS: it commits to the whole
	// sealed zone, so equal values mean the same evidence.
	SealSHA256     string `json:"seal_sha256"`
	ManifestFile   string `json:"manifest_file,omitempty"`
	ManifestSHA256 string `json:"manifest_sha256,omitempty"`
	// InputsDigest identifies the current records the analysis read (see
	// analysis.analysisInputs).
	InputsDigest string `json:"inputs_digest,omitempty"`
	Artifacts    int    `json:"artifacts"`
	// RetiredSHA256 is the hash of normalized/retired.json, the records
	// collection policy left out of the scan set, when there is one.
	RetiredSHA256 string `json:"retired_sha256,omitempty"`
}

// Options are the effective analysis options that change what is found.
type Options struct {
	EndpointLogs   []FileRef `json:"endpoint_logs,omitempty"`
	EndpointFormat string    `json:"endpoint_format,omitempty"`
	WindowMS       int64     `json:"window_ms,omitempty"`
	ShellHistory   *FileRef  `json:"shell_history,omitempty"`
	GatewayLog     *FileRef  `json:"gateway_log,omitempty"`
	GatewayMap     *FileRef  `json:"gateway_map,omitempty"`
	GatewayServers []string  `json:"gateway_servers,omitempty"`
	NoBuiltinPacks bool      `json:"no_builtin_packs"`
	SpawnThreshold int       `json:"spawn_threshold"`
	KnownDests     []string  `json:"known_destinations,omitempty"`
	IOCFiles       []FileRef `json:"ioc_files,omitempty"`
	RetireExcluded bool      `json:"retire_excluded,omitempty"`
	// Honeytokens are planted secrets: the manifest records how many and
	// a digest of the list, never the values.
	Honeytokens       int    `json:"honeytokens,omitempty"`
	HoneytokensSHA256 string `json:"honeytokens_sha256,omitempty"`
	// ReusedCorrelation is set when this analysis was given no endpoint
	// logs but carried forward the endpoint-correlation results of an
	// earlier run on the same overlay; those findings depend on logs this
	// run did not read.
	ReusedCorrelation         bool `json:"reused_correlation,omitempty"`
	ReusedCorrelationFindings int  `json:"reused_correlation_findings"`
	// OverlayReused is set when the analysis read normalized events an
	// earlier run had built (and annotated with evidence states, e.g. from
	// --shell-history) instead of rebuilding them from the sealed zone.
	OverlayReused bool `json:"overlay_reused,omitempty"`
}

// FindingsSummary describes the fingerprinted findings.
type FindingsSummary struct {
	Count     int      `json:"count"`
	File      string   `json:"file"`
	Algorithm string   `json:"algorithm"`
	Fields    []string `json:"fields"`
}

// netstring writes len ":" bytes "," — an unambiguous field encoding.
func netstring(b *strings.Builder, s string) {
	b.WriteString(strconv.Itoa(len(s)))
	b.WriteByte(':')
	b.WriteString(s)
	b.WriteByte(',')
}

// CanonicalEntry is one finding's fingerprint entry: a netstring per
// fingerprinted field, then the number of evidence references and each
// reference, sorted bytewise.
func CanonicalEntry(f schema.Finding) string {
	var b strings.Builder
	for _, s := range []string{f.RuleID, f.Severity, f.Status, f.Endpoint, f.SessionID, f.AgentID} {
		netstring(&b, s)
	}
	refs := append([]string(nil), f.EvidenceRefs...)
	sort.Strings(refs)
	netstring(&b, strconv.Itoa(len(refs)))
	for _, r := range refs {
		netstring(&b, r)
	}
	return b.String()
}

// Fingerprint is the findings fingerprint: "sha256:" and the hex SHA-256
// of the canonical entries, sorted bytewise, each written as a netstring.
// Duplicates count; order does not.
func Fingerprint(findings []schema.Finding) string {
	entries := make([]string, len(findings))
	for i, f := range findings {
		entries[i] = CanonicalEntry(f)
	}
	sort.Strings(entries)
	h := sha256.New()
	for _, e := range entries {
		var b strings.Builder
		netstring(&b, e)
		io.WriteString(h, b.String())
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil))
}

// FingerprintJSON computes the fingerprint of findings.json bytes exactly
// as a third party reading the file would.
func FingerprintJSON(data []byte) (string, int, error) {
	var fs []schema.Finding
	if err := json.Unmarshal(data, &fs); err != nil {
		return "", 0, err
	}
	return Fingerprint(fs), len(fs), nil
}

// RoundTrip returns findings as they read back from JSON: what is
// fingerprinted must be what findings.json holds (encoding/json replaces
// invalid UTF-8, so the in-memory strings can differ from the file).
func RoundTrip(findings []schema.Finding) []schema.Finding {
	data, err := json.Marshal(findings)
	if err != nil {
		return findings
	}
	var out []schema.Finding
	if json.Unmarshal(data, &out) != nil {
		return findings
	}
	return out
}

// HashFile names a file by path, size and SHA-256.
func HashFile(p string) FileRef {
	ref := FileRef{Path: p}
	f, err := os.Open(p)
	if err != nil {
		ref.Error = err.Error()
		return ref
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		ref.Error = err.Error()
		return ref
	}
	ref.Size = fi.Size()
	if fi.IsDir() {
		ref.Error = "is a directory"
		return ref
	}
	if fi.Size() > maxInputHash {
		ref.Error = fmt.Sprintf("larger than %d bytes; recorded by size only", int64(maxInputHash))
		return ref
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		ref.Error = err.Error()
		return ref
	}
	ref.SHA256 = hex.EncodeToString(h.Sum(nil))
	return ref
}

// HashFiles hashes every path, in the order given.
func HashFiles(ps []string) []FileRef {
	if len(ps) == 0 {
		return nil
	}
	out := make([]FileRef, len(ps))
	for i, p := range ps {
		out[i] = HashFile(p)
	}
	return out
}

// HashOptional is HashFile for an option that may be unset.
func HashOptional(p string) *FileRef {
	if p == "" {
		return nil
	}
	r := HashFile(p)
	return &r
}

// RulesDirFiles hashes every .json file in a --rules directory, sorted
// by name: the rule packs and the chain packs analysis reads from it.
func RulesDirFiles(dir string) []FileRef {
	if dir == "" {
		return nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return []FileRef{{Path: dir, Error: err.Error()}}
	}
	var out []FileRef
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		out = append(out, HashFile(filepath.Join(dir, e.Name())))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// HoneytokenDigest is the digest the manifest records for a honeytoken
// list: blank lines dropped, order kept.
func HoneytokenDigest(tokens []string) (int, string) {
	h := sha256.New()
	n := 0
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		n++
		io.WriteString(h, t)
		h.Write([]byte{'\n'})
	}
	if n == 0 {
		return 0, ""
	}
	return n, hex.EncodeToString(h.Sum(nil))
}

// SealInput fills the evidence identity from the package's sealed files:
// the SHA-256 of SHA256SUMS and of the manifest form the package uses.
func SealInput(pkg string) Input {
	var in Input
	if r := HashFile(filepath.Join(pkg, "SHA256SUMS")); r.Error == "" {
		in.SealSHA256 = r.SHA256
	}
	for _, name := range []string{"manifest.jsonl", "manifest.json"} {
		if r := HashFile(filepath.Join(pkg, name)); r.Error == "" {
			in.ManifestFile, in.ManifestSHA256 = name, r.SHA256
			break
		}
	}
	if r := HashFile(filepath.Join(pkg, "normalized", "retired.json")); r.Error == "" {
		in.RetiredSHA256 = r.SHA256
	}
	return in
}

// Path is where a package's manifest lives.
func Path(pkg string) string { return filepath.Join(pkg, "detections", ManifestFile) }

// Write stores the manifest as plain, indented JSON: it is small, and a
// reviewer should be able to read it with no tool at all.
func Write(pkg string, m *Manifest) error {
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	p := Path(pkg)
	_ = os.Remove(p + ".gz")
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

// Read loads a manifest file, bounded.
func Read(p string) (*Manifest, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxManifestBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", p, maxManifestBytes)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	if m.Schema != ManifestSchema {
		return nil, fmt.Errorf("%s: schema %q, want %q", p, m.Schema, ManifestSchema)
	}
	return &m, nil
}

// ErrNoManifest is returned when a package has no analysis manifest.
var ErrNoManifest = errors.New("no analysis manifest (detections/analysis-manifest.json); the package was analyzed by a version before 4.5 or not at all")
