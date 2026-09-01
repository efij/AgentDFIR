// Package supportpkg derives a privacy-reduced "support" package from a
// sealed forensic package (plan §4, §17). Redaction happens post-hoc on
// a copy — the original forensic evidence is never modified. A
// redaction-manifest records categories/counts/offsets only, never
// values, and binds the derived package to its source by hash.
package supportpkg

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/efij/AgentDFIR/internal/casepkg"
)

// redactors run over each artifact blob. Order matters (longest/most
// specific first is not required — all applied).
var redactors = []struct {
	category string
	re       *regexp.Regexp
}{
	{"AWS_ACCESS_KEY", regexp.MustCompile(`AKIA[0-9A-Z]{16}`)},
	{"GITHUB_TOKEN", regexp.MustCompile(`ghp_[A-Za-z0-9]{36}`)},
	{"GITHUB_PAT", regexp.MustCompile(`github_pat_[A-Za-z0-9_]{22,}`)},
	{"SLACK_TOKEN", regexp.MustCompile(`xox[bpars]-[A-Za-z0-9-]{10,}`)},
	{"ANTHROPIC_API_KEY", regexp.MustCompile(`sk-ant-[A-Za-z0-9_-]{20,}`)},
	{"OPENAI_API_KEY", regexp.MustCompile(`sk-[A-Za-z0-9_-]{20,}`)},
	{"PRIVATE_KEY_BLOCK", regexp.MustCompile(`(?s)-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----`)},
	{"EMAIL", regexp.MustCompile(`[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`)},
}

// RedactionEntry records one artifact's redactions (no values).
type RedactionEntry struct {
	LogicalPath    string         `json:"logical_path"`
	OriginalSHA256 string         `json:"original_sha256"`
	RedactedSHA256 string         `json:"redacted_sha256"`
	Categories     map[string]int `json:"categories"`
}

// RedactionManifest binds the support package to its forensic source.
type RedactionManifest struct {
	GeneratedUTC    string           `json:"generated_utc"`
	SourceCaseID    string           `json:"source_case_id"`
	SourcePackage   string           `json:"source_package"`
	SourceSumsSHA   string           `json:"source_sha256sums_digest"`
	RedactedEntries []RedactionEntry `json:"redacted_entries"`
	Note            string           `json:"note"`
}

// Export derives a redacted support package from srcPkg into dstPkg.
// It rebuilds a fresh sealed package containing redacted copies, so the
// support package is itself verifiable.
func Export(srcPkg, dstPkg string) (*RedactionManifest, error) {
	man, err := readManifest(srcPkg)
	if err != nil {
		return nil, err
	}
	ci, _ := readCaseInfo(srcPkg)

	info := casepkg.CaseInfo{Notes: map[string]string{"derived_from": srcPkg, "mode": "support-redacted"}}
	if ci != nil {
		info.OperatorOSUser = ci.OperatorOSUser
		info.OperatorAsserted = ci.OperatorAsserted
	}
	b, err := casepkg.New(dstPkg, man.CaseID+"-support", info)
	if err != nil {
		return nil, err
	}

	rm := &RedactionManifest{
		GeneratedUTC:  time.Now().UTC().Format(time.RFC3339),
		SourceCaseID:  man.CaseID,
		SourcePackage: srcPkg,
		SourceSumsSHA: sumsDigest(srcPkg),
		Note:          "Categories and counts only; no secret values are stored. Original forensic package is unmodified.",
	}

	tmpDir, err := os.MkdirTemp("", "adfir-support-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpDir)

	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK {
			_ = b.RecordNonFile(a)
			continue
		}
		blob := filepath.Join(srcPkg, "raw", a.ArtifactID)
		data, err := os.ReadFile(blob)
		if err != nil {
			continue
		}
		redacted, counts := redact(data)
		rec := casepkg.ArtifactRecord{
			SourcePath: a.SourcePath, LogicalPath: a.LogicalPath, Host: a.Host,
			User: a.User, Product: a.Product, CollectorRule: a.CollectorRule,
			ArtifactType: a.ArtifactType, Sensitivity: a.Sensitivity, Status: casepkg.StatusOK,
		}
		if len(counts) > 0 {
			tmp := filepath.Join(tmpDir, a.ArtifactID)
			if err := os.WriteFile(tmp, redacted, 0o600); err != nil {
				return nil, err
			}
			if err := b.IngestFile(tmp, rec); err != nil {
				return nil, err
			}
			sum := sha256.Sum256(redacted)
			rm.RedactedEntries = append(rm.RedactedEntries, RedactionEntry{
				LogicalPath: a.LogicalPath, OriginalSHA256: a.ArtifactID,
				RedactedSHA256: hex.EncodeToString(sum[:]), Categories: counts,
			})
		} else {
			// Unchanged content: re-ingest original.
			if err := b.IngestFile(blob, rec); err != nil {
				return nil, err
			}
		}
	}

	if err := b.Seal(); err != nil {
		return nil, err
	}
	// Write the redaction manifest into the support package (analysis
	// overlay — outside the sealed zone).
	data, _ := json.MarshalIndent(rm, "", "  ")
	if err := os.WriteFile(filepath.Join(dstPkg, "redaction-manifest.json"), append(data, '\n'), 0o600); err != nil {
		return nil, err
	}
	return rm, nil
}

func redact(data []byte) ([]byte, map[string]int) {
	counts := map[string]int{}
	out := data
	for _, r := range redactors {
		matches := r.re.FindAll(out, -1)
		if len(matches) == 0 {
			continue
		}
		counts[r.category] += len(matches)
		out = r.re.ReplaceAll(out, []byte("[REDACTED:"+r.category+"]"))
	}
	return out, counts
}

func sumsDigest(pkgDir string) string {
	data, err := os.ReadFile(filepath.Join(pkgDir, "SHA256SUMS"))
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func readManifest(pkgDir string) (*casepkg.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var m casepkg.Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func readCaseInfo(pkgDir string) (*casepkg.CaseInfo, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "case.json"))
	if err != nil {
		return nil, err
	}
	var ci casepkg.CaseInfo
	if err := json.Unmarshal(data, &ci); err != nil {
		return nil, err
	}
	return &ci, nil
}
