// Package-aware detection rules (plan §14: the rule input contract is
// the whole package — events alone cannot express these).
package detect

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/schema"
)

// RunPackage evaluates event rules plus package-aware rules.
func RunPackage(res *schema.Normalized, pkgDir string) []schema.Finding {
	findings := Run(res)
	man, err := readManifest(pkgDir)
	if err == nil {
		findings = append(findings, permissionBypass(man, pkgDir)...)
		findings = append(findings, secretExposure(man, pkgDir)...)
	}
	return sortBySeverity(findings)
}

func readManifest(pkgDir string) (*casepkg.Manifest, error) {
	data, err := os.ReadFile(filepath.Join(pkgDir, "manifest.json"))
	if err != nil {
		return nil, err
	}
	var man casepkg.Manifest
	if err := json.Unmarshal(data, &man); err != nil {
		return nil, err
	}
	return &man, nil
}

const blobScanBound = 16 << 20 // per-artifact scan bound

// bypassMarkers are config values that disable permission/sandbox
// controls. Substring match on config-category blobs only.
var bypassMarkers = []string{
	`"defaultMode": "bypassPermissions"`,
	`"defaultMode":"bypassPermissions"`,
	`"dangerouslySkipPermissions"`,
	`approval_policy = "never"`,
	`sandbox_mode = "danger-full-access"`,
	`"yolo": true`,
	`"yolo":true`,
}

// PERMISSION_BYPASS_ENABLED — a collected configuration disables the
// product's permission prompting or sandboxing.
func permissionBypass(man *casepkg.Manifest, pkgDir string) []schema.Finding {
	var out []schema.Finding
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK {
			continue
		}
		if a.ArtifactType != "product_config" && a.ArtifactType != "managed_config" {
			continue
		}
		data, err := boundedBlob(pkgDir, a.ArtifactID)
		if err != nil {
			continue
		}
		content := string(data)
		for _, marker := range bypassMarkers {
			if strings.Contains(content, marker) {
				out = append(out, schema.Finding{
					RuleID:      "PERMISSION_BYPASS_ENABLED",
					Severity:    "HIGH",
					Title:       "Permission/Sandbox Controls Disabled",
					Description: "Collected configuration disables permission prompting or sandboxing: " + marker,
					EvidenceRefs: []string{fmt.Sprintf("%s (artifact %.12s)",
						a.LogicalPath, a.ArtifactID)},
					Status:        schema.StateObserved,
					Endpoint:      schema.StateUnknown,
					FalsePositive: "Developers legitimately enable bypass modes on trusted machines; assess against org policy.",
				})
				break
			}
		}
	}
	return out
}

// secretPatterns match well-known credential formats. Values are NEVER
// included in findings — category, artifact and offset only (plan §18).
var secretPatterns = []struct {
	name string
	re   *regexp.Regexp
}{
	{"AWS_ACCESS_KEY", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GITHUB_TOKEN", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)},
	{"GITHUB_FINE_GRAINED_TOKEN", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{"SLACK_TOKEN", regexp.MustCompile(`\bxox[bpars]-[A-Za-z0-9-]{10,}\b`)},
	{"OPENAI_API_KEY", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`)},
	{"ANTHROPIC_API_KEY", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{"PRIVATE_KEY_BLOCK", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
}

// POTENTIAL_SECRET_EXPOSURE — credential material present in collected
// transcripts or prompt history (i.e. it passed through an agent
// conversation and may have left the machine via a model API).
func secretExposure(man *casepkg.Manifest, pkgDir string) []schema.Finding {
	var out []schema.Finding
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK {
			continue
		}
		if a.ArtifactType != "agent_session" && a.ArtifactType != "prompt_history" {
			continue
		}
		data, err := boundedBlob(pkgDir, a.ArtifactID)
		if err != nil {
			continue
		}
		for _, sp := range secretPatterns {
			locs := sp.re.FindAllIndex(data, 5)
			if len(locs) == 0 {
				continue
			}
			out = append(out, schema.Finding{
				RuleID:   "POTENTIAL_SECRET_EXPOSURE",
				Severity: "HIGH",
				Title:    "Credential Material in Agent Conversation",
				Description: fmt.Sprintf("%s detected %d time(s) inside an agent transcript/history — content of this type passes through the model provider. Value: [REDACTED]",
					sp.name, len(locs)),
				EvidenceRefs: []string{fmt.Sprintf("%s (artifact %.12s, first match at byte offset %d)",
					a.LogicalPath, a.ArtifactID, locs[0][0])},
				Status:        schema.StateObserved,
				Endpoint:      schema.StateUnknown,
				MitreATTACK:   "T1552", // Unsecured Credentials
				FalsePositive: "Pattern matches can hit synthetic/test keys; verify against the referenced offset with inspect --reveal-sensitive.",
			})
		}
	}
	return out
}

func boundedBlob(pkgDir, artifactID string) ([]byte, error) {
	path := filepath.Join(pkgDir, "raw", artifactID)
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > blobScanBound {
		return nil, fmt.Errorf("blob exceeds scan bound")
	}
	return os.ReadFile(path)
}
