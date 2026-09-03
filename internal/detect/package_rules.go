// Package-aware detection rules (plan §14: the rule input contract is
// the whole package — events alone cannot express these). All content
// scans stream (see scan.go) so artifact size never causes a skip.
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

// Options tunes package-aware detection.
type Options struct {
	Honeytokens       []string
	SpawnThreshold    int      // AGENT_SPAWN_EXPLOSION per-session threshold (default 10)
	KnownDestinations []string // additional allowlisted network destinations
}

// RunPackage evaluates event rules plus package-aware rules.
func RunPackage(res *schema.Normalized, pkgDir string) []schema.Finding {
	return RunPackageWithOptions(res, pkgDir, nil)
}

// RunPackageWithOptions keeps the historical signature (honeytokens only).
func RunPackageWithOptions(res *schema.Normalized, pkgDir string, honeytokens []string) []schema.Finding {
	return RunAll(res, pkgDir, Options{Honeytokens: honeytokens})
}

// RunAll is the full deterministic rule set: event rules, package
// content scans, and the v0.5.0 behavioral/integrity rules.
func RunAll(res *schema.Normalized, pkgDir string, opts Options) []schema.Finding {
	findings := Run(res)
	man, err := readManifest(pkgDir)
	if err == nil {
		findings = append(findings, permissionBypass(man, pkgDir)...)
		findings = append(findings, permissionEscalation(man, pkgDir)...)
		findings = append(findings, secretExposure(man, pkgDir)...)
		findings = append(findings, promptInjectionIndicator(man, pkgDir)...)
		findings = append(findings, invisibleUnicodeInstruction(man, pkgDir)...)
		if len(opts.Honeytokens) > 0 {
			findings = append(findings, HoneytokenFindings(man, pkgDir, opts.Honeytokens)...)
		}
		findings = append(findings, behavioralRules(res, man, opts)...)
		findings = append(findings, integrityRules(res, man)...)
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

func isType(a casepkg.ArtifactRecord, types ...string) bool {
	if a.Status != casepkg.StatusOK {
		return false
	}
	for _, t := range types {
		if a.ArtifactType == t {
			return true
		}
	}
	return false
}

func artRef(a casepkg.ArtifactRecord, off int64) string {
	return fmt.Sprintf("%s (artifact %.12s, byte offset %d)", a.LogicalPath, a.ArtifactID, off)
}

// bypassMarkers are config values that disable permission/sandbox controls.
var bypassMarkers = []string{
	`"defaultMode": "bypassPermissions"`,
	`"defaultMode":"bypassPermissions"`,
	`"dangerouslySkipPermissions"`,
	`approval_policy = "never"`,
	`sandbox_mode = "danger-full-access"`,
	`"yolo": true`,
	`"yolo":true`,
}

// PERMISSION_BYPASS_ENABLED — configuration disables permission prompting
// or sandboxing entirely.
func permissionBypass(man *casepkg.Manifest, pkgDir string) []schema.Finding {
	var out []schema.Finding
	for _, a := range man.Artifacts {
		if !isType(a, "product_config", "managed_config") {
			continue
		}
		marker, off, ok := scanContains(blobPath(pkgDir, a.ArtifactID), bypassMarkers)
		if !ok {
			continue
		}
		out = append(out, schema.Finding{
			RuleID:        "PERMISSION_BYPASS_ENABLED",
			Severity:      "HIGH",
			Title:         "Permission/Sandbox Controls Disabled",
			Description:   "Collected configuration disables permission prompting or sandboxing: " + marker,
			EvidenceRefs:  []string{artRef(a, off)},
			Status:        schema.StateObserved,
			Endpoint:      schema.StateUnknown,
			MitreATTACK:   "T1562.001", // Impair Defenses: Disable or Modify Tools
			MitreATLAS:    "AML.T0081", // Modify AI Agent Configuration
			FalsePositive: "Developers legitimately enable bypass modes on trusted machines; assess against org policy.",
		})
	}
	return out
}

// escalationMarkers grant blanket tool permissions without per-command review.
var escalationMarkers = []string{`"Bash(*)"`, `"Bash(*:*)"`, `"allow": ["*"]`, `"allow":["*"]`, `"Bash"`}

// PERMISSION_ESCALATION — blanket allow rules.
func permissionEscalation(man *casepkg.Manifest, pkgDir string) []schema.Finding {
	var out []schema.Finding
	for _, a := range man.Artifacts {
		if !isType(a, "product_config", "managed_config") {
			continue
		}
		marker, off, ok := scanContains(blobPath(pkgDir, a.ArtifactID), escalationMarkers)
		if !ok {
			continue
		}
		out = append(out, schema.Finding{
			RuleID:        "PERMISSION_ESCALATION",
			Severity:      "MEDIUM",
			Title:         "Blanket Tool Permission Granted",
			Description:   "Configuration grants wildcard/blanket tool permission (" + marker + "), removing per-command review.",
			EvidenceRefs:  []string{artRef(a, off)},
			Status:        schema.StateObserved,
			Endpoint:      schema.StateUnknown,
			MitreATTACK:   "T1562.001",
			MitreATLAS:    "AML.T0081",
			FalsePositive: "Intentional on sandboxed CI hosts; compare against the org baseline (agentdfir baseline check).",
		})
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
	{"ANTHROPIC_API_KEY", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{"OPENAI_API_KEY", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`)},
	{"GOOGLE_API_KEY", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"PRIVATE_KEY_BLOCK", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"JWT", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
}

// SecretKind classifies a value against the well-known credential formats
// and returns the category name (never the value). Used by the MCP audit
// for inline env/header values in server configs.
func SecretKind(value string) (string, bool) {
	for _, p := range secretPatterns {
		if p.re.MatchString(value) {
			return p.name, true
		}
	}
	return "", false
}

// POTENTIAL_SECRET_EXPOSURE — credential material inside agent
// conversations (it passed through the model provider).
func secretExposure(man *casepkg.Manifest, pkgDir string) []schema.Finding {
	var out []schema.Finding
	for _, a := range man.Artifacts {
		if !isType(a, "agent_session", "prompt_history") {
			continue
		}
		hits, counts := scanRegex(blobPath(pkgDir, a.ArtifactID), secretPatterns)
		for _, h := range hits {
			out = append(out, schema.Finding{
				RuleID:   "POTENTIAL_SECRET_EXPOSURE",
				Severity: "HIGH",
				Title:    "Credential Material in Agent Conversation",
				Description: fmt.Sprintf("%s detected %d time(s) inside an agent transcript/history — content of this type passes through the model provider. Value: [REDACTED]",
					h.name, counts[h.name]),
				EvidenceRefs:  []string{artRef(a, h.offset)},
				Status:        schema.StateObserved,
				Endpoint:      schema.StateUnknown,
				MitreATLAS:    "AML.T0057", // LLM Data Leakage
				MitreATTACK:   "T1552",     // Unsecured Credentials
				FalsePositive: "Pattern matches can hit synthetic/test keys; verify at the referenced offset with inspect --reveal-sensitive.",
			})
		}
	}
	return out
}

// sensitivePathRe flags reads of well-known credential/config locations.
var sensitivePathRe = regexp.MustCompile(`(?i)(\.ssh/|id_rsa|id_ed25519|authorized_keys|\.aws/credentials|\.netrc|\.kube/config|/etc/shadow|\.gnupg/|\.npmrc|\.pypirc|\.docker/config\.json|\.env\b|keychain|wallet\.dat|\.gcloud/|\.azure/|credentials\.json|token\.json)`)

func containsSensitivePath(s string) (string, bool) {
	m := sensitivePathRe.FindString(s)
	return m, m != ""
}

func lowerHas(s string, subs ...string) bool {
	l := strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}
