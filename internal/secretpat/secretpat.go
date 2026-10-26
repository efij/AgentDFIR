// Package secretpat holds the credential formats AgentDFIR recognizes:
// the table the SECRET detection rules (internal/detect) match and
// derivative redaction (internal/redact) masks. It is a leaf package so
// parsers can mask values without depending on the detection engine.
package secretpat

import "regexp"

// Pattern is one credential format. Lit is a literal every match contains,
// used as a cheap prefilter.
type Pattern struct {
	Name string
	Lit  string
	Re   *regexp.Regexp
}

// Patterns are the credential formats in rule order. The regexps are
// shared and safe for concurrent use; callers must not modify the slice.
var Patterns = []Pattern{
	{"AWS_ACCESS_KEY", "AKIA", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GITHUB_TOKEN", "ghp_", regexp.MustCompile(`\bghp_[A-Za-z0-9]{36}\b`)},
	{"GITHUB_FINE_GRAINED_TOKEN", "github_pat_", regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{22,}\b`)},
	{"SLACK_TOKEN", "xox", regexp.MustCompile(`\bxox[bpars]-[A-Za-z0-9-]{10,}\b`)},
	{"ANTHROPIC_API_KEY", "sk-ant-", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}\b`)},
	{"OPENAI_API_KEY", "sk-", regexp.MustCompile(`\bsk-[A-Za-z0-9_-]{20,}\b`)},
	{"GOOGLE_API_KEY", "AIza", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"ALIBABA_ACCESS_KEY", "LTAI", regexp.MustCompile(`\bLTAI[0-9A-Za-z]{12,20}\b`)},
	{"TENCENT_SECRET_ID", "AKID", regexp.MustCompile(`\bAKID[0-9A-Za-z]{32}\b`)},
	{"PRIVATE_KEY_BLOCK", "-----BEGIN ", regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},
	{"JWT", "eyJ", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
}
