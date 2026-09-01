// Package rulepack implements declarative, shareable detection rules
// (plan §14, killer feature #4 — Sigma-style shareability). Rules are
// JSON documents loadable at triage time (`--rules <dir>`); no code
// changes are needed to add org- or community-specific detections.
//
// Rule inputs follow the whole-package contract: rules can match
// normalized event fields (command, summary) or raw artifact content
// (config, transcript). All matching is deterministic; matched VALUES
// from secret-like rules are never echoed into findings.
package rulepack

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

// Rule is one declarative detection.
type Rule struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Description   string   `json:"description"`
	Severity      string   `json:"severity"`   // INFO|LOW|MEDIUM|HIGH|CRITICAL
	Confidence    string   `json:"confidence"` // low|medium|high
	Match         Match    `json:"match"`
	FalsePositive string   `json:"false_positive_notes"`
	References    []string `json:"references,omitempty"`
	MitreATLAS    string   `json:"mitre_atlas,omitempty"`
	MitreATTACK   string   `json:"mitre_attack,omitempty"`

	re *regexp.Regexp
}

// Match declares what a rule inspects.
//
//	type: "command"    — tool-call command lines (normalized events)
//	      "summary"    — event summaries
//	      "config"     — raw config-category artifact content
//	      "transcript" — raw agent_session / prompt_history content
type Match struct {
	Type     string   `json:"type"`
	Contains []string `json:"contains,omitempty"` // any-of, case-insensitive
	Regex    string   `json:"regex,omitempty"`
}

// Pack is a versioned collection of rules.
type Pack struct {
	Pack    string `json:"pack"`
	Version string `json:"version"`
	Rules   []Rule `json:"rules"`
}

const maxRegexLen = 2048 // hostile-pack guard

var validSev = map[string]bool{"INFO": true, "LOW": true, "MEDIUM": true, "HIGH": true, "CRITICAL": true}
var validType = map[string]bool{"command": true, "summary": true, "config": true, "transcript": true}

// LoadDir loads and validates every *.json pack in dir.
func LoadDir(dir string) ([]Pack, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var packs []Pack
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		p, err := LoadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		packs = append(packs, *p)
	}
	return packs, nil
}

// LoadFile loads and validates one pack.
func LoadFile(path string) (*Pack, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Pack
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("invalid pack JSON: %w", err)
	}
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID == "" || r.Title == "" {
			return nil, fmt.Errorf("rule %d: id and title are required", i)
		}
		if !validSev[r.Severity] {
			return nil, fmt.Errorf("rule %s: invalid severity %q", r.ID, r.Severity)
		}
		if !validType[r.Match.Type] {
			return nil, fmt.Errorf("rule %s: invalid match.type %q", r.ID, r.Match.Type)
		}
		if r.FalsePositive == "" {
			return nil, fmt.Errorf("rule %s: false_positive_notes is mandatory", r.ID)
		}
		if len(r.Match.Contains) == 0 && r.Match.Regex == "" {
			return nil, fmt.Errorf("rule %s: match needs contains or regex", r.ID)
		}
		if r.Match.Regex != "" {
			if len(r.Match.Regex) > maxRegexLen {
				return nil, fmt.Errorf("rule %s: regex exceeds %d bytes", r.ID, maxRegexLen)
			}
			re, err := regexp.Compile(r.Match.Regex)
			if err != nil {
				return nil, fmt.Errorf("rule %s: bad regex: %w", r.ID, err)
			}
			r.re = re
		}
	}
	return &p, nil
}

// Apply evaluates packs against a normalized result + sealed package.
func Apply(packs []Pack, res *schema.Normalized, pkgDir string) ([]schema.Finding, error) {
	var out []schema.Finding
	var man *casepkg.Manifest
	for _, p := range packs {
		for i := range p.Rules {
			r := &p.Rules[i]
			switch r.Match.Type {
			case "command", "summary":
				out = append(out, matchEvents(r, res)...)
			case "config", "transcript":
				if man == nil {
					m, err := readManifest(pkgDir)
					if err != nil {
						return out, err
					}
					man = m
				}
				out = append(out, matchArtifacts(r, man, pkgDir)...)
			}
		}
	}
	return out, nil
}

func matchEvents(r *Rule, res *schema.Normalized) []schema.Finding {
	var out []schema.Finding
	for _, ev := range res.Events {
		var subject string
		switch r.Match.Type {
		case "command":
			subject = ev.Command
		case "summary":
			subject = ev.Summary
		}
		if subject == "" || !matches(r, subject) {
			continue
		}
		out = append(out, finding(r, ev.SessionID, ev.AgentID, ev.Corroboration,
			fmt.Sprintf("%s:%d (artifact %.12s)", ev.SourcePath, ev.SourceLine, ev.SourceArtifact)))
	}
	return out
}

func matchArtifacts(r *Rule, man *casepkg.Manifest, pkgDir string) []schema.Finding {
	wantTypes := map[string]bool{}
	if r.Match.Type == "config" {
		wantTypes["product_config"] = true
		wantTypes["managed_config"] = true
		wantTypes["agent_definitions"] = true
		wantTypes["agent_instructions"] = true
	} else {
		wantTypes["agent_session"] = true
		wantTypes["prompt_history"] = true
	}
	var out []schema.Finding
	for _, a := range man.Artifacts {
		if a.Status != casepkg.StatusOK || !wantTypes[a.ArtifactType] {
			continue
		}
		data, err := boundedRead(filepath.Join(pkgDir, "raw", a.ArtifactID), 16<<20)
		if err != nil {
			continue
		}
		if !matches(r, string(data)) {
			continue
		}
		out = append(out, finding(r, "", "", schema.StateObserved,
			fmt.Sprintf("%s (artifact %.12s)", a.LogicalPath, a.ArtifactID)))
	}
	return out
}

func matches(r *Rule, s string) bool {
	if r.re != nil && r.re.MatchString(s) {
		return true
	}
	low := strings.ToLower(s)
	for _, c := range r.Match.Contains {
		if strings.Contains(low, strings.ToLower(c)) {
			return true
		}
	}
	return false
}

func finding(r *Rule, session, agent, status, evidence string) schema.Finding {
	return schema.Finding{
		RuleID:        r.ID,
		Severity:      r.Severity,
		Title:         r.Title,
		Description:   r.Description,
		SessionID:     session,
		AgentID:       agent,
		EvidenceRefs:  []string{evidence},
		Status:        status,
		Endpoint:      schema.StateUnknown,
		MitreATLAS:    r.MitreATLAS,
		MitreATTACK:   r.MitreATTACK,
		FalsePositive: r.FalsePositive,
	}
}

func boundedRead(path string, max int64) ([]byte, error) {
	st, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if st.Size() > max {
		return nil, fmt.Errorf("blob exceeds bound")
	}
	return os.ReadFile(path)
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
