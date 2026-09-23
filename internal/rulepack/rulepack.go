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
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/schema"
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
	return parsePack(data)
}

// validatePack checks one pack's rules and compiles their regexes. Shared
// by the filesystem and embedded loaders so a pack cannot pass one and fail
// the other.
func validatePack(p *Pack) error {
	for i := range p.Rules {
		r := &p.Rules[i]
		if r.ID == "" || r.Title == "" {
			return fmt.Errorf("rule %d: id and title are required", i)
		}
		if !validSev[r.Severity] {
			return fmt.Errorf("rule %s: invalid severity %q", r.ID, r.Severity)
		}
		if !validType[r.Match.Type] {
			return fmt.Errorf("rule %s: invalid match.type %q", r.ID, r.Match.Type)
		}
		if r.FalsePositive == "" {
			return fmt.Errorf("rule %s: false_positive_notes is mandatory", r.ID)
		}
		if len(r.Match.Contains) == 0 && r.Match.Regex == "" {
			return fmt.Errorf("rule %s: match needs contains or regex", r.ID)
		}
		if r.Match.Regex != "" {
			if len(r.Match.Regex) > maxRegexLen {
				return fmt.Errorf("rule %s: regex exceeds %d bytes", r.ID, maxRegexLen)
			}
			re, err := regexp.Compile(r.Match.Regex)
			if err != nil {
				return fmt.Errorf("rule %s: bad regex: %w", r.ID, err)
			}
			r.re = re
		}
	}
	return nil
}

// artifactReads counts artifacts read by Apply. A test pins it to one per
// artifact: the store used to be read once per artifact-scoped rule, ten
// full passes with the shipped packs.
var artifactReads atomic.Int64

// matchWorkers bounds the artifacts matched at once. Each holds one
// artifact (16 MB at most) and its lowercase copy.
func matchWorkers() int {
	n := runtime.GOMAXPROCS(0)
	if n > 8 {
		n = 8
	}
	if n < 1 {
		n = 1
	}
	return n
}

// Apply evaluates packs against a normalized result + sealed package.
func Apply(packs []Pack, res *schema.Normalized, pkgDir string) ([]schema.Finding, error) {
	var out []schema.Finding
	var artRules []*Rule
	for _, p := range packs {
		for i := range p.Rules {
			r := &p.Rules[i]
			switch r.Match.Type {
			case "command", "summary":
				out = append(out, matchEvents(r, res)...)
			case "config", "transcript":
				artRules = append(artRules, r)
			}
		}
	}
	if len(artRules) > 0 {
		man, err := readManifest(pkgDir)
		if err != nil {
			return out, err
		}
		out = append(out, matchArtifacts(artRules, man, casepkg.NewStore(pkgDir, man))...)
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

// artifactClass names the match type whose rules inspect this artifact.
func artifactClass(a casepkg.ArtifactRecord) string {
	switch a.ArtifactType {
	case "product_config", "managed_config", "agent_definitions", "agent_instructions":
		return "config"
	case "agent_session", "prompt_history":
		return "transcript"
	}
	return ""
}

// matchArtifacts reads each artifact once and evaluates every rule of its
// class against it. The lowercased copy for "contains" rules is made once
// per artifact too, not once per rule. Binaries are skipped: a content
// rule's phrase or regex inside a .pptx or a node_modules blob is noise,
// and the other content rules already stay off them.
func matchArtifacts(rules []*Rule, man *casepkg.Manifest, store *casepkg.Store) []schema.Finding {
	cur := man.Current()
	results := make([][]schema.Finding, len(cur))
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < matchWorkers(); w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				results[i] = matchOneArtifact(rules, cur[i], store)
			}
		}()
	}
	for i := range cur {
		next <- i
	}
	close(next)
	wg.Wait()
	var out []schema.Finding
	for _, r := range results {
		out = append(out, r...)
	}
	return out
}

// matchOneArtifact evaluates every rule of the artifact's class against it.
func matchOneArtifact(rules []*Rule, a casepkg.ArtifactRecord, store *casepkg.Store) []schema.Finding {
	if a.Status != casepkg.StatusOK {
		return nil
	}
	class := artifactClass(a)
	if class == "" {
		return nil
	}
	var applicable []*Rule
	for _, r := range rules {
		if r.Match.Type == class {
			applicable = append(applicable, r)
		}
	}
	if len(applicable) == 0 || !store.IsText(a) {
		return nil
	}
	data, err := store.ReadAll(a.ArtifactID, 16<<20)
	if err != nil {
		return nil
	}
	artifactReads.Add(1)
	s := string(data)
	low := ""
	var out []schema.Finding
	for _, r := range applicable {
		if len(r.Match.Contains) > 0 && low == "" {
			low = strings.ToLower(s)
		}
		if !matchesPrepared(r, s, low) {
			continue
		}
		out = append(out, finding(r, "", "", schema.StateObserved,
			fmt.Sprintf("%s (artifact %.12s)", a.LogicalPath, a.ArtifactID)))
	}
	return out
}

func matches(r *Rule, s string) bool {
	low := ""
	if len(r.Match.Contains) > 0 {
		low = strings.ToLower(s)
	}
	return matchesPrepared(r, s, low)
}

// matchesPrepared is matches with the lowercased subject supplied by the
// caller, so one artifact is lowercased once for all its rules.
func matchesPrepared(r *Rule, s, low string) bool {
	if r.re != nil && r.re.MatchString(s) {
		return true
	}
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

// readManifest reads the package manifest in whichever form it was
// written (append-only manifest.jsonl, or the legacy manifest.json array).
func readManifest(pkgDir string) (*casepkg.Manifest, error) {
	return casepkg.ReadManifest(pkgDir)
}
