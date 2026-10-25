package detect

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"path"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v3/internal/accounts"
	"github.com/efij/AgentDFIR/v3/internal/artmemo"
	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// secretSighting is one credential-shaped value seen in one artifact,
// remembered by fingerprint only. The value itself never leaves the scan.
type secretSighting struct {
	FP   string `json:"fp"`   // first 16 hex digits of SHA-256 of the value
	Kind string `json:"kind"` // secretPatterns name
	Off  int64  `json:"off"`  // first byte offset in the artifact
}

// maxSightings bounds what one artifact can contribute.
const maxSightings = 256

// SecretFingerprint is the one-way fingerprint secret-reuse findings name:
// enough to say "the same value", never enough to recover it.
func SecretFingerprint(value []byte) string {
	h := sha256.Sum256(value)
	return hex.EncodeToString(h[:8])
}

// scanSightings streams one artifact and fingerprints every credential the
// POTENTIAL_SECRET_EXPOSURE patterns accept (placeholders excluded). Key
// headers say nothing about which key follows, so they are not
// fingerprinted.
func scanSightings(store *casepkg.Store, a casepkg.ArtifactRecord) []secretSighting {
	seen := map[string]bool{}
	var out []secretSighting
	_ = streamChunks(blobReader{store, a.ArtifactID}, func(chunk []byte, base int64) bool {
		for _, p := range secretPatterns {
			if p.name == "PRIVATE_KEY_BLOCK" {
				continue
			}
			for _, at := range anchoredMatches(chunk, p) {
				if base > 0 && int64(at) < scanOverlap {
					continue // already seen at the end of the previous chunk
				}
				lo := at - 1
				if lo < 0 {
					lo = 0
				}
				hi := at + anchorWindow
				if hi > len(chunk) {
					hi = len(chunk)
				}
				loc := p.re.FindIndex(chunk[lo:hi])
				if loc == nil {
					continue
				}
				v := chunk[lo+loc[0] : lo+loc[1]]
				if isPlaceholderSecret(v) {
					continue
				}
				fp := SecretFingerprint(v)
				if seen[fp] {
					continue
				}
				seen[fp] = true
				out = append(out, secretSighting{FP: fp, Kind: p.name, Off: base + int64(at)})
				if len(out) >= maxSightings {
					return false
				}
			}
		}
		return true
	})
	return out
}

// secretContext is where a transcript sits: product, login profile and
// project. Two artifacts in the same context may be one conversation
// (resumed, continued, a subagent of it); two contexts are unrelated work.
type secretContext struct {
	key, product, profile, project string
	art                            casepkg.ArtifactRecord
	off                            int64
}

// AGENT_CROSS_SESSION_SECRET_REUSE — the same credential (by fingerprint)
// appears in transcripts of unrelated work: different projects, products
// or AI logins. POTENTIAL_SECRET_EXPOSURE reports each transcript on its
// own; this rule links them, which is how one leaked key is told apart from
// several. Cross-case linking is `correlate-cases`' job, not this rule's.
func crossSessionSecretReuse(events []schema.Event, pkgDir string, man *casepkg.Manifest, store *casepkg.Store) []schema.Finding {
	// The project of a transcript is the working directory its records
	// name; the path is the fallback.
	cwd := map[string]string{}
	for _, e := range events {
		if e.Cwd != "" && e.SourceArtifact != "" {
			if _, ok := cwd[e.SourceArtifact]; !ok {
				cwd[e.SourceArtifact] = e.Cwd
			}
		}
	}
	var cur []casepkg.ArtifactRecord
	for _, a := range man.Current() {
		if isType(a, "agent_session", "prompt_history") && a.ArtifactID != "" {
			cur = append(cur, a)
		}
	}
	memo := artmemo.Open[[]secretSighting](pkgDir, "detect-secret-reuse", "v1")
	per := make([][]secretSighting, len(cur))
	forEachParallel(len(cur), func(i int) {
		if m, ok := memo.Get(cur[i]); ok {
			per[i] = m
			return
		}
		per[i] = scanSightings(store, cur[i])
		memo.Put(cur[i], per[i])
	})
	_ = memo.Save() // advisory, like the content-scan memo

	type entry struct {
		kind  string
		ctxs  map[string]*secretContext
		order []string
	}
	byFP := map[string]*entry{}
	var fps []string
	for i, a := range cur {
		if len(per[i]) == 0 {
			continue
		}
		project := cwd[a.ArtifactID]
		if project == "" {
			project = projectOf(a.LogicalPath)
		}
		profile := accounts.Key(a.LogicalPath, a.Product)
		key := a.Product + "|" + profile + "|" + project
		for _, s := range per[i] {
			en := byFP[s.FP]
			if en == nil {
				en = &entry{kind: s.Kind, ctxs: map[string]*secretContext{}}
				byFP[s.FP] = en
				fps = append(fps, s.FP)
			}
			if _, ok := en.ctxs[key]; !ok {
				en.ctxs[key] = &secretContext{key: key, product: a.Product, profile: profile, project: project, art: a, off: s.Off}
				en.order = append(en.order, key)
			}
		}
	}
	sort.Strings(fps)
	var out []schema.Finding
	for _, fp := range fps {
		en := byFP[fp]
		if len(en.ctxs) < 2 {
			continue
		}
		products, profiles := map[string]bool{}, map[string]bool{}
		var where, refs []string
		for _, k := range en.order {
			c := en.ctxs[k]
			products[c.product], profiles[c.profile] = true, true
			if len(refs) < 5 {
				refs = append(refs, artRef(c.art, c.off))
				where = append(where, fmt.Sprintf("%s %s (%s)", c.product, c.project, c.profile))
			}
		}
		sev, conf := "MEDIUM", "MEDIUM"
		reasons := []string{"the same SHA-256 fingerprint was computed from credential-shaped values in each transcript; the value itself is not stored"}
		if len(products) > 1 || len(profiles) > 1 {
			sev = "HIGH"
			reasons = append(reasons, "the transcripts belong to different products or AI logins")
		}
		out = append(out, schema.Finding{
			RuleID: "AGENT_CROSS_SESSION_SECRET_REUSE", Severity: sev,
			Title: "Same Credential Seen in Unrelated Agent Sessions",
			Description: fmt.Sprintf("A %s with fingerprint sha256:%s… appears in %d unrelated contexts: %s. One secret moved between pieces of work, so it may have left the place it was issued for. Value: [REDACTED]",
				en.kind, fp, len(en.ctxs), strings.Join(where, "; ")),
			EvidenceRefs: refs,
			Status:       schema.StateObserved, Endpoint: schema.StateUnknown,
			MitreATTACK: "T1552", MitreATLAS: "AML.T0057",
			Confidence: conf, Reasons: reasons,
			FalsePositive: "A shared development token used on purpose in several projects, or one person's key pasted into two of their own sessions. Ask who owns the credential and where it is meant to be used.",
		})
	}
	return out
}

// projectOf names the project a transcript belongs to from its path:
// the directory under projects/ for Claude-style layouts, the parent
// directory otherwise.
func projectOf(logical string) string {
	p := strings.TrimPrefix(logical, "/")
	if i := strings.Index(p, "projects/"); i >= 0 {
		rest := p[i+len("projects/"):]
		if j := strings.IndexByte(rest, '/'); j > 0 {
			return rest[:j]
		}
	}
	return path.Dir(p)
}
