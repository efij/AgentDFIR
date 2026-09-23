package detect

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/efij/AgentDFIR/v2/internal/casepkg"
	"github.com/efij/AgentDFIR/v2/internal/schema"
)

// The content rules — credential formats, injection phrases, invisible
// Unicode, honeytokens — each used to stream every transcript on their
// own: four reads of the same 2 GB. contentScans reads each artifact once
// and feeds every rule that applies to it from the same chunks, with
// artifacts scanned in parallel. Findings come out in the order the four
// separate passes produced them (all secret findings, then injection,
// then Unicode, then honeytokens), each group in manifest order, so the
// result is identical to the sequential passes.

// scanWorkers bounds the artifacts in flight. Each holds one chunk plus
// its lowercase copy, so memory stays a few MB per worker.
func scanWorkers() int {
	n := runtime.GOMAXPROCS(0)
	if n > 8 {
		n = 8
	}
	if n < 1 {
		n = 1
	}
	return n
}

// forEachParallel runs fn(i) for i in [0, n) on scanWorkers goroutines.
// Results are the caller's: index into a preallocated slice.
func forEachParallel(n int, fn func(i int)) {
	workers := scanWorkers()
	if workers > n {
		workers = n
	}
	if workers <= 1 {
		for i := 0; i < n; i++ {
			fn(i)
		}
		return
	}
	var wg sync.WaitGroup
	next := make(chan int)
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range next {
				fn(i)
			}
		}()
	}
	for i := 0; i < n; i++ {
		next <- i
	}
	close(next)
	wg.Wait()
}

// secretAcc accumulates credential-format hits across chunks.
type secretAcc struct {
	patterns []secretPattern
	counts   map[string]int
	first    map[string]int64
}

func newSecretAcc(patterns []secretPattern) *secretAcc {
	return &secretAcc{patterns: patterns, counts: map[string]int{}, first: map[string]int64{}}
}

func (s *secretAcc) feed(chunk []byte, base int64) {
	for _, p := range s.patterns {
		for _, start := range anchoredMatches(chunk, p) {
			if base > 0 && start < scanOverlap {
				continue // already counted in previous chunk
			}
			m := p.re.Find(chunk[start:])
			if isPlaceholderSecret(m) || (p.name == "PRIVATE_KEY_BLOCK" && !privateKeyHasBody(chunk[start+len(m):])) {
				continue // documentation example or an elided key, not a credential
			}
			s.counts[p.name]++
			if _, seen := s.first[p.name]; !seen {
				s.first[p.name] = base + int64(start)
			}
		}
	}
}

// hits returns one hit per pattern that matched, in pattern order.
func (s *secretAcc) hits() []scanHit {
	var out []scanHit
	for _, p := range s.patterns {
		if off, ok := s.first[p.name]; ok {
			out = append(out, scanHit{name: p.name, offset: off})
		}
	}
	return out
}

// phraseAcc finds the first occurrence (case-insensitive) of any phrase.
type phraseAcc struct {
	phrases []string
	lower   []string
	phrase  string
	offset  int64
	found   bool
}

func newPhraseAcc(phrases []string) *phraseAcc {
	a := &phraseAcc{phrases: phrases, lower: make([]string, len(phrases))}
	for i, p := range phrases {
		a.lower[i] = strings.ToLower(p)
	}
	return a
}

// feed reports whether the scan is finished (a phrase was found).
func (a *phraseAcc) feed(chunk []byte, base int64) bool {
	if a.found {
		return true
	}
	low := strings.ToLower(string(chunk))
	for i, p := range a.lower {
		if idx := strings.Index(low, p); idx >= 0 {
			if base > 0 && idx < scanOverlap {
				continue
			}
			a.phrase, a.offset, a.found = a.phrases[i], base+int64(idx), true
			return true
		}
	}
	return false
}

// containsAcc finds the first occurrence of any exact marker.
type containsAcc struct {
	markers [][]byte
	names   []string
	marker  string
	offset  int64
	found   bool
}

func newContainsAcc(markers []string) *containsAcc {
	a := &containsAcc{}
	for _, m := range markers {
		if m == "" {
			continue
		}
		a.markers = append(a.markers, []byte(m))
		a.names = append(a.names, m)
	}
	return a
}

// feed reports whether the scan is finished (a marker was found).
func (a *containsAcc) feed(chunk []byte, base int64) bool {
	if a.found {
		return true
	}
	for i, m := range a.markers {
		if idx := bytes.Index(chunk, m); idx >= 0 {
			if base > 0 && idx < scanOverlap {
				continue
			}
			a.marker, a.offset, a.found = a.names[i], base+int64(idx), true
			return true
		}
	}
	return false
}

// unicodeAcc counts invisible/reordering runes across an artifact.
type unicodeAcc struct {
	tags, bidi, zw int
	firstOff       int64 // -1 until the first hit
}

func newUnicodeAcc() *unicodeAcc { return &unicodeAcc{firstOff: -1} }

func (u *unicodeAcc) feed(chunk []byte, base int64) {
	start := 0
	if base > 0 {
		start = scanOverlap
	}
	// Decode in place. This runs over every byte of every artifact, so
	// it stays on the byte slice: ranging over string(chunk) would copy
	// a megabyte per chunk, and every non-ASCII rune would allocate
	// again to measure its width. Single-byte runes — nearly all of
	// transcript evidence — never reach the Unicode tables.
	for off := start; off < len(chunk); {
		c := chunk[off]
		if c < utf8.RuneSelf {
			off++
			continue
		}
		r, size := utf8.DecodeRune(chunk[off:])
		hit := false
		switch {
		case r >= 0xE0000 && r <= 0xE007F:
			u.tags++
			hit = true
		case (r >= 0x202A && r <= 0x202E) || (r >= 0x2066 && r <= 0x2069):
			u.bidi++
			hit = true
		case r >= 0x200B && r <= 0x200F, r == 0xFEFF:
			u.zw++
			hit = true
		case unicode.Is(unicode.Cf, r) && r != '­':
			u.zw++
			hit = true
		}
		if hit && u.firstOff == -1 {
			u.firstOff = base + int64(off)
		}
		off += size
	}
}

// contentFindings is one artifact's share of each content rule's output.
type contentFindings struct {
	secret, injection, unicode, honey []schema.Finding
}

// contentScans runs POTENTIAL_SECRET_EXPOSURE, the injection-surface
// rules, INVISIBLE_UNICODE_INSTRUCTION and SECRET_ACCESS (honeytokens)
// with one read of each artifact.
func contentScans(man *casepkg.Manifest, pkgDir string, honeytokens []string) []schema.Finding {
	store := casepkg.NewStore(pkgDir, man)
	cur := man.Current()
	results := make([]contentFindings, len(cur))
	forEachParallel(len(cur), func(i int) {
		results[i] = scanArtifactContent(store, cur[i], honeytokens)
	})
	var secret, injection, uni, honey []schema.Finding
	for _, r := range results {
		secret = append(secret, r.secret...)
		injection = append(injection, r.injection...)
		uni = append(uni, r.unicode...)
		honey = append(honey, r.honey...)
	}
	out := append(secret, injection...)
	out = append(out, uni...)
	return append(out, honey...)
}

// scanArtifactContent decides which content rules apply to one artifact,
// streams it once, and builds their findings.
func scanArtifactContent(store *casepkg.Store, a casepkg.ArtifactRecord, honeytokens []string) contentFindings {
	var res contentFindings
	conversation := isType(a, "agent_session", "prompt_history")
	wantSecret := conversation
	wantHoney := conversation && len(honeytokens) > 0
	var surface *surfaceRule
	if !selfReferentialPath(a.LogicalPath) {
		for i := range injectionSurfaces {
			if isType(a, injectionSurfaces[i].types...) {
				surface = &injectionSurfaces[i]
				break
			}
		}
	}
	wantUnicode := isType(a, "agent_session", "prompt_history", "agent_instructions", "agent_definitions")
	// The text gate belongs to the instruction-content rules only; the
	// credential and honeytoken scans never had one.
	if (surface != nil || wantUnicode) && !store.IsText(a) {
		surface, wantUnicode = nil, false
	}
	if !wantSecret && !wantHoney && surface == nil && !wantUnicode {
		return res
	}

	var sa *secretAcc
	var pa *phraseAcc
	var ca *containsAcc
	var ua *unicodeAcc
	if wantSecret {
		sa = newSecretAcc(secretPatterns)
	}
	if surface != nil {
		pa = newPhraseAcc(injectionPhrases)
	}
	if wantHoney {
		ca = newContainsAcc(honeytokens)
	}
	if wantUnicode {
		ua = newUnicodeAcc()
	}
	_ = streamChunks(blobReader{store, a.ArtifactID}, func(chunk []byte, base int64) bool {
		more := false
		if sa != nil {
			sa.feed(chunk, base)
			more = true
		}
		if ua != nil {
			ua.feed(chunk, base)
			more = true
		}
		if pa != nil && !pa.feed(chunk, base) {
			more = true
		}
		if ca != nil && !ca.feed(chunk, base) {
			more = true
		}
		return more
	})

	if sa != nil {
		for _, h := range sa.hits() {
			res.secret = append(res.secret, schema.Finding{
				RuleID:   "POTENTIAL_SECRET_EXPOSURE",
				Severity: "HIGH",
				Title:    "Credential Material in Agent Conversation",
				Description: fmt.Sprintf("%s detected %d time(s) inside an agent transcript/history — content of this type passes through the model provider. Value: [REDACTED]",
					h.name, sa.counts[h.name]),
				EvidenceRefs:  []string{artRef(a, h.offset)},
				Status:        schema.StateObserved,
				Endpoint:      schema.StateUnknown,
				MitreATLAS:    "AML.T0057", // LLM Data Leakage
				MitreATTACK:   "T1552",     // Unsecured Credentials
				FalsePositive: "Pattern matches can hit synthetic/test keys; verify at the referenced offset with inspect --reveal-sensitive.",
			})
		}
	}
	if pa != nil && pa.found {
		res.injection = append(res.injection, schema.Finding{
			RuleID:        surface.ruleID,
			Severity:      severityFor(surface.ruleID),
			Title:         surface.title,
			Description:   fmt.Sprintf(surface.desc, pa.phrase),
			EvidenceRefs:  []string{artRef(a, pa.offset)},
			Status:        schema.StateObserved,
			Endpoint:      schema.StateUnknown,
			MitreATLAS:    surface.atlas,
			FalsePositive: "Security discussions, test fixtures and documentation legitimately contain these phrases; review the surrounding context at the referenced offset.",
		})
	}
	if ua != nil && !(ua.tags == 0 && ua.bidi < 3 && ua.zw < 8) {
		// Severity follows which characters were found. Unicode tag
		// characters (U+E0000–U+E007F) have no legitimate use in prompts and
		// can carry a whole instruction invisibly. Bidi controls occur in
		// every right-to-left language and zero-width joiners in ordinary
		// emoji — on a real machine all 43 HIGH findings had tags == 0.
		sev := "INFO"
		switch {
		case ua.tags > 0:
			sev = "HIGH"
		case ua.bidi >= 3:
			sev = "MEDIUM"
		}
		firstOff := ua.firstOff
		if firstOff == -1 {
			firstOff = 0
		}
		res.unicode = append(res.unicode, schema.Finding{
			RuleID:   "INVISIBLE_UNICODE_INSTRUCTION",
			Severity: sev,
			Title:    "Invisible Unicode in Agent-Facing Content",
			Description: fmt.Sprintf("Invisible characters detected (tag: %d, bidi controls: %d, zero-width: %d). Unicode tag characters can smuggle instructions invisible to a human reviewer but readable by the model.",
				ua.tags, ua.bidi, ua.zw),
			EvidenceRefs:  []string{artRef(a, firstOff)},
			Status:        schema.StateObserved,
			Endpoint:      schema.StateUnknown,
			MitreATLAS:    "AML.T0068", // LLM Prompt Obfuscation
			FalsePositive: "Bidi controls occur in legitimate RTL text; zero-width joiners in some scripts and emoji. Tag characters (U+E0000–U+E007F) have no legitimate use in prompts.",
		})
	}
	if ca != nil && ca.found {
		res.honey = append(res.honey, schema.Finding{
			RuleID:        "SECRET_ACCESS",
			Severity:      "HIGH",
			Title:         "Honeytoken Accessed by Agent",
			Description:   "A planted canary marker appears inside an agent conversation. The agent read the bait content; treat any network activity in the same session as a potential transmission path. Marker value: [REDACTED]",
			EvidenceRefs:  []string{artRef(a, ca.offset)},
			Status:        schema.StateObserved,
			Endpoint:      schema.StateUnknown,
			MitreATTACK:   "T1552",
			MitreATLAS:    "AML.T0055", // Unsecured Credentials
			FalsePositive: "Low: honeytokens are planted precisely so that any access is signal. Verify the marker was not legitimately referenced by the operator.",
		})
	}
	return res
}
