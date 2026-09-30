package rulepack

import (
	"regexp/syntax"
	"strings"
	"unicode"
	"unicode/utf8"
)

// The literal prefilter.
//
// Most subjects match no rule, and Go's regexp engine is linear but not
// cheap: on a real case the rule packs spent a minute running 81 regexes
// over 359,000 events. Nearly every one of those regexes cannot match
// without some literal text appearing in the subject — `curl`, `.ssh/`,
// `base64`. requiredLiterals works that set out from the regex's syntax
// tree, and a subject that contains none of them is not handed to the
// regexp engine at all.
//
// It must never skip a subject the regex would match. Two things make that
// hold. The extraction is conservative: any construct it does not fully
// understand (a character class, an optional or repeated-zero-times part,
// an alternation with an un-analyzable branch) makes it give up, and a
// rule with no prefilter runs the regex on everything. And the comparison
// folds case exactly the way regexp's (?i) does — every rune is mapped to
// the smallest member of its Unicode case-folding orbit, so "ſ" (U+017F)
// and "s", or "K" (U+212A, the Kelvin sign) and "k", compare equal — and
// it folds both sides whether or not the regex is case-insensitive. Folding
// is a rune-by-rune function, so a literal that occurs in a subject still
// occurs after both are folded: the filter can only let more through than
// the regex matches, never less.

// maxLiterals bounds the set: a rule with more alternatives than this is
// cheaper to run directly.
const maxLiterals = 16

// minLiteral is the shortest literal worth filtering on.
const minLiteral = 2

// requiredLiterals returns folded literals at least one of which occurs in
// every string the regex matches, or nil when no such set can be proven.
func requiredLiterals(expr string) []string {
	re, err := syntax.Parse(expr, syntax.Perl)
	if err != nil {
		return nil
	}
	set, ok := required(re.Simplify())
	if !ok || len(set) == 0 || len(set) > maxLiterals {
		return nil
	}
	for _, s := range set {
		if utf8.RuneCountInString(s) < minLiteral {
			return nil
		}
	}
	return set
}

func required(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		return []string{fold(string(re.Rune))}, true
	case syntax.OpCapture:
		return required(re.Sub[0])
	case syntax.OpPlus:
		return required(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return required(re.Sub[0])
		}
		return nil, false
	case syntax.OpConcat:
		// Any one mandatory part is enough; take the most selective.
		var best []string
		bestLen := -1
		for _, sub := range re.Sub {
			set, ok := required(sub)
			if !ok {
				continue
			}
			if l := shortest(set); l > bestLen {
				best, bestLen = set, l
			}
		}
		return best, best != nil
	case syntax.OpAlternate:
		var all []string
		for _, sub := range re.Sub {
			set, ok := required(sub)
			if !ok {
				return nil, false
			}
			all = append(all, set...)
		}
		return all, true
	}
	return nil, false
}

func shortest(set []string) int {
	n := -1
	for _, s := range set {
		if l := utf8.RuneCountInString(s); n < 0 || l < n {
			n = l
		}
	}
	return n
}

// fold maps every rune to the smallest rune of its case-folding orbit —
// the equivalence regexp's (?i) matches under.
func fold(s string) string {
	ascii := true
	for i := 0; i < len(s); i++ {
		if s[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		return strings.ToUpper(s) // an ASCII letter's orbit minimum is its capital
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		b.WriteRune(foldRune(r))
	}
	return b.String()
}

func foldRune(r rune) rune {
	if r < utf8.RuneSelf {
		if 'a' <= r && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}
	lo := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		if f < lo {
			lo = f
		}
	}
	return lo
}

// mayMatch reports whether a folded subject contains any required literal.
func mayMatch(need []string, folded string) bool {
	for _, n := range need {
		if strings.Contains(folded, n) {
			return true
		}
	}
	return false
}
