// Package sanitize neutralizes hostile content in evidence-derived
// strings before they reach a terminal or log. Evidence can contain ANSI
// escape sequences, control characters and invisible Unicode designed to
// mislead the analyst (anti-analysis). Mandatory for all console output
// that includes data read from a suspect host.
package sanitize

import (
	"strings"
	"unicode"
)

// Terminal returns s safe for terminal display: C0/C1 control characters
// (except space) are replaced with U+FFFD, and invisible/reordering
// Unicode (bidi controls, zero-width, tag characters) is removed.
func Terminal(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			b.WriteRune(' ')
		case r < 0x20 || (r >= 0x7f && r <= 0x9f):
			b.WriteRune('�') // C0/C1 controls incl. ESC — kills ANSI sequences
		case isInvisible(r):
			// dropped entirely
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func isInvisible(r rune) bool {
	switch {
	case r >= 0x200B && r <= 0x200F: // zero-width space/joiners, LRM/RLM
		return true
	case r >= 0x202A && r <= 0x202E: // bidi embedding/override
		return true
	case r >= 0x2066 && r <= 0x2069: // bidi isolates
		return true
	case r == 0xFEFF: // zero-width no-break space / BOM
		return true
	case r >= 0xE0000 && r <= 0xE007F: // Unicode tag characters (ASCII smuggling)
		return true
	case unicode.Is(unicode.Cf, r): // remaining format characters
		return true
	}
	return false
}
