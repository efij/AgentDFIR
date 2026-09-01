package sanitize

import (
	"strings"
	"testing"
)

func TestStripsANSIEscapes(t *testing.T) {
	in := "before\x1b[2J\x1b[1;31mafter"
	out := Terminal(in)
	if strings.Contains(out, "\x1b") {
		t.Fatalf("ESC survived sanitization: %q", out)
	}
}

func TestStripsBidiAndZeroWidth(t *testing.T) {
	// RLO override + zero-width space + BOM.
	in := "user\u202Etxt.exe\u200B\uFEFF"
	out := Terminal(in)
	if out != "usertxt.exe" {
		t.Fatalf("invisible runes survived: %q", out)
	}
}

func TestStripsUnicodeTagSmuggling(t *testing.T) {
	// Tag characters can smuggle invisible ASCII instructions.
	in := "hello\U000E0069\U000E0067\U000E006E\U000E006F\U000E0072\U000E0065"
	out := Terminal(in)
	if out != "hello" {
		t.Fatalf("tag characters survived: %q", out)
	}
}

func TestPreservesNormalText(t *testing.T) {
	in := "normal path /Users/x/.claude/projects — עברית 中文 ok"
	if got := Terminal(in); got != in {
		t.Fatalf("normal text altered: %q -> %q", in, got)
	}
}
