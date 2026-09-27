package witness

import (
	"strings"
	"testing"
)

func TestAppendNoteIsIdempotent(t *testing.T) {
	n := "tool said ok"
	add := "host witness: MEMORY.md exists, 7385 bytes, sha256 1f374b123d0a"
	for i := 0; i < 5; i++ {
		n = appendNote(n, add)
	}
	if strings.Count(n, "host witness") != 1 || !strings.HasPrefix(n, "tool said ok; ") {
		t.Fatalf("note grew on re-analysis: %q", n)
	}
	n = appendNote(n, "host witness: MEMORY.md was not present at acquisition time")
	if strings.Count(n, "host witness") != 1 || !strings.Contains(n, "not present") {
		t.Fatalf("a newer witness result must replace the old one: %q", n)
	}
	n = appendNote(n, "host witness: other.md exists, 1 bytes, sha256 aa")
	if strings.Count(n, "host witness") != 2 {
		t.Fatalf("a different file keeps its own segment: %q", n)
	}
}
