package genericchat

import "testing"

// sessions.json entries cite the line each entry starts on, not their
// position in the array (a one-line index has one line).
func TestTopArrayLocs(t *testing.T) {
	oneLine := []byte(`[{"sessionId":"a"},{"sessionId":"b"}]`)
	for _, l := range topArrayLocs(oneLine, 2) {
		if l.line != 1 || l.off != 0 {
			t.Fatalf("one-line index: %+v", l)
		}
	}
	pretty := []byte("[\n  {\"sessionId\": \"a\"},\n  {\"sessionId\": \"b\"}\n]\n")
	locs := topArrayLocs(pretty, 2)
	if locs[0] != (srcLoc{2, 2}) || locs[1] != (srcLoc{24, 3}) {
		t.Fatalf("pretty index: %+v", locs)
	}
	if got := topArrayLocs([]byte(`{"x":1}`), 1); got[0] != (srcLoc{0, 1}) {
		t.Fatalf("not an array: %+v", got)
	}
}
