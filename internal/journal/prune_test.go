package journal

import "testing"

func TestPruneVerdict(t *testing.T) {
	i := func(n int64) *int64 { return &n }
	const pre = "aa"
	for name, tc := range map[string]struct {
		r  rec
		ok bool
	}{
		"same size, same hash":             {rec{Size: 10, SHA256: pre}, true},
		"same size, other hash":            {rec{Size: 10, SHA256: "bb"}, false},
		"shorter than journaled":           {rec{Size: 9, SHA256: pre}, false},
		"longer, prefix matches":           {rec{Size: 20, SHA256: "cc", PrunePrefixSz: i(10), PrunePrefix: pre}, true},
		"longer, prefix differs":           {rec{Size: 20, SHA256: "cc", PrunePrefixSz: i(10), PrunePrefix: "bb"}, false},
		"longer, no prefix hash":           {rec{Size: 20, SHA256: "cc"}, false},
		"longer, prefix of the wrong size": {rec{Size: 20, SHA256: "cc", PrunePrefixSz: i(5), PrunePrefix: pre}, false},
		"claimed journaled size differs":   {rec{Size: 10, SHA256: pre, JournaledSize: i(8)}, false},
	} {
		if got := pruneVerdict(10, pre, &tc.r) == ""; got != tc.ok {
			t.Errorf("%s: accepted=%v, want %v (%s)", name, got, tc.ok, pruneVerdict(10, pre, &tc.r))
		}
	}
}
