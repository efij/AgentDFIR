package endpoint

import (
	"path/filepath"
	"testing"
)

func TestPlasoWitness(t *testing.T) {
	for _, c := range []struct {
		file          string
		net, proc, fs int
	}{
		{"timeline.jsonl", 2, 1, 1}, // the undated and the non-JSON line are skipped
		{"timeline.l2tcsv", 1, 0, 0}, // the CET line keeps no time; FILE lines are not fs: data types
	} {
		path := filepath.Join("..", "parsers", "suite", "testdata", "plaso", c.file)
		if f, err := Sniff(path); err != nil || f != FormatPlaso {
			t.Fatalf("%s: sniff %q %v", c.file, f, err)
		}
		res, err := Load(path, FormatAuto)
		if err != nil {
			t.Fatal(err)
		}
		kinds := map[string]int{}
		for _, r := range res.Records {
			kinds[r.Kind]++
			if !IsSighting(r) {
				t.Errorf("%s: plaso record must be a sighting (never coverage): %+v", c.file, r)
			}
		}
		if kinds["network"] != c.net || kinds["process"] != c.proc || kinds["file"] != c.fs {
			t.Errorf("%s: kinds %v", c.file, kinds)
		}
		if res.Skipped == 0 {
			t.Errorf("%s: skipped lines not counted", c.file)
		}
	}
}
