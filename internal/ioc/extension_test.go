package ioc

import (
	"strings"
	"testing"
)

// Extension indicators are user-supplied (no IDs ship embedded); the ids
// below are synthetic.
func TestVSCodeExtensionIndicator(t *testing.T) {
	feed := []byte(`{"pack":"t","version":"1","incidents":[{"id":"ext-test","title":"synthetic extension wave","first_seen":"2026-01-01",
	  "indicators":[
	    {"kind":"vscode_extension","value":"Example-Pub.Bad-Ext","below_version":"1.4.0"},
	    {"kind":"vscode_extension","value":"example-pub.other","versions":["0.0.7"]},
	    {"kind":"vscode_extension","value":"no-dot-id"},
	    {"kind":"vscode_extension","value":"evil/../path.x"}]}]}`)
	incs, skipped, err := Parse(feed, "test")
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 2 || len(incs[0].Indicators) != 2 {
		t.Fatalf("validation: skipped %d, kept %d", skipped, len(incs[0].Indicators))
	}
	bad := incs[0].Indicators[0]
	if bad.Label() != "vscode_extension:example-pub.bad-ext@<1.4.0" {
		t.Errorf("label %q", bad.Label())
	}
	for v, want := range map[string]bool{"1.3.9": true, "1.4.0": false, "2.0.0": false, "": false} {
		if got := bad.MatchExtension("example-pub.bad-ext", v); got != want {
			t.Errorf("bad-ext@%q = %v, want %v", v, got, want)
		}
	}
	if bad.MatchPackage("npm", "example-pub.bad-ext", "1.0.0") {
		t.Error("an extension indicator must not match an npm package")
	}
	vs := Hunt(incs, Inputs{Extensions: []ExtRef{
		{ID: "example-pub.bad-ext", Version: "1.2.0", Evidence: ".cursor/extensions/example-pub.bad-ext-1.2.0", Time: "2026-02-01T00:00:00Z"},
		{ID: "example-pub.other", Version: "0.0.8", Evidence: "x"},
	}})
	if len(vs) != 1 || vs[0].Status != "HIT" || len(vs[0].Hits) != 1 || vs[0].Hits[0].Surface != "extension_inventory" ||
		vs[0].Hits[0].InWindow != "yes" || vs[0].Hits[0].TimeSrc != "install_record" {
		t.Fatalf("verdict: %+v", vs)
	}
	f := Findings(vs)
	if len(f) != 1 || !strings.Contains(f[0].Description, "installed editor extension") {
		t.Fatalf("finding: %+v", f)
	}
}
