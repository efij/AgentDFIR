package export

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/ioc"
	"github.com/efij/AgentDFIR/v5/internal/repro"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

func stixFixture() STIXInput {
	inc := ioc.Incident{ID: "INC-1", Title: "Example compromise"}
	return STIXInput{
		CaseID:  "C-STIX",
		Created: time.Date(2026, 8, 30, 10, 0, 0, 0, time.UTC),
		Findings: []schema.Finding{
			{RuleID: "DESTRUCTIVE_COMMAND", Severity: "HIGH", Title: "rm", Description: "d", Status: schema.StateCorroborated, Endpoint: schema.StateCorroborated,
				EvidenceRefs: []string{"a.jsonl:3 (artifact 1)"}, MitreATTACK: "T1485", MitreATLAS: "AML.T0048"},
			{RuleID: "KNOWN_INCIDENT_IOC", Severity: "CRITICAL", Title: "ioc", Description: "d", Status: schema.StateObserved,
				Related: []string{"incident: INC-1", "indicator: domain:evil.example"}, MitreATTACK: "T1071.001"},
		},
		Hunt: []ioc.Verdict{{Incident: inc, Status: "HIT", Hits: []ioc.Hit{
			{Indicator: ioc.Indicator{Kind: ioc.KindDomain, Value: "evil.example"}, Where: "OBSERVED", Surface: "command", Count: 2,
				FirstSeen: "2026-08-30T10:00:05Z", LastSeen: "2026-08-30T10:01:00Z"},
			{Indicator: ioc.Indicator{Kind: ioc.KindDomain, Value: "203.0.113.7"}, Where: "OBSERVED", Surface: "command", Count: 1},
			{Indicator: ioc.Indicator{Kind: ioc.KindSHA256, Value: strings.Repeat("ab", 32)}, Where: "OBSERVED", Surface: "artifact_hash", Count: 1},
			{Indicator: ioc.Indicator{Kind: ioc.KindURL, Value: "evil.example/drop"}, Where: "OBSERVED", Surface: "command", Count: 1},
			{Indicator: ioc.Indicator{Kind: ioc.KindPackage, Value: "badpkg", Ecosystem: "npm"}, Where: "OBSERVED", Surface: "lockfile", Count: 1},
		}, Mentions: []ioc.Hit{{Indicator: ioc.Indicator{Kind: ioc.KindDomain, Value: "mentioned.example"}, Where: "MENTIONED"}}}},
	}
}

func TestSTIXBundleObservablesAndDeterminism(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.json"), filepath.Join(dir, "b.json")
	if err := WriteSTIXBundle(stixFixture(), a); err != nil {
		t.Fatal(err)
	}
	if err := WriteSTIXBundle(stixFixture(), b); err != nil {
		t.Fatal(err)
	}
	da, _ := os.ReadFile(a)
	db, _ := os.ReadFile(b)
	if !bytes.Equal(da, db) {
		t.Fatal("re-export is not byte-identical")
	}
	if p, n := repro.CheckSTIX(da); len(p) > 0 {
		t.Fatalf("STIX check: %v %v", p, n)
	}
	var bundle struct {
		Objects []map[string]any `json:"objects"`
	}
	_ = json.Unmarshal(da, &bundle)
	types := map[string]int{}
	byID := map[string]map[string]any{}
	for _, o := range bundle.Objects {
		types[o["type"].(string)]++
		byID[o["id"].(string)] = o
	}
	want := map[string]int{"identity": 1, "report": 1, "note": 2, "indicator": 4, "domain-name": 1, "ipv4-addr": 1, "file": 1, "observed-data": 1, "relationship": 3}
	for k, v := range want {
		if types[k] != v {
			t.Errorf("%s: %d objects, want %d (all: %v)", k, types[k], v, types)
		}
	}
	if types["url"] != 0 {
		t.Error("a URL prefix must not become a url object")
	}
	if bytes.Contains(da, []byte("mentioned.example")) {
		t.Error("a mention is not an observable")
	}
	// The SCO id is the one STIX 2.1 defines for {"value":"evil.example"}.
	if _, ok := byID["domain-name--"+repro.UUIDv5(repro.STIXSCONamespace, `{"value":"evil.example"}`)]; !ok {
		t.Error("domain-name id is not the STIX deterministic id")
	}
	if !bytes.Contains(da, []byte(`https://attack.mitre.org/techniques/T1071/001/`)) || !bytes.Contains(da, []byte(`https://atlas.mitre.org/techniques/AML.T0048`)) {
		t.Error("technique external references missing")
	}
	// The IOC finding's note points at its indicator.
	for _, o := range bundle.Objects {
		if o["type"] == "note" && o["abstract"] == "ioc" {
			if refs := o["object_refs"].([]any); len(refs) != 2 {
				t.Errorf("IOC note refs %v", refs)
			}
		}
	}
	if !bytes.Contains(da, []byte(`"created": "2026-08-30T10:00:00.000Z"`)) {
		t.Error("timestamps must come from the case, not the clock")
	}
}

// Negative cases for the checker, on mutations of a real bundle.
func TestSTIXCheckerRejects(t *testing.T) {
	p := filepath.Join(t.TempDir(), "b.json")
	if err := WriteSTIXBundle(stixFixture(), p); err != nil {
		t.Fatal(err)
	}
	orig, _ := os.ReadFile(p)
	mutate := func(name string, f func(objs []map[string]any) []map[string]any) {
		t.Run(name, func(t *testing.T) {
			var b map[string]any
			_ = json.Unmarshal(orig, &b)
			var objs []map[string]any
			for _, o := range b["objects"].([]any) {
				objs = append(objs, o.(map[string]any))
			}
			b["objects"] = f(objs)
			data, _ := json.Marshal(b)
			if probs, _ := repro.CheckSTIX(data); len(probs) == 0 {
				t.Fatal("not rejected")
			}
		})
	}
	find := func(objs []map[string]any, typ string) map[string]any {
		for _, o := range objs {
			if o["type"] == typ {
				return o
			}
		}
		t.Fatalf("no %s", typ)
		return nil
	}
	mutate("indicator-without-pattern", func(o []map[string]any) []map[string]any { delete(find(o, "indicator"), "pattern"); return o })
	mutate("note-without-object-refs", func(o []map[string]any) []map[string]any { delete(find(o, "note"), "object_refs"); return o })
	mutate("bad-id", func(o []map[string]any) []map[string]any { find(o, "report")["id"] = "report--1"; return o })
	mutate("wrong-spec-version", func(o []map[string]any) []map[string]any { find(o, "identity")["spec_version"] = "2.0"; return o })
	mutate("dangling-relationship", func(o []map[string]any) []map[string]any {
		find(o, "relationship")["target_ref"] = "observed-data--00000000-0000-5000-8000-000000000000"
		return o
	})
	mutate("bad-timestamp", func(o []map[string]any) []map[string]any { find(o, "note")["created"] = "2026-08-30 10:00"; return o })
	mutate("duplicate-id", func(o []map[string]any) []map[string]any { return append(o, find(o, "note")) })
	mutate("number-observed-zero", func(o []map[string]any) []map[string]any { find(o, "observed-data")["number_observed"] = 0; return o })
}
