package repro

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/schema"
)

func sample() []schema.Finding {
	return []schema.Finding{
		{RuleID: "A", Severity: "HIGH", Status: "OBSERVED", Endpoint: "UNKNOWN", SessionID: "s", EvidenceRefs: []string{"b:2", "a:1"}, Title: "t1"},
		{RuleID: "B", Severity: "LOW", Status: "REPORTED", Endpoint: "UNKNOWN", Title: "t2"},
	}
}

func TestFingerprintIgnoresOrderProseAndTime(t *testing.T) {
	a := sample()
	b := []schema.Finding{a[1], a[0]}
	b[1].EvidenceRefs = []string{"a:1", "b:2"}
	b[0].Title, b[0].Description, b[0].Timestamp = "other words", "different prose", "2026-01-01T00:00:00Z"
	if Fingerprint(a) != Fingerprint(b) {
		t.Fatal("order, refs order, prose or time changed the fingerprint")
	}
	for name, mut := range map[string]func(f *schema.Finding){
		"severity": func(f *schema.Finding) { f.Severity = "CRITICAL" },
		"status":   func(f *schema.Finding) { f.Status = "CORROBORATED" },
		"endpoint": func(f *schema.Finding) { f.Endpoint = "CONTRADICTED" },
		"refs":     func(f *schema.Finding) { f.EvidenceRefs = []string{"a:1"} },
		"rule":     func(f *schema.Finding) { f.RuleID = "C" },
		"agent":    func(f *schema.Finding) { f.AgentID = "x" },
	} {
		c := sample()
		mut(&c[0])
		if Fingerprint(c) == Fingerprint(a) {
			t.Errorf("%s change did not change the fingerprint", name)
		}
	}
	// Duplicates count.
	if Fingerprint(append(sample(), sample()[0])) == Fingerprint(a) {
		t.Error("a duplicated finding did not change the fingerprint")
	}
	// Netstrings: field boundaries cannot be shifted.
	x := []schema.Finding{{RuleID: "AB", Severity: "C"}}
	y := []schema.Finding{{RuleID: "A", Severity: "BC"}}
	if Fingerprint(x) == Fingerprint(y) {
		t.Error("field boundaries are ambiguous")
	}
	if !strings.HasPrefix(Fingerprint(nil), "sha256:") {
		t.Error("format")
	}
}

// A known answer, so an independent implementation (tools/adfir-verify)
// can be checked against the same value.
func TestFingerprintKnownAnswer(t *testing.T) {
	const want = "sha256:a2ce7d70c8fbac319c41007a3e4458bfbad85048a0816106266ca8f705ba7736" // computed independently in Python from the spec text
	got := Fingerprint(sample())
	data, _ := json.Marshal(sample())
	fj, n, err := FingerprintJSON(data)
	if err != nil || n != 2 || fj != got || got != want {
		t.Fatalf("%s %s %d %v", got, fj, n, err)
	}
	e := CanonicalEntry(sample()[0])
	if e != "1:A,4:HIGH,8:OBSERVED,7:UNKNOWN,1:s,0:,1:2,3:a:1,3:b:2," {
		t.Fatalf("canonical entry %q", e)
	}
}

func manifestFor(t *testing.T, fs []schema.Finding) []byte {
	t.Helper()
	m := Manifest{Schema: ManifestSchema, Spec: Spec, Tool: Tool{Name: "agentdfir", Version: "x", AnalysisFingerprint: strings.Repeat("a", 64)},
		RuleSet: RuleSet{BuiltinFingerprint: strings.Repeat("a", 64), Packs: []Pack{}}, Input: Input{SealSHA256: strings.Repeat("b", 64)},
		AnalyzedUTC: "2026-10-25T00:00:00Z", Findings: FindingsSummary{Count: len(fs), File: FindingsFile, Algorithm: FindingsAlgorithm, Fields: FingerprintFields},
		FindingsFingerprint: Fingerprint(fs)}
	data, _ := json.Marshal(m)
	return data
}

func TestCheckManifest(t *testing.T) {
	fs := sample()
	fdata, _ := json.Marshal(fs)
	man := manifestFor(t, fs)
	if p, n := CheckManifest(man, fdata, strings.Repeat("b", 64)); len(p) > 0 || len(n) > 0 {
		t.Fatalf("valid manifest: %v %v", p, n)
	}
	if _, n := CheckManifest(man, fdata, strings.Repeat("c", 64)); len(n) == 0 {
		t.Error("a later seal should be noted")
	}
	edited := sample()
	edited[0].Severity = "INFO"
	edata, _ := json.Marshal(edited)
	if p, _ := CheckManifest(man, edata, ""); len(p) == 0 {
		t.Error("edited findings not detected")
	}
	if p, _ := CheckManifest(man, nil, ""); len(p) == 0 {
		t.Error("missing findings not reported")
	}
	if p, _ := CheckManifest([]byte(`{"schema":"x"}`), fdata, ""); len(p) == 0 {
		t.Error("malformed manifest accepted")
	}
	if p, _ := CheckManifest([]byte(`not json`), fdata, ""); len(p) == 0 {
		t.Error("non-JSON accepted")
	}
}

const graphOK = `{"schema":"agentdfir.lineage/1","adfir_spec":"0.2.2","case_id":"c","nodes":[
 {"id":"agent:a","kind":"agent","label":"a"},{"id":"tool:1","kind":"tool_call","label":"t"},{"id":"process:x","kind":"process","label":"p"}],
 "edges":[
 {"from":"agent:a","to":"tool:1","relation":"invoked","basis":"b","evidence_state":"CORROBORATED","source_refs":[{"event_id":"e1"}],"limitations":["inherited"]},
 {"from":"tool:1","to":"process:x","relation":"executed_as","basis":"correlated","evidence_state":"CORROBORATED","confidence":"HIGH","source_refs":[{"event_id":"e1"},{"telemetry_ref":"audit 7"}]}]}`

func TestCheckGraph(t *testing.T) {
	if p, n := CheckGraph([]byte(graphOK)); len(p) > 0 || len(n) > 0 {
		t.Fatalf("valid graph: %v %v", p, n)
	}
	for name, edit := range map[string][2]string{
		"dangling-endpoint":       {`"to":"process:x"`, `"to":"process:gone"`},
		"no-source-ref":           {`"source_refs":[{"event_id":"e1"}],"limitations"`, `"source_refs":[],"limitations"`},
		"corroborated-no-witness": {`,"limitations":["inherited"]`, ``},
		"correlated-no-telemetry": {`,{"telemetry_ref":"audit 7"}`, ``},
		"empty-ref":               {`[{"event_id":"e1"},{"telemetry_ref"`, `[{},{"telemetry_ref"`},
		"bad-state":               {`"evidence_state":"CORROBORATED","source_refs":[{"event_id":"e1"}]`, `"evidence_state":"CONFIRMED","source_refs":[{"event_id":"e1"}]`},
		"duplicate-node":          {`{"id":"process:x","kind":"process","label":"p"}`, `{"id":"tool:1","kind":"process","label":"p"},{"id":"process:x","kind":"process","label":"p"}`},
	} {
		g := strings.Replace(graphOK, edit[0], edit[1], 1)
		if g == graphOK {
			t.Fatalf("%s: edit did not apply", name)
		}
		if p, _ := CheckGraph([]byte(g)); len(p) == 0 {
			t.Errorf("%s not detected", name)
		}
	}
	// Before 0.2.2 the per-edge CORROBORATED rule is not applied.
	old := strings.Replace(strings.Replace(graphOK, `"adfir_spec":"0.2.2",`, ``, 1), `,"limitations":["inherited"]`, ``, 1)
	if p, n := CheckGraph([]byte(old)); len(p) > 0 || len(n) == 0 {
		t.Fatalf("pre-0.2.2 graph: %v %v", p, n)
	}
}

func TestCompareExplains(t *testing.T) {
	a := &Manifest{FindingsFingerprint: Fingerprint(sample()), Tool: Tool{Version: "4.5.0", AnalysisFingerprint: "x"}}
	b := &Manifest{FindingsFingerprint: Fingerprint(sample()[:1]), Tool: Tool{Version: "4.6.0", AnalysisFingerprint: "y"}}
	c := Compare(a, b, sample(), sample()[:1])
	if c.Reproduced || c.OnlyRecordedCount != 1 || c.OnlyNowCount != 0 {
		t.Fatalf("%+v", c)
	}
	found := false
	for _, d := range c.Differences {
		found = found || (d.Field == "tool.analysis_fingerprint" && d.Affects)
	}
	if !found {
		t.Error("code difference not explained")
	}
	same := Compare(a, &Manifest{FindingsFingerprint: a.FindingsFingerprint, Tool: a.Tool}, nil, nil)
	if !same.Reproduced || len(same.Differences) != 0 {
		t.Fatalf("%+v", same)
	}
	// Nothing finding-relevant differs, yet findings do: a determinism defect.
	d := Compare(a, &Manifest{FindingsFingerprint: b.FindingsFingerprint, Tool: a.Tool}, sample(), sample()[:1])
	if len(d.Notes) == 0 || !strings.Contains(strings.Join(d.Notes, " "), "determinism") {
		t.Errorf("notes %v", d.Notes)
	}
	ht := Compare(&Manifest{FindingsFingerprint: "x", Options: Options{Honeytokens: 2}}, &Manifest{FindingsFingerprint: "x", Options: Options{Honeytokens: 2}}, nil, nil)
	if !strings.Contains(strings.Join(ht.Notes, " "), "count") {
		t.Errorf("honeytoken identity caveat missing: %v", ht.Notes)
	}
}

func TestUUIDv5KnownAnswer(t *testing.T) {
	// Python: uuid.uuid5(uuid.NAMESPACE_URL, "https://efij.github.io/AgentDFIR/stix")
	if got := UUIDv5("6ba7b811-9dad-11d1-80b4-00c04fd430c8", "https://efij.github.io/AgentDFIR/stix"); got != STIXNamespace {
		t.Fatalf("UUIDv5 = %s, want %s", got, STIXNamespace)
	}
}
