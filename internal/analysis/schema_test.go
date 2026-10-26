package analysis

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/repro"
)

// A small JSON Schema (draft 2020-12) validator covering the keywords the
// published schemas use: $ref (local), type, const, enum, required,
// properties, additionalProperties, items, anyOf, pattern, minLength,
// minimum, minItems. It exists so the schemas in docs/schema are tested
// against what the code actually writes, without a dependency.
type validator struct {
	root map[string]any
	errs []string
}

func loadSchema(t *testing.T, name string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "schema", name))
	if err != nil {
		t.Fatal(err)
	}
	var s map[string]any
	if err := json.Unmarshal(data, &s); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if s["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Fatalf("%s: not draft 2020-12", name)
	}
	return s
}

func validate(schema map[string]any, doc []byte) []string {
	d := json.NewDecoder(bytes.NewReader(doc))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return []string{err.Error()}
	}
	val := &validator{root: schema}
	val.check(schema, v, "$")
	return val.errs
}

func (val *validator) resolve(ref string) map[string]any {
	if !strings.HasPrefix(ref, "#/") {
		val.errs = append(val.errs, "unsupported $ref "+ref)
		return nil
	}
	var cur any = val.root
	for _, p := range strings.Split(ref[2:], "/") {
		m, _ := cur.(map[string]any)
		cur = m[p]
	}
	m, _ := cur.(map[string]any)
	return m
}

func typeOK(t string, v any) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		_, err := n.Int64()
		return err == nil
	case "number":
		_, ok := v.(json.Number)
		return ok
	case "null":
		return v == nil
	}
	return false
}

func equalJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func (val *validator) check(s map[string]any, v any, at string) {
	if s == nil {
		return
	}
	fail := func(f string, a ...any) { val.errs = append(val.errs, at+": "+fmt.Sprintf(f, a...)) }
	if ref, ok := s["$ref"].(string); ok {
		val.check(val.resolve(ref), v, at)
	}
	if t, ok := s["type"].(string); ok && !typeOK(t, v) {
		fail("want %s, have %T", t, v)
		return
	}
	if c, ok := s["const"]; ok {
		if n, isNum := v.(json.Number); isNum {
			v = n.String()
		}
		if !equalJSON(c, v) {
			fail("want const %v, have %v", c, v)
		}
	}
	if e, ok := s["enum"].([]any); ok {
		found := false
		for _, x := range e {
			found = found || equalJSON(x, v)
		}
		if !found {
			fail("%v not in enum", v)
		}
	}
	if any_, ok := s["anyOf"].([]any); ok {
		matched := false
		for _, sub := range any_ {
			trial := &validator{root: val.root}
			sm, _ := sub.(map[string]any)
			trial.check(sm, v, at)
			if len(trial.errs) == 0 {
				matched = true
				break
			}
		}
		if !matched {
			fail("matches none of anyOf")
		}
	}
	if str, ok := v.(string); ok {
		if p, ok := s["pattern"].(string); ok && !regexp.MustCompile(p).MatchString(str) {
			fail("%q does not match %s", str, p)
		}
		if ml, ok := s["minLength"].(float64); ok && len([]rune(str)) < int(ml) {
			fail("shorter than %v", ml)
		}
	}
	if n, ok := v.(json.Number); ok {
		if mn, ok := s["minimum"].(float64); ok {
			r, _ := new(big.Rat).SetString(n.String())
			if r != nil && r.Cmp(new(big.Rat).SetFloat64(mn)) < 0 {
				fail("%s below minimum %v", n, mn)
			}
		}
	}
	if m, ok := v.(map[string]any); ok {
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if _, ok := m[r.(string)]; !ok {
					fail("missing required %s", r)
				}
			}
		}
		props, _ := s["properties"].(map[string]any)
		for k, x := range m {
			if ps, ok := props[k].(map[string]any); ok {
				val.check(ps, x, at+"."+k)
			} else if ap, ok := s["additionalProperties"]; ok {
				switch a := ap.(type) {
				case bool:
					if !a {
						fail("unexpected property %s", k)
					}
				case map[string]any:
					val.check(a, x, at+"."+k)
				}
			}
		}
	}
	if l, ok := v.([]any); ok {
		if mi, ok := s["minItems"].(float64); ok && len(l) < int(mi) {
			fail("fewer than %v items", mi)
		}
		if it, ok := s["items"].(map[string]any); ok {
			for i, x := range l {
				val.check(it, x, fmt.Sprintf("%s[%d]", at, i))
			}
		}
	}
}

// The schemas describe what the code writes: an analysis with a second
// witness (so the graph has correlated and telemetry edges) produces a
// lineage.json that validates against action-graph.schema.json and an
// analysis manifest that validates against analysis-manifest.schema.json.
func TestPublishedSchemasMatchOutput(t *testing.T) {
	pkg := buildPkg(t)
	if _, err := Run(pkg, Options{EndpointLogs: []string{auditLog(t)}}); err != nil {
		t.Fatal(err)
	}
	graph, err := overlay.ReadFile(filepath.Join(pkg, "normalized", LineageFile))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(graph, []byte(`"confidence"`)) || !bytes.Contains(graph, []byte(`"telemetry_ref"`)) || !bytes.Contains(graph, []byte(`"limitations"`)) {
		t.Fatalf("fixture graph lacks correlated edges or limitations; the test would prove little:\n%s", graph)
	}
	gs := loadSchema(t, "action-graph.schema.json")
	if errs := validate(gs, graph); len(errs) > 0 {
		t.Fatalf("lineage.json does not validate against action-graph.schema.json: %v", errs)
	}
	if p, _ := repro.CheckGraph(graph); len(p) > 0 {
		t.Fatalf("lineage.json fails the graph check: %v", p)
	}
	// A graph written before 0.2.2 (no adfir_spec, no limitations) still validates.
	var g map[string]any
	_ = json.Unmarshal(graph, &g)
	delete(g, "adfir_spec")
	for _, e := range g["edges"].([]any) {
		delete(e.(map[string]any), "limitations")
	}
	old, _ := json.Marshal(g)
	if errs := validate(gs, old); len(errs) > 0 {
		t.Fatalf("a pre-0.2.2 graph no longer validates: %v", errs)
	}
	if p, _ := repro.CheckGraph(old); len(p) > 0 {
		t.Fatalf("a pre-0.2.2 graph fails the graph check: %v", p)
	}
	man, err := os.ReadFile(repro.Path(pkg))
	if err != nil {
		t.Fatal(err)
	}
	if errs := validate(loadSchema(t, "analysis-manifest.schema.json"), man); len(errs) > 0 {
		t.Fatalf("analysis-manifest.json does not validate: %v", errs)
	}
	// And the validator is not vacuous.
	if errs := validate(gs, []byte(`{"schema":"agentdfir.lineage/1","nodes":[],"edges":[{"from":"a"}]}`)); len(errs) == 0 {
		t.Fatal("validator accepted an invalid graph")
	}
}
