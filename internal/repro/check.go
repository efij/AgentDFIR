package repro

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// The checks below read the overlay files as untyped JSON, the way a
// third party would, so that a field of the wrong type or a missing one is
// reported instead of silently decoded to a zero value. They mirror the
// checks tools/adfir-verify performs; docs/adfir-spec.md (0.2.2) is the
// reference for both.

// Bounds on a graph a check walks.
const (
	maxGraphNodes = 2_000_000
	maxGraphEdges = 5_000_000
	maxSTIXObjs   = 2_000_000
)

var (
	fingerprintRe = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	hex64Re       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// evidenceStates are the corroboration states an edge may carry.
var evidenceStates = map[string]bool{
	schema.StateRequested: true, schema.StateReported: true, schema.StateObserved: true, schema.StatePartial: true,
	schema.StateCorroborated: true, schema.StateContradicted: true, schema.StateUnknown: true,
}

func decode(data []byte) (any, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	var v any
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	if d.More() {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	return v, nil
}

func str(m map[string]any, k string) (string, bool) {
	s, ok := m[k].(string)
	return s, ok
}

func obj(m map[string]any, k string) (map[string]any, bool) {
	o, ok := m[k].(map[string]any)
	return o, ok
}

// CheckManifest checks an analysis manifest's shape and recomputes its
// findings fingerprint from findings.json. sealSHA, when set, is the
// SHA-256 of the package's current SHA256SUMS.
func CheckManifest(manifest, findings []byte, sealSHA string) (problems, notes []string) {
	v, err := decode(manifest)
	if err != nil {
		return []string{"analysis-manifest.json: not JSON: " + err.Error()}, nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return []string{"analysis-manifest.json: not an object"}, nil
	}
	bad := func(f string, a ...any) { problems = append(problems, "analysis-manifest.json: "+fmt.Sprintf(f, a...)) }
	if s, _ := str(m, "schema"); s != ManifestSchema {
		bad("schema %q, want %q", s, ManifestSchema)
	}
	for _, k := range []string{"adfir_spec", "analyzed_utc", "findings_fingerprint"} {
		if _, ok := str(m, k); !ok {
			bad("missing string %s", k)
		}
	}
	tool, ok := obj(m, "tool")
	if !ok {
		bad("missing object tool")
	} else {
		for _, k := range []string{"name", "version", "analysis_fingerprint"} {
			if s, _ := str(tool, k); s == "" {
				bad("tool.%s missing", k)
			}
		}
	}
	if rs, ok := obj(m, "rule_set"); !ok {
		bad("missing object rule_set")
	} else {
		if s, _ := str(rs, "builtin_fingerprint"); s == "" {
			bad("rule_set.builtin_fingerprint missing")
		}
		packs, ok := rs["packs"].([]any)
		if !ok {
			bad("rule_set.packs is not an array")
		}
		for i, p := range packs {
			po, _ := p.(map[string]any)
			if po == nil {
				bad("rule_set.packs[%d] is not an object", i)
				continue
			}
			if h, ok := str(po, "sha256"); ok && h != "" && !hex64Re.MatchString(h) {
				bad("rule_set.packs[%d].sha256 is not a SHA-256", i)
			}
		}
	}
	in, ok := obj(m, "input")
	if !ok {
		bad("missing object input")
	}
	if _, ok := obj(m, "options"); !ok {
		bad("missing object options")
	}
	fs, ok := obj(m, "findings")
	if !ok {
		bad("missing object findings")
		return problems, notes
	}
	fp, _ := str(m, "findings_fingerprint")
	if !fingerprintRe.MatchString(fp) {
		bad("findings_fingerprint %q is not sha256:<64 hex>", fp)
	}
	if alg, _ := str(fs, "algorithm"); alg != FindingsAlgorithm {
		bad("findings.algorithm %q is not one this verifier implements (%s)", alg, FindingsAlgorithm)
		return problems, notes
	}
	if findings == nil {
		bad("%s is missing, so the findings fingerprint cannot be checked", FindingsFile)
		return problems, notes
	}
	got, n, err := FingerprintJSON(findings)
	if err != nil {
		bad("%s is not a JSON array of findings: %v", FindingsFile, err)
		return problems, notes
	}
	if cnt, ok := fs["count"].(json.Number); !ok || cnt.String() != fmt.Sprint(n) {
		bad("findings.count %v, but %s holds %d finding(s)", fs["count"], FindingsFile, n)
	}
	if got != fp {
		bad("findings_fingerprint %s does not match %s (recomputed %s): the findings or the manifest were changed after the analysis", fp, FindingsFile, got)
	}
	if sealSHA != "" && in != nil {
		if s, _ := str(in, "seal_sha256"); s != sealSHA {
			notes = append(notes, "analysis-manifest.json: the analysis was made on a different seal than the package carries now (a later collection round); re-analyze for current results")
		}
	}
	return problems, notes
}

// CheckGraph checks an action graph (normalized/lineage.json): every edge
// joins two nodes the graph holds, cites at least one source reference,
// and a correlated edge cites the independent witness it was paired with.
// A graph that declares adfir_spec 0.2.2 or later also may not mark an
// edge CORROBORATED unless the edge cites a telemetry reference or states
// in limitations why it does not.
func CheckGraph(data []byte) (problems, notes []string) {
	v, err := decode(data)
	if err != nil {
		return []string{"lineage.json: not JSON: " + err.Error()}, nil
	}
	g, ok := v.(map[string]any)
	if !ok {
		return []string{"lineage.json: not an object"}, nil
	}
	bad := func(f string, a ...any) { problems = append(problems, "lineage.json: "+fmt.Sprintf(f, a...)) }
	if s, _ := str(g, "schema"); !strings.HasPrefix(s, "agentdfir.lineage/") {
		bad("schema %q is not agentdfir.lineage/*", s)
	}
	strict := false
	if s, ok := str(g, "adfir_spec"); ok {
		strict = specAtLeast(s, "0.2.2")
	}
	nodes, ok := g["nodes"].([]any)
	if !ok {
		bad("nodes is not an array")
		return problems, notes
	}
	edges, ok := g["edges"].([]any)
	if !ok {
		bad("edges is not an array")
		return problems, notes
	}
	if len(nodes) > maxGraphNodes || len(edges) > maxGraphEdges {
		bad("%d nodes / %d edges is over the checker's bound", len(nodes), len(edges))
		return problems, notes
	}
	ids := make(map[string]bool, len(nodes))
	for i, n := range nodes {
		no, _ := n.(map[string]any)
		if no == nil {
			bad("nodes[%d] is not an object", i)
			continue
		}
		id, _ := str(no, "id")
		if id == "" {
			bad("nodes[%d] has no id", i)
			continue
		}
		if ids[id] {
			bad("node %q is listed twice", id)
		}
		ids[id] = true
		if k, _ := str(no, "kind"); k == "" {
			bad("node %q has no kind", id)
		}
		if s, ok := str(no, "evidence_state"); ok && s != "" && !evidenceStates[s] {
			bad("node %q has evidence_state %q", id, s)
		}
	}
	const maxReported = 50
	reported := 0
	for i, e := range edges {
		if reported >= maxReported {
			bad("more problems in edges not listed")
			break
		}
		before := len(problems)
		eo, _ := e.(map[string]any)
		if eo == nil {
			bad("edges[%d] is not an object", i)
			reported++
			continue
		}
		from, _ := str(eo, "from")
		to, _ := str(eo, "to")
		label := fmt.Sprintf("edge %d (%s -> %s)", i, from, to)
		if !ids[from] {
			bad("%s: from-node %q is not in the graph", label, from)
		}
		if !ids[to] {
			bad("%s: to-node %q is not in the graph", label, to)
		}
		if r, _ := str(eo, "relation"); r == "" {
			bad("%s: no relation", label)
		}
		if _, ok := str(eo, "basis"); !ok {
			bad("%s: no basis", label)
		}
		state, _ := str(eo, "evidence_state")
		if state != "" && !evidenceStates[state] {
			bad("%s: evidence_state %q", label, state)
		}
		refs, ok := eo["source_refs"].([]any)
		if !ok || len(refs) == 0 {
			bad("%s: no source reference", label)
		}
		telemetry, record := false, false
		for j, r := range refs {
			ro, _ := r.(map[string]any)
			if ro == nil {
				bad("%s: source_refs[%d] is not an object", label, j)
				continue
			}
			t, _ := str(ro, "telemetry_ref")
			a, _ := str(ro, "artifact_id")
			ev, _ := str(ro, "event_id")
			if t == "" && a == "" && ev == "" {
				bad("%s: source_refs[%d] names no artifact, event or telemetry record", label, j)
			}
			telemetry = telemetry || t != ""
			record = record || a != "" || ev != ""
		}
		if lim, ok := eo["limitations"]; ok {
			if l, ok := lim.([]any); !ok {
				bad("%s: limitations is not an array", label)
			} else {
				for _, x := range l {
					if _, ok := x.(string); !ok {
						bad("%s: limitations holds a non-string", label)
						break
					}
				}
			}
		}
		_, correlated := eo["confidence"]
		if correlated && !(telemetry && record) {
			bad("%s: a correlated edge (it has confidence) must cite both the agent record and the telemetry record it was paired with", label)
		}
		if strict && state == schema.StateCorroborated && !telemetry {
			if l, _ := eo["limitations"].([]any); len(l) == 0 {
				bad("%s: CORROBORATED with no telemetry reference and no limitation saying why", label)
			}
		}
		if len(problems) > before {
			reported++
		}
	}
	if !strict {
		notes = append(notes, "lineage.json does not declare adfir_spec 0.2.2; the per-edge CORROBORATED rule was not applied (graphs from earlier versions)")
	}
	return problems, notes
}

// specAtLeast compares dotted revision numbers.
func specAtLeast(have, want string) bool {
	h, w := strings.Split(have, "."), strings.Split(want, ".")
	for i := 0; i < len(w); i++ {
		var a, b int
		if i < len(h) {
			fmt.Sscan(h[i], &a)
		}
		fmt.Sscan(w[i], &b)
		if a != b {
			return a > b
		}
	}
	return true
}

// ---- STIX 2.1

// STIX identifiers. AgentDFIR's own objects (SDOs and SROs) take UUIDv5
// ids in STIXNamespace, itself uuid5(NAMESPACE_URL,
// "https://efij.github.io/AgentDFIR/stix"); cyber-observable objects use
// the namespace STIX 2.1 section 2.9 fixes for them, over their
// ID-contributing properties, so equal observables get equal ids in any
// producer's bundle.
const (
	STIXNamespace    = "6a44158c-b5d0-56ae-8976-a8dc20c62f96"
	STIXSCONamespace = "00abedb4-aa42-466c-9c01-fed23315a9b7"
)

// UUIDv5 is RFC 9562 UUID version 5 (SHA-1, name-based).
func UUIDv5(namespace, name string) string {
	ns, err := hex.DecodeString(strings.ReplaceAll(namespace, "-", ""))
	if err != nil || len(ns) != 16 {
		panic("repro: bad UUID namespace " + namespace)
	}
	h := sha1.New()
	h.Write(ns)
	h.Write([]byte(name))
	b := h.Sum(nil)[:16]
	b[6] = (b[6] & 0x0f) | 0x50
	b[8] = (b[8] & 0x3f) | 0x80
	x := hex.EncodeToString(b)
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

// STIXToolIdentity is the id of the identity object naming AgentDFIR as
// the producer of a bundle. A bundle that does not hold it was not
// produced under 0.2.2.
var STIXToolIdentity = "identity--" + UUIDv5(STIXNamespace, "identity|agentdfir")

var (
	stixIDRe   = regexp.MustCompile(`^([a-z0-9][a-z0-9-]*[a-z0-9])--[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	stixTypeRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,248}[a-z0-9]$`)
	stixTSRe   = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$`)
)

// sdoRequired lists, per object type this producer writes, the properties
// STIX 2.1 requires beyond type, spec_version and id (and created and
// modified, which every SDO and SRO has).
var sdoRequired = map[string][]string{
	"identity":       {"name"},
	"indicator":      {"pattern", "pattern_type", "valid_from"},
	"note":           {"content", "object_refs"},
	"report":         {"name", "published", "object_refs"},
	"observed-data":  {"first_observed", "last_observed", "number_observed", "object_refs"},
	"relationship":   {"relationship_type", "source_ref", "target_ref"},
	"sighting":       {"sighting_of_ref"},
	"attack-pattern": {"name"},
}

var scoRequired = map[string][]string{
	"domain-name": {"value"},
	"ipv4-addr":   {"value"},
	"ipv6-addr":   {"value"},
	"url":         {"value"},
	"file":        {}, // hashes or name, checked below
}

// CheckSTIX checks a STIX 2.1 bundle against the properties the
// specification requires of the object types it holds, that ids are
// well-formed and unique, timestamps are STIX timestamps, and that every
// reference resolves inside the bundle (a 0.2.2 export is self-contained).
// Object types it does not know are noted, not failed.
func CheckSTIX(data []byte) (problems, notes []string) {
	v, err := decode(data)
	if err != nil {
		return []string{"STIX bundle: not JSON: " + err.Error()}, nil
	}
	b, ok := v.(map[string]any)
	if !ok {
		return []string{"STIX bundle: not an object"}, nil
	}
	bad := func(f string, a ...any) { problems = append(problems, "STIX: "+fmt.Sprintf(f, a...)) }
	if t, _ := str(b, "type"); t != "bundle" {
		bad("type %q, want bundle", t)
	}
	if id, _ := str(b, "id"); !stixIDRe.MatchString(id) || !strings.HasPrefix(id, "bundle--") {
		bad("bundle id %q is not bundle--<uuid>", id)
	}
	objs, ok := b["objects"].([]any)
	if !ok {
		bad("objects is not an array")
		return problems, notes
	}
	if len(objs) > maxSTIXObjs {
		bad("%d objects is over the checker's bound", len(objs))
		return problems, notes
	}
	ids := map[string]bool{}
	type ref struct{ from, to, prop string }
	var refs []ref
	unknown := map[string]int{}
	for i, o := range objs {
		m, _ := o.(map[string]any)
		if m == nil {
			bad("objects[%d] is not an object", i)
			continue
		}
		typ, _ := str(m, "type")
		id, _ := str(m, "id")
		label := fmt.Sprintf("objects[%d] (%s)", i, id)
		if !stixTypeRe.MatchString(typ) {
			bad("%s: type %q is not a STIX type name", label, typ)
			continue
		}
		mm := stixIDRe.FindStringSubmatch(id)
		if mm == nil || mm[1] != typ {
			bad("%s: id is not %s--<uuid>", label, typ)
		}
		if ids[id] {
			bad("%s: id used twice", label)
		}
		ids[id] = true
		if sv, _ := str(m, "spec_version"); sv != "2.1" {
			bad("%s: spec_version %q, want 2.1", label, sv)
		}
		req, isSDO := sdoRequired[typ]
		sreq, isSCO := scoRequired[typ]
		switch {
		case isSDO:
			created, _ := str(m, "created")
			modified, _ := str(m, "modified")
			if !stixTSRe.MatchString(created) {
				bad("%s: created %q is not a STIX timestamp", label, created)
			}
			if !stixTSRe.MatchString(modified) {
				bad("%s: modified %q is not a STIX timestamp", label, modified)
			} else if stixTSRe.MatchString(created) && tsBefore(modified, created) {
				bad("%s: modified is before created", label)
			}
			for _, k := range req {
				if _, ok := m[k]; !ok {
					bad("%s: missing required property %s", label, k)
				}
			}
		case isSCO:
			for _, k := range sreq {
				if s, _ := str(m, k); s == "" {
					bad("%s: missing required property %s", label, k)
				}
			}
			if typ == "file" {
				h, _ := obj(m, "hashes")
				if n, _ := str(m, "name"); len(h) == 0 && n == "" {
					bad("%s: a file needs hashes or name", label)
				}
			}
		default:
			unknown[typ]++
		}
		for _, k := range []string{"created", "modified", "valid_from", "valid_until", "published", "first_observed", "last_observed"} {
			if s, ok := m[k]; ok {
				if ts, _ := s.(string); !stixTSRe.MatchString(ts) {
					bad("%s: %s %v is not a STIX timestamp", label, k, s)
				}
			}
		}
		if typ == "observed-data" {
			if fo, lo := fmt.Sprint(m["first_observed"]), fmt.Sprint(m["last_observed"]); stixTSRe.MatchString(fo) && stixTSRe.MatchString(lo) && tsBefore(lo, fo) {
				bad("%s: last_observed is before first_observed", label)
			}
			n, _ := m["number_observed"].(json.Number)
			if k, err := n.Int64(); err != nil || k < 1 || k > 999999999 {
				bad("%s: number_observed %v is not in 1..999999999", label, m["number_observed"])
			}
		}
		if typ == "indicator" {
			if pt, _ := str(m, "pattern_type"); pt == "stix" {
				if p, _ := str(m, "pattern"); !strings.HasPrefix(p, "[") || !strings.HasSuffix(p, "]") {
					bad("%s: a stix pattern must be [ ... ]", label)
				}
			}
		}
		if er, ok := m["external_references"]; ok {
			l, ok := er.([]any)
			if !ok {
				bad("%s: external_references is not an array", label)
			}
			for j, x := range l {
				xo, _ := x.(map[string]any)
				if s, _ := str(xo, "source_name"); s == "" {
					bad("%s: external_references[%d] has no source_name", label, j)
				}
			}
		}
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			switch {
			case strings.HasSuffix(k, "_ref"):
				s, _ := m[k].(string)
				refs = append(refs, ref{id, s, k})
			case strings.HasSuffix(k, "_refs"):
				l, ok := m[k].([]any)
				if !ok {
					bad("%s: %s is not an array", label, k)
					continue
				}
				if len(l) == 0 && (k == "object_refs") {
					bad("%s: object_refs is empty", label)
				}
				for _, x := range l {
					s, _ := x.(string)
					refs = append(refs, ref{id, s, k})
				}
			}
		}
	}
	for _, r := range refs {
		if !stixIDRe.MatchString(r.to) {
			bad("%s: %s %q is not a STIX id", r.from, r.prop, r.to)
		} else if !ids[r.to] {
			bad("%s: %s %s does not resolve inside the bundle", r.from, r.prop, r.to)
		}
	}
	for _, t := range sortedKeys(unknown) {
		notes = append(notes, fmt.Sprintf("STIX: %d object(s) of type %s not checked beyond id and spec_version", unknown[t], t))
	}
	return problems, notes
}

func tsBefore(a, b string) bool {
	ta, err1 := time.Parse(time.RFC3339Nano, a)
	tb, err2 := time.Parse(time.RFC3339Nano, b)
	return err1 == nil && err2 == nil && ta.Before(tb)
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---- the overlay as a whole

// OverlayCheck is the result of checking a package's analysis files.
type OverlayCheck struct {
	Checked  []string `json:"checked"`
	Problems []string `json:"problems"`
	Notes    []string `json:"notes"`
}

// STIXReport is where `agentdfir report --format stix` writes by default.
const STIXReport = "reports/findings.stix.json"

// CheckOverlay checks whichever 0.2.2 analysis files a package holds:
// the analysis manifest against findings.json, the action graph, and the
// default STIX export. All are optional; a package with none of them has
// nothing to check. A STIX bundle that does not carry AgentDFIR's 0.2.2
// tool identity predates 0.2.2 and is noted, not checked.
func CheckOverlay(pkg string) *OverlayCheck {
	c := &OverlayCheck{Checked: []string{}, Problems: []string{}, Notes: []string{}}
	seal := ""
	if r := HashFile(filepath.Join(pkg, "SHA256SUMS")); r.Error == "" {
		seal = r.SHA256
	}
	if man, err := overlay.ReadFile(Path(pkg)); err == nil {
		c.Checked = append(c.Checked, "detections/"+ManifestFile)
		findings, ferr := overlay.ReadFile(filepath.Join(pkg, filepath.FromSlash(FindingsFile)))
		if ferr != nil {
			findings = nil
		}
		p, n := CheckManifest(man, findings, seal)
		c.Problems, c.Notes = append(c.Problems, p...), append(c.Notes, n...)
	} else if !os.IsNotExist(err) {
		c.Problems = append(c.Problems, "analysis-manifest.json: unreadable: "+err.Error())
	}
	if g, err := overlay.ReadFile(filepath.Join(pkg, "normalized", "lineage.json")); err == nil {
		c.Checked = append(c.Checked, "normalized/lineage.json")
		p, n := CheckGraph(g)
		c.Problems, c.Notes = append(c.Problems, p...), append(c.Notes, n...)
	} else if !os.IsNotExist(err) {
		c.Problems = append(c.Problems, "lineage.json: unreadable: "+err.Error())
	}
	if s, err := overlay.ReadFile(filepath.Join(pkg, filepath.FromSlash(STIXReport))); err == nil {
		if !bytes.Contains(s, []byte(STIXToolIdentity)) {
			c.Notes = append(c.Notes, STIXReport+" predates 0.2.2 (no AgentDFIR tool identity); not checked")
		} else {
			c.Checked = append(c.Checked, STIXReport)
			p, n := CheckSTIX(s)
			c.Problems, c.Notes = append(c.Problems, p...), append(c.Notes, n...)
		}
	}
	return c
}
