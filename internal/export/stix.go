package export

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/ioc"
	"github.com/efij/AgentDFIR/v4/internal/repro"
	"github.com/efij/AgentDFIR/v4/internal/schema"
	"github.com/efij/AgentDFIR/v4/internal/version"
)

// --- STIX 2.1 ---
//
// The bundle `report --format stix` writes (spec 0.2.2):
//
//   - one identity: AgentDFIR, the producer (created_by_ref of every
//     object it makes);
//   - one report for the case, referencing everything else;
//   - one note per finding: abstract = title, content = description and
//     evidence states and references, labels = rule id and severity, and
//     external_references to MITRE ATT&CK and ATLAS technique ids;
//   - for known-incident indicators that the evidence actually holds (IOC
//     hunt hits observed in commands, files, tool output, configs; never
//     mere mentions or low-confidence context): an indicator with a STIX
//     pattern, the cyber-observable (domain-name, ipv4-addr, ipv6-addr, or
//     file by SHA-256), an observed-data when the evidence dates the
//     sighting, and a relationship (indicator based-on observed-data, or
//     indicator related-to the observable when there is no date);
//   - nothing for indicator kinds with no STIX observable (packages, paths,
//     strings, command patterns): those stay in the finding notes, and the
//     report says how many. A URL indicator is a prefix without a scheme,
//     not a URL, so it gets an indicator with a LIKE pattern and no url
//     object.
//
// Ids are UUIDv5: AgentDFIR's objects in repro.STIXNamespace over
// "<type>|<case>|<identity>", observables in the STIX 2.1 SCO namespace
// over their ID-contributing properties, so a re-export of the same case
// is byte-identical. Timestamps are the case's creation time, never the
// clock, for the same reason.

// STIXInput is what a bundle is made from.
type STIXInput struct {
	Findings []schema.Finding
	CaseID   string
	// Created stamps created/modified/published/valid_from (the case's
	// creation time). Zero means the Unix epoch, which keeps output
	// deterministic and is plainly not a real observation time.
	Created time.Time
	// Hunt is the known-incident IOC hunt (detections/hunt.json).
	Hunt []ioc.Verdict
}

func stixTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func sdoID(typ, caseID string, parts ...string) string {
	return typ + "--" + repro.UUIDv5(repro.STIXNamespace, typ+"|"+caseID+"|"+strings.Join(parts, "|"))
}

// scoID is the STIX 2.1 deterministic id over ID-contributing properties,
// canonicalized (RFC 8785: sorted keys, no HTML escaping).
func scoID(typ string, props map[string]any) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(props) // map keys are sorted by encoding/json
	return typ + "--" + repro.UUIDv5(repro.STIXSCONamespace, strings.TrimSuffix(buf.String(), "\n"))
}

func stixString(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, `\`, `\\`), `'`, `\'`)
}

func mitreURL(source, id string) string {
	switch source {
	case "mitre-attack":
		return "https://attack.mitre.org/techniques/" + strings.ReplaceAll(id, ".", "/") + "/"
	case "mitre-atlas":
		return "https://atlas.mitre.org/techniques/" + id
	}
	return ""
}

func techniqueRefs(f schema.Finding) []map[string]string {
	var out []map[string]string
	for _, src := range []struct{ name, ids string }{{"mitre-attack", f.MitreATTACK}, {"mitre-atlas", f.MitreATLAS}} {
		for _, id := range strings.FieldsFunc(src.ids, func(r rune) bool { return r == ',' || r == ' ' || r == ';' }) {
			out = append(out, map[string]string{"source_name": src.name, "external_id": id, "url": mitreURL(src.name, id)})
		}
	}
	return out
}

// observable maps an IOC to its STIX cyber-observable and pattern; ok is
// false for kinds STIX has no observable for.
func observable(ind ioc.Indicator) (sco map[string]any, pattern string, ok bool) {
	v := strings.TrimSpace(ind.Value)
	if v == "" {
		return nil, "", false
	}
	switch ind.Kind {
	case ioc.KindDomain:
		if ip := net.ParseIP(v); ip != nil {
			typ := "ipv6-addr"
			if ip.To4() != nil {
				typ, v = "ipv4-addr", ip.To4().String()
			}
			return map[string]any{"type": typ, "spec_version": "2.1", "id": scoID(typ, map[string]any{"value": v}), "value": v},
				fmt.Sprintf("[%s:value = '%s']", typ, stixString(v)), true
		}
		v = strings.ToLower(v)
		return map[string]any{"type": "domain-name", "spec_version": "2.1", "id": scoID("domain-name", map[string]any{"value": v}), "value": v},
			fmt.Sprintf("[domain-name:value = '%s']", stixString(v)), true
	case ioc.KindSHA256:
		v = strings.ToLower(v)
		h := map[string]any{"SHA-256": v}
		return map[string]any{"type": "file", "spec_version": "2.1", "id": scoID("file", map[string]any{"hashes": h}), "hashes": h},
			fmt.Sprintf("[file:hashes.'SHA-256' = '%s']", stixString(v)), true
	case ioc.KindURL:
		// A prefix without a scheme: an indicator, no url object.
		return nil, fmt.Sprintf("[url:value LIKE '%%%s%%']", stixString(v)), true
	}
	return nil, "", false
}

// WriteSTIXBundle writes the case as a STIX 2.1 bundle (see above).
func WriteSTIXBundle(in STIXInput, path string) error {
	created := in.Created
	if created.IsZero() {
		created = time.Unix(0, 0)
	}
	ts := stixTime(created)
	identity := repro.STIXToolIdentity
	reportID := sdoID("report", in.CaseID)
	objects := []map[string]any{{
		"type": "identity", "spec_version": "2.1", "id": identity, "created": ts, "modified": ts,
		"name": "AgentDFIR", "identity_class": "system",
		"description": "AgentDFIR " + version.Version + ", offline AI-agent forensics; the producer of this bundle",
	}}
	var refs []string
	seen := map[string]bool{identity: true}
	add := func(o map[string]any) bool {
		id := o["id"].(string)
		if seen[id] {
			return false
		}
		seen[id] = true
		objects = append(objects, o)
		refs = append(refs, id)
		return true
	}

	// Observables first: notes for KNOWN_INCIDENT_IOC findings refer to
	// the indicator they cite.
	type indKey struct{ incident, label string }
	indicatorOf := map[indKey]string{}
	unmapped := 0
	for _, v := range in.Hunt {
		for _, h := range v.Hits {
			sco, pattern, ok := observable(h.Indicator)
			if !ok {
				unmapped++
				continue
			}
			indID := sdoID("indicator", "", h.Indicator.Kind, strings.ToLower(h.Indicator.Value))
			indicatorOf[indKey{v.Incident.ID, h.Indicator.Label()}] = indID
			add(map[string]any{
				"type": "indicator", "spec_version": "2.1", "id": indID, "created": ts, "modified": ts, "created_by_ref": identity,
				"name": "Known-incident indicator: " + h.Indicator.Label(), "indicator_types": []string{"malicious-activity"},
				"pattern": pattern, "pattern_type": "stix", "valid_from": ts,
				"description": "Indicator of " + v.Incident.Title + " (" + v.Incident.ID + "), present in this case's evidence.",
			})
			if sco == nil {
				continue
			}
			scoRef := sco["id"].(string)
			add(sco)
			first, err1 := time.Parse(time.RFC3339Nano, h.FirstSeen)
			last, err2 := time.Parse(time.RFC3339Nano, h.LastSeen)
			if err2 != nil {
				last, err2 = first, err1
			}
			if err1 == nil && err2 == nil && !last.Before(first) {
				n := h.Count
				if n < 1 {
					n = 1
				}
				if n > 999999999 {
					n = 999999999
				}
				odID := sdoID("observed-data", in.CaseID, v.Incident.ID, h.Indicator.Kind, h.Indicator.Value, h.Where, h.Surface)
				if add(map[string]any{
					"type": "observed-data", "spec_version": "2.1", "id": odID, "created": ts, "modified": ts, "created_by_ref": identity,
					"first_observed": stixTime(first), "last_observed": stixTime(last), "number_observed": n, "object_refs": []string{scoRef},
					"labels": []string{"where:" + h.Where, "surface:" + h.Surface},
				}) {
					add(map[string]any{
						"type": "relationship", "spec_version": "2.1", "id": sdoID("relationship", in.CaseID, indID, "based-on", odID),
						"created": ts, "modified": ts, "created_by_ref": identity,
						"relationship_type": "based-on", "source_ref": indID, "target_ref": odID,
					})
				}
			} else {
				add(map[string]any{
					"type": "relationship", "spec_version": "2.1", "id": sdoID("relationship", in.CaseID, indID, "related-to", scoRef),
					"created": ts, "modified": ts, "created_by_ref": identity,
					"relationship_type": "related-to", "source_ref": indID, "target_ref": scoRef,
					"description": "the evidence holds this observable; it does not date the sighting",
				})
			}
		}
	}

	for i, f := range in.Findings {
		key := f.RuleID + "|" + f.SessionID + "|" + f.AgentID + "|" + strings.Join(f.EvidenceRefs, "|") + "|" + f.Title
		id := sdoID("note", in.CaseID, key)
		if seen[id] {
			id = sdoID("note", in.CaseID, key, fmt.Sprint(i))
		}
		content := f.Description
		content += fmt.Sprintf("\n\nRule: %s. Severity: %s. Evidence state: %s. Second witness: %s.", f.RuleID, f.Severity, f.Status, f.Endpoint)
		if f.Confidence != "" {
			content += " Confidence: " + f.Confidence + "."
		}
		for _, r := range f.EvidenceRefs {
			content += "\nEvidence: " + r
		}
		objRefs := []string{reportID}
		if f.RuleID == "KNOWN_INCIDENT_IOC" {
			var inc, lab string
			for _, r := range f.Related {
				if s, ok := strings.CutPrefix(r, "incident: "); ok {
					inc = s
				}
				if s, ok := strings.CutPrefix(r, "indicator: "); ok {
					lab = s
				}
			}
			if ind, ok := indicatorOf[indKey{inc, lab}]; ok {
				objRefs = append(objRefs, ind)
			}
		}
		note := map[string]any{
			"type": "note", "spec_version": "2.1", "id": id, "created": ts, "modified": ts, "created_by_ref": identity,
			"abstract": f.Title, "content": content, "object_refs": objRefs,
			"labels": []string{f.RuleID, "severity:" + f.Severity}, "confidence": confidence(f.Status),
		}
		if er := techniqueRefs(f); len(er) > 0 {
			note["external_references"] = er
		}
		add(note)
	}

	desc := fmt.Sprintf("Findings of AgentDFIR case %s: %d finding note(s). Observables are known-incident indicators the evidence holds; evidence states are the case's own and are never upgraded.", in.CaseID, len(in.Findings))
	if unmapped > 0 {
		desc += fmt.Sprintf(" %d indicator hit(s) of kinds with no STIX observable (packages, paths, strings, command patterns) are described in the notes only.", unmapped)
	}
	sort.Strings(refs)
	if len(refs) == 0 {
		refs = []string{identity}
	}
	objects = append(objects, map[string]any{
		"type": "report", "spec_version": "2.1", "id": reportID, "created": ts, "modified": ts, "created_by_ref": identity,
		"name": "AgentDFIR findings: " + in.CaseID, "published": ts, "report_types": []string{"threat-report"},
		"description": desc, "object_refs": refs,
	})
	return writeJSON(path, map[string]any{
		"type":    "bundle",
		"id":      "bundle--" + repro.UUIDv5(repro.STIXNamespace, "bundle|"+in.CaseID),
		"objects": objects,
	})
}
