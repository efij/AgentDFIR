# .adfir conformance fixtures

Each directory holds `package/` and `expected.json` (the verdict a
conforming verifier must reach, and the key to pin when one is needed).
Regenerate with `go test ./internal/benchmark -run TestConformance -update-conformance`
(everything) or `-update-conformance-analysis` (only the `analysis-*` set).

- `valid`, `invalid-*` (spec 0.2 / 0.2.1): integrity. Packages written by
  the tool's own sealing code; each `invalid-*` is `valid` with one
  mutation applied by `Mutations()` in internal/benchmark/integrity.go.
- `analysis-*` (spec 0.2.2, `"kind": "analysis"`): the optional analysis
  files. `analysis-valid` was collected and analyzed by the tool (a
  synthetic transcript, a synthetic auditd log as second witness, a
  synthetic IOC feed), then reduced to the files under test, stored
  uncompressed: `detections/analysis-manifest.json`,
  `detections/findings.json`, `normalized/lineage.json`,
  `reports/findings.stix.json`. The manifest's recorded input paths were
  temporary and are cut to base names (paths are not part of the
  fingerprint). `analysis-valid-pre022-graph` drops `adfir_spec` and edge
  `limitations` from the graph, as a pre-0.2.2 binary wrote it. Each
  `analysis-invalid-*` is `analysis-valid` with one hand-applied edit
  (`analysisMutations()` in internal/benchmark/conformance_analysis_test.go);
  their sealed zones verify, so the expected `FAILED` is about the
  analysis files alone.
