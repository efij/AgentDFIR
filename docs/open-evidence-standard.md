# Verifying a case without trusting AgentDFIR

An `.adfir` package is meant to be checked by someone who has no reason
to trust the tool that made it, its explorer, or the analyst who ran it.
Everything below works from files and published rules: the
specification ([adfir-spec.md](adfir-spec.md), revision 0.2.2), the JSON
Schemas in [schema/](schema/), and an independent verifier,
`tools/adfir-verify/adfir_verify.py`, written from the specification
with the Python 3 standard library only (including its own ed25519).

## What a third party can establish, and how

| Question | Check | Without AgentDFIR |
|---|---|---|
| Is the evidence what was collected? | `SHA256SUMS` covers the sealed zone; every artifact's plaintext hashes to its `artifact_id`; both hash chains are intact | `python3 -I adfir_verify.py case.adfir` |
| Who sealed it? | `SEAL.sig` is an ed25519 signature over SHA-256(`SHA256SUMS`) | `--pubkey <hex>` pins the key you were given out of band |
| Were the findings changed after the analysis? | `detections/analysis-manifest.json` records a `findings_fingerprint`; recompute it from `detections/findings.json` | the verifier does this whenever the manifest is present |
| What produced the findings? | the manifest names the tool version, the hash of its analysis code, every rule pack by SHA-256, the seal it analyzed, and every option and input file (by SHA-256) | read the manifest; it is plain JSON |
| Would the same tool reach the same findings again? | re-run the recorded analysis from the sealed zone and compare fingerprints | needs the tool once: `agentdfir verify --reproduce case.adfir` with the version the manifest names; the comparison itself is the published fingerprint |
| Is every link in the "who did what" graph backed by evidence? | every edge joins nodes that exist and cites a source reference; a correlated edge cites both the agent record and the telemetry record; a CORROBORATED edge cites telemetry or says why not | the verifier checks `normalized/lineage.json` |
| Is the STIX export well formed? | STIX 2.1 required properties, ids, timestamps, references inside the bundle | the verifier checks `reports/findings.stix.json`, or any bundle with `--stix FILE` |
| Is a production set complete and unaltered? | every file the production manifest lists hashes to its recorded SHA-256, nothing else is present, and the manifest is signed | `python3 -I adfir_verify.py case.production [--pubkey hex]` |

The verifier prints one verdict and, with `--json`, separate
`integrity_verdict` and `analysis_verdict`: the analysis files are
derived data outside the seal, so their problems never say anything
about the evidence, only about whether the conclusions on top of it are
the ones the analysis wrote.

## What these checks do not prove

- A valid signature proves who sealed a package only as far as you
  trust the key. Get the producer's public key, or the seal digest the
  collection printed, through a channel the producer does not control.
- The findings fingerprint proves the findings were not edited after the
  analysis and lets anyone reproduce it; it does not prove the rules are
  right. The rules are open source; the manifest says exactly which ones
  ran.
- Honeytokens are recorded by count only (a digest of planted secrets in
  the package would let its holder confirm guesses), so a reproduction
  can check that the same number were supplied, not that they were the
  same.
- An analysis that reused an earlier run's results (`overlay_reused`,
  `reused_correlation` in the manifest) cannot be reproduced from the
  sealed zone alone; reproduce the run that read those inputs.
- Absence of telemetry is never proof of non-execution, in the graph or
  anywhere else; edges state their limitations.

## Conformance

`testdata/conformance/` holds the fixtures any verifier must agree with:
integrity tamper cases, and from 0.2.2 the analysis set (valid manifest,
graph and bundle, a pre-0.2.2 graph, and one fixture per inconsistency).
Both `agentdfir verify` and `adfir_verify.py` are tested against all of
them and against packages written by released versions. A third-party
verifier that reaches every `expected.json` verdict implements the
standard.
