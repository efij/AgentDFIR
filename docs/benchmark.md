# Benchmark and conformance

`agentdfir benchmark` measures how AgentDFIR behaves on labeled synthetic
evidence, and `tools/adfir-verify/adfir_verify.py` checks `.adfir`
packages without AgentDFIR. Both run offline.

> **Synthetic results are not evidence of real-world accuracy.** Every
> fixture was written for this purpose. The detection fixtures reproduce
> shapes seen on real machines and in published incidents, but a score on
> them says how the tool behaves on those shapes. It says nothing about
> how many real attacks it would catch or how noisy it is on a real
> machine. Every report says so in its first line.

## Running it

```
agentdfir benchmark                      # Markdown report on stdout, exit 1 if a hard check fails
agentdfir benchmark --json               # the same as JSON
agentdfir benchmark --out report.md      # also write it to a file (.json writes JSON)
agentdfir benchmark --quick              # the fast subset go test runs; no performance case
agentdfir benchmark --no-perf            # everything except the performance case
agentdfir benchmark --corpus <dir>       # score a different labeled corpus (benign/, attack/)
agentdfir benchmark --baseline f.json    # compare performance with another baseline
agentdfir benchmark --save-baseline f.json   # write this run's performance numbers as a baseline
```

Progress goes to stderr. The fixtures (the corpus, the historical
packages, the performance baseline) are built into the binary, so an
installed binary runs the same benchmark as a source checkout. Everything
is written to a temporary directory that is removed afterwards.

Exit status: `0` every hard check held, `1` at least one failed (listed
under "Failures"), `2` usage. A performance regression is a warning and
never changes the exit status.

`go test ./internal/benchmark` runs the quick subset: a sample of the
detection fixtures plus every evidence-state scenario, integrity
mutation, historical package and robustness case. Performance is never
measured in `go test`.

## What is measured

| Section | Input | Hard check |
|---|---|---|
| Detection | the labeled corpus (`internal/corpus/testdata`) and every `simulate` scenario, collected and analyzed by the real pipeline | no lost detection; benign false positives within the corpus budget (`budget.json`) |
| Evidence states | five scenarios with endpoint telemetry in formats read today (auditd, Sysmon XML, generic JSONL) or none | every labeled state matches; every event keeps the contract below |
| Provenance | every package the other sections analyze | zero dangling references |
| Integrity | a signed, two-round package with plain, gzip and chunked blobs and an archived seal, mutated one way per copy | every mutation detected by `agentdfir verify` |
| Compatibility | packages written by v1.0.0, v2.0.0, v2.7.0, v3.0.0 and v3.2.0 binaries | each verifies (signature included) and analyzes |
| Robustness | truncated, rewritten, clock-skewed, timestamp-manipulated and corrupted transcripts; contradictory telemetry; Claude Code and Codex sessions side by side | no crash, the expected gap findings, the contract, the case's own state expectations |
| Performance | a generated case: 400 sessions, 24,000 tool calls, 48,800 events | none: compared with `internal/benchmark/testdata/perf-baseline.json`, warning above 25% |

**Detection scoring.** A true positive is a rule an attack fixture names
and got; a false negative is one it named and did not get; a false
positive is a firing on a benign fixture that its label does not allow.
Building blocks (context rules such as `SHELL_EXECUTION`) are never
scored as alerts. A firing on an attack fixture that its label does not
mention is listed as "unlabeled" and not scored either way, because
nobody has decided whether it is right. Coverage gaps are the alert rules
(built-in and embedded packs) that no attack fixture names.

**The evidence-state contract**, checked on every event:

- CONFIRMED (stored `CORROBORATED`) or PARTLY CONFIRMED only with a
  second-witness record: a "corroborated by <source>" note from endpoint
  correlation, or a host-witness note.
- Model narrative and human prompts are never promoted, even when the
  telemetry shows exactly the command the narrative claims.
- DISPROVED (stored `CONTRADICTED`) only on endpoint telemetry covering
  that time, or a host-witness note. A tool call outside the telemetry's
  coverage stays RECORDED.

**Provenance.** An event must name an acquired artifact in the manifest,
a line that exists in it, and the byte offset where that line starts. A
finding reference (`path:line (artifact <id>, offset n)`, `path (artifact
<id>)`, `path:line`, `path (note)`) must resolve to an artifact in the
package, and any line or offset it names must exist. Findings the
endpoint witness raises from records with no transcript counterpart cite
the external log; those are counted separately, because that log is not
sealed into the package.

**Integrity mutations.** Each runs on a fresh copy of the reference
package: flip a byte in a plain and in a gzip blob, truncate, delete or
plant a blob, delete or edit a manifest record, plant a legacy
`manifest.json`, reorder `collection.jsonl`, append a correctly chained
forged custody record, drop the last custody record, replace or plant an
archived seal, replace the archived signature, corrupt or delete
`SEAL.sig`, remove a blob's, `case.json`'s or an archived seal's line
from `SHA256SUMS`, list a file twice, name a path outside the package,
edit `case.json`, edit it and re-seal, and edit it, re-seal, change the
recorded signer and re-sign with another key. The last one is verified
with the signer's key pinned (`verify --pubkey`): someone who controls a
package can always rewrite and re-sign it, and only a key or seal digest
kept outside the package detects that. Likewise, without a pinned key, a
deleted `SEAL.sig` is detected because `case.json` (which is sealed)
records the last round's signer; a package whose `case.json` cannot be
read reports that as a problem rather than passing.

## Current numbers

agentdfir 3.2.0 + this branch, darwin/arm64, 11 CPUs, go1.27.1. Synthetic.

| Section | Result |
|---|---|
| Detection | precision 100.0%, recall 100.0% (29 TP, 0 FP, 0 FN) over 3 attack cases, 8 scenarios, 24 benign cases |
| Rule coverage | 26 of 171 alert rules have an attack fixture; 145 have none (listed in the report); 4 building blocks |
| Evidence states | 12/12 labeled checks, 0 contract violations over 25 events |
| Provenance | 0 dangling: 259/259 events resolved to artifact, line and line start; 159 of 161 finding references resolved, 2 cite external endpoint logs |
| Integrity mutations | 24/24 detected |
| Compatibility | 5/5 historical packages verify and analyze |
| Robustness | 7/7 cases |
| Performance | analyze 3.6–4.4 s, peak heap 152–170 MiB on 48,800 events (baseline 3,574 ms, 152.3 MiB) |

Read the detection line for what it is. The labels were written next to
the rules, and the corpus gates the build, so 100% means the rules still
do what their fixtures say, not that they are 100% accurate. The number
that carries information is the coverage gap: 145 alert rules have no
attack fixture at all. Performance was recorded on a shared, loaded
machine; re-record the baseline with `--save-baseline` on a quiet one
before relying on the 25% warning.

### Defects the benchmark found (fixed on this branch)

| Found by | Defect | Fix |
|---|---|---|
| integrity mutation `manifest-plant-legacy` | `verify` only looked for unlisted files in `raw/`. A `manifest.jsonl` planted next to a sealed legacy `manifest.json` is what every reader uses, and it passed. | unlisted manifest forms and unlisted `seals/` files are reported |
| `seal-archive-plant` | an unlisted file in `seals/` passed as round history | as above |
| `sums-path-escape` | a `SHA256SUMS` path climbing out of the package was read | reported as malformed, not read |
| `sig-delete` | deleting `SEAL.sig` turned a signed package into "unsigned" and still VERIFIED, even with `--pubkey` | a problem when a key is pinned, when the last round recorded a signer, or when `case.json` is unreadable |
| `sums-duplicate-line` | a path listed twice was silently accepted | reported |
| robustness, cross-agent | `collector.Run` panicked on the nil manifest of an unknown product id | returns an error |

## Independent verifier

`tools/adfir-verify/adfir_verify.py` is written from
[`adfir-spec.md`](adfir-spec.md), not ported from the Go code, with the
Python 3 standard library only:

```
python3 tools/adfir-verify/adfir_verify.py [--json] [--pubkey HEX] <package-dir>
```

| Checked | Not checked |
|---|---|
| every `SHA256SUMS` line (format, path safety, duplicates, hash) | the analysis overlay (`normalized/`, `detections/`, `reports/`): derived, not sealed |
| unlisted files in `raw/`, `seals/`, and unlisted manifest forms | the anchor log outside the package |
| each acquired artifact's plaintext against `artifact_id`, through gzip (bounded by the recorded size) and chunks, and each unit against `stored_sha256` | blobs over 256 MiB (reported as a note, not re-derived) |
| both hash chains (`prev`, `seq`) | encrypted `.adfir.enc` envelopes |
| `SEAL.sig` with a pure-Python RFC 8032 ed25519 verifier; a missing signature when pinned or recorded | |
| archived seals against `case.json`'s `prev_seal_sha256`, archived signatures, and that no blob an earlier round sealed has changed | |

Exit status `0` verified, `1` problems, `2` usage or unreadable package.

## Conformance fixtures

`testdata/conformance/` holds `valid/` and one `invalid-<mutation>/` per
integrity mutation, each a `package/` directory and an `expected.json`
(`verdict`, `description`, and `pubkey` when the case pins a key). Go
tests require `agentdfir verify` to reach every expected verdict and,
when `python3` is on `PATH`, the Python verifier too, on the fixtures and
on the historical packages. Regenerate the fixtures with
`scripts/gen-conformance-fixtures.sh` (Docker; the packages then record a
neutral host) and the historical packages with
`scripts/gen-compat-fixtures.sh` (Docker, git; each built by its own tag).
