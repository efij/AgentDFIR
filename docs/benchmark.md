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
agentdfir benchmark --repo <checkout>    # where the disk-image, telemetry and interop fixtures are
```

Progress goes to stderr. The corpus, the historical packages and the
performance baseline are built into the binary. The disk-image, telemetry
and interop fixtures and the Python verifier are not (they would add
megabytes to every binary): the suites that need them look for a source
checkout from the working directory up, or where `--repo` points, and
report SKIP with the reason when there is none. Everything is written to
a temporary directory that is removed afterwards; decompressed disk
images are written sparse and deleted one at a time.

Exit status: `0` every hard check held, `1` at least one failed (listed
under "Failures"), `2` usage. A performance regression is a warning and
never changes the exit status.

`go test ./internal/benchmark` runs the quick subset: a sample of the
detection fixtures plus every evidence-state scenario, integrity
mutation, historical package and robustness case, and every
cross-platform suite. Performance is never measured in `go test`.

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

## Cross-platform suites

Five suites run after the sections above, and each ends in its own
**PASS / FAIL / SKIP** verdict, in the Markdown report and under
`suites` in the JSON. Every suite carries the label *synthetic or
tool-generated fixtures; not a comparison with any other product*.
Nothing in them runs, imitates the output of, or scores against another
product; a third party who wants a comparison can run the same fixtures
through another tool.

| Suite | Input | Hard checks |
|---|---|---|
| Acquisition | every disk-image fixture under `internal/diskimage/**/testdata` (41): NTFS in raw, split raw, E01 (one and nine segments), VHD fixed/dynamic, VHDX, VMDK sparse/stream/flat; the USN and VSS NTFS volumes; ext4, ext2, ext4 inline-data; FAT12/16/32, exFAT; XFS v5 and v4; Btrfs; QCOW2 v2/v3/deflate and the two refused QCOW2 variants; LVM2; APFS, HFS+, HFSX; DMG UDZO/UDBZ/ULFO; the sparsebundle; the three-volume APFS DMG; the encrypted DMG header | each opens with the `collect --image` reader (or is refused with the documented UNSUPPORTED / ENCRYPTED kind); every volume is enumerated and every regular file read; files and symlinks match the fixture's manifest where one exists (the coreutils listings `xfs.manifest` / `btrfs.manifest` made from a read-only mount, the `expected.txt` files from `shasum` on the source tree), containers match the raw image they wrap byte for byte; every UNSUPPORTED state reported is one the fixture documents and the documented ones are all reported; the fixture and every segment file hash the same after every reader closed (read-only proof). Fixtures without a manifest (the NTFS volumes, HFSX, the three-volume APFS DMG) are reported "enumerated, not compared" |
| Per-OS corroboration | generated Claude Code sessions whose tool calls claim commands, a file write and network use, with synthetic telemetry in each source's documented shape: Windows Sysmon in a native `.evtx`, macOS eslogger JSON and unified log ndjson, Linux auditd, Tetragon, Falco and docker events; then every labeled corpus case that carries endpoint telemetry | each claim's labeled state and the expected CORROBORATED count per scenario; the evidence-state contract on every event; for corpus cases, the expected rules fire. The incomplete-telemetry contract, per platform, on observable states: telemetry without file or network records never contradicts a write or a fetch; a sequence gap (EVTX EventRecordID, eslogger seq_num / global_seq_num, audit serial) never turns a claim inside it into DISPROVED, while a claim where numbering is contiguous still is; a process file that stops does not keep processes "covered" because a file of another kind goes on; Falco, docker events and the unified log corroborate, never contradict |
| Forensic interop | the hand-made UFDR, UFD/UFDX, AXIOM CSV, AXIOM Portable Case, Plaso (json_line, l2tcsv) and Autopsy fixtures in `internal/parsers/suite/testdata`, sealed the way `collect --suite-export` seals them and analyzed | record, UNSUPPORTED and unparsed-line counts equal the ones the reader's own tests pin; every original sealed byte-identical; `Case.mfdb` yields the `AXIOM_CASE_DB_UNSUPPORTED` finding |
| Detection quality | the detection section above | as above, plus a breakdown by the platform of each fixture's telemetry (windows, macos, linux; "any" for transcript-only fixtures), and each of the three platforms has labeled attack fixtures |
| Evidence integrity | the integrity and compatibility sections above, and `tools/adfir-verify/adfir_verify.py` (Python 3 standard library) over every package this run built and the five historical packages | every mutation detected, every historical package verifies, the Python verifier says VERIFIED on every package; SKIP, with the reason, when `python3` is not on `PATH` |

**Expected failures.** A check can be marked as failing on this build for
a documented reason. It is then reported **XFAIL** and does not fail the
run; if it passes, it is reported **XPASS** and the run warns, so the
mark can be removed. On this build the per-OS sequence-gap and
stopped-kind checks (two per platform, six in all) are XFAIL with the
reason "fixed by per-kind coverage": correlation still treats the
telemetry as one time window for every record kind and every file, and
does not track sequence numbers, so a missing record inside a gap, or
after a process file stopped, still reads as absence. The labeled
control in each scenario (a claim where coverage is contiguous) passes
as DISPROVED either way.

## Current numbers

A 4.5.0 development build (it still reports `4.0.0` until the release
version bump), `benchmark --no-perf` from a source checkout,
darwin/arm64, 11 CPUs, go1.27.1, 12 s wall time. Synthetic.

| Section | Result |
|---|---|
| Detection | precision 100.0%, recall 100.0% (69 TP, 0 FP, 0 FN) over 29 attack cases, 8 scenarios, 48 benign cases |
| Rule coverage | 60 of 206 alert rules have an attack fixture; 146 have none (listed in the report); 4 building blocks |
| Evidence states | 12/12 labeled checks, 0 contract violations over 25 events |
| Provenance | 0 dangling over 124 packages: 637 of 669 events resolved to artifact, line and line start (the other 32 describe a whole artifact, line 0); 337 of 381 finding references resolved, 44 cite external endpoint logs |
| Integrity mutations | 24/24 detected |
| Compatibility | 5/5 historical packages verify and analyze |
| Robustness | 7/7 cases |
| Performance | not measured in this run (`--no-perf`). A full run on the same loaded machine measured 4,504 ms and 178.1 MiB peak heap on 48,800 events, 26% over the recorded baseline (3,574 ms, 152.3 MiB): a warning, not a failure |

Cross-platform suites, same run:

| Suite | Verdict | Measured |
|---|---|---|
| Acquisition | PASS | 41 fixtures in 2.4 s (35 compared with a manifest or the image they wrap, 6 enumerated only); 45 volumes; 16,031 files enumerated, 16,026 read; manifest files 14,179 of 14,185 recovered with matching SHA-256, the other 6 reported UNSUPPORTED as documented (ext4 fscrypt directory, the Btrfs zstd extent in the raw image and both QCOW2 copies, the LZVN-compressed file on APFS and HFS+); 17 UNSUPPORTED / ENCRYPTED states in all (also: QCOW2 backing file and zstd cluster type, DMG LZFSE chunks, encrypted DMG, the FileVault volume, five non-linear LVM2 LVs); source unchanged 41/41 |
| Per-OS corroboration | PASS | 57 of 63 checks pass, 6 XFAIL (above). Windows (Sysmon .evtx): CORROBORATED 5 of 5 labeled; macOS (eslogger, unified log): 5 of 5; Linux (auditd, Tetragon, Falco, docker events): 10 of 10. Corpus cases with telemetry: 8 Windows, 2 macOS, 2 Linux, every expected rule fired, 0 contract violations |
| Forensic interop | PASS | 6 exports; 17 of 17 expected records (UFDR 5, AXIOM CSV 4, Portable Case 2, Plaso 4, Autopsy 2, UFD 0); 13 of 13 originals sealed byte-identical; UNSUPPORTED notices: Case.mfdb (with the `AXIOM_CASE_DB_UNSUPPORTED` finding) and the unknown UFDR element; Plaso's 2 unparsable lines reported |
| Detection quality | PASS | as above; by platform: Windows 4 attack / 4 benign fixtures, macOS 1 / 1, Linux 1 / 1, transcript-only 31 / 42, each 100.0% / 100.0% |
| Evidence integrity | PASS | 24/24 mutations, 5/5 historical packages; Python 3.12 verifier: 27 of 27 packages VERIFIED (the signed reference package, the 21 packages the suites built, the 5 historical ones) |

Read the detection line for what it is. The labels were written next to
the rules, and the corpus gates the build, so 100% means the rules still
do what their fixtures say, not that they are 100% accurate. The number
that carries information is the coverage gap: 146 alert rules have no
attack fixture at all. The per-platform rows are small (one attack
fixture each on macOS and Linux). The performance baseline was recorded
on a shared, loaded machine; re-record it with `--save-baseline` on a
quiet one before relying on the 25% warning.

### Defects the benchmark found (fixed in 4.0.0)

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
