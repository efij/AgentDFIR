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
agentdfir benchmark --repo <checkout>    # where the disk-image, telemetry and interop fixtures are; also runs the Python verifier
agentdfir benchmark --python-verifier    # run the Python verifier from the checkout found from the working directory
```

Progress goes to stderr. The corpus, the historical packages and the
performance baseline are built into the binary. The disk-image, telemetry
and interop fixtures and the Python verifier are not (they would add
megabytes to every binary): the suites that need them look for a source
checkout from the working directory up, or where `--repo` points, and
report SKIP with the reason when there is none. Those suites only read
the fixtures. The Python verifier is different: it is a script, and a
checkout found by walking up from the working directory may be anyone's
directory, so it runs only with `--repo` (which must name a checkout of
this module) or `--python-verifier`, and the report and stderr print the
resolved script path. Everything is written to
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
| Detection | the labeled synthetic corpus (`internal/corpus/testdata`) and every `simulate` scenario, collected and analyzed by the real pipeline | no lost detection; benign false positives within the corpus budget (`budget.json`) |
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

## Cross-platform and v5 suites

Nine suites run after the sections above, and each ends in its own
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
| v5 detections | the 17 attack cases and 17 benign twins for the v5 rules and chains (`internal/corpus/testdata/README-v5-rules.md`): Claude Code transcripts, MCP gateway logs, an MCP client log with a cached tool declaration and an agent definition, all through the real parsers, so `arg_keys`, `safe_args`, `result_status`, `approval_state`, `permission_from`, `input_modality`, `mcp_server_version` and `tool_def_digest` are filled the way collected evidence fills them | for each of MCP_ARGUMENT_BEHAVIOR_MISMATCH, MCP_TOOL_IDENTITY_DRIFT, AGENT_PERMISSION_STATE_DRIFT, AGENT_CREDENTIAL_TO_EXTERNAL_TOOL, AGENT_UNAUTHORIZED_RESOURCE_CHANGE, AGENT_AUTONOMOUS_RECON_SEQUENCE, AGENT_ADAPTIVE_ATTACK_SEQUENCE, AGENT_DELEGATION_SCOPE_EXPANSION, AGENT_RESOURCE_EXHAUSTION, AGENT_MULTIMODAL_TRIGGER_CHAIN and the chains CHAIN_SKILL_POISON_TO_EXEC, CHAIN_MCP_RUG_PULL_TO_ACTION, CHAIN_TOOL_RESPONSE_TO_SECRET_EXFIL, CHAIN_SHARED_MEMORY_TO_SUBAGENT, CHAIN_BROWSER_TOKEN_TO_ACCOUNT_ACTION, CHAIN_AGENT_RECON_TO_IMPACT, CHAIN_ADAPTIVE_RETRY_TO_BYPASS: an attack case raises it and its benign twin (which names the attack case back) does not. The twins also count as ordinary benign cases, so any other unallowed firing on them fails the detection section |
| Evidence fields | a generated transcript whose tool calls carry three credential-shaped values (built at run time) in an MCP message, nested MCP arguments, a URL query and file content | the MCP call records its sorted top-level argument keys, an argument digest and its paired outcome; nested values never surface; a URL is reduced to scheme and host; AGENT_CREDENTIAL_TO_EXTERNAL_TOOL sees the credential; and no credential value appears in any file of the package outside the sealed source (`normalized/`, `detections/`, reports) or in the events and findings |
| Cross-case graph | four sealed, analyzed packages, compared in pairs with `correlate-cases --graph`. Strong pair: a session runs `ssh devbox "claude --resume <id> …"` and the session with that id, in the other package, deletes a release directory. Weak-only pair: two unrelated sessions sharing only a destination IP and near-identical prompt text. Both packages of a pair are collected on the benchmark machine, so each package's events are stamped with an execution environment (the field a container or endpoint witness sets) to stand for two hosts | strong pair: a strong `session_id_in_command` edge and the CHAIN_CROSS_HOST_AGENT_PROPAGATION finding; weak pair: weak edges only, no finding, no prompt text in the graph |
| MITRE catalogs | every ATLAS and ATT&CK reference of the built-in rules, embedded pack rules and built-in chains, and of every finding the detection section produced; the ATLAS relevance inventory (`internal/mitre/data/atlas-relevance.json`) | every ATLAS ID exists in ATLAS 2026.09; every ATT&CK ID is active (not revoked or deprecated) in ATT&CK Enterprise v20.0; the inventory gate passes (208/208 classified, no errors, no planned placeholders, every P0 observable technique covered or excepted); all 17 v5 rules and chains are listed in the inventory |
| Evidence integrity | the integrity and compatibility sections above, and `tools/adfir-verify/adfir_verify.py` (Python 3 standard library) over every package this run built and the five historical packages | every mutation detected, every historical package verifies, the Python verifier says VERIFIED on every package; SKIP, with the reason, without `--repo` / `--python-verifier` or when `python3` is not on `PATH` |

**Expected failures.** A check can be marked as failing on this build for
a documented reason. It is then reported **XFAIL** and does not fail the
run; if it passes, it is reported **XPASS** and the run warns, so the
mark can be removed. No check is marked on this build. The six per-OS
sequence-gap and stopped-kind checks (two per platform) were XFAIL while
correlation treated the telemetry as one time window for every record
kind; with per-kind coverage and collection health
([action-proof.md](action-proof.md)) they pass, and the marks were
removed. The labeled control in each scenario (a claim where coverage is
contiguous) passes as DISPROVED either way.

## Current numbers

The v5 integration branch (`feat/v5-bench`; the binary still reports
4.5.0 until the version bump), `benchmark --no-perf --repo .` from a source
checkout, darwin/arm64, go1.27.1, on a machine shared with parallel builds
(wall time not meaningful). Synthetic.

| Section | Result |
|---|---|
| Detection | precision 100.0%, recall 100.0% **on the synthetic corpus** (98 TP, 0 FP, 0 FN) over 51 attack cases, 8 scenarios, 75 benign cases |
| Rule coverage | 87 of 232 alert rules have an attack fixture; the rest are listed in the report; 4 building blocks |
| Evidence states | 14/14 labeled checks, 0 contract violations over 30 events |
| Provenance | 0 dangling of 1,143 events and 569 finding references |
| Integrity mutations | 24/24 detected |
| Compatibility | 5/5 historical packages verify and analyze |
| Robustness | 7/7 cases |
| Performance | measured separately, below |

Suites, same run:

| Suite | Verdict | Measured |
|---|---|---|
| Acquisition | PASS | 41 fixtures (35 compared with a manifest or the image they wrap, 6 enumerated only); 45 volumes; 16,031 files enumerated; manifest files 14,179 of 14,185 recovered with matching SHA-256, the other 6 reported UNSUPPORTED as documented; 17 UNSUPPORTED / ENCRYPTED states in all; source unchanged 41/41 |
| Per-OS corroboration | PASS | 72 of 72 checks, 0 expected failures. Windows: 4 scenarios, CORROBORATED 5 of 5, 11 corpus cases; macOS: 5 scenarios, 5 of 5, 5 corpus cases; Linux: 6 scenarios, 10 of 10, 5 corpus cases |
| Forensic interop | PASS | 6 exports; 17 of 17 expected records; 13 of 13 originals sealed byte-identical; 2 UNSUPPORTED notices |
| Detection quality | PASS | as above, on the synthetic corpus; by platform: Windows 5 attack / 6 benign fixtures (6 rules), macOS 2 / 3 (6 rules), Linux 2 / 3 (5 rules), transcript-only 50 / 63 (71 rules), each 100.0% / 100.0% |
| v5 detections | PASS | 17 of 17 v5 rules and chains raised by their attack case, benign twin silent |
| Evidence fields | PASS | 3 credentials in 4 tool calls; argument keys, digests, allowlisted values and paired outcomes filled; no credential value in 22 derived files, 10 events, 7 findings |
| Cross-case graph | PASS | strong pair: `session_id_in_command` edge (strong) and CHAIN_CROSS_HOST_AGENT_PROPAGATION; weak-only pair: 2 weak edges, 0 strong or moderate, 0 findings |
| MITRE catalogs | PASS | ATLAS 2026.09 and ATT&CK Enterprise 20.0: 242 ATLAS and 331 ATT&CK references, all valid; inventory 208/208 classified, 0 errors, 0 planned; P0 observable 31 = 30 covered + 1 exception; 17 of 17 v5 detections listed |
| Evidence integrity | PASS | 24/24 mutations, 5/5 historical packages; Python verifier: 32 of 32 packages VERIFIED |

Read the detection line for what it is. The 100% is measured on the
synthetic corpus: the labels were written next to the rules, and the
corpus gates the build, so 100% means the rules still do what their
fixtures say, not that they are 100% accurate. Detection metrics on an
independent corpus are reported separately; none are published yet. The
number that carries information is the coverage gap: 145 alert rules
have no attack fixture at all. The per-platform rows are small (two
attack fixtures each on macOS and Linux).

### Performance: v5 against v4.5

The performance case (400 generated sessions, 24,000 tool calls, 48,800
events) was run on v4.5.0 (`release/v4.5.0`, 12b5eaf, built from a
temporary worktree) and on this branch, alternating the two so that both
saw the same machine load. Machine: darwin/arm64, 11 CPUs, go1.27.1,
shared with parallel builds (1-minute load average 5 to 9 throughout),
so single runs vary by up to 25%; the table gives medians.

| | v4.5.0 | v5 branch | Change |
|---|---:|---:|---:|
| analyze, median of 10 interleaved runs | 14,624 ms (12,707 to 16,047) | 15,745 ms (13,695 to 19,392) | +7.7% (median of the paired ratios +8.5%) |
| peak live heap, median | 181 MiB (156 to 202) | 224 MiB (217 to 282) | +24% |
| allocated during analyze | 4,409 MB | 4,760 MB | +8.0% |
| events | 48,800 | 48,800 | same |

A first round on this branch, before the two fixes below, measured
analyze +14% (median of 6 pairs), allocation +13% and peak heap +35%. A
profile showed two avoidable costs in v5 code, both fixed: the argument
allowlist built a `strings.Replacer` for every argument name of every
tool call (153 MB of the 590 MB extra allocation), and
AGENT_RESOURCE_EXHAUSTION kept full event copies in its sliding windows
(75 MB); it now keeps indices.

What remains is explained, not noise, and within the 25% tolerance:

- **Peak heap +24%.** `schema.Event` grew from 584 to 816 bytes (the
  fifteen structured tool-call fields of the v5 evidence contract), and
  calls and results now carry two 64-character digests. That is about
  18 MB per resident copy of the 48,800 events; the detector's index and
  the chain engine each hold one.
- **Analyze +8%, allocation +8%.** Every tool call and result is now
  digested over its canonical JSON and paired with its result, the
  larger events are written to and read back from the overlay, and ten
  rules and seven chains were added. The analyze delta is smaller than
  the run-to-run spread on this machine, but 9 of 10 pairs were slower on
  v5, so it is reported as a real cost, not as noise.

Re-measure on a quiet machine before release and record the baseline
with `--save-baseline`.

### Defects the v5 suites found (fixed on this branch)

Running the v5 rules end to end, through the real parser instead of on
hand-made events, found three defects the unit tests could not see; the
performance comparison found two avoidable costs (above):

| Found by | Defect | Fix |
|---|---|---|
| `write-denied-then-shell-copy` | CHAIN_ADAPTIVE_RETRY_TO_BYPASS never matched collected evidence: its steps read the outcome (`result_status`) on the tool call, and the parsers recorded it only on the result event. | The call/result pairer (`internal/toolargs`) copies the paired result's status onto a call that has none, so the call says whether it was refused, failed or completed. No v4.5 chain output changed (`chains-v45.golden`). |
| `permission-mode-widened-by-person` | AGENT_PERMISSION_STATE_DRIFT fired when the person changed the mode and typed a prompt (the common shape): the parser emits a line's `permission_change` event before the prompt on the same line, so the rule saw the change before the approval. | A change event that shares its source line with a prompt the person typed counts as recorded approval; a prompt on a later line still does not. |
| `skill-written-from-fetched-page-then-run` | CHAIN_SKILL_POISON_TO_EXEC could not join a `Skill` tool invocation on collected evidence: the skill name was not in the allowlisted arguments, so `safe_args.skill` was always empty. | `skill` (an identifier) is allowlisted in `internal/toolargs`. |

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
