# Action proof: per-kind coverage, collection health and the evidence chain

`agentdfir report <pkg> --format proof [--json] [--session ID] [--max N] [--out file]`

For every tool call an agent recorded, the proof report shows:

- the **claim** (the command, file or destination the call names, secrets masked);
- the **evidence chain**: Human → Agent (→ subagents) → Tool call → Process → File / Network / Cloud resource → Outcome, one step per edge of the action graph (`normalized/lineage.json`);
- for every step: its **evidence state**, its **assurance** (how the link is known), its **limitations** (what it does not show) and its **source references**;
- the **coverage facts** that justify the call's state: which kind of telemetry the claim needs, whether that kind covered the call's host and time, and whether that coverage was complete.

A top section, **Telemetry coverage & health**, lists every imported telemetry file with its SHA-256, its sequence domains and gaps, the drop signals it carries, and the coverage per host and kind.

The report decides nothing new. It reads what analysis wrote (`normalized/events.jsonl`, `detections/corroboration.json`) and the action graph built from them. The output is deterministic: no wall-clock time and no absolute paths, and every list has a defined order.

## The coverage rule

Absence of a record means something only for the **kind** of telemetry that would have recorded it, on the **host** it would have been recorded on, at a **time** that telemetry was recording **completely**.

v4 computed one coverage window across every record kind. Network or file records could stretch that window, so process telemetry that had already stopped could still disprove a command. v4.5 computes coverage per (host, kind) instead:

1. **Kinds.** `process`, `file`, `network`, plus every other kind a source produces (syscall, process-fork, …). Only records that count as coverage are used: host process, file and network telemetry. DNS, proxy, auth-log, journal, PowerShell script-block, 4688-without-command-line, Windows context and cloud records only corroborate. They are listed with `counts_as_coverage: false`.
2. **Windows per source file.** A file covers a kind when it recorded that kind at least once. It then covers that kind for the whole span its records show the collector running on that host, from its first record of any kind to its last. One file is one collector configuration: one eslogger subscription, one audit rule set, one Sysmon channel. Two files with a hole between them leave the hole uncovered.
3. **Hosts.** A record names its host when the source does: EVTX `Computer`, Tetragon `node_name`, Falco `hostname`, journald `_HOSTNAME`.
   - The tool call's host is the host the case was acquired on, which is not always the machine the agent ran on.
   - A record without a host covers every host, as in v4.
   - When the telemetry names exactly one host, that host is taken to be the agent's machine, and the decision says `host attribution unverified`.
   - When it names several, only the matching one covers the call.
4. **Health.** Each window carries the intervals where its source's collection health says events may be missing (below). The coverage state of a claim is one of:
   - `healthy`: covered, and the source's sequence numbers are contiguous across the match window;
   - `unverified`: covered, but the source has no sequence numbers. This is v4 behaviour, labelled "completeness unverified";
   - `partial`: covered, but a gap or drop signal touches the match window;
   - `no_telemetry`: no telemetry of that kind for that host;
   - `outside_window`: telemetry of that kind exists, but not at that time.

A command is **DISPROVED** (CONTRADICTED) only when its coverage is `healthy` or `unverified`. `partial` never yields a contradiction: the call keeps its state, is counted under `outside_coverage_reasons.partial`, and its summary says why it was not checked for absence. File-only and network-only claims are still never disproved by absence, as in v4: telemetry may not record every file access or connection.

Decision on sources without sequence numbers: they keep the v4 time-window behaviour, so they can still disprove a command, but every report labels them "completeness unverified". No v4 test expectation changed, except tests that compared records or results across input formats; those now strip the new provenance fields.

## Collection health

`collection_health` in `detections/corroboration.json` has one entry per telemetry file:

| field | meaning |
|---|---|
| `file`, `sha256`, `format` | the file as imported, and its hash |
| `records`, `first`, `last`, `kinds`, `hosts` | what it produced |
| `sequence_domains[]` | per domain: events, first/last number, gaps, missing count, gap ranges (with the times of the events on either side), the record kinds the domain produced |
| `drops[]` | signals the source wrote about itself, with the interval affected |
| `verdict` | `HEALTHY` (sequence numbers present and contiguous, no drop), `PARTIAL` (a gap or a drop), `UNKNOWN` (no sequence numbers: completeness not established) |

Sequence domains:

| source | domain | notes |
|---|---|---|
| EVTX (native) | `evtx/<channel>` | Record header id, which equals EventRecordID. Tracked for every parsed event, mapped or not. Sorted before checking, so a wrapped circular log is not read as a gap. |
| auditd | `auditd/<file>` | Audit serial, tracked for every event in the file. It restarts at boot; repeated numbers are not read as gaps, so the downtime across a reboot is not detected. |
| eslogger | `eslogger/<event type>`, `eslogger/global` | `seq_num` per type and `global_seq_num`, in stream order. A number going backwards is a collector restart, which is a gap. Close events the adapter does not import still count. |
| journald | `journald/<__SEQNUM_ID>` | `__SEQNUM`. A filtered export (`journalctl -u …`) skips numbers by design and shows as PARTIAL. Journal records only corroborate either way. |
| records given directly | their `seq` / `seq_domain` / `global_seq` | Used when a record did not come through `endpoint.Load`. |

Drop signals: Tetragon `rate_limit_info` (the interval up to the event) and `process_throttle` (from the event on); bpftrace `lost_events` (not placed in time: whole window); auditd `DAEMON_ERR` / `DAEMON_ABORT` and nonzero `lost=` / `audit_lost=`; Windows log clear 1102/104 (everything before the clear, applied to every EVTX source of that host, because 104 is written to System when any channel is cleared); Windows context records past the per-file bound (`ContextDropped`, for that kind only, whole window).

Not covered: Sysmon XML and evtx_dump JSON exports do not fill sequence numbers (UNKNOWN). The generic JSONL/CSV, Zeek, Falco, Tetragon and bpftrace adapters have no sequence numbers (UNKNOWN, apart from their drop signals). A sequence domain with more than 65,536 discontinuities is reported as too fragmented to check and counts as a gap.

## Action graph additions

- Node kind `outcome`, reached from a file, network or cloud_resource node by a `resulted_in` edge. Its `attributes.effect` is one of `file_written`, `file_deleted`, `file_renamed`, `destination_reached`, `cloud_api_accepted` or `cloud_api_refused`. An outcome exists only when a record of the effect exists: a telemetry file operation, a connection record, a cloud audit record, or the host witness finding the claimed content on disk.
- Edge `assurance`:
  - `verified`: an identifier or record both ends carry (recorded ids, pid/ppid, a record of the effect, the host witness);
  - `corroborated`: a scored correlation between two independent sources;
  - `inferred`: only named in the recorded command or tool input.
- Edge `limitations` also carry the coverage facts for the step, for example `process telemetry partial: sequence gap in auditd/audit.log: 5 missing after 14 (audit.log, 10:00:30–10:00:50)` or `completeness unverified: process telemetry carries no sequence numbers`.
- The existing edge `confidence` field keeps its v4 meaning: the correlation's HIGH/MEDIUM/LOW, on correlated edges only. All additions are optional, so earlier graphs still validate against `docs/schema/action-graph.schema.json`.

## Checking the JSON independently

`--json` is self-describing: its `verification` object repeats these rules.

- **Transcript references.** `artifact_id` is the SHA-256 of the artifact's plaintext. `manifest.jsonl` lists it with its logical path, and `artifacts[]` lists every one the report cites. The bytes are `raw/<artifact_id>`, `raw/<artifact_id>.gz`, or the chunks the manifest record lists. Hash the plaintext and compare. `line` and `offset` locate the record.
- **Telemetry references.** `telemetry_ref` is `<adapter> <record ref>` as the adapter wrote it: `audit.log:7 (serial 13)`, `sysmon:1 (record 77)`, `eslogger.jsonl:12`. `telemetry_file` names an entry of `telemetry.sources[]`, and `telemetry_sha256` is that file's hash at import. Telemetry files live outside the package, so hash your copy and find the record in it. When two imported files share a base name, `telemetry_sha256` is left empty rather than guessed.
- **Derived files.** `derived_from[]` lists `normalized/events.jsonl` and `detections/corroboration.json` with the SHA-256 of their JSON content, decompressed when stored as `.gz`. The overlay is regenerable: re-analysis of the same evidence and telemetry reproduces it.

`internal/proof/proof_test.go` does exactly this on a collected package: it re-hashes every cited artifact through the store, the telemetry file and the derived files, and ties every telemetry reference to its source.

## Bounds

At most 5,000 actions (`--max`); the rest are counted in `actions_omitted`. Chains have at most 64 steps and go three hops below the tool call. Coverage keeps at most 256 hosts, 256 windows per (host, kind) and 100 partial intervals per entry. Coverage decisions are bounded like correlation matches (20,000). Sources keep at most 200 drop signals and 50 gap ranges per domain; the rest are counted.

## Fixtures

The coverage, health and proof tests use synthetic fixtures built in the tests: EVTX files written by `internal/endpoint/evtx/evtxtest`, auditd text, eslogger JSON lines, and a Claude Code transcript collected into a real sealed package. The Tetragon rate-limit case uses `internal/endpoint/testdata/linuxtel/tetragon.jsonl`, which is hand-made (see its README).
