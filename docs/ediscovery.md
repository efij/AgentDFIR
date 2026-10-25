# eDiscovery and legal interoperability: RSMF, production sets, redaction

AgentDFIR can turn a sealed case into derivative files for legal review: RSMF conversations, a production set with a manifest, and redacted copies. Everything is written locally and nothing is sent anywhere. The sealed case is read and never modified.

**Scope.** RSMF output is checked against the RSMF 2.0 structure by AgentDFIR's own validator. It has **not** been loaded into a review platform (Relativity or any other) during development. Nothing here is a claim of admissibility, and nothing here is legal advice. A qualified person decides how the files are used.

## RSMF export (`agentdfir report <pkg> --format rsmf`)

```
agentdfir report <pkg> --format rsmf [--out dir] [--session ID ...] [--redact secrets,emails,paths,ips[,custom:<file>]]
```

Writes one `.rsmf` file per agent session. The default location is `<pkg>/reports/rsmf`. Use `--session` more than once, or give it a comma-separated list, to export only some sessions. Every file goes through `report.ValidateRSMF` before it is written, and a file that fails validation is an error. `--format all` does **not** include RSMF, so the existing `all` output is unchanged.

Each file is an RFC 5322 message (CRLF line endings) with these parts:

| Part | Content |
|---|---|
| Headers | `X-RSMF-Version: 2.0.0`, `X-RSMF-Generator`, `X-RSMF-Application` (product name), `X-RSMF-BeginDate` / `X-RSMF-EndDate` (earliest/latest event, ISO-8601 UTC), `X-RSMF-EventCount`, `X-RSMF-AttachmentCount`, `X-RSMF-Custodian` (only when the session has exactly one human account), `X-RSMF-Participants`, plus `From`, `Subject`, `Date` and `Message-ID`, all derived from the content |
| `text/plain` body | One line per event: time, participant, event type, evidence label (CLAIMED, RECORDED, …) and text. Quoted-printable. Terminal control and invisible characters are stripped. |
| `rsmf.zip` attachment | `rsmf_manifest.json`, plus one file for each command too long for a message body (over 2 KiB) |

### Manifest mapping

| AgentDFIR | RSMF |
|---|---|
| agent session | `conversations[]`: `id` `session:<id>`, `platform` = product name, `type` `direct` (2 participants) or `channel` (3 or more) |
| human account (`user`) | participant `human:<account>`, `display` "User <account>", `account_id` |
| main agent / subagent | participant `agent:<agent_id>`, `display` "<Product> agent 5f0c9c1e" / "<Product> subagent adad4e2c". The product name comes from the product registry by id, and an unknown id is shown exactly as recorded. |
| `human_prompt`, `model_response`, `agent_message`, `tool_call`, `tool_result` | `message` |
| `tool_result` | `parent` is set to the matching `tool_call` event (threaded by `tool_call_id`) |
| `agent_spawn` with a task id | `join` by the spawned subagent |
| `trace_gap`, `session_meta` | `disclaimer` |
| any other event type | `unknown` |
| AgentDFIR facts RSMF has no field for | `custom[]` name/value pairs on the event: `agentdfir_event_id`, `agentdfir_event_type`, `agentdfir_actor_type`, `agentdfir_agent_id`, `agentdfir_parent_agent_id`, `evidence_state` (CLAIMED / RECORDED / …), `evidence_state_code` (REPORTED / OBSERVED / …), `source_artifact_id`, `source_logical_path`, `source_line`, `source_offset`, `timestamp_source`, `tool`, `tool_call_id`, `mcp_server`, `mcp_tool`, `model`, `cwd`, `file`, `network_destination`, `result`, `witness_note`, `finding_ids` |

Event ids are the AgentDFIR event ids. Every RSMF event names the sealed artifact (sha256) and the line it was read from. `finding_ids` lists the rules whose evidence cites that source line, or the event itself for attack-chain steps. The `deleted` and `edited` flags exist in the manifest but are never set, because agent transcripts carry no edit or delete history to map.

### Validator rules (`report.ValidateRSMF`, `report.ValidateRSMFManifest`)

Envelope checks: the file parses as RFC 5322; it has the required headers; `X-RSMF-Version` is `2.0.0`; the body is `multipart/mixed`; there is a `text/plain` body; there is exactly one `rsmf.zip`; the zip opens and contains `rsmf_manifest.json`.

Header and manifest agreement: `X-RSMF-EventCount` and `X-RSMF-AttachmentCount` equal the manifest counts; `X-RSMF-BeginDate` and `X-RSMF-EndDate` equal the earliest and latest event times.

Manifest checks:
- `version` is `2.0.0`.
- Participant, conversation, event and attachment ids are present and unique.
- Every participant has a `display`.
- Conversation `type` is `direct` or `channel`.
- Referential integrity holds: conversation participants exist, event conversation and participant exist, `parent` names another event.
- `message`, `join` and `leave` events have a participant.
- Timestamps are ISO-8601 in UTC.
- Event `type` is one of message, disclaimer, join, leave, history, unknown or call.
- Every attachment is in the zip with the stated size.
- Every custom field has a name.

Reads are bounded: 512 MiB per file, 256 MiB for the manifest, 100,000 zip entries and 64 MIME parts.

The validator checks the structure as implemented here from the published RSMF 2.0 manifest description. It is not a conformance suite, and passing it does not prove that a review platform will ingest the file.

## Production sets (`agentdfir export <pkg> --production`)

```
agentdfir export <pkg> --production [--out dir] [--examiner name] [--session ID ...]
                 [--redact secrets,emails,paths,ips[,custom:<file>]] [--produced-at RFC3339]
```

`export` without `--production` behaves exactly as before. It still writes the portable `.adfir.tgz`, and `--support` and `export custody` are unchanged.

The default output is `<pkg>.production`. An output directory inside the case package is refused, so derivatives never go into the evidence directory. An existing non-empty directory is also refused, so a production is never mixed with older files.

| File | Content |
|---|---|
| `rsmf/session-<id>.rsmf` | RSMF per session, as above |
| `report/report.html`, `report/report.pdf` | The standard reports, rendered from the same (optionally redacted) case. Their usual row caps apply. |
| `timeline/timeline.csv`, `timeline/findings.csv` | The full timeline and the findings |
| `traceability.csv` | One row per produced item (each RSMF event, timeline row and finding reference): `produced_file, item_id, item_type, source_artifact_id, source_logical_path, source_line, source_offset, evidence_state`. A finding that cites a whole artifact by byte offset has line 0 and the offset in `source_offset`. |
| `production-manifest.json` | See below |
| `production-manifest.csv` | One row per produced file: path, sha256, size, kind, items, source artifact ids |

`production-manifest.json` (`schema: agentdfir.production/1`) contains:

- `files[]`: every produced file with its SHA-256, size, kind, item count, and `derived_from` (each source artifact id with its logical path, first and last line, and item count). The two manifest files are not listed in themselves. The CLI prints the JSON manifest's SHA-256 and records it in the custody activity log.
- `traceability`: row counts, events in scope, events in RSMF, events that could not be represented, and rows without a source reference.
- `case`: case id, package name, seal digest (the sha256 of `SHA256SUMS` at production time), integrity result from a full verify, signature state, and the collection operator and authorization reference.
- `examiner`: the `--examiner` value (`source: "--examiner"`). Without the flag, the case's asserted operator (`source: "case operator"`) or its OS account (`source: "os user"`) is used. The examiner is never redacted; see below.
- `tool`: name, version and the SHA-256 of the running binary.
- `processing_history`: the sealed custody log, collection rounds, run-level collection log records, the stored analysis run, the post-seal activity log, and this run's stages (verify, redact, rsmf, report, timeline, manifest), all stamped with `produced_at`.
- `redaction`: categories, the custom-file SHA-256 and pattern count, totals per category, and a log of category, credential kind, location and count. The log never holds values.
- `missing_records_and_limitations` (each entry has a count and, where records exist, references to artifacts and lines; references are capped at 1000 per entry):

| Code | Meaning |
|---|---|
| `TRACE_GAP` | transcript regions that could not be parsed |
| `NOT_IN_RSMF_UNDATED` | events with no usable timestamp. RSMF requires one, so these are listed instead of being given an invented time. They are in `timeline.csv`. |
| `SESSION_WITHOUT_TRANSCRIPT` | sessions known from metadata that have no transcript messages |
| `UNSUPPORTED_OR_UNPARSED_SESSION` | session artifacts that were acquired and sealed but from which no parser produced events |
| `ARTIFACT_NOT_ACQUIRED` | collector statuses other than OK or NOT_PRESENT, for example ACCESS_DENIED, ERROR or SKIPPED_* |
| `INTEGRITY_FAILED` | the package did not verify, with the verify problems listed |
| `NO_EVENTS` | there is nothing in scope |
| `ITEMS_WITHOUT_SOURCE_REF` | some traceability rows have no source reference |
| `SCOPE_LIMITED_TO_SESSIONS` | `--session` was used |
| `RSMF_BODY_IS_NORMALIZED_EXTRACT` | always listed (see coverage below) |
| `RSMF_VALIDATION_SCOPE` | always listed: structural validation only |

### Reproducibility

The same package and options with the same `produced_at` give byte-identical files. `produced_at` is resolved in this order: `--produced-at` (RFC 3339), then `SOURCE_DATE_EPOCH` (Unix seconds), then the clock truncated to whole seconds. `reproducibility.files_whose_bytes_follow_produced_at` names the four files that change with it: `report/report.html` and `report/report.pdf` print it as their generation time, the JSON manifest carries it, and the CSV manifest lists the two report hashes.

The RSMF files, CSVs and `traceability.csv` contain no wall-clock time. MIME boundaries and Message-IDs are digests of the content, and zip entry times are the conversation's last event time.

Earlier production runs are left out of `processing_history`, so re-running a production reproduces it. Every run is still in `custody/activity.jsonl`. Other post-seal activity, such as a new authorization, does change the history, because the case's recorded state has changed.

### Custody

Each production appends a `production_generated` record to the case's post-seal activity log, `custody/activity.jsonl`. That log is a hash chain outside the sealed zone, and each record names the seal digest it was made against. The record holds the output path, file count, manifest SHA-256, `produced_at`, examiner, redaction categories and sessions. The sealed zone and `SHA256SUMS` are not touched. `agentdfir case log` and `export custody` show these records.

## Derivative redaction (`--redact`)

`--redact` works on `report --format rsmf` and `export --production`. It applies **only to the derivative files**. Redaction runs on an in-memory copy of the derived case (events, findings, entities, manifest, case info, verify result, notes, custody excerpt). The package on disk, including the sealed evidence, `normalized/` and the detections, is never modified. A test hashes every package file before and after a redacted production and runs a full verify.

| Category | What is masked |
|---|---|
| `secrets` | The credential formats the SECRET detection rules match, reused from `internal/detect` (AWS, GitHub, Slack, Anthropic, OpenAI, Google, Alibaba and Tencent keys, JWTs, private keys). For a private key, the body up to the END marker is masked too; with no END marker, the rest of the value is masked. Documentation placeholders are masked as well, because redaction does not use detection's placeholder filter. |
| `emails` | `local@domain.tld` addresses |
| `paths` | Absolute paths with at least two components: `/…/…`, `~/…`, `$HOME/…`, `C:\…`, `C:/…` and UNC `\\host\…`. Relative paths and URL paths are left alone. Transcript logical paths such as `.claude/projects/-Users-x-app/…` are relative and are **not** masked. |
| `ips` | IPv4 literals (version strings like `1.2.3.4.5` excluded) and IPv6 literals that contain `::` or have eight groups (so `14:00:05` and `std::string` are not masked) |
| `custom:<file>` | One RE2 regular expression per line, with `#` starting a comment line. Limits: 64 KiB, 256 patterns, and no pattern may match the empty string. The file's SHA-256 is recorded. |
| `all` | secrets, emails, paths and ips |

A masked value becomes `[REDACTED:<category>:<first 8 hex of sha256(value)>]`. The same value always gets the same marker, so a reviewer can see repetition without seeing the value. This also lets anyone who already has a candidate value confirm it, so do not rely on the marker to hide low-entropy values such as short emails. Redacting an already-redacted text changes nothing.

**Examiner identity is never redacted.** The examiner is the producing party, and masking them would break accountability. The manifest's redaction section says so (`examiner_note`), and this run's processing-history stages name the examiner as their actor. The tool identity and seal digest are not redacted either. Everything else in the manifest that is taken from evidence is redacted with the same categories: the case section (including integrity problems), the earlier processing history, and every `missing_records_and_limitations` entry.

## Coverage

| Area | Covered | Not covered / reported |
|---|---|---|
| Conversation content | Normalized event text: prompts, responses, tool calls with the full command, tool results as their normalized summary | The full raw transcript line. The body is the normalized extract, and the authoritative bytes are the sealed source line named in the custom fields (`RSMF_BODY_IS_NORMALIZED_EXTRACT`). |
| Products | Any product AgentDFIR normalizes into events; the platform name comes from the product registry | Sessions with no parser produce no RSMF (`UNSUPPORTED_OR_UNPARSED_SESSION`) |
| Timestamps | ISO-8601 UTC from the transcript | Undated events are listed, never invented (`NOT_IN_RSMF_UNDATED`) |
| Edits / deletions | — | Agent transcripts carry no edit or delete history; the flags are never set |
| Attachments | Overlong command text | Files the agent read or wrote are not attached. They are separate sealed artifacts referenced by path. |
| Review platforms | Structural RSMF 2.0 validation | Not tested against Relativity or any other platform |
| Admissibility | — | No claim |

All fixtures used in tests are synthetic: generated profiles, planted fake credentials and emails, and a deliberately truncated transcript line.
