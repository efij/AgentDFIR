# Investigation layer — `gaps`, `lineage`, `correlate-cases`

Findings say what the evidence holds. Three commands answer the questions
that come next:

| Command | Question | Stored by `analyze` |
|---|---|---|
| `agentdfir gaps <case> [--json]` | What does this case **not** show, and what should be collected next? | `normalized/coverage.json(.gz)` |
| `agentdfir lineage <case> [--finding id \| --session id] [--format text\|json\|mermaid\|dot]` | Who did what, through whom? | `normalized/lineage.json(.gz)` (whole case, bounded) |
| `agentdfir correlate-cases <a> <b> [...] [--json] [--allow-unverified] [--include-common]` | What do several cases have in common? | nothing (computed on demand) |

All three read the analysis that is already in the case. None of them changes
an event, a finding, an evidence state or the sealed evidence. Output order is
deterministic: the same case gives the same bytes.

`agentdfir correlate` is unchanged: it is endpoint-telemetry correlation for one
case. Cross-case comparison is the separate `correlate-cases`.

## Where the files live

Every `analyze` (and therefore `run`, `open`, `serve`'s refresh) writes
`normalized/coverage.json` and `normalized/lineage.json` after the findings are
final. Like the rest of the overlay they are stored gzip-compressed
(`coverage.json.gz`; `gunzip -c` reads them), are outside `SHA256SUMS`, and are
rebuilt by the next analysis. This stage cannot fail an analysis: an error,
including a panic on unanticipated input, becomes a note in
`detections/analysis.json` and the findings stand. `gaps` and `lineage` build
the report on the fly when the stored file is missing.

The endpoint correlation summary in `detections/corroboration.json` gained two
optional fields used here: `matches` (the pairing behind each corroborated
tool call; at most 20,000, `matches_omitted` counts the rest) and
`cloud_coverage_start` / `cloud_coverage_end`. Existing fields are unchanged.

---

## 1. Evidence gaps — `agentdfir gaps`

The report is a list of plain items, each one of:

- **known** — established by the evidence in the case;
- **unknown** — the case cannot answer it;
- **verify_next** — what to collect next, and what it would verify, e.g.
  *"Process telemetry (Sysmon event 1, auditd EXECVE, EDR process events)
  covering 2026-10-02 13:00–15:40 UTC on host X would verify 41 shell
  command(s)."*

Nothing is speculative: a time gap says nothing was recorded, never that
something was hidden; an unverified command says no witness covered it, never
that it did not run.

### What it checks

| Section | What is computed | From |
|---|---|---|
| `sessions[].time_gaps` | Silences inside a session at least 15 min **and** at least 30 × the session's median spacing between records. Each gap names the last record before and the first after it. | event timestamps |
| `transcript_integrity` | `TRACE_GAP` (malformed/truncated region), `CHAIN_BREAK` (a record whose parent record is missing), and the `TRANSCRIPT_REWRITTEN` / `_TRUNCATED` / `_REPLACED` / `_DELETED` / `SESSION_TAMPERING` findings | events, findings |
| `acquisition` | Rounds (case.json); per product: earliest/latest evidence timestamp, first/last collection time, lag, artifacts read fresh vs carried forward from an earlier round, paths not present, artifacts found but not acquired by status | manifest, case.json, events |
| `second_witness.sources` | Endpoint telemetry window and record count, cloud audit window, host witness, shell history — each with the number of tool calls it confirmed | corroboration summary, host witness, event notes |
| `second_witness.activity` | Runs of tool calls per host (calls closer than 30 min join one range), each marked `full`/`partial`/`none` against the endpoint telemetry window, with shell / network / cloud / file-write counts and how many stayed unverified | events |
| `second_witness.actions` | Per action kind (`shell_command`, `network`, `cloud_command`, `file_write`, `file_read`, `mcp_call`, `other`): total, verified, disproved, unverified, and why unverified: `no_telemetry_in_window`, `telemetry_present_no_match`, `no_timestamp`, `nothing_a_witness_can_check`, `host_witness_inconclusive` | events |
| `clock` | Events timestamped more than 5 min after their transcript was collected; timestamps stepping back more than 1 min inside one append-only file; a transcript whose mtime is before its own last record; the median/min/max offset between endpoint records and transcript times over matched pairs; files whose host-witness mtime is before the confirmed write | events, manifest, correlation matches, host witness |
| `agent_chains` | Orphan agents (`ORPHAN_AGENT`), spawn records whose subagent left no records, spawn records citing a tool call not in the case, parent ids naming an agent with no records, tool results without their call, conversation chain breaks | events, findings |

Thresholds are recorded in `thresholds`. Lists are bounded (20 gaps per
session, 200 activity ranges, 25 items per kind, 5 examples); `truncated` and
the `*_omitted` counters say when a bound was hit.

### `coverage.json` schema (`agentdfir.coverage/1`)

```text
{
  "schema": "agentdfir.coverage/1",
  "case_id", "host",
  "thresholds": {min_gap_seconds, cadence_factor, clock_tolerance_seconds, activity_join_seconds},
  "summary": {sessions, tool_calls, tool_calls_verified, tool_calls_disproved, tool_calls_unverified,
              time_gaps, known, unknown, verify_next},
  "sessions": [{session_id, product, start, end, events, events_without_timestamp,
                median_spacing_seconds, time_gaps: [{start, end, seconds, last_record_before, first_record_after}],
                time_gaps_omitted}],
  "transcript_integrity": [{session_id, code, detail, evidence_ref}],
  "acquisition": {
    "rounds": [{round, started_utc, completed_utc, artifacts_ok, artifacts_carried_forward, artifacts_not_acquired}],
    "products": [{product, events, earliest_evidence, latest_evidence, first_collected, last_collected,
                  collection_lag_seconds, artifacts, artifacts_fresh, artifacts_carried_forward,
                  paths_not_present, not_acquired: {STATUS: n}}]},
  "second_witness": {
    "sources": [{name, start, end, records, tool_calls_verified, note}],
    "activity": [{host, start, end, tool_calls, shell_commands, network_actions, cloud_commands, file_writes,
                  endpoint_coverage: "full|partial|none", unverified, verified_by: [source]}],
    "activity_omitted",
    "actions": [{action, total, verified, disproved, unverified, unverified_reasons: {reason: n}}],
    "narrative_claims"},
  "clock": {events_after_collection, events_after_collection_examples: [ClockExample],
            out_of_order: [{logical_path, count, max_step_back_seconds, example_ref}],
            transcript_mtime_before_last_record: [ClockExample],
            endpoint_offset: {pairs, median_ms, min_ms, max_ms},
            witness_mtime_before_write: [ClockExample], omitted: {kind: n}},
  "agent_chains": {orphan_agents, spawned_agents_without_records, spawns_citing_unknown_tool_call,
                   parent_agent_not_in_evidence: [{agent_id, parent_agent_id, tool_call_id, session_id, evidence_ref}],
                   tool_results_without_call, conversation_chain_breaks: [{session_id, count, example_ref}], omitted},
  "items": [{status: "known|unknown|verify_next", category: "acquisition|transcript|second_witness|clock|agent_chain",
             text, collect, count, evidence_refs: [ref]}],
  "limits": [string],
  "truncated": bool
}
ClockExample = {evidence_ref, recorded, reference, basis, seconds}
```

Times are RFC 3339 UTC. Evidence references use the finding format
`logical_path:line (artifact <12 hex>, offset N)`. Items are ordered known →
unknown → verify_next, then by category, then in the order the section produced
them.

---

## 2. Lineage graph — `agentdfir lineage`

Nodes: `human` (the AI account the transcript ran under) → `agent` →
`subagent` → `tool_call` → `process` → `network` / `file` / `cloud_resource`
(plus `mcp_server`).

**Every edge is backed by something the evidence records, and says what.**
Two things that merely happened close together are never joined. The bases:

| Relation | Basis | Evidence state |
|---|---|---|
| human → agent `prompted` | human prompt recorded in this agent's transcript; the transcript's profile, and the login file that names the account when one was collected | the prompt event's |
| agent → subagent `spawned` | `tool_use_id match` (the spawn tool call and its launch record name the agent), `spawn record` (the spawning call is not in the evidence), or `recorded parent id` (parent_agent_id on the record) | the spawn event's |
| agent → tool call `invoked` | recorded agent id on the tool call | the call's |
| tool call → network `named_destination` | destination named in the recorded command (not proof of a connection) | the call's |
| tool call → file `wrote` / `edited` / `read` / `named_file` | file path in the recorded tool input (+ the host witness note when the write was confirmed on disk) | the call's |
| tool call → mcp_server `called` | MCP server named in the recorded tool name | the call's |
| tool call → process `executed_as`, → file `touched`, → network `connected_to`, → cloud_resource `acted_on` | `correlated within ±<window>: <basis> (<witness>, score N)` — the pairing the correlate package made, with its **confidence** | the call's (CORROBORATED) |
| process → network `connected_to`, → file `touched` | `endpoint pid` (same pid, from the process's start to 10 min later) | OBSERVED |
| process → process `child_process` | `endpoint ppid` | OBSERVED |

Correlation confidence is defined once, in `correlate.MatchBasis`:

| Witness | Score | Basis | Confidence |
|---|---|---|---|
| process | 100 | same command line | HIGH |
| process | 90 | same command inside a shell wrapper | HIGH |
| process | 70 | command matches a truncated telemetry copy | MEDIUM |
| process | 60 | same program with most arguments shared | LOW |
| file / network | 80 | same path / same destination | MEDIUM |
| cloud | 95 / 75 / 70 | same operation on the named resource / no resource named by the command / none in the record | HIGH / MEDIUM / LOW |

Process edges need endpoint telemetry imported with `analyze --endpoint`; the
pairings are kept in `corroboration.json` so a later analysis without the log
still draws them.

Scopes: whole case (default); `--session <id>`; `--finding <sel>` where `sel` is
the finding's index in `findings.json` (the explorer's numbering), its key
`finding:RULE|evidence-ref`, or a rule id (every finding of that rule). A
finding scope keeps the cited events, their agent ancestry up to the human, and
what the cited tool calls led to — not sibling calls.

Bounds: 20,000 nodes / 50,000 edges by default (`--max-nodes`, `--max-edges`).
When hit, `truncated` is true, `omitted` counts what was left out and a note
says so; no edge ever points at a dropped node. Commands, command lines, file
paths and witness notes are passed through credential masking **before** any
cut, so a key in a command appears as `ghp_…[GITHUB_TOKEN sha256:…]` and a cut
can never expose part of one.

Formats: `text` (default), `json`, `mermaid` (flowchart; node ids are
positional, labels escaped and cut to 80 characters), `dot` (Graphviz).

### `lineage.json` schema (`agentdfir.lineage/1`)

```text
{
  "schema": "agentdfir.lineage/1",
  "case_id",
  "scope": {session_id, finding, finding_keys: [string], events_considered},
  "nodes": [{id, kind, label, evidence_state, attributes: {k: v}, source_refs: [Ref]}],
  "edges": [{from, to, relation, basis, evidence_state, confidence, note, source_refs: [Ref]}],
  "limits": {max_nodes, max_edges},
  "truncated": bool,
  "omitted": {nodes, edges},
  "notes": [string]
}
Ref = {artifact_id, logical_path, line, offset, event_id} | {telemetry_ref: "<source> <file:line>"}
```

Node ids: `human:<profile>`, `agent:<agent id>`, `tool:<event id>`,
`process:<source>:<telemetry ref>`, `network:<host>`, `file:<path>`,
`cloud:<provider>:<resource>`, `mcp:<server>`. Nodes are ordered by kind
(human, agent, subagent, tool_call, process, mcp_server, network, file,
cloud_resource) then id; edges by from, to, relation. Edge evidence states are
the stored values (`OBSERVED`, `CORROBORATED`, …); text output prints the plain
labels (RECORDED, CONFIRMED, …).

---

## 3. Cross-case correlation — `agentdfir correlate-cases`

Before anything is compared, each package must:

1. **verify** — the full check `agentdfir verify` runs (every blob re-hashed,
   both hash chains, the signature when present). A package that fails is
   refused; `--allow-unverified` compares it anyway, sets
   `includes_unverified_cases`, and marks every occurrence from it
   `from_unverified_case`;
2. **be analyzed by this version** — otherwise it is refused with the command to
   run (`agentdfir analyze <case>`), so two cases are never compared through two
   different rule sets.

Shared items (seen in at least two cases):

| Kind | Key | From |
|---|---|---|
| `account` | `email:<addr>` / `account_uuid:<uuid>` | collected login files (`~/.claude.json`, Codex `auth.json`) |
| `ioc` | `<incident>\|<kind>:<value>` | `detections/hunt.json` HIT verdicts |
| `secret_fingerprint` | `<TYPE>\|sha256:<16 hex>` | artifacts cited by `POTENTIAL_SECRET_EXPOSURE` / `MCP_SECRET_IN_CONFIG`, re-scanned with the same patterns and placeholder rules; the value is never read into the report. Budget 512 MiB of evidence per case. |
| `network_destination` | host | hosts named in agent commands; connections in endpoint telemetry pairings. Allowlisted hosts (model providers, package registries) only with `--include-common`. |
| `mcp_server` | `package:<ref>`, `url:sha256:…`, `package_url:sha256:…`, `binary:<sha256>` | `detections/mcp-audit.json`. URLs are keyed on the SHA-256 of the normalized URL (scheme, host, port, path, query names with fingerprinted values) and displayed without userinfo, with query values replaced by fingerprints. |
| `tool_definition` | definition SHA-256 | MCP tool definitions in the inventory |
| `instruction_file` | content SHA-256 (the artifact id) | collected CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, .windsurfrules, .clinerules, copilot-instructions.md, instructions.md, memory.md, `.cursor/rules/`, `.github/instructions/`, `.claude/{agents,commands,skills}/` |
| `session_id`, `agent_id` | the id | events (main-agent ids derived from the session id are not repeated) |
| `host_name` | lower-cased host | manifest — with the note that a host name is not a unique machine identifier |

**Identity.** Hosts, OS users and profiles are listed per case and never
merged. `identity_links` lists entities in different cases that share an exact
identifier — an account email or account uuid — and names that identifier.

Every key, display string, location and evidence reference passes through
credential masking.

### Schema (`agentdfir.crosscase/1`)

```text
{
  "schema": "agentdfir.crosscase/1",
  "includes_unverified_cases": bool,
  "cases": [{label: "C1"…, path, case_id, host, os, os_users: [string],
             integrity: {result: "VERIFIED|FAILED", signature: "valid|none|INVALID|error", problems},
             accounts: [{profile, product, email, account_uuid, login_source}], events, findings}],
  "shared": [{kind, key, display, note,
              cases: [{case, count, first_seen, last_seen, time_source: "transcript|endpoint_telemetry|file_mtime|ioc_hunt",
                       where: [string], evidence_refs: [string], from_unverified_case}]}],
  "identity_links": [{identifier: "email|account_uuid", value, entities: ["C1: Claude Code profile .claude", …]}],
  "timeline": [{time, time_source, case, kind, key, display, event: "first_seen|last_seen"}],
  "omitted": {"timeline": n},
  "notes": [string],
  "limits": [string]
}
```

Cases are labelled in argument order. Shared items are ordered by kind (as in
the table) then key; occurrences by case; the timeline by time, case, kind,
key (at most 2,000 entries). Exit status: 0 compared, 1 a package was refused,
2 usage.

---

## Honest limits

| Area | What is read | What is not |
|---|---|---|
| Time gaps | transcript timestamps | anything outside the transcript; a gap is "nothing recorded", not "something hidden" |
| Second-witness coverage | telemetry imported with `--endpoint`, the host witness recorded at acquisition, shell-history corroboration | telemetry that exists but was not imported; network/file kinds the export does not log are reported as `telemetry_present_no_match`, not as disproof |
| Cloud / shell history | confirmations | never contradictions — their absence of a record is not evidence |
| Clock | timestamps the evidence carries; no clock is assumed correct | the host's real time at the moment of the action |
| Lineage processes | processes paired by the correlate package and records sharing their pid/ppid within 10 minutes | process trees from telemetry that was not imported; pid reuse beyond that window is not followed |
| Cross-case | each case's stored analysis and sealed evidence | indicators not collected in a case; equivalence of hosts or users without a shared exact identifier |
| Secrets | the 11 credential formats `POTENTIAL_SECRET_EXPOSURE` knows | other secret shapes; fingerprints are 64-bit truncated SHA-256 of the value |
| Lineage labels | credential formats masked before any cut | a secret that matches none of the known formats (e.g. an opaque token in a URL path) is not recognised as one |

All test fixtures are synthetic (simulate scenarios and generated profiles); no
real evidence is used.
