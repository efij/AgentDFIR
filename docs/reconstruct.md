# Incident reconstruction — `agentdfir reconstruct`

```
agentdfir reconstruct <pkg|case> [<pkg|case> ...] [--json | --mermaid | --dot] [--out file]
                      [--allow-unverified] [--include-common] [--no-overlay] [--max-timeline N]
```

`reconstruct` takes one or more analyzed cases and lays them out as one
incident. It covers:

- a merged timeline across hosts, agents, sessions and users;
- who delegated work to whom;
- where a session or a piece of work was handed off;
- what links the hosts;
- the attack stages in kill-chain order;
- for every segment and stage, the telemetry that would confirm or refute it.

The command assembles results that other packages already compute. It does not
re-analyze the evidence:

| Part | Comes from |
|---|---|
| Delegation (subagents) | the lineage graph (`normalized/lineage.json`, package `lineage`) |
| Shared destinations, credential fingerprints, instruction files, MCP packages, account identity links | `correlate-cases` (package `crosscase`), with the same seal and staleness rules |
| Evidence gaps, what to collect next, endpoint coverage per activity range | `normalized/coverage.json` (package `gaps`) |
| Stage material | attack-chain findings (`docs/attack-chains.md`) and HIGH/CRITICAL findings with an ATT&CK technique |
| Timeline | the normalized events and findings of each case |

The output is deterministic correlation only: the same input always gives the
same bytes. No model writes any part of it (see "Narrative extension point"
below).

## Input rules

- An argument is a package path or a case name under the AgentDFIR home
  (`cases/<name>` or `cases/<name>.adfir`).
- A package whose analysis is missing or stale is analyzed first, the same way
  `gaps` and `lineage` do it.
- Every seal is fully verified. A package that fails verification is refused
  unless `--allow-unverified` is passed. In that case
  `includes_unverified_cases` is `true` and the case's `integrity` is `FAILED`.
- When there are two or more cases, the shared items come from `crosscase.Run`.
  Allowlisted destinations are skipped unless `--include-common` is passed.
- The JSON is also written to each input case as `normalized/reconstruct.json`
  (gzip-compressed like the rest of the overlay, and outside the seal).
  `--no-overlay` skips this. The next reconstruction that includes the case
  replaces the file. Writing it never makes the stored analysis stale.

## Identity rules

- Hosts, OS users, sessions and agents belong to their case. Each case's host is
  its own entity, written `C1:<hostname>`. Two cases with the same host name
  stay two entities, and `identities.notes` says so.
- Two cases are joined only by an identifier that the evidence carries:
  - the same session id;
  - a session named in a resume command;
  - an account email or uuid read from login files (the crosscase identity
    rule);
  - a commit id of 12 or more hex digits.
- A **segment** is one agent's recording of one session, from one source file,
  in one case. Its id is `C<n>/<session>/<agent>`. When the same session and
  agent appear in more than one file of a case, the id gets the suffix `@1`,
  `@2`, … in time order.

## Verified versus inferred

Every link between segments or stages carries a `link` value:

- **verified**: explicit evidence connects the two ends:
  - the same session;
  - a recorded spawn path in the lineage graph;
  - endpoint process lineage (pid/ppid edges in the lineage graph);
  - steps of one attack-chain finding;
  - a session handed off by id;
  - a resume command that names the session;
  - a full commit id named on both sides.
- **inferred**: only order in time and shared attributes connect them. The
  `basis` text always starts with `order in time only` and lists up to three
  items the two cases share. Two other cases are also inferred: a branch name
  pushed on one host and pulled on another, and an abbreviated commit id.
- **unresolved** (delegations and hand-offs only): the other end is not in the
  evidence. Examples are an agent CLI launch with no matching session, or a
  resume command that names a session nobody collected.

Each stage item gets at most one predecessor: an item of an earlier stage that
happened no later. A verified predecessor always wins, so an inferred edge
appears only where no verified one exists. The text report lists verified
edges first, then inferred edges, and labels each.

## Attack stages

The stages, in order: `initial_access`, `execution`, `persistence`,
`privilege_escalation`, `credential_access`, `collection`, `exfiltration`,
`impact`, `anti_forensics`.

How an item gets its stage:

- An attack-chain step is placed by its step name (`StepStage`).
- If the step name does not match, the chain's ATT&CK technique decides.
- Other HIGH/CRITICAL findings are placed by their technique
  (`TechniqueStage`).
- A technique the table does not map leaves the finding unstaged. It still
  appears on the timeline and is counted in `summary.high_findings_unstaged`.
  Nothing is dropped silently.

T1685 (disable or modify tools), T1686 (disable or modify system firewall)
and T1070 (indicator removal) count as anti-forensics. T1562, revoked in
ATT&CK v20.0, is still placed there for findings stored by earlier releases.

## Hand-offs

| kind | When | link |
|---|---|---|
| `session_resumed_across_files` | the same session and agent in two source files of one case | verified |
| `session_continued_across_hosts` | the same session and agent in two cases | verified |
| `session_in_export_and_transcript` | the same conversation id in a provider export (ChatGPT, Claude.ai, Gemini, DeepSeek) and in an endpoint transcript | verified |
| `session_resumed_by_command` | a shell command runs `claude/codex/... --resume <id>` (or `-r`, `--session-id`, `resume <id>`) | verified if that session is in the evidence, otherwise unresolved |
| `git_branch` | `git push <remote> <branch>` in one case, then a pull, fetch, checkout or switch of the same branch in another case, later | inferred |
| `git_commit` | the same commit id named in git commands in two cases | verified if both are 12+ hex digits, otherwise inferred |

For hand-offs between files and hosts, `relation` is `continued` when the
second recording starts after the first one ends. It is `overlapping` when the
two overlap in time. An overlapping pair may be two copies of the same evidence,
and the basis says so.

Some segments hold only index or metadata records, such as a sessions list.
These segments are not treated as recordings of the session, so they never
produce hand-offs.

## Delegation

- `subagent`: every `spawned` edge in the lineage graph. Its `basis` is
  lineage's own basis text (tool_use_id match, spawn record, or recorded
  parent id). If the child has no records in the case, the delegation is
  `unresolved`.
- `agent_cli`: a shell tool call that starts `claude`, `codex`, `gemini`,
  `cursor-agent` or `copilot`. The child is taken to be the first session of
  that product that starts on the same host within two minutes. That match is
  `inferred`, because order in time is the only link. If no such session
  exists, the delegation is `unresolved`.

## Missing evidence

`missing_evidence[]` collects the following, in this order:

1. **Hosts with no second witness.** These are cases with neither endpoint
   telemetry nor any other witness. The entry gives the span to collect for and
   the `analyze --endpoint` command to run.
2. **Coverage items.** Every `coverage.json` item with status `unknown` or
   `verify_next`. If an item's evidence ref resolves to an event, the item is
   placed on that event's segment.
3. **Segments without full coverage.** Segments that made tool calls while
   endpoint coverage was `none`, `partial` or unknown. This is how a host with
   no telemetry during its segment is reported.
4. **Unconfirmed stage items.** Stage items that no second witness confirmed,
   with the telemetry that would confirm them for that stage.
5. **Inferred stage edges.** Each one lists the evidence that would turn it
   into a verified edge.
6. **Delegations and hand-offs that are not verified.**

Absence of evidence is never reported as proof that something did not happen.

## JSON (schema `agentdfir.reconstruct/1`)

| Field | Content |
|---|---|
| `schema`, `includes_unverified_cases` | |
| `summary` | counts: cases, host entities, sessions, agents, segments, timeline entries, delegations, hand-offs, links, stage items, verified/inferred edges, unstaged HIGH findings, missing items |
| `cases[]` | `label`, `path`, `package_id` (the sealed case id), `host`, `host_entity`, `os`, `os_users`, `integrity`, `events`, `findings`, `telemetry` (witness names from coverage.json), `telemetry_start/end` |
| `identities` | `hosts[]` (one per case), `identity_links[]` (crosscase), `notes[]` |
| `segments[]` | `id`, `case`, `package_id`, `host`, `user`, `session_id`, `agent_id`, `product`, `source_logical_path`, `parent_agent_id`, `start`, `end`, `events`, `tool_calls`, `findings`, `endpoint_coverage` (`full`/`partial`/`none`/`unknown`/`not_applicable`), `first_ref`, `last_ref` |
| `timeline[]` | `seq`, `time` (UTC), `time_source` (`transcript`, `provider_export…`, `recorded`, `cited_event`, `finding`, `none`), `case`, `package_id`, `host`, `user`, `session_id`, `agent_id`, `product`, `segment`, `kind` (event type or `finding`), `summary` (credential-masked), `evidence_state`, `event_id`, `rule_id`, `severity`, `source_ref` |
| `delegations[]` | `case`, `kind`, `parent_agent_id`, `child_agent_id`, `parent_segment`, `child_segment`, `session_id`, `tool_call_id`, `time`, `link`, `basis`, `evidence_state`, `source_refs` |
| `handoffs[]` | `kind`, `key`, `from_segment`, `to_segment`, `from_case`, `to_case`, `from_time`, `to_time`, `relation`, `link`, `basis`, `source_refs` |
| `cross_host_links[]` | `kind` (a crosscase kind), `key`, `display`, `class` (`shared_attribute` or `identity`), `cases`, `segments` (network destinations and agent ids; other kinds are case-level), `basis`, `note` |
| `stages[]` | `stage`, `order`, `items` (stage item ids), `cases` |
| `stage_items[]` | `id` (`S1`…), `stage`, `case`, `host`, `segment`, `session_id`, `agent_id`, `rule_id`, `severity`, `title`, `chain_step`, `mitre_attack`, `placed_by` (`chain_step`/`technique`), `time`, `event_id`, `evidence_state`, `source_ref` |
| `stage_edges[]` | `from`, `to`, `from_stage`, `to_stage`, `link`, `basis`, `seconds_between`, `cross_host` |
| `missing_evidence[]` | `scope` (`case`/`segment`/`stage_item`/`stage_edge`/`delegation`/`handoff`), `target`, `case`, `host`, `status` (`unknown`/`verify_next`), `category`, `text`, `collect`, `source` (`coverage.json`/`reconstruct`), `evidence_refs` |
| `narrative` | the fixed extension-point record (see below) |
| `omitted`, `notes`, `limits` | bounds hit, notes, and the rules above in words |

The output is bounded:

| List | Bound |
|---|---|
| timeline | 5,000 entries (`--max-timeline`) |
| stage items | 500 |
| missing-evidence items | 500 |
| coverage items per case | 100 |
| agent CLI launches per case | 200 |
| git references | 2,000 |

Anything cut by a bound is counted in `omitted`. Credential-shaped values are
masked everywhere. Secrets appear only as crosscase fingerprints.

## Narrative extension point

OSS v4.5 does not generate a narrative, because doing so would require a model
or network access. The JSON document is the input a narrative layer would
consume. The `narrative` field always reads:

- `implemented: false`;
- `input`: the sections of this document;
- `requirement`: the contract any such layer must follow. A narrative made from
  this document is **not evidence**. It must be labeled NON-EVIDENCE wherever it
  is shown. It must cite the segment, timeline seq, stage item and edge ids it
  rests on. It must keep verified and inferred links distinct. It must never
  state as fact anything this document lists as inferred or missing.

## Mermaid and DOT

Each case is drawn as a subgraph (or cluster) of its segments. Delegation and
hand-off edges are solid when verified and dashed when inferred. A shared
destination is drawn as a dotted line between segments on different hosts.
Stage items are hexagons, joined by the stage edges, solid for verified and
dashed for inferred.

## What is not covered

- Process-tree spawns of agent CLIs are matched only through the shell command
  that the transcript records. A launch that does not appear in a transcript
  can show up only through the lineage graph's process edges.
- Git hand-offs are read from recorded shell commands. Reflogs and remote audit
  logs are not read; the `collect` text names them as the evidence to obtain.
- `gitBranch` fields in transcripts are not used, because the parser does not
  keep them.
- Every case is loaded twice when there are two or more: once by crosscase, once
  for the timeline. Memory therefore scales with the total number of events.

## Fixture origin

The tests use these fixtures:

- **Host A**: the `simulate` scenarios `orphan-agent` and `toxic-chain`, plus one
  hand-written session that pushes a branch. They are analyzed with a
  hand-written endpoint JSONL that has the same shape as the lineage command's
  test.
- **Host B**: a hand-written, synthetic Claude Code profile. It contains the
  toxic-chain session continued under the same id, a pull of the pushed branch,
  and a session that contacts the same destination and deletes transcripts.
  Host B has no telemetry.
- **Single-package benign case**: the precision corpus case
  `continue-routine-session`, built with `corpus.BuildPackage`.

All of these fixtures are built at test time. None is committed.
