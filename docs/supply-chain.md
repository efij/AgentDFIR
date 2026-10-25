# Agent supply-chain forensics

```sh
agentdfir supply-chain [<case.adfir>] [--json] [--out file] [--since T]
                       [--baseline file]... [--peer case]... [--window 10m]
```

Reconstructs the supply chain of an agent environment from a sealed case:
every component an agent loads on its own, where it came from, when it was
first and last seen and by which clock, how its hash changed across the
case's collection rounds and any baselines, how MCP tool definitions and
agent settings drifted, and the path from a component to the invocations
that used it, the commands that followed and the processes endpoint
telemetry tied to them.

Every analysis builds the same report and stores it as
`normalized/supplychain.json` (overlay data, outside the seal, regenerable),
so the explorer can read it. The command reads that file, or rebuilds it
when `--baseline` or `--window` is given.

It is not a second inventory engine. Components come from the extension,
plugin and skill inventory (`internal/extinv`) and the MCP audit
(`internal/mcpaudit`) the analysis already runs; history comes from the
append-only manifest every `run` round extends; invocations come from the
normalized events; commands and processes come from the stored endpoint
correlation.

## Verified and inferred

Every relationship carries `class`:

| class | basis |
|---|---|
| `verified` | a hash-identical artifact; a logged invocation that names the component (a `Skill` tool call, an `mcp__<server>__<tool>` call, a hook record naming the identical declared command); an explicit reference (a hook record's tool_use id, an install registry entry, a file inside a plugin directory, an endpoint pid/ppid) |
| `inferred` | time proximity (a command after an invocation in the same session, inside `--window`), a name match shared by several components, a hook record that names only its event, endpoint correlation (command line within a time window, with the correlation's confidence) |

The JSON keeps them in two lists (`relations.verified`,
`relations.inferred`); the text report prints them in two sections. An
inferred link is never promoted. A rule that combines a verified invocation
with a temporal link says which half is which.

## What is read

| Component | Source | Origin | Hash |
|---|---|---|---|
| plugin | host install registry (`installed_plugins.json`), plugin manifest | marketplace (name, repo/URL), version, git commit as recorded | plugin manifest content |
| marketplace | `known_marketplaces.json`, settings `extraKnownMarketplaces` | github / git / url / directory; default or third-party | — |
| skill, slash command, sub-agent | files under skills/, commands/, agents/ (user and plugin) | inherited from the containing plugin, else repository (git metadata collected) or local | file content |
| hook | plugin `hooks.json`, settings `hooks` | the declaring plugin or settings file | declared command string |
| MCP server | every config the MCP audit knows | npm / pypi package + version, git, URL, local command | command/args or URL, env value fingerprint, header names, resolved binary |
| IDE extension | editor extension registry | gallery / vsix / unregistered | entry file (or package.json) content |
| instruction file | CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, … | repository or local | file content |
| agent settings | Claude Code settings / managed settings, Gemini settings, every MCP config | repository or local | file content |

Git remote and commit are read only from a `.git/config`, `.git/HEAD`,
`refs/…` or `packed-refs` collected in the evidence for an enclosing
directory. Credentials are never kept: URL userinfo is dropped, query
values are replaced by `<redacted>`, `user:secret@` is removed from
scp-style remotes, and credential-shaped strings are masked.

Timestamps name their clock (`source`): `install_manifest` (installedAt,
lastUpdated), `file_mtime` (settable by anything that can write the file),
`log_record` (a transcript record of an invocation), `collection` (when a
round collected it). Times from evidence are normalized to RFC 3339 UTC;
an unparseable one is flagged, not printed as given.

Hash history (`hash_history`) lists every distinct hash per collection
round (`source: round`), per MCP baseline (`baseline`) and per package
snapshot (`package_snapshot`, from `agentdfir baseline`).

### Drift

- `mcp_tool_definition` / `mcp_server_definition`: consecutive snapshots of
  one server — config rounds after any MCP baselines; cached tool manifests
  (artifacts holding `inputSchema`) per round; tool lists logged by stream-json
  `system/init` records per session (names only).
- `agent_settings`: consecutive versions of a settings or MCP config file:
  permission allow/deny/ask rules, `defaultMode`, hooks,
  `enableAllProjectMcpServers`, `enabledMcpjsonServers`, MCP server names.

`permission_expansion` lists what grew: new tools, env keys, header names,
auto-approved tools, new filesystem path arguments, a server re-enabled,
new allow rules, removed deny/ask rules, a more permissive `defaultMode`,
new hooks, new MCP servers.

### Invocations

- `Skill` / `SlashCommand` tool calls: the skill name is re-read from the
  raw transcript line (bounded: 1 MiB per line, 20000 lines per build).
- `<command-name>` in a prompt record: a slash command, matched only to a
  collected command or skill (built-in commands get no component).
- `mcp__<server>__<tool>` tool calls.
- Hook records: `attachment` lines of type `hook_*`, `progress` lines of type
  `hook_progress`, `stop_hook_summary` system lines.

A component known only from a transcript is listed with
`observed_only: true` and origin `unknown`.

### Cross-session and cross-case reuse

`reuse` lists components invoked in two or more sessions: `verified` when
every round holds them with one hash, `inferred` when the hash changed
between rounds or the component is observed only (a name, not a hash).
`--peer <case>` adds hash-identical components in other analyzed cases
(another host, or another collection); each peer must be analyzed by this
version and its seal is checked (an unverified peer is marked).

## Rules

| Rule | Severity | Fires when | ATT&CK / ATLAS |
|---|---|---|---|
| `SUPPLY_MCP_TOOL_DRIFT_EXPANSION` | HIGH (MEDIUM for name-only init-record drift that only adds tools) | the same MCP server, two snapshots, and the later one has a permission expansion | T1195.002 / AML.T0110 |
| `SUPPLY_UNTRUSTED_COMPONENT_BEFORE_HIGH` | HIGH | a skill, slash command, sub-agent or plugin hook with origin trust third_party, unregistered or repository is invoked (verified) and within the window a command in the same session draws a HIGH/CRITICAL finding | T1195.002 / AML.T0010.005 |
| `SUPPLY_FLAGGED_COMPONENT_REUSED` | HIGH | a component cited by a malicious-indicating finding (EXTENSION_INVISIBLE_CODE, EXTENSION_OBFUSCATED_LOADER, PLUGIN_HOOK_EXECUTES_REMOTE, SKILL_HIDDEN_INSTRUCTIONS, MCP_TOOL_DESCRIPTION_POISONING, MCP_REMOTE_FETCH_COMMAND, MCP_PACKAGE_TYPOSQUAT, KNOWN_INCIDENT_IOC, TOOL_POISONING_INDICATOR, INVISIBLE_UNICODE_INSTRUCTION) ran in two or more sessions, or (with `--peer`) is present hash-identical in another case | T1195.002 / AML.T0010.005 |

These complement, and do not repeat, `MCP_TOOL_DEFINITION_CHANGED` /
`MCP_TOOL_ADDED` (against an explicit `mcp audit --baseline`) and
`PLUGIN_MARKETPLACE_UNTRUSTED` (a configuration fact with no execution).

## JSON (`agentdfir.supplychain/1`)

```
schema, case_id, host, since?, inference_window
rounds[]        {round, started_utc, completed_utc}
components[]    {id, kind, name, host, parent?, origin{type, trust, marketplace?, location?,
                 package?, version?, git_remote?, git_commit?, url?, local_path?, basis},
                 paths[], sha256, hash_basis, first_seen{time, source, detail, ref},
                 last_seen{…}, hash_history[{sha256, source, label, rounds[], path, mtime}],
                 observed_only?, invocations, sessions[], flagged_by[], tools[]}
drift[]         {kind, component, subject, from{label, source, round?, session?, time,
                 time_source, sha256?, ref?}, to{…}, added[], removed[], changed[],
                 permission_expansion[], class, basis}
relations       {verified[], inferred[]}  each {from, to, type, class, basis, time?, session?,
                 confidence?, label?, source_refs[{artifact_id, logical_path, line, offset,
                 event_id, telemetry_ref}]}
reuse[]         {component, sha256?, sessions[], cases[{label, case_id, host, component,
                 from_unverified_case?}], class, basis, flagged_by[]}
timeline[]      {time, time_source, kind, component?, class?, session?, text, ref?}  (chronological)
findings[]      the rule findings (also in detections/findings.json)
omitted{}, unsupported[], notes[], limits[]
```

Node ids in relations: component ids (`skill:claude-code:<plugin>@<mkt>:<name>`,
`mcp_server:<host>/<scope>/<name>`, `hook:…`, `plugin:…`, `marketplace:…`),
`event:<event_id>`, `process:<telemetry ref>`, `record:<telemetry ref>`,
`finding:<RULE>|<ref>`.

Relation types: `installed_from`, `contains`, `invoked`, `hook_executed`,
`hook_for_tool_call`, `followed_by`, `produced`, `related_record`,
`flagged_by`.

## Not read, and UNSUPPORTED

- MCP gateway logs: their `tools/list` responses are not parsed for drift;
  gateway invocation corroboration stays in the MCP audit.
- Codex plugin stores are reported by the extension inventory as
  unsupported (layout not documented); those entries appear in
  `unsupported`.
- A baseline file that is neither an MCP baseline (`servers`) nor a package
  snapshot (`artifacts`) is refused as UNSUPPORTED.
- Package snapshots hold hashes only: drift against one says the content
  differs, without field-level detail.
- Which version of a changed component a session ran is not recorded; reuse
  across a hash change is inferred from collection times.
- Absence in a round is not proof a component was not installed, and no
  invocation is invented for a component the transcripts do not name.

## Fixtures

`internal/supplychain/testdata` holds hand-made home directories (README
there): a two-round chain (third-party marketplace → modified skill → MCP
tool call after its tool list grew → credential read) and a two-round
benign home with no change. `internal/corpus/testdata` has one attack case
per rule and a benign case (official marketplace, steady tool lists).
