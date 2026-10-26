# v5 detections

v5 adds structured tool-call fields to the normalized events (`arg_keys`,
`args_digest`, `safe_args`, `result_status`, `tool_def_digest`,
`mcp_server_version`, `approval_state`, `permission_from`, …). They carry
names, digests and allowlisted values only; raw arguments and results stay in
the sealed source artifact. This page lists the rules built on them, what
each one answers, what evidence it needs, and where it stops.

Every rule here is deterministic. When the fields a rule reads are empty
(a parser that does not fill them yet, an older transcript), the rule emits
nothing. That silence is missing evidence, not a clean result.

## P0 rules

### Dedupe verdicts

| Proposed capability | Verdict | Shipped as |
|---|---|---|
| MCP_ARGUMENT_BEHAVIOR_MISMATCH | **NEW**. v4 family 6 (MCP_SCHEMA_BEHAVIOR_DIVERGENCE) had no evidence source; `arg_keys` and captured tool declarations are that source. | `MCP_ARGUMENT_BEHAVIOR_MISMATCH` |
| MCP_TOOL_IDENTITY_DRIFT | **NEW**, runtime only. `MCP_SERVER_CHANGED` / `MCP_TOOL_DEFINITION_CHANGED` diff configuration against a baseline; `SUPPLY_MCP_TOOL_DRIFT_EXPANSION` compares snapshots (incl. session init tool *names*) and reports capability gains only. None reads the server version or definition digest recorded on the calls. | `MCP_TOOL_IDENTITY_DRIFT` |
| AGENT_PERMISSION_STATE_DRIFT | **NEW**, narrow. `PERMISSION_ESCALATION` and `PERMISSION_BYPASS_ENABLED` read configuration at rest. `AGENT_TOOL_PERMISSION_ESCALATION` reports a mid-session move into `bypassPermissions` (whatever the approval) and grants the agent writes into its own config. Nothing reported a widening to `acceptEdits`/`auto` or out of `plan`, and nothing asked whether an approval was recorded. Moves into `bypassPermissions` stay with `AGENT_TOOL_PERMISSION_ESCALATION` and are not repeated. Tool allowlist expansion by the agent is `AGENT_TOOL_PERMISSION_ESCALATION` (HIGH); transcripts do not otherwise record allowlist changes. | `AGENT_PERMISSION_STATE_DRIFT` |
| AGENT_CREDENTIAL_TO_EXTERNAL_TOOL | **NEW**. `CHAIN_SECRET_TO_EXFIL` / `CHAIN_CROSS_TOOL_EXFIL` link a credential read to a later upload by time and session; `POTENTIAL_SECRET_EXPOSURE` reports a credential anywhere in a transcript. None sees the credential inside a specific tool call's arguments. | `AGENT_CREDENTIAL_TO_EXTERNAL_TOOL` |
| AGENT_UNAUTHORIZED_RESOURCE_CHANGE | **NEW** for plan mode. The `permissions.deny` half is a **DUPLICATE** of `AGENT_PERMISSION_BOUNDARY_CROSSING` (deny rule covers a call whose result is neither error nor refusal) and is not re-implemented. | `AGENT_UNAUTHORIZED_RESOURCE_CHANGE` |
| AGENT_EVIDENCE_SUPPRESSION | **DUPLICATE** of `AGENT_AUDIT_COVERAGE_LOSS`, `LOG_DELETION`, `OS_LOG_TAMPER`, `HISTORY_CLEARING`, `CLOUD_LOGGING_DISABLE` and `CHAIN_ACTION_THEN_LOG_TAMPER`. The narrow AGENT_TRANSCRIPT_RETENTION_REDUCED was **not added**: `AGENT_AUDIT_COVERAGE_LOSS` already reports `cleanupPeriodDays` set below a week, and any agent write to its own settings is `AGENT_SELF_MODIFICATION`. The one uncovered piece, the agent turning off its own OpenTelemetry export, was folded into `AGENT_AUDIT_COVERAGE_LOSS` (`CLAUDE_CODE_ENABLE_TELEMETRY=0/false`). Generic switches such as `OTEL_SDK_DISABLED=true` are deliberately not matched: they are routine in test runs. | extension of `AGENT_AUDIT_COVERAGE_LOSS` (pack) |
| AGENT_SKILL_SUPPLY_CHAIN_CHANGE | **DUPLICATE**. `agentdfir baseline check` already compares every collected skill, hook, plugin and agent definition by content hash against a recorded baseline and reports `SKILL_CHANGED`, `HOOK_CHANGED`, `PLUGIN_CHANGED`, `AGENT_DEFINITION_CHANGED`; content risk is `SKILL_HIDDEN_INSTRUCTIONS` / `PLUGIN_HOOK_EXECUTES_REMOTE`. | — |
| MCP_RUNTIME_RESPONSE_POISONING | **EXTENDS** `INSTRUCTION_FROM_TOOL_RESULT` and `CHAIN_MCP_RESULT_TO_PRIVILEGED`. No new rule. For the relevance inventory: `INSTRUCTION_FROM_TOOL_RESULT` keeps `AML.T0080.000` as its primary mapping and maps to `AML.T0110.002` (AI Agent Tool Poisoning: Runtime Response) as a secondary technique; `MCP_TOOL_POISONING` (instruction content in an MCP result, `AML.T0099`) is the other runtime-response detection. | — |

### Rules

| Rule | Severity | ATLAS | ATT&CK |
|---|---|---|---|
| `AGENT_CREDENTIAL_TO_EXTERNAL_TOOL` | CRITICAL | AML.T0086 Exfiltration via AI Agent Tool Invocation | T1567 |
| `MCP_ARGUMENT_BEHAVIOR_MISMATCH` | HIGH | AML.T0110.001 AI Agent Tool Poisoning: Implementation | T1195.002 |
| `MCP_TOOL_IDENTITY_DRIFT` | HIGH | AML.T0109 AI Supply Chain Rug Pull | T1195.002 |
| `AGENT_UNAUTHORIZED_RESOURCE_CHANGE` | HIGH | AML.T0053 AI Agent Tool Invocation | T1548 |
| `AGENT_PERMISSION_STATE_DRIFT` | MEDIUM | AML.T0081 Modify AI Agent Configuration | T1548 |

ATLAS IDs are from ATLAS 2026.09, ATT&CK IDs from Enterprise v20.0; none is
revoked.

#### MCP_ARGUMENT_BEHAVIOR_MISMATCH
- **Question:** did an MCP call do something its tool's declaration says it does not?
- **Logic:** the call's tool declaration is resolved from the declarations clients cache in their configuration and state files (`product_config`, `product_state`, `debug_logs`, `managed_config`; ≤ 8 MiB each, ≤ 4096 declarations): by the `tool_def_digest` the call recorded (only that one; a recorded digest that matches no captured declaration means the captured one was not in force, and the rule stays silent), otherwise by tool name when exactly one distinct declaration of that name was captured. Then either (a) `arg_keys` holds names the input schema's `properties` does not declare (skipped when the schema declares none, or sets `additionalProperties` to true or a schema), or (b) the tool is annotated `readOnlyHint: true` and a write, delete, network send or state-changing command was observed inside the same call, or annotated `destructiveHint: false` and a delete was observed. "Inside the same call" means an event linked to the call by its id (`parent_tool_call_id`, or a non-call/result record carrying the same `tool_call_id`), or an event on a path named in the call's `safe_args`, recorded between the call and its result. Without a recorded result the path link is not attempted.
- **Evidence needed:** a captured tool declaration; `arg_keys` for (a); an effect event for (b).
- **Confidence:** HIGH for an id-linked effect under a digest-matched declaration; MEDIUM for a digest-matched declaration otherwise; LOW when the declaration was matched by name only.
- **Limits:** a mismatch is not compromise. Annotations are hints the server author writes, schemas go stale across upgrades, and clients add bookkeeping arguments. Argument values are never read.

#### MCP_TOOL_IDENTITY_DRIFT
- **Question:** did the code answering calls under one configured MCP server name change during the case?
- **Logic:** per configured server name, the distinct `mcp_server_version` values recorded on its events; per server and tool, the distinct `tool_def_digest` values (case- and `sha256:`-prefix-insensitive). Two or more distinct values raise one finding per server (version) or per tool (digest). At most 8 values per key and 4096 keys are tracked.
- **Evidence needed:** the version or digest recorded on at least two events.
- **Confidence:** HIGH when every value was first seen inside one session; MEDIUM across sessions.
- **Limits:** an owner's upgrade, or an unpinned `npx`/`uvx` launch picking up a new release between sessions, produces the same drift. The definitions behind the digests are not compared here; `MCP_TOOL_DEFINITION_CHANGED` does that against a baseline.

#### AGENT_PERMISSION_STATE_DRIFT
- **Question:** did the permission mode widen mid-session with no recorded approval?
- **Logic:** per agent, in recorded order. A change is an event with `permission_from` and `permission_mode` (explicit), or a `permission_mode` that differs from the previous one recorded (inferred). Widening uses the ranking `plan < default < acceptEdits = auto`; unranked modes never count, and moves into `bypassPermissions` are left to `AGENT_TOOL_PERMISSION_ESCALATION`. The change is reported when none of these is recorded between the last line in the old mode and the change: a person's prompt (client-written lines such as `[Request interrupted…]` do not count), `approval_state: approved`, or an ExitPlanMode result whose text records the plan as approved. A change event with `approval_state: denied` is not reported. At most 5 per agent.
- **Evidence needed:** recorded permission modes on transcript lines, or permission_change events.
- **Confidence:** MEDIUM for an explicit change event; LOW when inferred from line modes.
- **Limits:** a missing approval record is not an unauthorized change. A person can switch modes with a key press while the agent works, and only the next line they type records it. Completion of a call is never read as approval.

#### AGENT_UNAUTHORIZED_RESOURCE_CHANGE
- **Question:** did the agent change something while the client recorded plan mode?
- **Logic:** per agent, the last recorded `permission_mode` is tracked; an approved ExitPlanMode result clears it. A Write/Edit/MultiEdit/NotebookEdit (or `write_file`/`edit_file`/`apply_patch`) or a non-read-only command, issued while the mode is `plan`, whose result is neither an error nor a refusal, is reported. Writes to the plan file (`.claude/plans/*`) are what plan mode is for and are skipped; MCP calls are skipped because whether a read-only MCP tool may run depends on annotations. A result recording a mode other than `plan` means the mode changed first, and is skipped. At most 20 per agent.
- **Evidence needed:** recorded permission modes and a paired tool result.
- **Confidence:** HIGH when `plan` is recorded on the call or its result; MEDIUM when it comes from an earlier line.
- **Limits:** client versions differ in what plan mode allows, and a late-recorded mode switch makes a legitimate call look like this. Deny-rule crossings are `AGENT_PERMISSION_BOUNDARY_CROSSING`.

#### AGENT_CREDENTIAL_TO_EXTERNAL_TOOL
- **Question:** was a credential handed to a tool that runs outside the agent?
- **Logic:** for MCP calls and WebFetch/WebSearch calls with a tool call id, the sealed source line is re-read once however many calls point at it (≤ 4 MiB per line, ≤ 20000 distinct lines, ≤ 64 MiB read and parsed across the rule), and only the object whose `id` / `call_id` / `tool_use_id` is that call id and that carries `input` / `arguments` / `params` is kept. Its bytes are fingerprinted with the `POTENTIAL_SECRET_EXPOSURE` patterns and placeholder rules (the same `SecretFingerprints` used for cross-case correlation), then dropped. The fingerprint is compared with the credential sightings of every collected transcript (the scan `AGENT_CROSS_SESSION_SECRET_REUSE` uses, shared through its memo); a sighting earlier in the case than the call is named as the credential's way in. At most 200 findings. When any of these bounds stops the rule, one INFO finding under the same rule id says how many calls were left unchecked and which bound was hit: no finding for them is missing evidence, not a clean result.
- **Evidence needed:** a readable sealed source line that holds the call. A line that does not parse, or does not hold the call id, gives no finding.
- **Confidence:** HIGH when an earlier sighting exists; MEDIUM otherwise.
- **Limits:** passing a tool the credential it is meant to use is intended use; a credential in the arguments is not proof of exfiltration. Shell commands are out of scope here (command rules and `CHAIN_SECRET_TO_EXFIL`). The finding carries the type and a 64-bit fingerprint, never the value.

### What the rules read

| Field / source | Read by | When empty |
|---|---|---|
| `arg_keys` | MCP_ARGUMENT_BEHAVIOR_MISMATCH | schema half silent |
| `safe_args` (path-like values only) | MCP_ARGUMENT_BEHAVIOR_MISMATCH | path link not attempted |
| `parent_tool_call_id`, `tool_call_id` | MCP_ARGUMENT_BEHAVIOR_MISMATCH | id link not attempted |
| `tool_def_digest` | MCP_ARGUMENT_BEHAVIOR_MISMATCH, MCP_TOOL_IDENTITY_DRIFT | name match (LOW) / no digest drift |
| `mcp_server_version` | MCP_TOOL_IDENTITY_DRIFT | no version drift |
| `permission_mode`, `permission_from` | AGENT_PERMISSION_STATE_DRIFT, AGENT_UNAUTHORIZED_RESOURCE_CHANGE | silent |
| `approval_state` | AGENT_PERMISSION_STATE_DRIFT | only prompts and approved plan exits count |
| cached MCP tool declarations | MCP_ARGUMENT_BEHAVIOR_MISMATCH | silent |
| sealed transcript line of the call | AGENT_CREDENTIAL_TO_EXTERNAL_TOOL | silent |
| endpoint telemetry | not read by these rules | — |
