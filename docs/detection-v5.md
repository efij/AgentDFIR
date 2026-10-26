# v5 detections

v5 adds structured tool-call fields to the normalized events (`arg_keys`,
`args_digest`, `safe_args`, `result_status`, `tool_def_digest`,
`mcp_server_version`, `approval_state`, `permission_from`,
`parent_tool_call_id`, `input_modality`, …). They carry names, digests and
allowlisted values only; raw arguments and results stay in the sealed
source artifact (see [mcp-forensics.md](mcp-forensics.md#what-a-normalized-tool-call-retains)).
This page lists the ten rules built on them, the proposals that were not
built because an existing rule already answers them, what each rule needs,
and where it stops.

Every rule here is deterministic, reads no network, and copies no raw
arguments, results or prompts into findings: findings cite evidence
references, recorded digests and normalized targets (paths, hosts,
resource IDs, secret-store names). None of them states an intent.
Autonomous discovery can be legitimate. A schema mismatch is not a
compromise. A sequence is not causation. A missing approval record is not
an unauthorized action, and completion of a call is never read as
approval. When the fields a rule reads are empty (a parser that does not
fill them yet, an older transcript), the rule emits nothing or lowers its
confidence: that silence is missing evidence, not a clean result.

The v5 attack chains (linked steps with `link_reason`) are in
[attack-chains.md](attack-chains.md#v5-linked-chains); the cross-case
findings `AGENT_CROSS_HOST_ACTIVITY` and `CHAIN_CROSS_HOST_AGENT_PROPAGATION`
are in [investigation-graph.md](investigation-graph.md#cross-case-activity-graph--correlate-cases---graph).
Which ATLAS techniques these answer, and which remain uncovered or out of
reach, is in [atlas-coverage.md](atlas-coverage.md).

## Rules

| Rule | Priority | Max severity | ATLAS 2026.09 | ATT&CK v20.0 |
|---|---|---|---|---|
| `AGENT_CREDENTIAL_TO_EXTERNAL_TOOL` | P0 | CRITICAL | AML.T0086 Exfiltration via AI Agent Tool Invocation | T1567 |
| `MCP_ARGUMENT_BEHAVIOR_MISMATCH` | P0 | HIGH | AML.T0110.001 AI Agent Tool Poisoning: Implementation | T1195.002 |
| `MCP_TOOL_IDENTITY_DRIFT` | P0 | HIGH | AML.T0109 AI Supply Chain Rug Pull | T1195.002 |
| `AGENT_UNAUTHORIZED_RESOURCE_CHANGE` | P0 | HIGH | AML.T0053 AI Agent Tool Invocation | T1548 |
| `AGENT_PERMISSION_STATE_DRIFT` | P0 | MEDIUM | AML.T0081 Modify AI Agent Configuration | T1548 |
| `AGENT_AUTONOMOUS_RECON_SEQUENCE` | P1 | HIGH (MEDIUM unless corroborated) | AML.T0116 Autonomous Reconnaissance | T1082 |
| `AGENT_ADAPTIVE_ATTACK_SEQUENCE` | P1 | HIGH | AML.T0117 Autonomous Attack-Path Adaptation | T1548 |
| `AGENT_DELEGATION_SCOPE_EXPANSION` | P1 | HIGH | AML.T0053 AI Agent Tool Invocation | T1548 |
| `AGENT_RESOURCE_EXHAUSTION` | P2 | MEDIUM | AML.T0034.002 Cost Harvesting: Agentic Resource Consumption | T1496 |
| `AGENT_MULTIMODAL_TRIGGER_CHAIN` | P2 | MEDIUM | AML.T0129 Triggers in Multimodal Inputs | T1027 |

P0 rules are in `internal/detect/agent_v5.go`, P1/P2 rules in
`internal/detect/agent_v5_p1.go`; both run from `RunAgentRules`. All ATLAS
IDs exist in ATLAS 2026.09 and all ATT&CK IDs are active in Enterprise
v20.0; none is revoked. The plan suggested AML.T0108 for delegation scope.
T0108 ("AI Agent") is a command-and-control technique; a subagent invoking
tools outside its grant is AML.T0053.

## Dedupe decisions

Every proposed capability was checked against the existing rules, chains
and packs before anything was written. Of the 16 proposed detections,
ten became new rules, one is cross-case, three were duplicates or
extensions of existing rules, and two are owned by chains. Of the proposed
chains, one was a duplicate and one an extension.

| Proposed capability | Existing coverage read first | Verdict | Shipped as |
|---|---|---|---|
| MCP_ARGUMENT_BEHAVIOR_MISMATCH | v4 family 6 (MCP_SCHEMA_BEHAVIOR_DIVERGENCE), never built | **NEW**. It had no evidence source; `arg_keys` and captured tool declarations are that source. | `MCP_ARGUMENT_BEHAVIOR_MISMATCH` |
| MCP_TOOL_IDENTITY_DRIFT | `MCP_SERVER_CHANGED`, `MCP_TOOL_DEFINITION_CHANGED`, `SUPPLY_MCP_TOOL_DRIFT_EXPANSION` | **NEW**, runtime only. The first two diff configuration against a baseline; the supply-chain rule compares snapshots (incl. session init tool *names*) and reports capability gains only. None reads the server version or definition digest recorded on the calls. | `MCP_TOOL_IDENTITY_DRIFT` |
| AGENT_PERMISSION_STATE_DRIFT | `PERMISSION_ESCALATION`, `PERMISSION_BYPASS_ENABLED`, `AGENT_TOOL_PERMISSION_ESCALATION` | **NEW**, narrow. The first two read configuration at rest. `AGENT_TOOL_PERMISSION_ESCALATION` reports a mid-session move into `bypassPermissions` (whatever the approval) and grants the agent writes into its own config. Nothing reported a widening to `acceptEdits`/`auto` or out of `plan`, and nothing asked whether an approval was recorded. Moves into `bypassPermissions` stay with `AGENT_TOOL_PERMISSION_ESCALATION` and are not repeated; tool allowlist expansion by the agent is also that rule's. | `AGENT_PERMISSION_STATE_DRIFT` |
| AGENT_CREDENTIAL_TO_EXTERNAL_TOOL | `CHAIN_SECRET_TO_EXFIL`, `CHAIN_CROSS_TOOL_EXFIL`, `POTENTIAL_SECRET_EXPOSURE` | **NEW**. The chains link a credential read to a later upload by time and session; `POTENTIAL_SECRET_EXPOSURE` reports a credential anywhere in a transcript. None sees the credential inside a specific tool call's arguments. | `AGENT_CREDENTIAL_TO_EXTERNAL_TOOL` |
| AGENT_UNAUTHORIZED_RESOURCE_CHANGE | `AGENT_PERMISSION_BOUNDARY_CROSSING` | **NEW** for plan mode. The `permissions.deny` half is a **DUPLICATE** of `AGENT_PERMISSION_BOUNDARY_CROSSING` (a deny rule covers a call whose result is neither error nor refusal) and is not re-implemented. | `AGENT_UNAUTHORIZED_RESOURCE_CHANGE` |
| AGENT_EVIDENCE_SUPPRESSION | `AGENT_AUDIT_COVERAGE_LOSS`, `LOG_DELETION`, `OS_LOG_TAMPER`, `HISTORY_CLEARING`, `CLOUD_LOGGING_DISABLE`, `CHAIN_ACTION_THEN_LOG_TAMPER` | **DUPLICATE, dropped.** The narrow AGENT_TRANSCRIPT_RETENTION_REDUCED was **not added**: `AGENT_AUDIT_COVERAGE_LOSS` already reports `cleanupPeriodDays` set below a week, and any agent write to its own settings is `AGENT_SELF_MODIFICATION`. The one uncovered piece, the agent turning off its own OpenTelemetry export, was folded into `AGENT_AUDIT_COVERAGE_LOSS` (`CLAUDE_CODE_ENABLE_TELEMETRY=0/false`). Generic switches such as `OTEL_SDK_DISABLED=true` are deliberately not matched: they are routine in test runs. | **extends** `AGENT_AUDIT_COVERAGE_LOSS` (pack) |
| AGENT_SKILL_SUPPLY_CHAIN_CHANGE | `agentdfir baseline check`, `SKILL_HIDDEN_INSTRUCTIONS`, `PLUGIN_HOOK_EXECUTES_REMOTE` | **DUPLICATE, dropped.** `baseline check` already compares every collected skill, hook, plugin and agent definition by content hash against a recorded baseline and reports `SKILL_CHANGED`, `HOOK_CHANGED`, `PLUGIN_CHANGED`, `AGENT_DEFINITION_CHANGED`; content risk is `SKILL_HIDDEN_INSTRUCTIONS` / `PLUGIN_HOOK_EXECUTES_REMOTE`. | — |
| MCP_RUNTIME_RESPONSE_POISONING | `INSTRUCTION_FROM_TOOL_RESULT`, `CHAIN_MCP_RESULT_TO_PRIVILEGED`, `MCP_TOOL_POISONING` | **EXTENDS**, no new rule. In the relevance inventory `INSTRUCTION_FROM_TOOL_RESULT` keeps `AML.T0080.000` as its primary mapping and maps to `AML.T0110.002` (AI Agent Tool Poisoning: Runtime Response) as a secondary technique; `MCP_TOOL_POISONING` (instruction content in an MCP result, `AML.T0099`) is the other runtime-response detection. The linked chain `CHAIN_TOOL_RESPONSE_TO_SECRET_EXFIL` carries T0110.002. | — |
| AGENT_AUTONOMOUS_RECON_SEQUENCE | `AGENT_CONFIG_DISCOVERY`, `NETWORK_PORT_SCAN`, `SENSITIVE_FILE_READ`, `ENV_SECRET_ECHO` (one command each) | **NEW**: none of them looks at breadth across resource kinds without an instruction. Their classifiers are reused. | `AGENT_AUTONOMOUS_RECON_SEQUENCE` |
| AGENT_ADAPTIVE_ATTACK_SEQUENCE | `AGENT_UNEXPECTED_AUTONOMOUS_RETRY` (same or near-identical action after a refusal) | **NEW**: a *different* method toward the *same* target. Any pair the retry rule calls the same is skipped, so the two never fire on one pair. | `AGENT_ADAPTIVE_ATTACK_SEQUENCE` |
| AGENT_DELEGATION_SCOPE_EXPANSION | `ORPHAN_AGENT`, `UNEXPECTED_TASK`, `AGENT_PERMISSION_BOUNDARY_CROSSING` (deny rules), `NESTED_AGENT_PERMISSION_BYPASS` | **NEW**: nothing compared a subagent's calls with its own definition's `tools:` list or with the parent's working directory. | `AGENT_DELEGATION_SCOPE_EXPANSION` |
| AGENT_RESOURCE_EXHAUSTION | `AGENT_SPAWN_EXPLOSION` (subagent count per session) | **NEW rule, not an extension**: a tool-call loop or call rate is a different question from fan-out, and the spawn rule lives in three code paths (batch, stream, live) that would all change. Spawn counts stay with `AGENT_SPAWN_EXPLOSION`. | `AGENT_RESOURCE_EXHAUSTION` |
| AGENT_MULTIMODAL_TRIGGER_CHAIN | none | **NEW**, LOW/MEDIUM | `AGENT_MULTIMODAL_TRIGGER_CHAIN` |
| AGENT_SHARED_ARTIFACT_POISONING | `INSTRUCTION_WRITTEN_BY_SUBAGENT` (the write only) | **dropped as a rule**; a chain owns it, because the question is write → another agent reads → acts | `CHAIN_SHARED_MEMORY_TO_SUBAGENT` |
| AGENT_BROWSER_SESSION_ABUSE | `BROWSER_CREDENTIAL_ACCESS` | **dropped as a rule**; a chain owns it (credential store read → authenticated account action) | `CHAIN_BROWSER_TOKEN_TO_ACCOUNT_ACTION` |
| AGENT_CROSS_HOST_ACTIVITY | none | **NEW, cross-case**: one case cannot see a second host | `AGENT_CROSS_HOST_ACTIVITY` (`correlate-cases --graph`) |
| CHAIN_ACTION_TO_AUDIT_DISABLE | `CHAIN_ACTION_THEN_LOG_TAMPER` | **DUPLICATE, dropped** | — |
| PERMISSION_EXPANSION_TO_CLOUD_CHANGE | `CHAIN_PERMISSION_ESCALATION_TO_IMPACT` | **EXTENDS** that chain with cloud IAM grants and cloud CLI mutations under the same ID | — |

## What the rules read

| Field / source | Read by | When empty |
|---|---|---|
| `arg_keys` | MCP_ARGUMENT_BEHAVIOR_MISMATCH | schema half silent |
| `safe_args` (path-like values only) | MCP_ARGUMENT_BEHAVIOR_MISMATCH | path link not attempted |
| `parent_tool_call_id`, `tool_call_id` | MCP_ARGUMENT_BEHAVIOR_MISMATCH | id link not attempted |
| `parent_tool_call_id` | AGENT_DELEGATION_SCOPE_EXPANSION | falls back to the spawn record (`agent_spawn.task_id` = subagent id) |
| `tool_def_digest` | MCP_ARGUMENT_BEHAVIOR_MISMATCH, MCP_TOOL_IDENTITY_DRIFT | name match (LOW) / no digest drift |
| `mcp_server_version` | MCP_TOOL_IDENTITY_DRIFT | no version drift |
| `permission_mode`, `permission_from` | AGENT_PERMISSION_STATE_DRIFT, AGENT_UNAUTHORIZED_RESOURCE_CHANGE | silent |
| `approval_state` | AGENT_PERMISSION_STATE_DRIFT; AGENT_ADAPTIVE_ATTACK_SEQUENCE (`denied`) | only prompts and approved plan exits count / falls back to refusal text |
| `result_status` (`denied`/`error`) | AGENT_ADAPTIVE_ATTACK_SEQUENCE | falls back to refusal text and access-control error text |
| `args_digest` | AGENT_RESOURCE_EXHAUSTION | only shell calls (exact command line) are compared; other tools are not keyed |
| `input_modality` (`image`/`audio`/`document`) | AGENT_MULTIMODAL_TRIGGER_CHAIN | **no finding** |
| `safe_args.subagent_type` / `safe_args.agent_type` on the spawn call | AGENT_DELEGATION_SCOPE_EXPANSION (tools) | tool-list comparison skipped |
| `safe_args.path`/`file_path`/`url`/`host`/`resource_id`, `network_destination`, `resource_id` | AGENT_ADAPTIVE_ATTACK_SEQUENCE (targets) | targets come from `file` and the command line only |
| `command`, `file`, `cwd`, `tool`, `mcp_server`/`mcp_tool` | the P1/P2 rules | that call is not classified |
| refusal text in a tool result, `result: error` | AGENT_ADAPTIVE_ATTACK_SEQUENCE | as v4 |
| cached MCP tool declarations | MCP_ARGUMENT_BEHAVIOR_MISMATCH | silent |
| sealed transcript line of the call | AGENT_CREDENTIAL_TO_EXTERNAL_TOOL | silent |
| collected `.claude/agents/*.md` (`claude.agents`) and plugin `agents/*.md` (`claude.plugins`) front matter: `name`, `tools`, `disallowedTools` | AGENT_DELEGATION_SCOPE_EXPANSION | no comparison |
| collected settings `permissions.additionalDirectories` | AGENT_DELEGATION_SCOPE_EXPANSION (paths) | only the parent cwd counts as in scope |
| Codex agent configuration | — | **not read**: Codex subagents get the path check only |
| project-level `.claude/agents` inside repositories | — | not collected |
| endpoint telemetry | not read by these rules, except as the corroboration that lifts AGENT_AUTONOMOUS_RECON_SEQUENCE to HIGH | — |

## P0 rules

### MCP_ARGUMENT_BEHAVIOR_MISMATCH
- **Question:** did an MCP call do something its tool's declaration says it does not?
- **Logic:** the call's tool declaration is resolved from the declarations clients cache in their configuration and state files (`product_config`, `product_state`, `debug_logs`, `managed_config`; ≤ 8 MiB each, ≤ 4096 declarations): by the `tool_def_digest` the call recorded (only that one; a recorded digest that matches no captured declaration means the captured one was not in force, and the rule stays silent), otherwise by tool name when exactly one distinct declaration of that name was captured. Then either (a) `arg_keys` holds names the input schema's `properties` does not declare (skipped when the schema declares none, or sets `additionalProperties` to true or a schema), or (b) the tool is annotated `readOnlyHint: true` and a write, delete, network send or state-changing command was observed inside the same call, or annotated `destructiveHint: false` and a delete was observed. "Inside the same call" means an event linked to the call by its id (`parent_tool_call_id`, or a non-call/result record carrying the same `tool_call_id`), or an event on a path named in the call's `safe_args`, recorded between the call and its result. Without a recorded result the path link is not attempted.
- **Evidence needed:** a captured tool declaration; `arg_keys` for (a); an effect event for (b).
- **Confidence:** HIGH for an id-linked effect under a digest-matched declaration; MEDIUM for a digest-matched declaration otherwise; LOW when the declaration was matched by name only.
- **Limits:** a mismatch is not compromise. Annotations are hints the server author writes, schemas go stale across upgrades, and clients add bookkeeping arguments. Argument values are never read.

### MCP_TOOL_IDENTITY_DRIFT
- **Question:** did the code answering calls under one configured MCP server name change during the case?
- **Logic:** per configured server name, the distinct `mcp_server_version` values recorded on its events; per server and tool, the distinct `tool_def_digest` values (case- and `sha256:`-prefix-insensitive). Two or more distinct values raise one finding per server (version) or per tool (digest). At most 8 values per key and 4096 keys are tracked.
- **Evidence needed:** the version or digest recorded on at least two events.
- **Confidence:** HIGH when every value was first seen inside one session; MEDIUM across sessions.
- **Limits:** an owner's upgrade, or an unpinned `npx`/`uvx` launch picking up a new release between sessions, produces the same drift. The definitions behind the digests are not compared here; `MCP_TOOL_DEFINITION_CHANGED` does that against a baseline.

### AGENT_PERMISSION_STATE_DRIFT
- **Question:** did the permission mode widen mid-session with no recorded approval?
- **Logic:** per agent, in recorded order. A change is an event with `permission_from` and `permission_mode` (explicit), or a `permission_mode` that differs from the previous one recorded (inferred). Widening uses the ranking `plan < default < acceptEdits = auto`; unranked modes never count, and moves into `bypassPermissions` are left to `AGENT_TOOL_PERMISSION_ESCALATION`. The change is reported when none of these is recorded between the last line in the old mode and the change: a person's prompt (client-written lines such as `[Request interrupted…]` do not count), `approval_state: approved`, or an ExitPlanMode result whose text records the plan as approved. A change event with `approval_state: denied` is not reported. Only a widening above the widest mode the session already held counts: a session that started in a wider mode and steps down, then back up, is not reported; a denied change does not raise that ceiling, and it resets when the agent starts a new session. At most 5 per agent.
- **Evidence needed:** recorded permission modes on transcript lines, or permission_change events.
- **Confidence:** MEDIUM for an explicit change event; LOW when inferred from line modes.
- **Limits:** a missing approval record is not an unauthorized change. A person can switch modes with a key press while the agent works, and only the next line they type records it. Completion of a call is never read as approval.

### AGENT_UNAUTHORIZED_RESOURCE_CHANGE
- **Question:** did the agent change something while the client recorded plan mode?
- **Logic:** per agent, the last recorded `permission_mode` is tracked; an approved ExitPlanMode result clears it. A Write/Edit/MultiEdit/NotebookEdit (or `write_file`/`edit_file`/`apply_patch`) or a non-read-only command, issued while the mode is `plan`, whose result is neither an error nor a refusal, is reported. Writes to the plan file (`.claude/plans/*`) are what plan mode is for and are skipped; MCP calls are skipped because whether a read-only MCP tool may run depends on annotations. A result recording a mode other than `plan` means the mode changed first, and is skipped. At most 20 per agent.
- **Evidence needed:** recorded permission modes and a paired tool result.
- **Confidence:** HIGH when `plan` is recorded on the call or its result; MEDIUM when it comes from an earlier line.
- **Limits:** client versions differ in what plan mode allows, and a late-recorded mode switch makes a legitimate call look like this. Deny-rule crossings are `AGENT_PERMISSION_BOUNDARY_CROSSING`.

### AGENT_CREDENTIAL_TO_EXTERNAL_TOOL
- **Question:** was a credential handed to a tool that runs outside the agent?
- **Logic:** for MCP calls and WebFetch/WebSearch calls with a tool call id, the sealed source line is re-read once however many calls point at it (≤ 4 MiB per line, ≤ 20000 distinct lines, ≤ 64 MiB read and parsed across the rule), and only the object whose `id` / `call_id` / `tool_use_id` is that call id and that carries `input` / `arguments` / `params` is kept. Its bytes are fingerprinted with the `POTENTIAL_SECRET_EXPOSURE` patterns and placeholder rules (the same `SecretFingerprints` used for cross-case correlation), then dropped. The fingerprint is compared with the credential sightings of every collected transcript (the scan `AGENT_CROSS_SESSION_SECRET_REUSE` uses, shared through its memo); a sighting earlier in the case than the call is named as the credential's way in. At most 200 findings. When any of these bounds stops the rule, one INFO finding under the same rule id says how many calls were left unchecked and which bound was hit: no finding for them is missing evidence, not a clean result.
- **Evidence needed:** a readable sealed source line that holds the call. A line that does not parse, or does not hold the call id, gives no finding.
- **Confidence:** HIGH when an earlier sighting exists; MEDIUM otherwise.
- **Limits:** passing a tool the credential it is meant to use is intended use; a credential in the arguments is not proof of exfiltration. Shell commands are out of scope here (command rules and `CHAIN_SECRET_TO_EXFIL`). The finding carries the type and a 64-bit fingerprint, never the value.


## P1/P2 rules


### AGENT_AUTONOMOUS_RECON_SEQUENCE
- **Logic:** per agent, the tool calls between two instructions (a person's prompt that is not a client-written line, or the parent's message to a subagent). A discovery call is classified into resource kinds: `credential` (sensitive paths of `SENSITIVE_FILE_READ` in reads, keychain / secrets-manager / vault / `gh auth token` / `kubectl get secret`), `environment` (`env`, `printenv`, `export -p`, `/proc/*/environ`), `system` (`whoami`, `id`, `uname`, `ps aux`, `/etc/passwd`…), `network` (`ifconfig`, `ip addr`, `netstat`, `nmap`, `dig`, `/etc/hosts`…), `cloud` (`aws … list-/describe-/get-caller-identity`, `gcloud … list`, `az … list/show`, `kubectl get`, metadata endpoints), `scm` (`gh auth status`, `git config --list`), `agent_config` (the `AGENT_CONFIG_DISCOVERY` file set, `claude|codex|gemini mcp list`). Shell commands are classified after quoted prose and heredocs are removed; scratch paths and the tool's own development tree do not count.
- **Thresholds** (named constants): `reconMinActions` = 6 calls, `reconMinKinds` = 3 kinds, inside a sliding `reconWindow` = 10 minutes. One finding per run.
- **Severity:** MEDIUM, confidence MEDIUM. HIGH only when the burst includes credential discovery **and** an independent witness corroborates at least one cited call (evidence state CORROBORATED).
- **Missing evidence:** a trace gap ends the run (the lost line may have been the instruction). Without timestamps, order alone links the run.
- **Limits:** autonomous recon can be legitimate: debugging a toolchain, a cloud task, or an onboarding prompt produces the same burst. The instruction before the run decides.

### AGENT_ADAPTIVE_ATTACK_SEQUENCE
- **Blocked call:** its result is a refusal (user, deny rule, approval not given), `result_status = denied`, `approval_state = denied`, or an error whose text is an access-control decision (`Permission denied`, `Operation not permitted`, `AccessDenied`, `403 Forbidden`, `EACCES`…). Ordinary failures (failing test, missing file) are deliberately not blocks. A rejection that carries the person's own instruction ("To tell you how to proceed, the user said: …") is not a block.
- **Target equality** (exact on kind + normalized key):
  - `file`: cleaned absolute path; a relative path is resolved against the call's recorded `cwd`, and dropped when there is none. Scratch paths and `/dev/*` are not targets.
  - `host`: lower-cased host without port, from URLs (`net/url`, never the userinfo), ssh/scp/nc arguments, `network_destination`, `safe_args.url`/`host`. Loopback is never a target.
  - `cloud`: recorded `resource_id`, an ARN in the command, or an `s3://`/`gs://`/`az://` bucket.
  - `secret`: the secret store a command reads: `keychain`, `aws-secretsmanager`, `aws-ssm`, `vault`, `gcp-secretmanager`, `azure-keyvault[:<vault>]`, `1password`, `kubernetes-secret`.
- **Different method:** the method is the tool; for shell calls the privilege wrapper (`sudo`, `doas`…), the program and, for multi-command CLIs (`aws`, `gcloud`, `az`, `kubectl`, `gh`, `git`, `security`, `vault`, `op`, `docker`…), the operation; MCP calls are `server/tool`. `cat` and `sudo cat` differ; `Write` and `Edit` differ; `security find-generic-password` and `security dump-keychain` differ.
- **Sequence:** same agent, before any new instruction or trace gap, within `adaptiveWindow` = 30 minutes. A blocked change followed only by a read of the same target (checking, not attempting) is skipped.
- **Severity:** HIGH when a policy block (refusal/denial) is followed by a second method that completed; otherwise MEDIUM. Confidence MEDIUM.
- **Limits:** trying another way after an error is also how agents fix legitimate problems. Sequence is not causation.

### AGENT_DELEGATION_SCOPE_EXPANSION
- **Link:** subagent events → spawn call by `parent_tool_call_id`, or by the spawn record naming the subagent id. Agent type: the spawn call's `safe_args.subagent_type` (Codex: `agent_type`). Definition: collected file whose front-matter `name` (or file name) equals the type, from the subagent's own login profile; a plugin agent is `<plugin>:<name>`. Ambiguity resolves to nothing.
- **Shape 1, tools:** the subagent called a tool its definition's `tools:` does not name, or `disallowedTools:` names. `Bash(git diff:*)` names `Bash`; `mcp__server` names every tool of that server; `Task`/`Agent` are aliases. No `tools:` key means the agent inherits all tools: nothing is compared. MEDIUM; HIGH when an out-of-list state-changing call completed. Confidence MEDIUM when the definition file's mtime is before the first such call, LOW otherwise.
- **Shape 2, paths:** the subagent changed files (Write/Edit targets, shell redirects, `tee`, `cp`/`mv` destinations, deletes) outside the parent's recorded `cwd` on the spawn call and outside `permissions.additionalDirectories` of the collected settings of the same profile. Reads and scratch paths are not counted. LOW; MEDIUM when a change completed. Confidence LOW.
- **Limits:** a definition edited after the run, a project-level definition (not collected) of the same name, `--add-dir` directories, and helper tools a client grants implicitly all produce a mismatch. A definition mismatch is not proof the call was unauthorized; outside the cwd is not the same as unauthorized.

### AGENT_RESOURCE_EXHAUSTION
- **Loop:** the same tool with the same arguments (`args_digest`; without a digest the exact whitespace-normalized shell command line) called `loopMinRepeats` = 25 times within `loopWindow` = 10 minutes. A poller sleeping 30 s between checks stays under it.
- **Rate:** more than `rateMaxCalls` = 120 tool calls by one agent within `rateWindow` = 1 minute.
- **Severity:** MEDIUM, one finding per shape per agent.
- **Missing evidence:** calls without a timestamp are not counted; non-shell calls without a digest are not compared.
- **Limits:** a codemod or batch job a person started on purpose runs this fast; a tight poll without sleep matches.

### AGENT_MULTIMODAL_TRIGGER_CHAIN
- **Logic:** an event with `input_modality` image, audio or document enters the turn: a tool result (content the agent fetched), or a prompt that carried only the attachment. The agent's next state-changing call (non-read-only shell, Write/Edit, MCP call, WebFetch, delegation) follows with no text instruction from a person in between. A prompt carrying text and an attachment is an instruction and starts nothing.
- **Severity:** LOW; MEDIUM when the input came from a tool result and the follow-up is a shell command, MCP call or fetch. Confidence LOW. The input's content is not inspected.
- **Missing evidence:** without a recorded `input_modality`, no finding.
- **Limits:** a screenshot of an error followed by a fix is the normal shape. Sequence is not causation.


## Limits, in one place

- **Mismatch is not compromise.** MCP annotations are hints the server author writes, schemas go stale across upgrades, and an owner's upgrade or an unpinned `npx`/`uvx` launch changes a server's identity the same way a rug pull does.
- **Missing approval is not unauthorized.** Most clients do not write down a person saying yes; a key-press mode switch is recorded only on the next line the person types. Completion of a call is never read as approval.
- **Recon and retries can be legitimate.** Debugging, cloud tasks and onboarding prompts produce discovery bursts; trying another way after an error is how agents fix problems.
- **Sequence is not causation.** A follow-up after non-text input, a different method after a block, an out-of-scope call by a subagent are recorded orders, not intent.
- **Silence is not clean.** A rule whose fields are empty, whose bounds were hit (`AGENT_CREDENTIAL_TO_EXTERNAL_TOOL` says so in an INFO finding), or whose input was never collected (Codex agent configuration, project-level agent definitions, client-side fetch logs) produces no finding, and that is missing evidence.
- **Not covered.** One P0 observable ATLAS technique, `AML.T0077` LLM Response Rendering, has a documented exception instead of a rule: the transcript holds the response but not whether the client rendered and fetched an embedded reference. See [atlas-coverage.md](atlas-coverage.md).

## Tests

`internal/detect/agent_v5_test.go` and `internal/detect/agent_v5_p1_test.go`,
all synthetic `schema.Event` values and synthetic packages: positive,
benign twin, missing evidence and hostile input for every rule,
evidence-state assertions (OBSERVED, CORROBORATED escalation), work-bound
tests, a deterministic-output test (repeat runs and reversed input order
give byte-identical JSON), and a mapping test (catalog entry, valid ATLAS
ID, checked active ATT&CK v20.0 ID, limits text present). The benign
corpus (`internal/corpus`) stays at zero false positives. These are
synthetic fixtures: they show the rules do what this page says, not how
often they fire on real evidence.
