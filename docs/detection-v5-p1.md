# v5 detections: P1/P2 agent-behaviour rules

Five rules, all in `internal/detect/agent_v5_p1.go`, run from
`RunAgentRules` over the decoded events of a package. They are deterministic,
read no network, and copy no raw arguments, results or prompts into findings:
they cite evidence references, recorded digests and normalized targets
(paths, hosts, resource IDs, secret-store names).

None of them states an intent. Autonomous discovery can be legitimate. A
sequence is not causation. A definition that omits a tool is not proof the
call was unauthorized when it ran. A missing approval record is not an
unauthorized action. A field the parser did not fill is never read as clean:
it produces no finding, or a lower confidence, and the limits below say which.

## Dedupe verdicts

| Spec capability | Existing coverage read first | Verdict | Shipped as |
|---|---|---|---|
| AGENT_AUTONOMOUS_RECON_SEQUENCE | `AGENT_CONFIG_DISCOVERY`, `NETWORK_PORT_SCAN`, `SENSITIVE_FILE_READ`, `ENV_SECRET_ECHO` (one command each) | **NEW**: none of them looks at breadth across resource kinds without an instruction. Their classifiers are reused. | `AGENT_AUTONOMOUS_RECON_SEQUENCE` |
| AGENT_ADAPTIVE_ATTACK_SEQUENCE | `AGENT_UNEXPECTED_AUTONOMOUS_RETRY` (same or near-identical action after a refusal) | **NEW**: a *different* method toward the *same* target. Any pair the retry rule calls the same is skipped, so the two never fire on one pair. | `AGENT_ADAPTIVE_ATTACK_SEQUENCE` |
| AGENT_DELEGATION_SCOPE_EXPANSION | `ORPHAN_AGENT`, `UNEXPECTED_TASK`, `AGENT_PERMISSION_BOUNDARY_CROSSING` (deny rules), `NESTED_AGENT_PERMISSION_BYPASS` | **NEW**: nothing compared a subagent's calls with its own definition's `tools:` list or with the parent's working directory. | `AGENT_DELEGATION_SCOPE_EXPANSION` |
| AGENT_RESOURCE_EXHAUSTION | `AGENT_SPAWN_EXPLOSION` (subagent count per session) | **NEW rule, not an extension**: a tool-call loop or call rate is a different question from fan-out, and the spawn rule lives in three code paths (batch, stream, live) that would all change. Spawn counts stay with `AGENT_SPAWN_EXPLOSION`. | `AGENT_RESOURCE_EXHAUSTION` |
| AGENT_MULTIMODAL_TRIGGER_CHAIN | none | **NEW**, LOW/MEDIUM | `AGENT_MULTIMODAL_TRIGGER_CHAIN` |
| AGENT_SHARED_ARTIFACT_POISONING, AGENT_BROWSER_SESSION_ABUSE | | dropped as rules; chains own them (workstream E) | — |
| AGENT_CROSS_HOST_ACTIVITY | | cross-case (workstream F) | — |

## Mappings

| Rule | Max severity | ATLAS 2026.09 | ATT&CK v20.0 |
|---|---|---|---|
| AGENT_AUTONOMOUS_RECON_SEQUENCE | HIGH (MEDIUM unless corroborated) | AML.T0116 Autonomous Reconnaissance | T1082 System Information Discovery |
| AGENT_ADAPTIVE_ATTACK_SEQUENCE | HIGH | AML.T0117 Autonomous Attack-Path Adaptation | T1548 Abuse Elevation Control Mechanism |
| AGENT_DELEGATION_SCOPE_EXPANSION | HIGH | AML.T0053 AI Agent Tool Invocation | T1548 Abuse Elevation Control Mechanism |
| AGENT_RESOURCE_EXHAUSTION | MEDIUM | AML.T0034.002 Cost Harvesting: Agentic Resource Consumption | T1496 Resource Hijacking |
| AGENT_MULTIMODAL_TRIGGER_CHAIN | MEDIUM | AML.T0129 Triggers in Multimodal Inputs | T1027 Obfuscated Files or Information |

The plan suggested AML.T0108 for delegation scope. T0108 ("AI Agent") is a
command-and-control technique; a subagent invoking tools outside its grant is
AML.T0053. All ATT&CK IDs are active in v20.0; none is revoked.

## What the rules read

| Field / source | Used by | When empty |
|---|---|---|
| `command`, `file`, `cwd`, `tool`, `mcp_server`/`mcp_tool` | all | that call is not classified |
| refusal text in a tool result, `result: error` | adaptive | as v4 |
| `result_status` (`denied`/`error`), `approval_state` (`denied`) | adaptive | falls back to refusal text and access-control error text |
| `args_digest` | resource exhaustion | only shell calls (exact command line) are compared; other tools are not keyed |
| `input_modality` (`image`/`audio`/`document`) | multimodal | **no finding** |
| `parent_tool_call_id` | delegation | falls back to the spawn record (`agent_spawn.task_id` = subagent id) |
| `safe_args.subagent_type` / `safe_args.agent_type` on the spawn call | delegation (tools) | tool-list comparison skipped |
| `safe_args.path`/`file_path`/`url`/`host`/`resource_id`, `network_destination`, `resource_id` | adaptive (targets) | targets come from `file` and the command line only |
| collected `.claude/agents/*.md` (`claude.agents`) and plugin `agents/*.md` (`claude.plugins`) front matter: `name`, `tools`, `disallowedTools` | delegation | no comparison |
| collected settings `permissions.additionalDirectories` | delegation (paths) | only the parent cwd counts as in scope |
| Codex agent configuration | — | **not read**: Codex subagents get the path check only |
| project-level `.claude/agents` inside repositories | — | not collected |

## Rules

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

## Tests

`internal/detect/agent_v5_p1_test.go`, all synthetic `schema.Event` values:
positive, benign twin, missing evidence and hostile input for every rule,
evidence-state assertions (OBSERVED, CORROBORATED escalation), a
deterministic-output test (repeat runs and reversed input order give
byte-identical JSON), and a mapping test (catalog entry, valid ATLAS ID,
checked active ATT&CK v20.0 ID, limits text present). The benign corpus
(`internal/corpus`) stays at zero false positives.
