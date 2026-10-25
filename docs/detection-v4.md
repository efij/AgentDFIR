# v4 detection families

Fifteen detection families were proposed for v4. Each was checked against the
existing rule IDs, rule logic and attack chains before anything was written.
Only families with a genuinely new question, or a measurable extension of an
existing rule, were implemented. Everything here is deterministic: no model
call, no network, no telemetry.

## Dedupe verdicts

<!-- v4-proposals:begin -->
| # | Proposed family | Verdict | Shipped as |
|---|---|---|---|
| 1 | AI_SESSION_IDENTITY_SWITCH | **NEW** (partial). The AI login is attributed per profile directory (`internal/accounts`), so a switch of AI account *inside* one transcript is not observable; one session id recorded under two profiles is, and so is an agent command that switches the cloud or code-hosting identity. | `AI_SESSION_IDENTITY_SWITCH` |
| 2 | AGENT_CROSS_SESSION_SECRET_REUSE | **NEW** within one case. `POTENTIAL_SECRET_EXPOSURE` reports each transcript on its own and never links them. Across cases this is `correlate-cases`' job. | `AGENT_CROSS_SESSION_SECRET_REUSE` |
| 3 | AGENT_UNAUTHORIZED_DELEGATION | **EXTENDS** `ORPHAN_AGENT`, `UNEXPECTED_TASK`, `AGENT_SPAWN_EXPLOSION`, `NESTED_AGENT_PERMISSION_BYPASS`. The one measurable new part, delegation while a deny rule covers `Task`/`Agent`, is folded into family 4. Transcripts do not record delegation approvals separately from other tool approvals. | part of `AGENT_PERMISSION_BOUNDARY_CROSSING` |
| 4 | AGENT_PERMISSION_BOUNDARY_CROSSING | **NEW**. Nothing compared collected deny rules with tool calls that completed. | `AGENT_PERMISSION_BOUNDARY_CROSSING` |
| 5 | MCP_TOOL_OUTPUT_INSTRUCTION_CHAIN | **EXTENDS** `CHAIN_MCP_RESULT_TO_DESTRUCTIVE` (destructive follow-up only), `CHAIN_CONTEXT_POISON_TO_EXEC`, `CHAIN_INJECTION_TO_PUSH`. New chain for the privileged follow-ups (credential read, permission grant, upload). | `CHAIN_MCP_RESULT_TO_PRIVILEGED` |
| 6 | MCP_SCHEMA_BEHAVIOR_DIVERGENCE | **NOT FEASIBLE: no evidence source.** Normalized events never keep MCP call arguments or result bodies (a 200-character summary only), and tool schemas exist only in baselines. The schema side is already `MCP_TOOL_DEFINITION_CHANGED` / `MCP_TOOL_ADDED` (rug-pull fingerprints). | — |
| 7 | AGENT_EXTERNAL_ARTIFACT_EXECUTION | **EXTENDS** `DOWNLOAD_THEN_EXECUTE` (same command line) and `CHAIN_DOWNLOAD_AND_EXECUTE` (any download, then any run). New: the downloaded path and the executed path are the same file across tool calls. `pip install <url>` is `PACKAGE_INSTALL_FROM_URL`; `npx` of a never-seen package needs a package-history baseline and is not implemented. | `AGENT_EXTERNAL_ARTIFACT_EXECUTION` |
| 8 | AGENT_SENSITIVE_DATA_STAGING | **EXTENDS** `CREDENTIAL_DIR_ARCHIVE` (directory archives) and `EVIDENCE_STAGING` (any archive). New: a single credential file encoded or copied into a temp directory. Staging followed by a shell upload is already chained (`SENSITIVE_FILE_READ` fires on the same command, then `CHAIN_SECRET_TO_EXFIL` / `POTENTIAL_DATA_EXFILTRATION`). | `AGENT_SENSITIVE_DATA_STAGING` (pack) |
| 9 | AGENT_CROSS_TOOL_EXFIL_CHAIN | **NEW**. `CHAIN_SECRET_TO_EXFIL` and `POTENTIAL_DATA_EXFILTRATION` only see shell uploads. | `CHAIN_CROSS_TOOL_EXFIL` |
| 10 | AGENT_UNVERIFIED_SUCCESS_CLAIM | **NEW**. CLAIMED is the evidence state of model text, not a rule; nothing compared a success claim with a failed or refused result. | `AGENT_UNVERIFIED_SUCCESS_CLAIM` |
| 11 | AGENT_AUDIT_COVERAGE_LOSS | **EXTENDS** `OS_LOG_TAMPER` (auditctl -D/-e, journald vacuum, wevtutil cl), `DISABLE_SECURITY_TOOL` (auditd, SELinux, Defender realtime), `WINDOWS_DEFENSE_DISABLE`, `CLOUD_LOGGING_DISABLE`, `HISTORY_CLEARING`, `LOG_DELETION`. Removing transcript hooks is a DUPLICATE of `AGENT_SELF_MODIFICATION`. New: logging/EDR agents unloaded or stopped, event logs and audit policy disabled, unified logging silenced, transcript retention set below a week. Missing telemetry alone is never a finding. | `AGENT_AUDIT_COVERAGE_LOSS` (pack) |
| 12 | AGENT_SESSION_CLOCK_ANOMALY | **EXTENDS** `SESSION_TAMPERING` (backward steps over 60 s) and `TIMESTOMP_INDICATOR` (mtime before content). New: records dated after collection, tool results before their call, dates before 2021. | `AGENT_SESSION_CLOCK_ANOMALY` |
| 13 | AGENT_CROSS_HOST_ACTIVITY_CHAIN | **NOT FEASIBLE** inside one case: a case is one host. Cross-host linking belongs to `correlate-cases` (separate v4 workstream). | — |
| 14 | AGENT_TOOL_PERMISSION_ESCALATION | **EXTENDS** `AGENT_SELF_MODIFICATION` (any config write), `PERMISSION_BYPASS_ENABLED` / `PERMISSION_ESCALATION` / `MCP_AUTO_APPROVE` (configuration at rest), `NESTED_AGENT_PERMISSION_BYPASS` (the `--dangerously-skip-permissions` relaunch). New: the recorded permission mode moving to `bypassPermissions` mid-session, and config writes whose *content* is a grant. | `AGENT_TOOL_PERMISSION_ESCALATION` |
| 15 | AGENT_UNEXPECTED_AUTONOMOUS_RETRY | **NEW**. `MCP_GATEWAY_DENIED_CALL` sees gateway refusals only and has no retry logic. | `AGENT_UNEXPECTED_AUTONOMOUS_RETRY` |
| + | permission escalation → impact | **NEW** combination: no earlier chain starts from a permission widening. | `CHAIN_PERMISSION_ESCALATION_TO_IMPACT` |

Implemented: 8 built-in Go rules, 2 rule-pack rules, 3 attack chains. Details: [detection-v4.md](detection-v4.md).
<!-- v4-proposals:end -->

## What the rules read

Two optional fields were added to the normalized events of Claude Code
transcripts; nothing else in the event format changed.

| Source | Read | Notes |
|---|---|---|
| `tool_result.is_error` (Claude Code JSONL) | yes → event `result: "error"` | Present on current builds. Older transcripts without it still match refusals by their text. |
| refusal text in a tool result | yes | "doesn't want to proceed with this tool use" (user), "Permission to use … has been denied" (deny rule), "This command requires approval" / "haven't granted it" / "MCP request blocked" (not approved). |
| `permissionMode` on transcript lines | yes → event `permission_mode` | `default`, `plan`, `acceptEdits`, `auto`, `bypassPermissions`. Unranked values never count as broadening. |
| `permissions.deny` in collected settings | yes | `~/.claude/settings.json`, `settings.local.json` and managed settings, at most 1 MiB each, at most 512 rules. A file that is not JSON contributes no rules (the client refuses it as well). |
| deny `WebFetch(domain:…)` rules | **UNSUPPORTED** | Events do not carry the fetched URL; such rules are skipped, never guessed. |
| project-level `.claude/settings.json` inside repositories | not collected | Only what the collection holds is compared. |
| MCP call arguments / result bodies | not read | Never kept in events; this is why family 6 is not feasible. |
| Codex, Gemini, Cursor transcripts | events only | The refusal, error-flag and permission-mode fields are Claude Code's; the command-shaped rules (identity switch, external artifact, staging, audit loss) work on every product's commands. |

## Rules

Severity is how bad it would be; confidence is how likely it is real. Every
sequence rule says "possible": a transcript records what the agent asked for
and what the client returned, and only a second witness confirms the rest.
No rule here claims a confirmed exfiltration.

### AGENT_UNEXPECTED_AUTONOMOUS_RETRY
- **Logic:** per agent, a state-changing call (non-read-only shell, Write/Edit, MCP, WebFetch, Task/Agent) is refused, and the same tool is called again on the same file, or with the same program and at least half the same words, before any new instruction (a person's prompt that is not a client-written line such as `[Request interrupted…]`, or the parent's message to a subagent).
- **Severity:** MEDIUM; HIGH when the repeat completed (result neither error nor refusal). **Confidence:** HIGH when identical, MEDIUM when similar.
- **MITRE:** ATT&CK T1548 (the approval step is the control being worked around).
- **False positives:** approval given outside the transcript; an agent deliberately re-asking. Failures (a failing test re-run) are not refusals and never match.

### AGENT_PERMISSION_BOUNDARY_CROSSING
- **Logic:** a deny rule from collected settings covers a tool call of the same login profile (managed settings: every Claude profile), and the call's recorded result is neither an error nor a refusal. `Bash(cmd:*)` is a prefix on the whole command or any stage of it; `Bash(… * …)` is a glob; other `Bash(…)` is exact. `Read/Edit(path)` globs match as path suffixes. `Task` and `Agent` cover each other; then the finding says *subagent delegation* (family 3).
- **Severity:** HIGH. **Confidence:** MEDIUM when the settings file's mtime is before the call, LOW otherwise (the rule may have been added later). Never higher: suffix matching is broader than the client's own matching.
- **MITRE:** ATT&CK T1548.
- **False positives:** a rule added after the call; project settings outside the collection.

### AGENT_TOOL_PERMISSION_ESCALATION
- **Logic:** (a) within one session the recorded `permission_mode` moves from a ranked narrower mode to `bypassPermissions`; (b) a shell command writes content that grants permissions (`bypassPermissions`, `"allow":`, `permissions.allow`, `allowedTools`, `alwaysAllow`, `autoApprove`, `enableAllProjectMcpServers`, Codex `approval_policy = never` / `danger-full-access`) to the agent's own configuration, or runs `claude config set|add allowedTools…`.
- **Severity:** (a) MEDIUM, confidence HIGH; (b) HIGH, confidence MEDIUM. **MITRE:** T1562.001, ATLAS AML.T0081.
- **False positives:** a person pressing Shift+Tab on purpose; a person asking the agent to stop prompting for a tool. Writes through the Write/Edit tools are `AGENT_SELF_MODIFICATION`'s; their content is not in the events.

### AGENT_UNVERIFIED_SUCCESS_CLAIM
- **Logic:** per agent, a state-changing call returns an error or a refusal, and the next event of that agent is a model message claiming success ("successfully", "has been pushed", "all tests pass", "Done…") with no admission of trouble ("failed", "couldn't", "however", "but"…) and no tool call in between.
- **Severity:** MEDIUM, confidence MEDIUM, evidence state CLAIMED. No MITRE technique fits; none is set.
- **False positives:** the success refers to an earlier step; a tool that flags warnings as errors.

### AGENT_EXTERNAL_ARTIFACT_EXECUTION
- **Logic:** per session, a curl/wget call saves a file (`-o`, `--output`, `-O`, wget's URL basename; not `-` or `/dev/null`), and a later call within 60 minutes runs it (`./x`, `/abs/x`, `bash|sh|python|node|perl|ruby|php x`, `chmod +x x`). Absolute paths compare exactly, relative ones by file name. One finding per download.
- **Severity:** HIGH, confidence HIGH. **MITRE:** T1105, ATLAS AML.T0011.001.
- **False positives:** toolchain bootstraps (rustup, nvm) fetched and run on purpose.

### AI_SESSION_IDENTITY_SWITCH
- **Logic:** (a) one session id whose records sit under two or more login profiles (`accounts.Key`); (b) an agent command that switches identity: `gh auth switch`, `gh auth login --with-token`, `aws sts assume-role*`, `gcloud config set account`, `gcloud auth activate-service-account`, `az login --service-principal`, `az account set`, `export AWS_PROFILE=` / `CLOUDSDK_CORE_ACCOUNT=` / `GOOGLE_APPLICATION_CREDENTIALS=`, `GH_TOKEN=$(gh auth token --user …)`.
- **Severity:** (a) MEDIUM, (b) LOW; confidence MEDIUM. **MITRE:** T1078.
- **False positives:** a person's second login used on purpose; profile directories renamed or synced. `gh auth status`, `aws sts get-caller-identity` and `git config user.email` do not match.

### AGENT_SESSION_CLOCK_ANOMALY
- **Logic:** per transcript artifact: records dated more than 5 minutes after the artifact's recorded collection time, tool results stamped more than one minute before their call, or records dated before 2021. Database-backed stores are skipped (their order is not append order).
- **Severity:** MEDIUM, confidence MEDIUM. **MITRE:** T1565.001.
- **False positives:** a wrong host clock (VM resume, CMOS battery); compare with the case clock data.

### AGENT_CROSS_SESSION_SECRET_REUSE
- **Logic:** every transcript is streamed with the `POTENTIAL_SECRET_EXPOSURE` credential patterns (placeholders and bare key headers excluded); each value is reduced to the first 16 hex digits of its SHA-256 and the value is discarded. A fingerprint seen in two or more contexts (product + login profile + project, the project being the transcript's recorded working directory) is one finding. Results are memoized per artifact like the other content scans.
- **Severity:** MEDIUM; HIGH when the contexts span products or logins. **Confidence:** MEDIUM. **MITRE:** T1552, ATLAS AML.T0057.
- **False positives:** a shared development token used in several projects on purpose. Two sessions of one project (a resumed conversation) are one context and never match.

### AGENT_SENSITIVE_DATA_STAGING (rule pack)
- **Logic:** command (shell scope) that base64/xxd/gzip/openssl-encodes, `cat`s or copies a credential file (`.ssh/id_*`, `.aws/credentials`, gcloud/azure credentials, `.kube/config`, `.docker/config.json`, `.netrc`, `.npmrc`, `.pypirc`, `.git-credentials`, `.env`, `.claude/.credentials.json`, `.codex/auth.json`, `/etc/shadow`, `.gnupg/`) into `/tmp`, `/var/tmp`, `/dev/shm`, `/private/tmp`, `$TMPDIR` or `%TEMP%`.
- **Severity:** HIGH. **MITRE:** T1074.001, ATLAS AML.T0055. **Sigma:** exported.

### AGENT_AUDIT_COVERAGE_LOSS (rule pack)
- **Logic:** `cleanupPeriodDays` set to 0–6 (in a command, or `claude config set`), `launchctl unload|bootout|disable|remove` of auditd/osquery/EDR/syslog daemons, `systemctl stop|disable|mask` of syslog, journald, osquery and EDR/log-shipper units, `Stop-Service`/`sc stop` of EventLog/Sysmon, `wevtutil sl … /e:false`, `auditpol /clear|/remove`, `log config --mode level:off`. Lines that are `git commit/log/show/tag` are excluded (prose about the commands).
- **Severity:** HIGH. **MITRE:** T1562.001. **Sigma:** exported (the exclusion is not part of the Sigma rule). A settings file that already *holds* a low `cleanupPeriodDays` is not reported: that is configuration, not the act.

### Chains
See [attack-chains.md](attack-chains.md): `CHAIN_CROSS_TOOL_EXFIL`, `CHAIN_MCP_RESULT_TO_PRIVILEGED`, `CHAIN_PERMISSION_ESCALATION_TO_IMPACT`. Chain steps gained one optional predicate, `tool_regex`, matched against the tool name (MCP tools are named `mcp__<server>__<tool>`).

## Corpus fixtures

Every rule above has an attack case that must fire and a benign twin that
must not, under `internal/corpus/testdata/` (synthetic transcripts, not copied
from real machines). The credential used by the reuse cases is a JWT-shaped
string assembled from harmless parts: no provider prefix, no placeholder
words, nothing that reads as a live key.

| Rule | Attack case | Benign twin |
|---|---|---|
| AGENT_UNEXPECTED_AUTONOMOUS_RETRY | `refused-then-retried` | `refusal-then-new-instruction` |
| AGENT_UNVERIFIED_SUCCESS_CLAIM | `failed-push-claimed-success` | `failure-acknowledged-then-fixed` |
| AGENT_EXTERNAL_ARTIFACT_EXECUTION | `download-then-run-later` | `download-not-executed` |
| AGENT_PERMISSION_BOUNDARY_CROSSING | `deny-rule-crossed` | `deny-rule-held` |
| AGENT_TOOL_PERMISSION_ESCALATION, CHAIN_PERMISSION_ESCALATION_TO_IMPACT | `permission-escalation-then-destroy` | `permission-mode-steady-or-narrowed` |
| AI_SESSION_IDENTITY_SWITCH | `identity-switch-in-session` | `identity-inspected-not-switched` |
| AGENT_SESSION_CLOCK_ANOMALY | `impossible-transcript-clock` | `small-clock-jitter` |
| AGENT_CROSS_SESSION_SECRET_REUSE | `secret-reused-across-projects` | `secret-within-one-project` |
| AGENT_SENSITIVE_DATA_STAGING, CHAIN_CROSS_TOOL_EXFIL | `staged-key-sent-via-mcp` | `build-artifact-then-slack` |
| AGENT_AUDIT_COVERAGE_LOSS | `telemetry-turned-off` | `telemetry-inspected` |
| CHAIN_MCP_RESULT_TO_PRIVILEGED | `mcp-instructions-then-credential-read` | `mcp-ticket-then-push` |

Unit tests (`internal/detect/agent_v4_test.go`, `internal/chain/v4_chains_test.go`,
`internal/rulepack/v4_rules_test.go`) add hit/miss tables, deny-rule parsing
and hostile input (garbage timestamps, missing ids, oversized commands).

## Not done, and why

- **MCP schema/behaviour divergence** needs call arguments, which events do not keep.
- **Cross-host chains** need more than one case (`correlate-cases`).
- **`npx` of a never-seen package** needs a per-machine package history.
- **Delegation approvals** are not recorded separately from other approvals in any transcript format read here.
- **Deny rules for WebFetch domains** are UNSUPPORTED (no URL in the events).
