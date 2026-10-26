# v4.5 detections

Eighteen detection items were proposed for v4.5. Each was checked against the
full inventory before anything was written: the built-in catalog
(`internal/catalog`, `agentdfir rules list`), the shipped rule packs, the
attack chains ([attack-chains.md](attack-chains.md)), the v4 families
([detection-v4.md](detection-v4.md)), and the rules other v4.5 workstreams
added (Windows, macOS, Linux host-tampering, supply-chain). Items that are
already covered are listed with the rules that cover them and nothing new
was added for them. Everything here is deterministic: no model call, no
network.

## Dedupe verdicts

<!-- v45-proposals:begin -->
| # | Proposed item | Verdict | Shipped as |
|---|---|---|---|
| 1 | Suspicious PowerShell execution by an agent (Windows) | **PARTIAL → NEW (OS side).** The transcript side is `POWERSHELL_ENCODED_OR_REMOTE_EXEC` and `ENCODED_PAYLOAD_EXECUTED` (packs, transcript commands only). Nothing read PowerShell in Windows telemetry: script-block records only corroborated tool calls. | `WIN_AGENT_SUSPICIOUS_POWERSHELL` |
| 2 | Agent execution outside recorded tool calls | **COVERED.** `UNLOGGED_AGENT_ACTIVITY`, `UNLOGGED_AGENT_NETWORK` (endpoint), `ENDPOINT_CONTRADICTED_COMMAND` (the reverse), `MCP_GATEWAY_UNLOGGED_CALL` (MCP). | — |
| 3 | Unexpected privilege changes by an agent-descended process | **NEW** for sudo / su / pkexec / polkit (auth.log, journal, eslogger). Windows: 4648 is already `WIN_AGENT_EXPLICIT_CREDENTIALS`; 4672 names no process and cannot be attributed (reported, not used). | `AGENT_PRIVILEGE_ELEVATION` |
| 4 | Sensitive-data staging, then network | **PARTIAL.** Covered: `AGENT_SENSITIVE_DATA_STAGING`, `CREDENTIAL_DIR_ARCHIVE`, `EVIDENCE_STAGING`, `DATABASE_DUMP`; staging → curl/scp upload is `CHAIN_SECRET_TO_EXFIL` (via `SENSITIVE_FILE_READ`), staging → MCP send is `CHAIN_CROSS_TOOL_EXFIL`. **New:** staging (including the working tree or home archived into a temp dir) → object storage, URL push, paste/webhook: the existing upload predicate never matched `aws s3 cp` or `git push`. | `CHAIN_STAGED_DATA_TO_TRANSFER` |
| 5 | MCP unexpected permission expansion | **COVERED.** `SUPPLY_MCP_TOOL_DRIFT_EXPANSION`, `MCP_TOOL_ADDED`, `MCP_TOOL_DEFINITION_CHANGED`, `MCP_SERVER_CHANGED`, `MCP_AUTO_APPROVE`, `MCP_WILDCARD_TOOL_PERMISSION`, `AGENT_TOOL_PERMISSION_ESCALATION`. | — |
| 6 | MCP tool-output instruction chains | **COVERED.** `CHAIN_MCP_RESULT_TO_PRIVILEGED`, `CHAIN_MCP_RESULT_TO_DESTRUCTIVE`, `CHAIN_CONTEXT_POISON_TO_EXEC`, `CHAIN_INJECTION_TO_PUSH`, `INSTRUCTION_FROM_TOOL_RESULT`. | — |
| 7 | Malicious skill installation | **COVERED.** The write: `AGENT_SELF_MODIFICATION` (`.claude/skills|plugins|agents|commands`), `AGENT_CONFIG_SHELL_WRITE`, `INSTRUCTION_FILE_REMOTE_CONTENT`. The content: `SKILL_HIDDEN_INSTRUCTIONS`, `TOOL_POISONING_INDICATOR`, `PLUGIN_HOOK_EXECUTES_REMOTE`, `PLUGIN_MARKETPLACE_UNTRUSTED`. Reuse: `SUPPLY_FLAGGED_COMPONENT_REUSED`. | — |
| 8 | Extension-hook execution | **COVERED.** Configuration: `REPO_AGENT_HOOK_AUTORUN`, `PLUGIN_HOOK_EXECUTES_REMOTE`, `CONFIG_HOOK_REMOTE_FETCH`. Execution: `supply-chain` re-reads hook records and links them to invocations; `SUPPLY_UNTRUSTED_COMPONENT_BEFORE_HIGH` fires when an untrusted hook ran before a high-severity command. | — |
| 9 | Package-to-agent compromise chain | **PARTIAL → NEW (OS side).** Covered: agent component → command (`SUPPLY_UNTRUSTED_COMPONENT_BEFORE_HIGH`), `PACKAGE_INSTALL_FROM_URL`, `REPO_LIFECYCLE_SCRIPT_RISK`, `NESTED_AGENT_PERMISSION_BYPASS` (when the transcript shows it). **New:** a package install's own scripts launching the agent CLI or writing its configuration, which no transcript records. | `PACKAGE_SCRIPT_TOUCHED_AGENT` |
| 10 | Cross-tool transfer chains | **COVERED.** `CHAIN_CROSS_TOOL_EXFIL`. | — |
| 11 | Cloud-storage staging | **COVERED** as a single act (`CLOUD_STORAGE_UPLOAD`, storage audit logs as a second witness); the staging → bucket sequence is item 4. | part of `CHAIN_STAGED_DATA_TO_TRANSFER` |
| 12 | Repository-based data transfer | **PARTIAL.** Covered: `GIT_REMOTE_ADDED`, `GIT_PUSH_TO_URL`, `GITHUB_EXFIL_REPO_CREATE`, `EGRESS_VIA_TRUSTED_SERVICE`, `CHAIN_INJECTION_TO_PUSH`. **New:** sensitive read → new remote/repo → push. "Large data" is **NOT FEASIBLE**: no byte counts in transcript events. | `CHAIN_SECRET_TO_NEW_REMOTE_PUSH` |
| 13 | Logging disruption | **PARTIAL → NEW (OS side).** Transcript side: `AGENT_AUDIT_COVERAGE_LOSS`, `OS_LOG_TAMPER`, `DISABLE_SECURITY_TOOL`, `WINDOWS_DEFENSE_DISABLE`, `CLOUD_LOGGING_DISABLE`. Event-log-cleared records were a notice with no rule; stop/kill commands seen only by the OS were not read. | `AGENT_LOGGING_DISRUPTED` |
| 14 | Transcript modification | **COVERED.** `SESSION_TAMPERING`, `TRANSCRIPT_REWRITTEN`, `TRANSCRIPT_TRUNCATED`, `TRANSCRIPT_REPLACED`, `JOURNAL_TAMPERED`, `AGENT_SESSION_CLOCK_ANOMALY`, `TIMESTOMP_INDICATOR`. | — |
| 15 | Evidence-source deletion | **PARTIAL → NEW (OS side).** Transcript side: `LOG_DELETION`, `HISTORY_CLEARING`, `OS_LOG_TAMPER`, `CHAIN_ACTION_THEN_LOG_TAMPER`, `TRANSCRIPT_DELETED` (journal). Deletes recorded only by the OS were not read. | `AGENT_EVIDENCE_SOURCE_DELETED` |
| 16 | Multi-agent unauthorized delegation | **COVERED** (v4 family 3): `ORPHAN_AGENT`, `UNEXPECTED_TASK`, `AGENT_SPAWN_EXPLOSION`, `NESTED_AGENT_PERMISSION_BYPASS`, delegation under a deny rule in `AGENT_PERMISSION_BOUNDARY_CROSSING`. | — |
| 17 | Suspicious handoff | **COVERED.** `AI_SESSION_IDENTITY_SWITCH` (one session under two logins), `UNEXPECTED_AGENT_RESUME`, `CROSS_SESSION_MESSAGE`; `reconstruct` lists handoffs. | — |
| 18 | Cross-agent credential reuse | **COVERED.** `AGENT_CROSS_SESSION_SECRET_REUSE` (HIGH when contexts span products or logins). | — |

Implemented: 5 built-in host-witness rules, 2 attack chains. 11 items were already covered.
<!-- v45-proposals:end -->

## Telemetry prerequisites

The host rules live in `internal/correlate/hostrules.go` and run after
endpoint correlation (`analyze --endpoint`, `correlate`). Each declares
what it needs. When that is absent it is **not evaluated**: it emits no
finding, the analysis log says `host rule X not evaluated: <what is
missing>`, and its silence means nothing. A rule never claims an act did
not happen, and no host rule changes a tool call's corroboration state.

"Process lineage" below means process records with parent linkage (Sysmon 1
or Security 4688, auditd EXECVE, eslogger exec, Tetragon process_exec) that
reach an agent binary. Records with no parent pid (auth.log sudo lines,
PowerShell script blocks) are joined to the process record of their own
pid. Auth.log / journal process lines are never lineage input.

| Rule | Needs | Optional | Not evaluated when |
|---|---|---|---|
| `WIN_AGENT_SUSPICIOUS_POWERSHELL` | Windows process telemetry with command lines | 4104 / 4103 (script content) | no Windows process records, even if script blocks exist |
| `AGENT_PRIVILEGE_ELEVATION` | sudo/su/pkexec/polkit records with a target identity, and process lineage | — | either is missing; 4672 alone is named as unusable |
| `AGENT_LOGGING_DISRUPTED` | process lineage, **or** EVTX 1102/104 plus transcripts | eslogger signal events | neither |
| `AGENT_EVIDENCE_SOURCE_DELETED` | process lineage | file delete records | no process lineage |
| `PACKAGE_SCRIPT_TOUCHED_AGENT` | process lineage that includes the install process | file records (config write / login read branch) | no process lineage |

## Rules

### WIN_AGENT_SUSPICIOUS_POWERSHELL
- **Logic:** an agent-descended `powershell`/`pwsh` whose command line has `-EncodedCommand` (any prefix, 16+ base64 characters; the payload is decoded from UTF-16LE and shown, bounded to 4 KiB), a hidden window, or suspicious content; or a 4104/4103 record joined by pid to such a process with suspicious content. Suspicious content: a download (`DownloadString`, `Invoke-WebRequest`, `iwr`, `irm`, `Net.WebClient`) handed to `IEX`/`Invoke-Expression`, `FromBase64String` run through IEX, AMSI bypass strings, `Set-MpPreference -Disable* $true`, `Add-MpPreference -Exclusion*`, `Invoke-Mimikatz`, `Invoke-Shellcode`, `[Reflection.Assembly]::Load`, BITS downloads of executables. `-ExecutionPolicy Bypass` alone is not suspicious.
- **Severity:** HIGH. **MITRE:** T1059.001, ATLAS AML.T0050.
- **False positives:** an agent asked to install Chocolatey or Scoop.

### AGENT_PRIVILEGE_ELEVATION
- **Logic:** a kind-auth record with operation `sudo`, `su`, `pkexec` or `polkit …` whose target identity (PrivTo, or eslogger's `USER=`) differs from the acting user, from a process in the agent's tree. One finding lists up to five changes.
- **Severity:** HIGH when any change was granted; MEDIUM when all were refused. **MITRE:** T1548.003.
- **False positives:** an agent asked to install a system package, using a cached sudo ticket.

### AGENT_LOGGING_DISRUPTED
- **Logic:** each invocation of an agent-descended process is judged on its argv (wrappers such as `sudo`, `env`, `nohup`, `timeout` are unwrapped; `bash -c` scripts are parsed): `systemctl stop|disable|mask|kill` / `service … stop` of a logging unit, `auditctl -D` / `-e 0`, `pkill|killall|taskkill` of a logger, `launchctl unload|bootout|disable|remove` of auditd/logd/syslogd/EDR labels, `log config --mode level:off`, `journalctl --vacuum-*`, `wevtutil cl` / `sl … /e:false`, `auditpol /clear|/remove`, `sysmon -u`, `fltmc unload SysmonDrv`, `sc stop|delete|config` of Sysmon/EventLog, PowerShell `Clear-EventLog` / `Stop-Service EventLog`; an eslogger signal from the agent's tree to a logging process; an EVTX 1102/104 inside an agent session (±2 min). `systemctl status`, `grep auditd`, `launchctl print`, `kill <pid>` (target unknown) do not match.
- **Severity:** HIGH (T1685) when any act is attributed to the agent's tree; MEDIUM (T1685.005) when only a log clear overlaps a session in time.
- **False positives:** logging-pipeline maintenance asked of the agent; an administrator clearing a log during a session.

### AGENT_EVIDENCE_SOURCE_DELETED
- **Logic:** a file delete record, or an `rm`/`unlink`/`shred`/`srm`/`truncate`/`del`/`Remove-Item` invocation, by a process in the agent's tree against: Claude Code, Codex, Gemini, opencode and aider transcripts and history, shell history (bash/zsh/sh/ksh/fish, PowerShell ConsoleHost), `/var/log/audit|auth.log|secure|syslog|messages|journal|wtmp|btmp|lastlog`, `/private/var/log`, the unified-log store, `winevt\Logs\*.evtx`, `.adfir` packages. Each path is canonicalized first: quotes removed, `~` / `$HOME` / `${HOME}` expanded, relative paths resolved against the record's working directory (the root when unknown), duplicate separators and `.`/`..` collapsed (Windows paths too). The agent client's own pruning of old transcripts (`cleanupPeriodDays`) is excluded only when the record's pid resolves, in the process telemetry, to the agent process at the root of the lineage; the record's own executable name is never trusted for this, and auth and signal records are never exempt. Log rotation by non-agent processes does not count.
- **Severity:** HIGH. **MITRE:** T1070.004, ATLAS AML.T0101.

### PACKAGE_SCRIPT_TOUCHED_AGENT
- **Logic:** for each agent CLI launch (process name in the agent-binary list), agent configuration write (settings, hooks, agents, commands, skills, plugins, `.mcp.json`, `.claude.json`, Codex/Gemini/Cursor/opencode/Copilot/aider configs, Claude Desktop config) or agent login read (`.claude/.credentials.json`, `.codex/auth.json`, Gemini oauth, Copilot hosts, opencode auth), walk its ancestors (pid at the record's time, and Tetragon exec_id, 32 hops, cycle-safe) to the nearest package install: `npm|pnpm|cnpm|bun install|i|add|ci|update|rebuild`, `yarn [install|add|upgrade]`, `pip|pip3|pipx install`, `python -m pip install`, `uv add|sync|pip install|tool install`, `poetry|pdm install|add`, `gem install`, `cargo install|build`, `composer install|require|update`, including `node …/npm-cli.js`. The "agent CLI being installed" exemption fails closed: it applies only when the install process's argv is exactly `<pm> install|i|add [-g|--global|-D|--save-dev|-y|--yes|-q|--quiet] <agent-spec>...`, argv[0] is the process's own image, and the package manager is npm, pnpm, yarn, bun, pip, pip3 or pipx (node only through `npm-cli.js` / `yarn.js` / `pnpm.cjs`, python only through `-m pip` / `-m pipx`). Any other option (registry or index overrides, `--@scope:registry`, `--userconfig`, attached values such as `-iURL`, abbreviated long options) makes it an ordinary install. A spec counts only when what follows the name is a plain semver or a dist-tag (`latest`, `next`, `stable`): `npm:` aliases, `file:`, `git+…`, URLs, ranges and PEP 508 `name @ url` / markers do not. Under an exempt install, agent launches without permission-bypass flags and writes inside the package-manager install tree are skipped; agent login reads, configuration writes elsewhere and bypass launches are still reported. One finding per install root, at most 20.
- **Severity:** CRITICAL when an agent is launched with permission checks off (`--dangerously-skip-permissions`, `--yolo`, `-y`, `--trust-all-tools`, `--allow-all-tools`, `--full-auto`, `--dangerously-bypass-approvals-and-sandbox`); otherwise HIGH. **MITRE:** T1195.002, ATLAS AML.T0011.001.
- **False positives:** an MCP-server or plugin installer whose purpose is to write the agent's settings.

### Chains
See [attack-chains.md](attack-chains.md): `CHAIN_STAGED_DATA_TO_TRANSFER` (session, 60 min) and `CHAIN_SECRET_TO_NEW_REMOTE_PUSH` (session, 120 min). Both need transcript shell commands; a session whose earlier part was not collected cannot complete them, and that is a gap, not a negative.

## Corpus fixtures

Every new rule has an attack case, a benign twin and an incomplete-telemetry
case under `internal/corpus/testdata/`, all synthetic and generated by
`internal/corpus/gen_v45_test.go`; see
`internal/corpus/testdata/README-v45-rules.md` for the table and how each
format is written. Incomplete-telemetry cases are benign cases, so a
finding there, including a false `ENDPOINT_CONTRADICTED_COMMAND`
(DISPROVED), fails the build. The benign false-positive budget stays 0.

Unit tests (`internal/correlate/hostrules_test.go`) add hit/miss tables for
each argv parser, the auth.log pid join, refused-only severity, session
overlap for log clears, and hostile input (pid cycles, exec_id cycles,
self-parenting, 1 MiB command lines, nested `sh -c`).

## Not done, and why

- **Windows 4672** carries no process id; it cannot be tied to the agent.
- **Large-data git pushes**: transcript events carry no byte counts.
- **What a push or upload contained**: commands name paths, not contents; both chains say "possible".
- **Package scripts seen only in the transcript**: lifecycle scripts run inside the package manager and are not tool calls; only OS telemetry sees them.
