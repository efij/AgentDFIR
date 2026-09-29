# Changelog

All notable changes to AgentDFIR are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Lessons from the 2026 agent-driven cloud attacks: Microsoft's Storm-3168,
Sysdig's JADEPUFFER and Sygnia's AI-assisted intrusion.

Repeat runs are a true delta, every round is signed and proven before the
next is added, and a run never chokes the machine.

### Added
- **Cloud audit logs as a second witness.** `--endpoint` (on `analyze`,
  `run` and `correlate`) now reads AWS CloudTrail, Azure Activity Log and
  GCP Cloud Audit Log exports as JSON, a JSON array or JSON Lines, sniffed
  per file (`--format cloud-audit` to force it). An agent's `az`, `aws` or
  `gcloud` command becomes CORROBORATED when the control plane recorded the
  same operation within ±2 minutes, on the same resource when the command
  names one; a call the cloud refused is noted with its error. A cloud log
  never contradicts a command, since the export may cover another account,
  and it never counts as host telemetry. Files only, no cloud API calls.
- **`CLOUD_DESTRUCTIVE_BURST`** (HIGH): the cloud audit log shows one
  identity deleting 10+ distinct resources within 10 minutes. It says
  whether any of the deletes match commands in the collected transcripts.
- **`CLOUD_RESOURCE_DELETION`** (HIGH): the agent deletes storage accounts
  or buckets, key vaults, secrets, KMS keys, apps, resource groups, VMs,
  clusters, stacks or projects through `az`, `aws`, `gcloud` or `gsutil`.
- **`CLOUD_RECOVERY_PROTECTION_REMOVED`** (CRITICAL): the agent deletes a
  resource lock, disables backup protection, deletes a backup vault,
  recovery point or snapshot, suspends bucket versioning or turns off
  deletion protection.
- **Guardrail pack `cloud-destructive`** (ask, friction 1): the agent must
  ask before those commands, before destroying databases and before
  stopping cloud logging. Claude Code and Codex. Read and list commands are
  never asked.
- **Incident `storm-3168-jadepuffer`** for `agentdfir hunt`: the published
  attacker addresses, and Langflow below 1.3.0 (CVE-2025-3248, the entry
  point) at low confidence. Package indicators gain `below_version` for
  vulnerable-version ranges. The ransom note's Bitcoin address is left out
  on purpose: it is the example address from the Bitcoin docs.
- **Authority-claim phrases** ("this is an approved red team exercise",
  "you are authorized to bypass" …) count as injection in tool and MCP
  results, fetched content, instruction files, tool definitions, MCP
  configs and repository files. Never in the person's own prompts, where a
  pen-tester writes exactly that.
- Secret formats `ALIBABA_ACCESS_KEY` (`LTAI…`) and `TENCENT_SECRET_ID`
  (`AKID…`).
- **Every round is signed** with a per-machine key (`--sign` for another
  key, `--no-sign` to opt out), and its digest is recorded in an anchor
  log outside the case and printed. Before a round is added, the previous
  signature, the anchor and the sealed files are verified
  (`--verify-prior full` also re-hashes every blob); a failure is recorded
  in the round (`prior_integrity: FAILED`) and the run exits 4.
- Each round archives the previous signature to `seals/SEAL.sig.<n>` and
  records `prev_seal_sha256`, `signer` and `prior_integrity`.
- The reused analysis overlay is integrity-checked: segment and event
  hashes, and a MAC over its state under the machine key. Anything that
  does not match is rebuilt from the sealed evidence.

### Changed
- `CLOUD_CREDENTIAL_EXPORT` also covers listing storage account keys and
  connection strings, Cosmos DB keys, service-principal credential resets
  and GCS HMAC keys.
- The Protect tab's steps for a leaked secret say that deleting it from an
  issue, pull request or commit does not remove it from edit history,
  forks or caches.
- **The content scans remember each artifact's result** (rule packs over
  raw transcripts and configs; credential, injection and invisible-character
  scans), keyed on its content address, its record, the analysis code and
  the rules, and authenticated with the machine key. An unchanged
  transcript is not scanned again. Rule-pack regexes are also prefiltered on
  the literals every match must contain (case-folded exactly as `(?i)`
  folds), and each event's match subject is prepared once instead of once
  per rule. On a real case (359,000 events) a repeat analysis went from
  111 s to 42 s, and a repeat `run` from about 5 minutes to under 1.
- **Repeat `run` recomputes only what changed.** Cached parses and stored
  results are keyed on a fingerprint of the parsing and analysis code, not
  on the release number, so a release that changes no parser or rule no
  longer re-parses and re-analyzes every case. Staleness is decided on the
  content of the evidence, not the manifest's modification time: a round
  that only carried files forward rebuilds nothing, and when neither the
  evidence nor the code changed, `run` reuses the stored results outright
  (`--reanalyze` forces it).
  The first run after upgrading re-parses once: caches written by earlier
  versions carry no fingerprint and no segment hashes, so they are not
  trusted.
- The host-witness step at collection time refreshes the per-artifact
  overlay instead of fully parsing every transcript; analysis then finds
  the overlay current. Analysis decodes the events once instead of seven
  times, and writes annotated events once.
- **One progress display for the whole run**: an overall bar, elapsed time,
  and a time remaining predicted from this machine's own history
  (`perf.jsonl` in the home), corrected by today's pace and counting down
  steadily. It never reads 0:00 while work remains.
- **Gentle by default** (`--priority gentle|background|normal`): lowered
  CPU priority, at most half the CPUs, a soft heap limit
  (`--max-memory-mb`), reads capped at 200 MB/s (`--max-read-mbps`), a
  pause while the machine is under load (`--no-governor`), and a free-disk
  floor it never crosses (`--min-free-gb`; exit 5 when a round cannot fit).

### Fixed
- Re-running analysis with the same endpoint log appended the same
  corroboration note to an event again on every run.
- **Every other repeat run re-read the whole profile.** A carried-forward
  record dropped the inode and change time it was judged unchanged on, so
  the next round had nothing to compare and re-read those files — 2.7 GB on
  a real machine, on alternate runs.
- **Every analysis re-parsed the whole case** once any `node_modules`/`.git`
  records existed: retiring them from the scan set counted every excluded
  record (and each round's own policy placeholders) as newly retired and
  forced a full re-parse. It now counts only newly retired content, and
  retiring is an incremental rebuild.
- **An interrupted round no longer damages the case.** A round that never
  sealed (an error, Ctrl+C, a crash) left records in both hash chains that
  no seal covered, so the case stopped verifying. Rounds are now
  transactional: an unsealed round is rolled back to the last seal and the
  next round records it as `round_aborted`.
- `run --sign` signed before sealing, so its signature covered the previous
  round's `SHA256SUMS` and never verified.
- The collect-step time remaining collapsed to about zero on repeat runs:
  carried-forward files counted as bytes read.

## [3.1.2] — 2026-09-29

### Changed
- Explorer **Findings are newest first.** Severity tiers stay (Act now,
  Serious, Worth a look, Minor), but inside each tier the kind of finding
  seen most recently comes first, and inside a kind the latest occurrence
  is shown first. Findings with no timestamp (configuration, file content)
  follow the dated ones.

## [3.1.1] — 2026-09-29

Precision pass on a real machine's case (2,495 findings): CRITICAL 19 → 14,
HIGH 403 → 167, MEDIUM 942 → 557. Every change removes a shape that was never
the attack; the attack corpus, the benign corpus (budget 0) and every
`simulate` scenario still produce their rules.

### Fixed
- **Heredoc bodies are data.** Pack command rules no longer match text inside
  `cat > f <<'EOF'` / `python3 - <<'EOF'` bodies (edit scripts, tests, plans):
  most HIGH false positives — `REVERSE_SHELL`, `AGENT_CONFIG_SHELL_WRITE`,
  credential-store and cloud rules — came from files being written. The
  same applies to sensitive-path detection.
- `.env.example` / `.sample` / `.template` / `.dist` are not secrets.
- `CHAIN_SECRET_TO_EXFIL` requires an upload-shaped step, not any outbound
  request (reading `.env` then fetching a README was CRITICAL).
- `CHAIN_DOWNLOAD_AND_EXECUTE` needs a download saved to a file and a file
  executed (`curl -sI`, `-o /dev/null` probes and `python3 -c` no longer
  count): 165 → 34.
- `INSTRUCTION_FROM_TOOL_RESULT` is HIGH only when the preceding tool result
  came from outside the machine (web, search, MCP, a subagent); the agent
  writing memory after its own local command is LOW context (101 → 3 HIGH).
- `REVERSE_SHELL` (python) needs the socket wired to a shell, not a port
  check; `LD_PRELOAD_INJECT` skips Apple's debug allocators and sanitizer
  runtimes; `CURL_FILE_UPLOAD` skips request bodies in the session's own
  scratch directory; `TOOL_POISONING_INDICATOR` skips source, test and
  bug-report files inside plugin trees.
- `DESTRUCTIVE_COMMAND` recognises scratch paths behind a variable
  (`S=…/scratchpad; rm -rf $S/x` is INFO); `UNEXPECTED_TASK` (nested
  subagents, now routine) is LOW.
- Rule packs gain `match.exclude_regex`; community pack v5.

## [3.1.0] — 2026-09-29

Guardrails can be applied and undone from the explorer, the Windows
one-liner works from Command Prompt, and Cmd/Ctrl+K works on every
keyboard layout.

### Added
- **Protect tab applies guardrails from the page.** On the machine the case
  came from, *Preview changes* shows every file, what goes into it and the
  exact diff; *Apply* makes the changes; every applied change is listed
  with *Undo*, plus *Undo all*. Same backup, hash-chained ledger and
  byte-exact revert as `agentdfir mitigate`. Writes go through
  `POST /api/mitigations/{plan,apply,revert}`: same-origin only (custom
  header, `Sec-Fetch-Site`, loopback `Origin`), a per-process token the
  page gets from `GET /api/mitigations`, and refused for a case collected
  on another computer, where the tab still builds the terminal command.

### Fixed
- Windows install one-liner only worked in PowerShell: pasted into Command
  Prompt, `$env:…; irm … | iex` fails ("'irm' is not recognized"), and the
  macOS/Linux `curl … | sh` line fails too (Windows has `curl` but no `sh`).
  The documented Windows line is now `powershell -NoProfile -ExecutionPolicy
  Bypass -Command "[Environment]::SetEnvironmentVariable('AGENTDFIR_RUN','1');
  irm …/install.ps1 | iex"` — no `$`, so it means the same thing in cmd.exe,
  Windows PowerShell 5.1 and PowerShell 7; CI pastes it into all three. The
  site's Chocolatey command no longer uses `;` (not a separator in cmd).
- Explorer: **Cmd/Ctrl+K did nothing on non-Latin keyboard layouts**
  (Hebrew, Russian, Greek…), and neither did `j`/`k` in Activity: the
  handler compared `e.key` to `"k"`. Shortcuts now match the physical key
  (`e.code`). A keydown whose target is not an element no longer throws
  and kills the handler, and the hint reads `Ctrl K` off macOS.

## [3.0.0] — 2026-09-28

Built from the incidents of the last twelve months — the Nx s1ngularity
compromise, Shai-Hulud 1, 2 and the keyv wave, SANDWORM_MODE, postmark-mcp,
codexui-android, Cursor MCPoison, Codex CVE-2025-61260 and branch-name
injection, Replit and PocketOS, and the OpenAI–Hugging Face agent
intrusion. Each capability is tested against a reproduction of the
incident it answers.

### Breaking
- **Module path is now `github.com/efij/AgentDFIR/v3`** (Go semantic import
  versioning). `go install github.com/efij/AgentDFIR/v3/cmd/agentdfir@latest`.
  The `.adfir` package format (0.2) and the event schema version (0.1) are
  unchanged; events gain an optional `command_full` field.
- Command rules now read the full command line (up to 64 KiB) instead of
  the 300-character display copy, so flags and payloads past the cut are
  matched. `NESTED_AGENT_PERMISSION_BYPASS` matches on the command as the
  shell parses it (quoted prose and heredoc bodies — files the agent
  writes — no longer fire it).
- `analyze` gains an incident-IOC step and a monitor-journal check; cases
  re-analyzed with 3.0 can carry `KNOWN_INCIDENT_IOC` and `TRANSCRIPT_*`
  findings that 2.x did not produce.

### Added
- **`agentdfir hunt`** — "was this machine hit by X?" for eight embedded
  incidents (indicators copied from each primary write-up, source per
  incident) plus STIX 2.1 bundles and MISP events (`--iocs`, also on
  `analyze`). Hits are classified by where they were seen — OBSERVED
  (command, file, configured package, lockfile, file on disk, SHA-256),
  SEEN_IN_OUTPUT (shell output), MENTIONED (questions, prose, web pages,
  `grep` arguments, heredocs: never findings) — and low-confidence
  shared-infrastructure indicators are context only. Verdicts are bounded
  by the evidence window: INCONCLUSIVE when the case starts after the
  incident. `--path` walks lockfiles (npm, yarn, pnpm, bun, pip, poetry,
  uv, npm's hidden lockfile), shell rc files, named payload files (hashed)
  and extension directories. Simulated cases say SIMULATED, never HIT.
- **`agentdfir scan-repo`** — checks a repository before an agent opens
  it: hooks, `statusLine`, credential helpers and `env` overrides in
  committed Claude settings; plugin, Cursor and Gemini hooks; VS Code
  `folderOpen` tasks and workspace files; devcontainer host commands;
  project MCP configs through the MCP audit; instruction files (injection
  phrases, invisible Unicode, remote-instruction callouts); install
  scripts launching AI CLIs headless; `.gitattributes` hiding agent config
  from review; git config exec hooks and shell syntax in ref names;
  symlinked, oversized or unparseable agent configs. Text, JSON and SARIF;
  `--fail-on` for CI; `action.yml` (builds from the pinned commit) and a
  pre-commit hook.
- **Offline decoder** (`agentdfir decode`, `internal/decode`) — base64,
  base32, hex, gzip, zlib, bzip2, UTF-16LE and `String.fromCharCode`,
  nested four deep, bounded against bombs. When a command executes decoded
  data every command rule also sees the decoded text;
  `ENCODED_PAYLOAD_EXECUTED` and `ENCODED_EXEC_UNRESOLVED`.
- **`monitor --journal`** and **`agentdfir journal verify [--anchor]`** —
  a hash-chained journal of every transcript append (range, SHA-256,
  running prefix hash, device:inode), sealed every 10 minutes with the
  chain head sent to the system log / stderr / `--journal-anchor`.
  Collected by `run`; analysis reports `TRANSCRIPT_REWRITTEN`,
  `TRANSCRIPT_TRUNCATED`, `TRANSCRIPT_REPLACED`, `JOURNAL_TAMPERED`,
  `TRANSCRIPT_DELETED`, `MONITOR_GAP`.
- **MCP audit** — baselines fingerprint tool definitions (description,
  schema, annotations) and env values: `MCP_TOOL_DEFINITION_CHANGED`,
  `MCP_TOOL_ADDED`; `MCP_PACKAGE_TYPOSQUAT` against widely installed MCP
  servers (npm and PyPI); `npx --package` / `uvx --from` resolved to the
  package actually installed.
- **Detections** — `AI_CLI_HEADLESS_BYPASS` (shell history, repo scripts),
  `HEADLESS_AGENT_SECRET_HUNT` (first prompt of a session only),
  `EGRESS_VIA_TRUSTED_SERVICE` (shorteners, screenshot services,
  serverless edges, blockchain RPC, tunnels; also inside decoded
  payloads), `GITHUB_EXFIL_REPO_CREATE`, and in the community pack (v4)
  `DNS_EXFIL_LABELS` and `CLOUD_DATA_DESTRUCTION`. Cloud-metadata
  detection knows the ECS, Alibaba and integer/hex spellings.
  `AGENT_CREDENTIAL_STORE_ACCESS` covers opencode, Kiro, Amazon Q and
  Windsurf stores. Rule packs gain `match.scope: "no_heredoc"`.
- **`simulate`** — six reproductions: `keyv-hook`, `sandworm-mcp`,
  `s1ngularity`, `mcpoison-rugpull`, `pocketos-wipe`,
  `swarm-antiforensics`; `--scenario list`. Every simulated profile
  carries `.agentdfir-simulated`, collected into the case. An end-to-end
  test runs every scenario through collect → analyze and requires its
  rules.
- Benign corpus cases for the new rules (secret-hunt discussion, web3 RPC
  calls, plain base64 decoding); the false-positive budget stays at zero.

### Fixed
- `MCP_TOOL_DESCRIPTION_POISONING` from cached tool manifests mapped to
  AML.T0053; it now maps to AML.T0110 like the config-declared form.
- `docs/detection-coverage.md` regenerated (172 rules, 28 ATLAS / 69 ATT&CK
  techniques).

- Windows one-liner: `irm …/install.ps1 | iex; agentdfir run` lost its
  `agentdfir run` tail whenever it was split, wrapped or pasted as the script
  body, so the install finished and nothing started. The one-liner is now
  `$env:AGENTDFIR_RUN=1; irm …/install.ps1 | iex`: the installer starts the
  run itself and clears the variable; without it, it prints the next command.

## [2.7.0] — 2026-09-27

Findings now lead somewhere: `agentdfir mitigate` writes guardrails into the
AI agents' own settings so what a case found cannot happen again, and a case
moves to another computer in two commands.

### Added
- **`agentdfir mitigate`** (`internal/mitigate`) — the only command that
  changes files outside a case. Plan first (exit 3 when there is something to
  apply), `--apply` per file or `--yes`, `--status`, `--revert <id>`,
  `--revert-all`, `--export managed`. Eight guardrail packs — `log-protect`
  and `secret-paths` on by default (friction 0), `outbound-upload`,
  `download-exec`, `persistence`, `self-modify`, `no-bypass`, `destructive`
  opt-in — rendered natively per agent: Claude Code `permissions.deny`/`ask`,
  one `PreToolUse` hook and `disableBypassPermissionsMode`; Codex
  `~/.codex/rules/agentdfir.rules` (`forbidden`/`prompt`); Cursor CLI
  `permissions.deny`. Fix-now controls pin `npx pkg@latest` MCP servers to the
  version in the local npx cache (nothing executed or fetched) and clear
  auto-approve lists, across `~/.claude.json` (including per-project servers),
  Cursor, Kiro, Gemini and Claude desktop configs.
- **`agentdfir guard log`** — the log-protect hook. Refuses Bash commands and
  file writes that delete, truncate or overwrite agent transcripts and history;
  Claude memory files are not covered; malformed input is allowed.
- **Safety model**: every file re-read and the change recomputed immediately
  before writing; byte-exact backup; atomic write; key order, number text and
  unknown keys preserved (ordered JSON editor); symlinks, other users' files,
  managed settings and invalid JSON refused; no agent binary executed.
- **Ledger** `~/.agentdfir/mitigations/ledger.jsonl`, hash-chained like the
  custody log; `--status` verifies each change against the file now (in
  place / drifted / file gone / reverted); `--revert` refuses to discard a
  later edit without `--force`. Collected by the next `run`
  (`agentdfir.mitigations` in the Claude manifest).
- **Protect tab** in the explorer (`/api/mitigations`, read-only): findings
  grouped into fix now / prevented / needs a person / not fixable by
  settings, analyst-cleared findings excluded, "N since <date>" once a
  guardrail is in, pack table with level and friction, and the command to run.
  A case from another machine says to run it there.
- **`agentdfir export [<case>]`** — one portable file, `<case>.adfir.tgz`, and
  its SHA-256: sealed evidence and case notes, no analysis overlay. Blobs
  hardlinked from the shared store are written as content. Without an
  argument it exports this machine's case.
- **`agentdfir open <file|dir|.enc>`** (alias `import`) — unpacks into
  `$AGENTDFIR_HOME/imported/`, verifies the seal (and says loudly when it does
  not), rebuilds the analysis with this binary and opens the explorer.
  Opening the same file again reuses the import.

### Fixed
- `witness_note` no longer grows by one "host witness" segment on every
  re-analysis of the same overlay; a newer witness result replaces the old one
  for the same file (#46).

## [2.6.0] — 2026-09-23

The case explorer, redesigned for someone who is not a security analyst.
Opened on a real machine (811 conversations, 260,469 recorded actions,
1,237 findings), the old explorer gave six tabs of jargon — RECORDED,
second witness UNKNOWN, ATLAS, building_block — a flat wall of 1,237 cards,
and an indented text tree for "how it happened". It answered none of the
questions an owner asks first: is something wrong, what, where did it
start, under which account, what do I do. The new one does, and it was
iterated against a non-technical reviewer until it did.

### Changed
- **`agentdfir serve` is a new UI** (`internal/serve/ui.html`), four
  screens instead of six tabs:
  - **Overview** — the answer first ("4 alerts need action now"), four
    tiers (Act now · Serious · Worth a look · Minor or routine), *Start
    here*, the accounts in the case, evidence integrity in words.
  - **Findings** — grouped by kind of issue (rule × severity; 1,237 → ~60),
    each with a plain title and *what happened · why it matters · ask
    yourself · what to do*, written for every built-in and community rule.
    Severity and confidence read as one line ("Act now if real · Needs your
    check"), so a red badge never sits next to "harmless".
  - **The story** — a swimlane diagram (*You · The AI agent · Tools &
    outside world*), one card per evidence line in time order, arrows for
    each hand-off, the flagged steps in red and numbered, the outside
    addresses they reach, an *In short* line, and the **most likely start**
    (your request, an automatic skill message, injected text the agent
    read, or a helper agent) marked on its card. Every card opens the sealed
    log line.
  - **Activity** — conversations named by what the person first asked
    (skill and harness text skipped), time-ordered, background bookkeeping
    records left out, *Only flagged* view.
  - **More** — search, plugin (MCP) activity, plugins installed, memory
    files, cross-check, agent map and evidence each on their own tab (the
    old "MCP · Provenance · Corroboration" tab stacked unrelated tables).
  - Verdicts read *Real problem · Expected · Detection mistake · Not sure
    yet* (stored values unchanged) and can be applied to every other time
    the same thing happened; *Copy a note for your IT contact*; a *What
    stands out* box on the raw line (safety prompts off, helper agent,
    tool error or refused login, invisible characters); light and dark
    themes; phone layout. Still loopback-only, no external resources, CSP
    unchanged. Old deep links keep working.

### Added
- **Accounts.** Every record, conversation, finding and plugin now carries
  the AI login it ran under. The identity is read from each collected
  profile's own settings — `~/.claude.json` `oauthAccount` (email,
  organisation), `<CODEX_HOME>/auth.json` `id_token` claims (email, ChatGPT
  plan) — and an event belongs to the profile directory its transcript sits
  in; Cowork sessions stored under a Claude account id match that account.
  Tokens and keys are never read out. `GET /api/accounts`; rows, sessions
  and findings gain `account`.
- **Plugin (MCP) activity timeline.** Every MCP call in time order with the
  account, plugin, tool, what the agent sent (read out of the call's sealed
  line) and what came back (the matching tool result).
- `/api/events` gains `account=`, `mcp=1|<server>`, `flagged=1`,
  `nometa=1` and `sort=time` (undated records last); rows carry `flags`.
  `/api/chain` nodes carry `dest`, the outside addresses a step names.
  `/api/case` gains per-server MCP event counts.

## [2.5.2] — 2026-09-23

Precision release. Every CRITICAL and HIGH rule was checked against the
commands and files behind its findings on a real 1,087-artifact case. About
half of the 312 CRITICAL+HIGH findings were the analyzer's mistakes, not the
agent's. A CRITICAL that turns out to be a port probe or a documentation
example costs more trust than the finding was ever worth, so these are
fixed as bugs, each with a benign corpus case that fails without the fix
and an attack case that still detects with it.

### Added
- **Chocolatey package.** `choco install agentdfir` joins Homebrew and Scoop.
  The release workflow renders `scripts/chocolatey/` for the tag, packs and
  pushes it to the community feed from a Windows runner (secret
  `CHOCO_API_KEY`, read by `choco push` alone), and commits the rendered
  package source to <https://github.com/efij/chocolatey-agentdfir> with a
  write deploy key, so the published package is auditable. The install
  script downloads the release's Windows zip (x64 or ARM64) and verifies
  its SHA256 from `SHA256SUMS.txt`. Missing secrets fail the release
  visibly, as for the other channels. `workflow_dispatch` gains a
  `chocolatey` switch to seed or retry the feed for an already-released tag.

### Fixed
- **Command-shape rules read heredoc bodies and quoted text as commands.**
  `CURL_PIPE_SHELL` fired on `curl … | sh` inside a `git commit -m "…"`
  message; the "data left the host" step of `CHAIN_SECRET_TO_EXFIL`
  (CRITICAL) matched a URL inside a Python docstring written through a
  heredoc — nine of fifteen CRITICAL chains on the real case had such a
  step. New `internal/shellshape.Strip` returns the command as the shell
  parses it (heredoc bodies gone, quoted strings emptied, a `bash -c '…'`
  script kept); pack rules opt in with `match.scope: "shell"`, and the
  chain's outbound step now requires a network verb the shell runs
  (`netdest.IsOutbound`) instead of a `https?://` anywhere in the text.
- **`nc -z` reachability probes counted as uploads.** 7 of 11 HIGH
  `POTENTIAL_DATA_EXFILTRATION` were `nc -z host port` and `scutil` VPN
  checks. `nc` is an upload only when data is fed into it (`… | nc`, `nc
  host port < file`) and never with `-z`.
- **`config` rule-pack rules scanned every plugin and skill file.**
  `CONFIG_HOOK_REMOTE_FETCH` ×6 and `MCP_INSECURE_TRANSPORT` ×10 were all a
  plugin's `SIGNATURES.md`, test script and skill docs quoting the shapes
  they warn about; `MEMORY_INSTRUCTION_CALLOUT` matched `Priority.ALWAYS` in
  a JavaFX CSV within 120 characters of a javadoc URL. `config` now means
  product and managed configuration only; a new match type `instructions`
  covers `agent_instructions` (CLAUDE.md, memory, rules). Pack rules of
  every artifact type skip agentdfir's own rules, fixtures and development
  transcripts, as the built-in injection rules already did — which also
  removes `PROMPT_SELF_REPLICATION` and `ROLE_MARKER_SMUGGLING` firing on
  the sessions that wrote those rules.
- **`POTENTIAL_SECRET_EXPOSURE` had no placeholder allowlist.** 92 of 95
  HIGH findings were `AKIAIOSFODNN7EXAMPLE` (the AWS documentation key),
  `AKIAFAKE…`, `xoxb-123…XXXX` and similar. Values carrying `EXAMPLE`,
  `FAKE`, `SAMPLE`, `TEST`, `XXXX`, `1234567890`, `ABCDEF` or a run of six
  identical characters are documentation, not credentials, and are no
  longer reported. Private-key headers are unaffected: a header alone
  cannot be judged.
- **`UNSAFE_MODEL_ARTIFACT_LOAD` fired on `pickle.load` of a file the same
  session had just written to its scratchpad** (20 findings, one session).
  Pack rules can now name the file a command acts on (`match.target_regex`)
  and stay quiet when every target is scratch space
  (`match.skip_scratch_target`).
- **`AGENT_SELF_MODIFICATION` matched `.claude.json` inside a scratchpad
  test fixture.** The write target is checked against `IsScratchPath`, as
  `LOG_DELETION` already did, after expanding the command's own `VAR=…`
  assignments (`S=/tmp/…/scratchpad; … > $S/home/.claude.json`).
- **Provenance matched relative write paths by basename.** `printf … >>
  .gitignore` in one repository was attributed to a plugin's `.gitignore`
  collected from `~/.claude/plugins`, producing `INSTRUCTION_FROM_TOOL_RESULT`
  and, chained with agentdfir's own test output, the case's only
  `CHAIN_CONTEXT_POISON_TO_EXEC` (CRITICAL). Events now carry the transcript's
  `cwd`; relative write paths resolve against it, and a path without a
  directory component never matches another file by suffix.
- **`DOWNLOAD_THEN_EXECUTE` fired on any interpreter after any download.**
  `curl -o paper.pdf … && python3 -c "count pages"` never executed the
  PDF. The rule moved from a pack regex to Go (`shellshape.DownloadThenExecute`):
  the executed or `chmod +x`-ed token must be the file the download saved.

- **A private-key header with an elided body counted as key material.**
  Summaries and reviews write `-----BEGIN RSA PRIVATE KEY-----\n...\n-----END
  RSA PRIVATE KEY-----`; 25 of the 27 private-key findings left on the real
  case had `...` for a body. The header now needs PEM material after it (a
  run of base64 before the END marker). A header at the edge of the scan
  window is still reported: unknown is not benign.
- **`skip_scratch_target` missed paths the 300-character command trim cut
  before their closing quote.** The captured target may now end at the
  trim marker; 12 more `pickle.load` findings on the session's own
  scratch cache went away.
- **A localhost health check satisfied the chain's outbound step.** `curl
  http://localhost:3000/api/health` after masking a `.env` was a CRITICAL
  `CHAIN_SECRET_TO_EXFIL`. Requests whose every destination is loopback are
  not data leaving the host.

### Changed
- Rule-pack schema: `match.type` gains `instructions`; `match.scope`,
  `match.target_regex` and `match.skip_scratch_target` are new and
  optional. Packs that use none of them are unchanged.
- Normalized events gain `cwd` when the transcript records it.

On the real case (1,087 artifacts, 2.7 GB), 2.4.3 → 2.5.2:

| | before | after |
|---|---|---|
| CRITICAL | 16 | 4 — every survivor has a network verb with a visible remote destination as its second step |
| HIGH | 295 | 167 |
| CHAIN_SECRET_TO_EXFIL | 15 | 4 |
| CHAIN_CONTEXT_POISON_TO_EXEC | 1 | 0 |
| POTENTIAL_SECRET_EXPOSURE | 95 | 21 |
| UNSAFE_MODEL_ARTIFACT_LOAD | 20 | 1 |
| POTENTIAL_DATA_EXFILTRATION | 11 | 3 |
| MEMORY_INSTRUCTION_CALLOUT · CONFIG_HOOK_REMOTE_FETCH · MCP_INSECURE_TRANSPORT · DOWNLOAD_THEN_EXECUTE | 10 · 6 · 10 · 2 | 0 |
| INSTRUCTION_FROM_TOOL_RESULT | 90 | 88 |

Twelve new benign corpus cases, one per defect, each seen failing before its
fix; every attack case still detects. The real chains kept: a hard-coded PAT
followed by `curl` to an internal TFS API, a keychain GitHub token followed
by `curl api.github.com`, and two more with a real remote destination.

## [2.5.1] — 2026-09-23

### Fixed
- **`analyze` took 13 minutes on a 2.1 GB case; three stages were doing
  the same work many times over.** Profiled on that case (v2.4.1, 843 s of
  CPU): provenance 375 s, the secret-exposure scan 197 s, rule packs 116 s.
  - **Provenance re-decompressed large transcripts once per tool call.** It
    opened each tool call's source artifact at the event's byte offset. On a
    plaintext blob that is a seek; on a gzip blob above the store's 32 MB
    seek cache it is a decompress-from-zero. Four transcripts over 32 MB held
    4,143 tool calls, which came to 107 GB of gunzip and 288 s. Each artifact
    is now opened once and read forward in offset order; the lines returned
    are byte-identical (a test compares the two paths, including reversed
    and repeated offsets).
  - **`POTENTIAL_SECRET_EXPOSURE` ran nine regexes over every megabyte of
    every transcript.** Go's regexp uses its slow NFA on inputs that size,
    and it was 197 s of the run. Every credential format starts with a
    literal (`AKIA`, `ghp_`, `sk-ant-`, `eyJ`, …), so the scan now byte-searches
    for that literal and runs the regex only around each occurrence.
    Offsets and counts equal a whole-blob `FindAllIndex` (tested: offset 0,
    glued to a word character, adjacent, two patterns on one token, across a
    chunk boundary).
  - **Rule packs read the whole store once per artifact-scoped rule.** Ten
    such rules ship embedded: ten full passes, each lowercasing every
    artifact again. One pass now reads each artifact once and evaluates all
    rules of its class against it; the lowercase copy is made once. Binaries
    are skipped, as the other content rules already do since 2.4.3.
  - **Provenance compared every instruction file against every write.**
    5,698 files × 3,291 writes, normalizing both paths each time: 18.7
    million comparisons, 72 s. Two paths that match share their last path
    element, so writes are indexed by it (tested against the brute force).
  - **The four content rules each streamed every transcript.** Credential
    formats, injection phrases, invisible Unicode and honeytokens now read
    each artifact once and share the chunks; findings keep their order.
  - **Artifacts are scanned in parallel.** The detection, rule-pack and
    provenance loops run on up to eight workers; output stays in manifest
    order, so results are identical to the sequential run. The two pack
    regexes that remain expensive (`ROLE_MARKER_SMUGGLING`,
    `PROMPT_SELF_REPLICATION`: 95 s of CPU over 984 MB of transcripts) are
    engine-bound and unchanged in meaning.
  Same case, same finding counts at every stage: 843 s → 50 s.
  The `0 reused from the overlay` on a first run after upgrading is by
  design: normalized segments are keyed on the binary version, and that
  stage took 13 s.

## [2.5.0] — 2026-09-23

### Added
- **Claude Cowork is a product.** The Claude desktop app's agent mode runs
  Claude Code inside a VM and keeps its evidence under the app's support
  directory, not `~/.claude`, so until now it was invisible to `detect`,
  `collect` and every rule. `claude-cowork` (`collect --product cowork`) is
  detected by its session store and collects, per session: the stream-json
  **audit log** (`audit.jsonl`, one HMAC per line, key preserved as
  `credentials`), the **CLI transcript written inside the VM**
  (`.claude/projects/**`, the format the Claude parser already reads), the
  in-VM `.claude` state and credentials, outputs and uploads, and the
  **sidecar** (`local_<id>.json`) that records the session's blast radius:
  the host folders the user shared, the egress domain allowlist, remote MCP
  servers, model, account and VM name. Org-level state (spaces, scheduled
  tasks, installed plugins, `git-shadow`), the desktop Claude Code tab's
  sidecars (`claude-code-sessions/`: permission mode, every "always allow"
  the user granted), `claude_desktop_config.json` and the Cowork/VM logs
  under `~/Library/Logs/Claude` are collected too. macOS paths are
  verified against a real install; Linux and Windows paths follow the
  Electron convention and are recorded as not-present when absent.

  The Claude parser reads the audit dialect (snake_case `session_id`,
  `parent_tool_use_id`, `tool_use_result`, `_audit_timestamp`) alongside
  the CLI transcript, stamps Cowork evidence `claude-cowork`, turns the
  SDK's `system:init` (model, permission mode, MCP servers) and `result`
  (turns, cost, permission denials) records into `session_meta` events,
  emits one event per shared folder (`File`) and per allowed egress domain
  (`NetworkDest`), and ties the in-VM CLI session to its Cowork session in
  the graph. `--detect --alert` recognises the session store path for live
  tailing. `mcp audit` inventories `claude_desktop_config.json`. The HMAC
  scheme is not public: signatures are counted and recorded per file
  (`audit_signed`), not verified.

- **Codex desktop app, and the SQLite thread store.** Codex (app and current
  CLI) writes each thread to `state_*.sqlite` (cwd, model, **sandbox and
  approval policy**, git origin and branch, source, spawn edges between
  threads) and `thread_history_*.sqlite` (every user message, agent
  message, command execution with exit code, file change with paths, MCP
  call with server/tool/status, web search). None of it was collected. The
  manifest now takes both stores **with their write-ahead logs**, the
  goals/queue/memories stores, `logs_*.sqlite`, `session_index.jsonl`, the
  app's global state, plugins, browser sessions, computer-use config,
  attachments and generated images, the Electron app's own state under
  `~/Library/Application Support/Codex` (preferences, history, local
  storage; not the 200 MB cache), and the ChatGPT app's Codex task caches.

  A new parser (`internal/parsers/codexdb`) emits a `session_meta` per
  thread (`source=vscode approval=never sandbox=danger-full-access …`),
  `agent_spawn` per spawn edge, and — for threads whose rollout JSONL is
  **not** in the package — the item rows as the transcript, so a pruned or
  never-written rollout no longer makes the thread disappear. Threads with
  a rollout are not duplicated. Rows are read with
  `internal/parsers/sqlitero`, a **stdlib-only read-only SQLite reader**
  (b-tree walk, overflow chains, WITHOUT ROWID tables, WAL frames verified
  by salt and checksum): the collector core stays dependency-free and
  cross-compiles as before. Checked against the sqlite3 CLI on a real
  57 MB store — identical row counts on every table.

### Changed
- **Explorer: findings are sorted by severity, then confidence,** on the
  server and again in the tab, and the "attack chains only" checkbox is
  replaced by a **confidence filter** (any / HIGH / MEDIUM / LOW); each
  finding row shows its confidence. The overview's single "critical + high
  findings" tile is **split into "critical findings" and "high findings"**.
  The **time span tile is a button** that opens the timeline with new
  **from / to date pickers** (UTC, to the minute) beside the existing
  filters; a scrubber click fills them in, Clear empties them.
- **Sessions tab is honest about "worst first".** Findings that no session
  claims — package-level rules on configs, MCP inventories and instruction
  files — used to be invisible there, so the Findings tab could show
  CRITICALs the Sessions tab never ranked. They now get one dashed
  "Findings not tied to a session" card, ranked with the rest and opening
  the Findings tab; findings raised on an event are attributed to that
  event's session when the rule left the field empty.

### Fixed
- **Codex rollout parser dropped the output of every desktop-app tool
  call.** The app writes `custom_tool_call` / `custom_tool_call_output`
  (exec, apply_patch); only `function_call_output` was handled, so the
  OBSERVED result side of those calls fell into a generic bucket and no
  rule that reads tool results saw it. `custom_tool_call` with an `exec`
  script is now a `shell_execution` with the script as its command, and
  its output is a `tool_result` paired by `call_id`.
- **`AGENT_IDENTITY_MISMATCH` and `SESSION_TAMPERING` no longer fire on
  database-sourced events.** A product store holds every thread in b-tree
  order, so one artifact with thirty session ids and non-monotonic
  timestamps is its normal shape; on the first real Codex-app collection
  the state store produced one HIGH and one MEDIUM finding of pure noise.
  Cowork's audit log had the same problem for a different reason: it opens
  under the Cowork session id and switches to the CLI session id after
  init, so every Cowork session was a HIGH identity mismatch and every
  Cowork main agent an `ORPHAN_AGENT` (the audit log's subagent lines run
  under the main agent id and were being marked as sidechains). On a real
  seven-session Cowork collection: 7 → 0 identity mismatches, 4 → 1
  orphans, 34 → 0 `UNEXPECTED_TASK`.
- **`turn_context` records were ignored.** They are the only place the
  rollout says which approval and sandbox policy a turn ran under. Each is
  now a `session_meta` (`approval=never sandbox=danger-full-access
  model=… cwd=…`) with the turn id.

## [2.4.3] — 2026-09-23

### Fixed
- **`serve`, `report` and the analyst commands showed whatever analysis was
  on disk, even one written by an older binary.** `analysis.Stale` compared
  file times only. A case analyzed before v1.8.0 and opened with 2.4.2 still
  showed 66 HIGH `INVISIBLE_UNICODE_INSTRUCTION` and 275 HIGH `ORPHAN_AGENT`;
  the running binary produces 1 and 4. Results now record which version
  produced them (they already did) and are recomputed when it is not the one
  running, with one line saying so:
  `Re-running analysis with agentdfir 2.4.3: analysis was produced by agentdfir 1.7.0.`
- **Content rules read binary files as instructions.** Category is assigned by
  path (`skills/**` → `agent_definitions`), and nothing asked whether the
  bytes were text. On a real case the only HIGH unicode finding left after
  re-analysis was a 6.3 MB `template_final.pptx`: bytes `F3 A0 80 BA` at
  offset 1,461,798 decode as tag character U+E003A. Two git pack files and an
  `icon.png` were MEDIUM; 47 of 66 unicode findings cited binary or `.git`
  evidence. `Store.IsText` — extension not a known binary type, first 8 KiB
  has no NUL and is valid UTF-8 — now gates the invisible-Unicode rule, the
  phrase-scan rules (`PROMPT_INJECTION_INDICATOR`, `TOOL_POISONING_INDICATOR`,
  `AGENT_CONTEXT_POISONING`) and provenance attribution. Transcripts,
  Markdown, JSON and source are unaffected.
- **Artifacts an older collector took from `node_modules` and `.git/objects`
  never left the scan set.** The manifest is append-only and the current view
  is newest-round-per-path, so a path that stops being collected stays current
  forever. A case whose first round ran under collector v1.0.0 carried 5,752
  plugin files (640 MB) that 1.5.0+ would not collect without
  `--full-plugins`, and every scan read all of them. `run` (without
  `--full-plugins`) and `analyze --renormalize` now retire records the current
  policy excludes: they stay in the manifest as evidence, `Current()` skips
  them, and a later round that collects the path on purpose wins. The list is
  derived data at `normalized/retired.json`.

  On the real case (1,087 artifacts, 2.7 GB), 2.4.2 → 2.4.3:
  `INVISIBLE_UNICODE_INSTRUCTION` 66 → 15 (HIGH 1 → 0, MEDIUM 8 → 5, INFO
  57 → 10; the 15 left are Persian-digit durations wrapped in bidi isolates
  and emoji joiners in transcripts), 0 findings cite binary or `.git`
  evidence (was 47), 734 records retired, `analyze --renormalize` 14 min 41 s
  → 8 min 32 s. No other rule moved.

## [2.4.2] — 2026-09-23

### Fixed
- **Most Claude Code tool results were being dropped as "malformed", and
  every subagent was an orphan.** Since v2.0.0 the parser decoded the
  transcript's `toolUseResult` field into a fixed struct. Claude Code writes
  that field as a plain **string** for Bash/Read output and an **array** for
  some tools; only subagent launches are objects. `json.Unmarshal` rejected
  the first two shapes, so the whole line was recorded as a `malformed_line`
  trace gap. On a real 2.7 GB package: **1,945 well-formed tool-result lines
  dropped, 1,947 `TRACE_GAP` findings, and 99 HIGH `SESSION_TAMPERING`**
  because every parentUuid chain that ran through a dropped line looked
  broken. Every rule that reads tool results — injection-in-tool-result,
  the poison chains, provenance — was blind to those lines.

  The same field carries the spawned child's `agentId` on the **result**
  line (`{"status":"async_launched","agentId":…}`). The parser looked for it
  on the tool-call line, where it never is, and never turned the result into
  an `agent_spawn` event, which is what `ORPHAN_AGENT` checks. So **275 real
  subagents with a perfectly good parent were HIGH orphans** — the count
  v1.8.0 was believed to have fixed by handling the `Task`→`Agent` rename;
  that fix was necessary but not sufficient.

  `toolUseResult` is now decoded leniently (objects only, for the spawn
  fields) and a launch result emits the spawn event. The regression test
  reproduces all four symptoms against the old code.

  **Re-analyze existing packages**: `agentdfir analyze --renormalize <pkg>`.

## [2.4.1] — 2026-09-22

### Fixed
- **`serve` never released the event overlay, and CI was red on `main`
  because of it.** The index keeps `normalized/events.jsonl` open so events
  can be read back by byte offset — that is the point of it — but nothing
  ever closed it. On Windows a file with an open handle cannot be unlinked,
  so every `internal/serve` test failed in teardown with *The process
  cannot access the file because it is being used by another process*, and
  a case directory served in-process could not be deleted afterwards.

  `serve.Server` gains a `Close`, `index.Index.Close` is idempotent, and
  the `serve` command and tests use them. Windows CI on `main` went red at
  v2.2.0, where the index landed, and stayed red through v2.4.0 — the
  assertions passed and only the cleanup failed, which is the kind of red
  that gets explained away.

- **The v2.3.0 overlay migration could not finish on Windows.**
  `overlay.Decompress` restores `normalized/events.jsonl` from the `.gz` a
  2.1.0–2.2.1 binary left behind, then removes the compressed form — but it
  still held the `.gz` open on a deferred close, and Windows will not unlink
  an open file. The removal failed, the `.gz` stayed, and readers prefer it,
  so the migration undid itself on the one platform where the case was
  hardest to open to begin with. The handles are now closed before the
  unlink, as `overlay.Compress` already did.

- A host-witness test asserted nothing on Windows: its fixture wrote a
  claimed path of `/Users/dev/...`, and `filepath.IsAbs` rejects a POSIX
  path there, so `witness.Apply` skipped it and the stage under test never
  ran. The fixture now builds an absolute path in the platform's own shape.

## [2.4.0] — 2026-09-22

### Added
- **Kiro is detected and collected.** `agentdfir detect` / `run` now report
  Kiro (`dev.kiro.desktop`, the VS Code-based agent IDE) and collect its
  agent surface: global `~/.kiro/steering/**` (auto-loaded instructions),
  `settings/mcp.json`, `skills/**`, the `powers/` and `extensions/`
  inventories, the Kiro SSO token at `~/.aws/sso/cache/kiro-auth-token.json`
  (recorded as `credentials`, critical), and — where a host has them — the
  VS Code `globalStorage` / `workspaceStorage/*/state.vscdb`, `History` and
  logs on macOS, Linux and Windows. Third-party source trees under `powers/`
  and `extensions/` stay behind `--full-plugins`, like every other product.

  Nothing new to parse: the manifest routes each file to the category the
  existing rules already read, so steering files get injection scanning,
  `mcp.json` gets the MCP audit (unpinned packages, `autoApprove`), and
  provenance and baseline cover them. Per-repository `.kiro/` directories
  (specs and steering inside a project) are reachable with
  `agentdfir collect --import <tree>`, as with per-repo `CLAUDE.md`.

- **Scoop bucket for Windows.** `scoop bucket add agentdfir
  https://github.com/efij/scoop-agentdfir; scoop install agentdfir`. The
  manifest carries both Windows zips (x64, ARM64) with their SHA256 from the
  release's `SHA256SUMS.txt` and is refreshed by the release workflow the same
  way the Homebrew tap is (`scripts/update-scoop.sh`, write deploy key); a
  release whose bucket did not update fails visibly.

## [2.3.0] — 2026-09-22

### Fixed
- **`agentdfir serve` could not open a case the second witness or endpoint
  correlation had touched.** Both stages stamp corroboration states onto
  events and rewrite `normalized/events.jsonl` in place, and since v2.1.0
  they did that with the compressing overlay writer — which writes
  `events.jsonl.gz` and deletes the plaintext form.

  `events.jsonl` is the one overlay file that must not be compressed:
  every row of `internal/index` is a byte offset into it, and a gzip
  stream cannot be seeked. So the index could not be built (`event index
  skipped` in the stage notes) and `serve` returned the error rather than
  opening the package.

  Nothing detected it, because the staleness check accepts either form:
  the case looks analyzed and current, so no re-analysis is ever
  triggered and it stays unopenable. The host witness is recorded on
  every `agentdfir run`, so this was not limited to analysts who supplied
  an endpoint log.

  **A case damaged by 2.1.0–2.2.1 heals itself** the next time anything
  opens its index — one streaming decompression of a file that was about
  to be read anyway, no re-parse.

### Added
- **Analysis re-parses only the transcripts a collection round actually
  changed.** Collection has been incremental since v1.5.0; analysis was
  not. Any new round invalidated the whole overlay — on a real two-round
  package, **7 minutes 27 seconds re-parsing 206,896 events out of
  transcripts that had not changed a byte**.

  The overlay is now segmented per source artifact, under
  `normalized/events/<parser>/<key>.jsonl.gz`, with
  `normalized/events.jsonl` as their concatenation in parse order — the
  same flat, uncompressed file every reader already expects. A rebuild
  decompresses the segments of artifacts whose content address is
  unchanged and re-parses only the rest.

  On the added benchmark (32,080 events, 80 transcripts) normalization
  after a round that changed nothing is **48 ms against 462 ms**. How
  much of that reaches a whole analysis depends on the case: on that
  fixture it is 20.4 s against 20.9 s, because detection, rule packs,
  provenance and chains still re-scan every event. The saving is
  proportional to how much parsing a case does — which is where the
  seven-minute cases were losing their time.

  The segments are gzipped like the rest of the overlay (nothing seeks
  them), so the cache costs about 3% of `events.jsonl` rather than
  doubling it. `agentdfir compact` still removes all of it, and
  `--renormalize` still rewrites all of it.

  **Correctness.** The parsers carry state across artifacts — one
  sequence counter, one merged entity map, one de-duplicated relationship
  list — so a subset parse that looked fine could still produce a
  different entity graph and a different agent lineage. Per-artifact
  contributions are therefore replayed as the *calls* the parser made,
  through the parser's own merge. Two aliasing defects were found and
  fixed while proving this: a recorded entity kept the parser's live
  attribute map, so it was persisted holding attributes contributed by
  artifacts read later and could reinstate them in a round where those
  artifacts had been superseded; and the same in reverse on the replay
  side. Acceptance tests compare an incrementally rebuilt overlay against
  a full re-parse of the identical package — identical bytes for events,
  entities and relationships, and an identical finding set — across five
  rounds of change shapes and all three parsers.

## [2.2.1] — 2026-09-22

### Fixed
- **Codex CLI sessions were invisible to every detection.**
  `codexjsonl.StreamPackage` never passed its sink to the parser, so events
  went into an in-memory slice that the streaming caller discards. It is the
  only parser that did this — Claude Code and the generic chat parser both
  wired theirs. `normalize.ParseStream` is what analysis uses, so **no Codex
  event has reached `normalized/events.jsonl`, or any rule reading it, since
  streaming normalization was introduced in v0.5.1.**

  `ParsePackage` passes a nil sink and returned the events correctly, which
  is why every existing test passed. The regression test asserts the two
  entry points agree; without the fix it reports *StreamPackage emitted 0
  events, ParsePackage produced 6*.

  **Re-analyze any package containing Codex sessions** — `agentdfir analyze
  --renormalize <pkg>` — as findings for them were never generated.

## [2.2.0] — 2026-09-22

### Added
- **A derived event index bounds `serve` memory.** The explorer read the
  whole of `normalized/events.jsonl` into memory and capped it at 500,000
  events — a real 206,896-event case cost **181 MB of live heap**, and a
  larger one silently lost evidence from the UI.

  `internal/index` writes `index/events.idx` after the overlay is final: a
  fixed-width record per event carrying its byte offset and fifteen interned
  summary fields. Every list, filter, bucket and graph query runs off those
  summaries with no disk reads; a full event is read by offset only when a
  detail view asks for it.

  **Live heap after load: 181 MB → 58 MB. Opening a case: 1.7 s → 0.4 s.
  The cap is gone.** `--max-events` is accepted and ignored.

  `index/` is derived and outside the sealed zone, so deleting it is
  allowed; it is rebuilt on open when missing, stale, corrupt, or written by
  an older version.

### Changed
- `normalized/events.jsonl` is the one overlay file written **uncompressed**,
  because the index addresses it by byte offset and a gzip stream cannot be
  seeked. Entities, relationships and detections are read whole and stay
  compressed.

## [2.1.0] — 2026-09-22

### Added
- **The analysis overlay is compressed.** On a real case the sealed evidence
  is 525 MB and the regenerable overlay on top of it was ~300 MB —
  `normalized/` 178 MB, `detections/` 120 MB — so the derived half of the
  package had grown larger than the evidence it came from.

  `internal/overlay` is now the single read/write path: writers gzip,
  readers accept either form, so packages written before this keep opening
  and `gunzip -c` still works on the new ones. Measured 30:1 on a synthetic
  package; expect nearer 10:1 on a real case, taking ~300 MB to ~30 MB.
  Decompression is bounded, as blob reads are — by ratio rather than a
  recorded size, because the overlay has no manifest to check against.

  An existing plaintext overlay is migrated in place on the next `analyze`:
  the reuse path never rewrites it, so an upgraded binary would otherwise
  carry the old one indefinitely.
- **`agentdfir compact <pkg> [--dry-run]`** deletes the overlay and reports
  what it reclaimed. Safe by construction — the overlay is excluded from
  `SHA256SUMS`, and `analyze` rebuilds it.

Detection results are unchanged, asserted by an equivalence test that fails
without the change.
### Changed
- **The case explorer no longer holds the case in memory, and no longer
  truncates it.** `serve` read `normalized/events.jsonl` into one
  `[]schema.Event` capped at 500,000 events. A real 206,896-event package
  cost 181 MB of live heap to open (471 MB of heap claimed from the OS),
  and the cap was the worse half: past it the tail of the case was dropped,
  the header said *truncated*, and the evidence simply was not in the UI to
  look at.

  A derived index at `<pkg>/index/events.idx` now records each event's byte
  offset and length in the overlay, plus the fields the timeline, graph and
  session cards filter and group on; the full event is read back by offset
  when a detail view asks for one. The same package opens in 58 MB, and in
  0.4 s instead of 1.7 s once `analyze` has written the index. There is no
  cap of any kind; `serve --max-events` is accepted and ignored.

  The index is derived data, not evidence: it lives outside the sealed
  zone, is not covered by `SHA256SUMS`, and deleting it is always safe. A
  package without one — including every package written by an earlier
  version — gets one rebuilt on load, as does one whose overlay has changed
  underneath it. Every endpoint returns exactly what it returned before,
  verified byte for byte across the whole corpus.

## [2.0.1] — 2026-09-22

### Fixed
- **`go install` was broken by v2.0.0.** Go requires a module path to carry
  its major version from v2 onward, so `go install
  github.com/efij/AgentDFIR/cmd/agentdfir@v2.0.0` failed with *module path
  must match major version*. The module is now
  `github.com/efij/AgentDFIR/v3` and the documented command is
  `go install github.com/efij/AgentDFIR/v3/cmd/agentdfir@latest`.

  Nothing else changes: the binary, the `.adfir` format, every command and
  the other three install paths are unaffected. Import paths inside the
  repository moved to `github.com/efij/AgentDFIR/v3/internal/...`.

## [2.0.0] — 2026-09-22

Confidence, separated from severity. A machine producing 592 HIGH and
CRITICAL findings gave an analyst no way to tell which were worth opening —
every one arrived identical. They are **85 groups**, and now they carry how
much to believe them and why.

### Added
- **`internal/verify` — confidence as its own answer.** Severity is how bad
  this is if it is real; confidence is how likely it is to be real. They
  were the same number, so deleting a build directory and deleting a user's
  SSH key arrived indistinguishable.

  Five deterministic verifiers run over the finished finding set: host
  witness (a `CONFIRMED` event raises it), self-referential evidence (a rule
  list or fixture lowers it), mirrored transcripts, building blocks, and
  findings citing no evidence line. Each may move confidence one step and
  **must** say why, in a sentence the UI shows verbatim under *Why this
  confidence*.

  **Severity is never touched by a verifier**, and there is **no LLM in the
  path**. A finding has to be reproducible from the sealed package alone,
  years later, by someone who does not have the binary that produced it.
- **Findings carry a timestamp** at last, taken from the evidence they cite.
  They had none, which made them impossible to filter or plot by time.
- **Grouping by rule and session** — `detections/groups.json` and
  `/api/groups`, each group carrying the worst severity, the best
  confidence, the count and the time span.
- **The `benign` verdict.** The rule was right and the activity was
  authorised. Without it an analyst had to mark a correct detection a false
  positive just to clear it, which is untrue and the wrong signal for
  tuning.
- Confidence and its reasons appear in the explorer, the HTML and PDF
  reports, and `analyze` output.

## [1.9.0] — 2026-09-22

The second witness, by default. Until now every finding this tool produced
was `RECORDED` at best — the transcript says a tool was called, and nothing
else was ever asked. On a real 206,896-event package **all 1,519 findings
carried `UNKNOWN`**. The corroboration model existed and was wired to
nothing, because it assumed the analyst already had auditd or Sysmon
exports.

### Added
- **`internal/witness` — host state, recorded during acquisition.** After
  collection and before sealing, `run` parses what it has just preserved,
  asks the filesystem about every file the agent claimed to write, reads the
  reflog of every repository it edited, and seals the answer into the
  package as `witness.json`, covered by `SHA256SUMS` and the custody chain
  like any other evidence.

  The timing is the design. Gathering happens at **acquisition**; comparing
  happens later in analysis, in the regenerable overlay. Asking the host at
  analysis time — days later, possibly on another machine — would describe a
  different world, and the tool would be manufacturing evidence rather than
  preserving it.

  Analysis then raises an event to **`CONFIRMED`** when the file is there
  with its content hash recorded, and notes the witness in a sentence an
  analyst can read. **Absence is deliberately not disproof**: a file can be
  removed by anything between the action and the acquisition, so a missing
  file is noted and the state is left alone.

  Bounded on purpose — 2,000 files, 8 MiB each, 100 repositories — because
  the paths come from evidence, which is hostile input. Read-only
  throughout, and git is never executed: the reflog is read as the text file
  it is.

  `--no-witness` turns it off.
- **Shell history is collected at last.** `correlate.ShellHistoryAdapter`
  has existed since v0.8.0 and **no manifest ever collected the file**, so
  `run` could never use it. zsh, bash, fish and PowerShell histories are now
  part of the collection.

## [1.8.0] — 2026-09-22

Precision. The benign corpus went from **13 false positives to zero** with
both attack cases still firing, and the budgets are now all zero so it stays
that way.

### Fixed
- **`ORPHAN_AGENT` — 275 false HIGH findings from one string.** Claude Code
  renamed its subagent tool from `Task` to `Agent`; the parser matched only
  `Task`, so a 206,896-event package contained **zero** `agent_spawn` events
  and every subagent in it was reported as having no verified parent. The
  spawned agent's id is also read from `toolUseResult.agentId`, where
  current builds put it.
- **`AGENT_SELF_MODIFICATION` — reading your own skills is not writing to
  them.** The rule matched any of `echo|>|sed|tee|cp|mv` anywhere plus a
  config path anywhere, so `ls ~/.claude/skills; sed -n 61,140p SKILL.md`
  was a self-modification. It now resolves actual write targets — redirects,
  `tee`, `cp`/`mv` destinations — and read-only commands never count.
- **`LOG_DELETION` — the log path must belong to the delete.**
  `rm -rf $S/perf && mkdir -p $S/perf/.claude/projects/-big` fired on the
  `mkdir` argument.
- **`SESSION_TAMPERING` — dangling parents are normal.** They come from
  `attachment`, `queue-operation` and `system` records, which are Claude
  Code's own bookkeeping.
- **`INVISIBLE_UNICODE_INSTRUCTION` was always HIGH.** Severity now follows
  which characters were found: Unicode tag characters are HIGH, three or
  more bidi controls MEDIUM, zero-width alone INFO. Every one of the 43 HIGH
  findings on a real machine had zero tag characters — they were emoji and
  Hebrew.
- **`UNEXPECTED_NETWORK_DESTINATION` parsed flags as hosts.**
  `nc -z -w 3 localhost 8080` reported `3` as the destination.
- **`TOOL_POISONING_INDICATOR` flagged security tools' own rules.** A
  plugin's `SIGNATURES.md` and `prompt-injection-context.regex` contain
  injection phrases because that is what they detect.
- **`DESTRUCTIVE_COMMAND` graded by target.** Clearing a scratch, cache or
  build directory is housekeeping and is reported as INFO.
- **`AGENT_CONFIG_DISCOVERY`** no longer matches an agent listing its own
  skills, agents or commands directories, which is how it uses them.
- **Attack-chain windows were unbounded** (`WindowMinutes: 0`), which
  matched a download and an unrelated deletion 21 hours apart. Now 120
  minutes.
- **The `.gitignore` rule hid the corpus from CI.** An unanchored `.claude/`
  rule matched the synthetic profiles under `internal/corpus/testdata`, so
  the cases existed only on the machine that wrote them.
- **Two implementations of the same rules had drifted.** `rules_v05.go` and
  `stream_helpers.go` both emit `AGENT_SELF_MODIFICATION` and
  `LOG_DELETION`, and only the streaming one runs in analysis. They now
  share one predicate each.

### Added
- **Building blocks are separated from detections.** `SHELL_EXECUTION`,
  `AGENT_GENERATED_COMMIT`, `AGENT_GENERATED_PUSH` and
  `MCP_PROJECT_SCOPED_SERVER` describe what an agent does all day. They are
  input for the chain rules and context for an analyst, not alerts, and
  carrying ATT&CK ids inflated the coverage claim — `SHELL_EXECUTION` is
  INFO and claimed `T1059`; `MCP_PROJECT_SCOPED_SERVER` is INFO, claimed
  `T1195` and fired 54 times on one machine.
- `internal/detect/shellparse.go` — write targets, delete targets,
  read-only detection and scratch-path classification, shared by the rules
  that used to match a verb anywhere and a path anywhere.

## [1.7.0] — 2026-09-22

A measurement harness for detection precision. **No behaviour changes**, no
rule edits, no new detections — this exists so that every change after it can
be judged instead of argued about.

### Added
- **`internal/corpus`** — corpus cases are collected into a real sealed
  package and run through the real analysis pipeline, nothing mocked.
  - `testdata/benign/` — seven cases, each reproducing a shape that caused a
    real false positive on a real machine: read-only skill inspection
    (`sed -n`, `ls`), emoji ZWJ and Hebrew bidi, scratchpad cleanup, a
    security plugin's own injection signature list, netcat value-flags and
    `git@` remotes, hook and attachment transcript lines, and a `.gitignore`
    in a plugin cache. Written rather than copied: real transcripts carry
    live secrets.
  - `testdata/attack/` — cases that must keep firing, so a change that
    quietens a rule by breaking it fails the build.
  - `testdata/budget.json` — a per-rule false-positive allowance, baselined
    against today. A rule over budget fails CI even when the total looks
    fine; a lost detection fails it from the other side.
- `go test ./internal/corpus -run TestCorpus -v` prints a per-rule
  false-positive table, worst first.

The harness found a real false positive on its first run:
`AGENT_CONFIG_DISCOVERY` fires on `ls ~/.claude/skills`, which is how an
agent uses its own skills rather than reconnaissance. It was invisible until
v1.6.0 started running the packs, and it is recorded in the budget with a
note rather than quietly excused.

## [1.6.0] — 2026-09-22

Ships the rules that were never running, says what it means in plain words,
and shows real time. No detection logic changed; one packaging bug did more
damage than any rule.

### Fixed
- **The shipped rule packs never ran.** `rules/*.json` was not embedded,
  `analysis.Options.RulesDir` only came from `analyze --rules <dir>`, `run`
  had no such flag at all, and the release archives contain only the binary.
  On any installed copy the whole declarative rule set was inert: a real run
  producing 1,519 findings had generated every one of them from the built-in
  Go rules, with **80 of 140 declared rules idle**. The packs are now
  `go:embed`-ed and load by default for `run` and `analyze`.
  `--rules <dir>` still adds packs on top; `--no-builtin-packs` restores the
  old behaviour. `run` gains `--rules` too.
- **`CURL_PIPE_SHELL` shipped in two packs**, so loading both reported it
  twice on the same evidence. Pack loading now de-duplicates by rule ID,
  first pack wins, and drops are recorded in the analysis notes.
- **`.git` was excluded wholesale** by the v1.5.0 collection policy, which
  also removed `.git/hooks` and `.git/config` — the artifacts a
  hook-installation detection exists to read, and exactly where a poisoned
  plugin marketplace repo would put one. Only `.git/objects`, `.git/lfs`
  and `.git/modules/*/objects` are skipped now.
- **Warp AI was detected and collected nothing, silently.** The manifest
  expected `warp.sqlite` at a fixed path; on a real machine it was not
  there. Paths now glob the per-install directory, and
  `telemetry_events.json` and `warp_network.log` are collected.

### Added
- **Absence is evidence.** A manifest path that was checked and does not
  exist is recorded as `NOT_PRESENT` with the path, instead of being
  discarded. A detected product that collects nothing now says how many
  paths it checked rather than printing `0 artifacts · 0 B`.
- **Rule-set provenance.** `analysis.json` records the name, version and
  SHA-256 of every pack that contributed, plus the AgentDFIR version, so
  "which rules decided this" stays answerable after the binary is replaced.
- **Real timing.** Every step of `run` reports how long it took, with a
  total. Acquisition shows a true percentage and time remaining, from a
  metadata-only pre-walk that costs a second or two and reads nothing.
  Analysis shows named stage progress (`stage 3/7 · detections`) and
  deliberately **no** ETA — stage costs differ by an order of magnitude and
  a fabricated number is worse than none.

### Changed
- **Plain words for evidence states**, everywhere a human reads them:
  `ASKED` · `CLAIMED` · `RECORDED` · `PARTLY CONFIRMED` · `CONFIRMED` ·
  `DISPROVED` · `UNKNOWN`. The feature that produces them is called
  **enrich**, or a second witness.
  "Enriched" is deliberately not one of the states: enrichment is the
  action, and the state has to say whether the host confirmed or disproved
  the claim, or it carries no information.
  **The stored values and the JSON are unchanged** — `.adfir` is a published
  format, packages exist in the wild, and OCSF/SARIF/STIX exports feed other
  systems. The timeline CSV now carries both: the stored state and the plain
  word beside it.

## [1.5.0] — 2026-09-19

The evidence-store release. Collecting the same machine twice used to mean
two complete copies of several gigabytes; on a real macOS profile a single
run wrote **3.9 GB**, and running from a different directory wrote another
3.9 GB. This release makes acquisition compressed, deduplicated, parallel
and incremental, and hardens the acquisition path while doing it. Every
command, flag and analysis result is unchanged, and packages written by
v1.0.0 still open, verify, analyze and accept new rounds — enforced in CI
against a package built by the released v1.0.0 binary (`internal/compat`).

Measured on the profile above (2.5 GB `~/.claude`, 1.3 GB `~/.codex`,
~22,000 files): **3.9 GB → 525 MB** sealed evidence; a second run re-read
10 files, carried 8,269 forward and added **157 KB**.

### Added
- **Per-blob compression** — evidence is gzipped when a 256 KiB sample says
  it pays (≥1.15x, >4 KiB); already-compressed content is stored as-is.
  stdlib gzip keeps runtime dependencies at zero and lets an analyst
  `gunzip` a single blob with no AgentDFIR binary in the loop. The codec is
  recorded per blob, so a denser one can be added later without breaking
  any package written today.
- **Collection rounds** — a second collection against an existing package
  appends instead of starting over: records carry their round, both hash
  chains continue from their previous last line, and the seal that closed
  the previous round is archived to `seals/SHA256SUMS.<n>`. Nothing already
  written is ever rewritten. `case.json` gains a per-round summary.
- **Carry-forward** — a file unchanged by size, inode and ctime is not
  re-read. It is recorded as `carried_forward` with `acquired_in_round`, so
  carried evidence is never rendered as a fresh acquisition. `--recollect`
  forces a full re-read when that assumption is itself in question.
- **Append-aware storage** — a transcript that only grew stores just the
  new tail, after proving the earlier bytes still hash to what was
  preserved. `artifact_id` remains the SHA-256 of the full plaintext, and
  `verify` streams the chunks and checks the concatenation.
- **Parallel acquisition** — a bounded worker pool (`--jobs`, default CPUs
  capped at 8) does the I/O; discovery stays serial and decides everything
  that affects *what* is collected, and results commit in discovery order.
  A parallel run produces a byte-identical manifest to a serial one, which
  is covered by a test.
- **Stable case location** — `run` with no `--out` writes to one case per
  host/user under `$AGENTDFIR_HOME` (default `~/.agentdfir`,
  `%LOCALAPPDATA%\AgentDFIR` on Windows), so the directory you happen to be
  standing in no longer decides whether you get a new multi-gigabyte copy.
  `--out` keeps the old explicit behavior; `--new` forces a fresh case.
- **Shared blob store** — identical bytes are stored once per machine and
  hardlinked into each case, so a case directory stays self-contained for
  `cp -a`, `tar` and `export`. `agentdfir store status` and
  `agentdfir store gc [--delete]` report and reclaim blobs no case
  references any more. `--no-share` disables sharing.
- **Quick verification depth** — `casepkg.VerifyQuick` checks the seal over
  the small sealed files, both hash chains end to end, the manifest
  cross-check and every blob's presence. The explorer uses it so opening a
  case is instant, and offers the full check on demand (`/api/verify`);
  `agentdfir verify` still runs the full re-hash and now reports its depth,
  the round count and how many artifacts were carried forward.
- **Collection policy for vendored subtrees** — `node_modules/` and `.git/`
  under agent plugin directories are recorded as `SKIPPED_BY_POLICY` with
  their file count and byte total rather than collected. The exclusion is
  visible in the manifest and reversible with `--full-plugins`.
- Benchmarks for ingest (compressed vs plain), sealing, both verification
  depths and an unchanged second round: `go test ./internal/casepkg -bench .`

### Changed
- `manifest.json` (a single JSON array) is now `manifest.jsonl`: a header
  line plus one record per line, appendable and streamable. Both forms are
  read; the eight duplicated manifest readers across the codebase now
  delegate to one implementation.
- Every read of evidence goes through `casepkg.Store` instead of joining
  `raw/<sha256>` in twenty places, so the on-disk representation is no
  longer part of every package's API.
- Sealing reuses hashes computed while writing instead of re-reading every
  blob it just hashed.
- `adfir` package format version 0.1 → 0.2.

### Security
- **Content, not filenames, decides reuse.** Dedupe previously trusted a
  blob because a file of that name existed. With a persistent shared store
  that would let anything able to write into the store pre-place a file
  under the hash of evidence it expects to be collected and have that
  substituted for the real bytes. Stored bytes are now verified before
  being reused, in the package and in the shared store.
- **The lstat→open window is closed.** Evidence lives in directories the
  agent — and anything that compromised it — can write. Sources are opened
  `O_NOFOLLOW` and the descriptor is confirmed to be the object `lstat`
  classified; a mismatch is recorded as an error, never ingested.
- **One writer per package.** Nothing previously stopped two collections
  writing the same package and interleaving lines into the hash chains. A
  collect→seal cycle now holds an exclusive lock; a lock whose owner is
  gone is reclaimed, a live one is never stolen.
- **Unchanged means unchanged.** Incremental collection judges identity on
  ctime and inode, never mtime alone, which an unprivileged writer can set
  at will. An mtime later than ctime is itself recorded.
- **Appending to a broken chain is refused.** `hashchain.NewAppender`
  verifies the entire existing chain before writing a byte; extending a
  broken chain would hide the break behind a valid-looking tail.
- **Decompression is bounded** by the recorded plaintext size and fails
  closed, before a hostile or tampered blob could expand.
- **The evidence home is checked before use** — refused if it is a symlink,
  not a directory, not owned by the current user, or group/world-writable.
  Home and store are 0700, stored blobs 0400. One directory now aggregates
  every transcript collected on the machine; see `SECURITY.md`.

### Platform notes
- `store gc` cannot prove a blob is unreferenced on Windows, where
  `os.FileInfo` carries no link count. It reports that plainly and removes
  nothing rather than guessing: refusing to reclaim disk is a much smaller
  failure than deleting evidence a case still points at.
- Carry-forward (skipping the re-read of an unchanged file) needs a change
  time an unprivileged writer cannot set. Unix has `ctime`; Windows exposes
  neither a change time nor a file index through `os.FileInfo`, so Windows
  re-reads its sources every round rather than guessing from creation or
  write time. That costs read time, not storage: unchanged files hash to
  the same content address and dedupe against what the package already
  holds, and a transcript that only grew still stores just its new tail.
  Compression, deduplication, cross-case sharing, rounds, parallelism and
  append-aware storage are identical on all three platforms.

### Known limitations
- Analysis still re-normalizes the whole package after a collection round
  rather than only the artifacts that changed. It is faster than before
  (it now reads compressed blobs), but incremental normalization needs
  per-artifact segmentation of the events overlay and cross-artifact entity
  state, and was deliberately left out of this release rather than risking
  the detection path.

## [1.0.0] — 2026-09-17

The investigation release. Findings stop being a list and become a story:
which session, which chain of steps, what led to each step, and what the
analyst concluded. Every existing command and file format is unchanged; the
`.adfir` package gains one optional directory (`notes/`) outside the sealed zone.

### Added
- **Attack chains (toxic combinations)** — `internal/chain`: ordered sequences
  of events inside one session or one agent's lineage, matched within a time
  window, built on the existing findings instead of re-deriving them. Eight
  built-ins ship (injection → self-modification → shell; secret access → upload;
  orphan agent → config change → tool use; poisoned MCP result → destructive
  command; injection → commit → push; download → execute; action → log
  deletion; spawn → cross-session message → outbound transfer). A match is one
  finding whose `chain_steps` list the exact events in order. Extra chains load
  from `*.chains.json` in the rule-pack directory (`analyze --rules`), validated
  like rules (`rules validate`). All chains are in the catalog, `rules list`
  and the coverage matrix (now 140 rules).
- **Sessions tab** in the explorer — the new landing view: a case strip
  (sessions, agents, events, critical+high, attack chains, contradicted,
  reviewed) and one card per session sorted by risk: product, first prompt,
  duration, prompts / tool calls / agents / files / destinations / MCP servers,
  corroboration bar, worst severity, chain titles, tags. Click opens the
  timeline filtered to that session with a metadata header. `GET /api/sessions`.
- **How it happened — the investigation tree** under every finding: for a
  chain, the steps in order; for any other finding, the evidence events. Under
  each event: the human prompt before it, the tool result the agent had just
  consumed, the spawn that created the agent, the message a parent sent to a
  subagent, the result the call returned. Every node opens the raw line;
  "what led here" walks further back. `GET /api/chain?finding=<i>|event=<id>`.
- **Search everything** — `Ctrl+K` / `Cmd+K`: every field of every event,
  every finding, and the raw bytes of every sealed artifact (streaming
  parallel scan, RE2 regex or literal, case option, 20 s / 500-hit budget,
  binary artifacts skipped). Raw hits map back to the event on that line.
  `GET /api/search`.
- **Case file (analyst notes)** — verdicts on findings (true positive / false
  positive / needs review) with notes, pinned key-evidence events, session
  tags and free notes. Appended to `<pkg>/notes/notes.jsonl` as a hash chain
  (same construction as the custody log), attributed to the OS user, outside
  the sealed evidence zone. The only write endpoint (`POST /api/notes`) is
  same-origin only and refuses everything else. HTML and PDF reports gain an
  *Analyst Investigation* section (verdicts, pinned evidence, tags, notes) and
  render chain steps under each chain finding; JSON reports carry `notes`.
- Deep links in the explorer: `#findings/<index>`, `#search/<query>`,
  `#session/<id>`, `#event/<id>`.
- `simulate --scenario toxic-chain`: a synthetic session where a fetched web
  page rewrites the agent's settings, credentials are read and uploaded, and
  logs are deleted — exercises three chains end to end.
- `schema.Finding.chain_steps` (optional) and `schema.ChainStep`.

### Changed
- Findings tab: filters by severity, attack chains only, verdict and text;
  chain findings show their steps inline; false positives are dimmed.
- Explorer detail panes: "pin as key evidence" and "what led here" on every
  event; analyst notes shown next to the event.
- `analyze` runs the chain stage after every other stage and reports
  "Attack chains: N evaluated, M matched"; `analysis.json` records `chains`.
- Help text and docs describe the explorer as sessions · attack chains ·
  timeline · raw evidence · search · case notes.

### Fixed
- Release workflow's tap-version check no longer trips on the `.tar.gz` suffix
  (it read `v0.16.0.`); the tap update itself was already succeeding via the
  deploy key.

## [0.16.0] — 2026-09-17

### Added
- **`install.ps1`** — Windows installer for the same one-line install-and-run
  as macOS / Linux: `irm https://raw.githubusercontent.com/efij/AgentDFIR/main/install.ps1 | iex; agentdfir run`.
  Detects x64 / ARM64, verifies SHA256, installs to `%LOCALAPPDATA%\agentdfir\bin`,
  adds it to the user PATH and the current session. PowerShell 5.1 and 7.
- **Windows ARM64** release assets (`agentdfir-vX.Y.Z-windows-arm64.exe` and `.zip`).
- `agentdfir run` shows a live status line while collecting (per agent:
  artifacts, bytes, elapsed), sealing, analyzing and loading the explorer, so
  long steps on big homes no longer look hung. Terminal only; silent in pipes.

### Changed
- README, install guide and website show one line per OS (macOS / Linux, Windows).
- Release `verify` on Windows checksums both Windows CPUs and runs `install.ps1`
  against the published release; CI smoke-tests `install.ps1` on `windows-latest`
  with both binaries built locally.

### Fixed
- Release workflow updates the Homebrew tap with a write deploy key
  (`HOMEBREW_TAP_SSH_KEY`), no personal token needed; `scripts/update-tap.sh`
  accepts `TAP_SSH_KEY`. `HOMEBREW_TAP_TOKEN` still works as a fallback.

## [0.15.0] — 2026-09-17

### Added
- **`agentdfir run`** — the whole workflow in one command for the common case
  (this machine, this user): detect every installed AI agent, collect all of
  them into one sealed `.adfir` package, analyze it, open the case explorer in
  the browser. Each step calls the same code as `detect` / `collect` /
  `analyze` / `serve`, which are unchanged. Flags: `--product`, `--out`,
  `--case-id`, `--operator`, `--authorization`, `--max-file-mb`, `--sign`,
  `--endpoint`, `--gateway-log`, `--port`, `--no-open`, `--no-serve` (print
  the findings and stop; exit 3 when anything above INFO was found).
- One-line install-and-run for macOS / Linux in the README, the install guide
  and on the website.

### Changed
- Help text, README and website lead with `run`; the four individual steps
  stay documented right below it.
- GitHub repository description and homepage link to
  https://efij.github.io/AgentDFIR/.

## [0.14.0] — 2026-09-03

Detection coverage release: every HIGH/CRITICAL detection now maps to MITRE
ATLAS 5.6 and/or ATT&CK, the agentic ATLAS technique family is covered, and the
mapping is enforced by tests.

### Added
- **40 community-pack rules** (v3, 77 rules total; 58 HIGH/CRITICAL) covering the
  MITRE ATLAS agentic techniques and the ATT&CK gaps: agent credential-store
  access (`AGENT_CREDENTIAL_STORE_ACCESS`, AML.T0083), agent config written via
  shell / MCP server added by the agent / nested agent launched with permission
  bypass (AML.T0081, AML.T0103), instruction files populated from remote content
  and standing instructions that order network activity (`MEMORY_INSTRUCTION_CALLOUT`,
  AML.T0080.000), exfiltration via tool invocation (cloud storage upload, scp/rsync
  to remote, curl file upload, git push to URL — AML.T0086), jailbreak templates,
  system-prompt extraction, prompt self-replication and chat-template role-marker
  smuggling (AML.T0054/T0056/T0061/T0051.001), agent config discovery (AML.T0084.001),
  unsafe AI artifact deserialization and package-from-URL installs (AML.T0011),
  OS credential dumping toolkit (CRITICAL, AML.T0090), bulk file encryption
  (CRITICAL, T1486), persistence (shell rc, systemd/launchd/Windows services,
  Run keys, scheduled tasks, git hooks, SUID, kernel modules), PowerShell encoded /
  remote execution, Windows Defender/firewall weakening, cloud IAM persistence and
  cloud audit-log disabling, privileged Kubernetes workloads, database dumps,
  toolchain credential files, SSH private-key reads, cryptominers, timestomp
  commands, secrets in URLs and echoed secret env vars. Every rule ships with a
  hit/miss sample table (`internal/rulepack/mitre_test.go`).
- **`mitre_atlas` on existing pack rules** where a valid technique exists (22 rules,
  e.g. `REVERSE_SHELL` → AML.T0072 Reverse Shell, `MCP_UNPINNED_PACKAGE` → AML.T0010.005).
- **Built-in rule catalog** (`internal/catalog`): machine-readable index of all 51
  built-in rules across detect / mcpaudit / provenance / correlate with their
  MITRE mapping; a test fails the build if a `RuleID` appears in source without a
  catalog entry or vice versa.
- **`agentdfir rules list [--packs dir] [--json]`**: every detection with severity,
  surface, ATT&CK and ATLAS (with technique name).
- **`docs/detection-coverage.md`**: generated matrix (ATLAS technique → rules,
  ATT&CK technique → rules, full table) via `scripts/coverage-matrix.sh`.
- **Embedded MITRE ATLAS 5.6.0 technique table** (`internal/rulepack/atlas_ids.go`,
  regenerated by `scripts/gen-atlas-ids.sh`); `rulepack.ValidATLAS` / `ATLASName`.
  Tests reject any `mitre_atlas` that is not a real technique.

### Changed
- Built-in mappings updated to the ATLAS 5.x agentic techniques:
  `MCP_TOOL_POISONING` → AML.T0099 (AI Agent Tool Data Poisoning),
  `TOOL_POISONING_INDICATOR` and `MCP_TOOL_DESCRIPTION_POISONING` → AML.T0110
  (AI Agent Tool Poisoning), `AGENT_CONTEXT_POISONING` and
  `INSTRUCTION_FROM_TOOL_RESULT` → AML.T0080.000 (AI Agent Context Poisoning:
  Memory), `INVISIBLE_UNICODE_INSTRUCTION` → AML.T0068 (LLM Prompt Obfuscation).
  ATLAS added to `DESTRUCTIVE_COMMAND` (AML.T0101), `POTENTIAL_DATA_EXFILTRATION`
  (AML.T0086), `AGENT_SELF_MODIFICATION` / `PERMISSION_BYPASS_ENABLED` /
  `PERMISSION_ESCALATION` (AML.T0081), `SENSITIVE_FILE_READ` / `SECRET_ACCESS`
  (AML.T0055), `UNEXPECTED_NETWORK_DESTINATION` metadata variant (AML.T0075),
  `AGENT_SPAWN_EXPLOSION` (AML.T0034.002), `SHELL_EXECUTION` (T1059 / AML.T0050).
- Starter pack v2 carries `mitre_atlas`; `PACKAGE_PUBLISH` refined to T1195.002,
  `MCP_AUTO_APPROVE_ALL` / `MCP_WILDCARD_PERMISSIONS` gain T1562.001.

## [0.13.0] — 2026-09-03

### Added
- **`agentdfir analyze <pkg>`** — one command runs every analysis stage in the
  right order: normalize (only when the overlay is missing or the package is
  newer), endpoint correlation (`--endpoint`, `--shell-history`), detections,
  rule packs, MCP audit (+ `--gateway-log`), instruction provenance; writes one
  consistent `detections/` set plus `analysis.json`. `triage` is the same command.
  `serve`, `investigate` and `report` now run this analysis automatically when
  results are missing or stale and render the SAME run — no more "run X and
  reload", no recomputation with different states. Single-stage commands
  (`correlate`, `mcp audit`, `provenance`, `normalize`) remain for scripting.

### Changed
- Help text reorganized by workflow step (detect → collect → analyze → look →
  export; before-an-incident; trust & keys) in plain language.
- Findings file is de-duplicated and severity-sorted across all stages.

### Fixed
- Re-running analysis without endpoint logs no longer discards earlier
  CORROBORATED/CONTRADICTED states or correlation findings; a re-parse
  (`--renormalize`, or a package sealed after the overlay) invalidates them
  explicitly instead of silently.
## [0.12.1] — 2026-09-02

Distribution-only release. No runtime code changes.

### Added
- **Portable raw binaries** as release assets (`agentdfir-vX.Y.Z-<os>-<arch>[.exe]`),
  uncompressed, for USB / air-gap use. Archives are still published; Windows now
  ships as `.zip` instead of `.tar.gz`.
- **Sigstore provenance**: every asset and `SHA256SUMS.txt` is signed keylessly by
  the release workflow (GitHub OIDC) with an offline-verifiable `.sigstore.json`
  bundle. `cosign verify-blob --offline` works on an air-gapped machine.
- **`install.sh`** (`curl -fsSL …/install.sh | sh`): OS/arch detection, SHA256
  verification, installs to `~/.local/bin`. No macOS Gatekeeper dialog because
  curl never sets the quarantine flag.
- **Homebrew tap**: `brew install efij/agentdfir/agentdfir`
  ([efij/homebrew-agentdfir](https://github.com/efij/homebrew-agentdfir)),
  refreshed by the release workflow via `scripts/update-tap.sh`.
- **`docs/install.md`**: every install path, air-gap first, with an honest
  explanation of the macOS Gatekeeper ("Apple could not verify…") and Windows
  SmartScreen prompts on unsigned browser downloads and the one-step fix for each.

### Changed
- **Release verification now exercises the user path.** A `verify` job on
  macOS, Linux and Windows downloads the *published* assets, checks SHA256 and
  cosign bundles, stamps the macOS quarantine flag / Windows mark-of-the-web,
  and runs the documented steps. CI gained a `release-smoke` job that builds the
  asset layout and runs `install.sh` and the Gatekeeper path on every PR.
  Previously the release was validated with `curl` only, which never triggers
  either OS gate.
- Release build logic moved to `scripts/release-build.sh`, shared by the
  release workflow, CI and local testing.
- Release publishing uses the `gh` CLI instead of a marketplace action:
  idempotent on re-run, sequential uploads, and the published asset count is
  asserted before the draft goes live. `verify` can be dispatched manually
  against an existing tag.

## [0.12.0] — 2026-09-02

### Added
- **Case explorer** (`agentdfir serve <pkg> [--port N] [--open]`): local browser UI
  from the single binary — sessions/agents tree with orphan and subagent badges,
  paginated timeline with text/type/state filters and a per-minute density
  scrubber, evidence pane showing the event and its raw transcript line, findings
  sorted by severity with jump-to-evidence, SVG agent topology, and MCP audit /
  provenance / endpoint-corroboration panels when present. Binds 127.0.0.1 only,
  GET-only, CSP `default-src 'none'` (no external resources), loopback `Host`
  check against DNS rebinding, server-side sanitization of every evidence string,
  never writes to the package. Docs: `docs/serve.md`.

## [0.11.0] — 2026-09-02

### Added
- **Container / CI / cloud-agent collection**: `collect --docker <container|export.tar>`
  snapshots a container via `docker export` (read-only, nothing runs inside;
  `AGENTDFIR_DOCKER=podman` supported) and keeps only agent homes/config/repo
  agent files while streaming; `collect --archive <zip|tar|tar.gz>` unpacks CI
  artifacts, support bundles and vendor exports with traversal refusal, symlink/
  device skipping and size bounds. Both feed the import-tree collector; archives
  without a profile layout preserve every JSON/JSONL as `archive.sessions`
  (product `ci-archive`). Vendor `conversations.json` exports (Claude.ai and
  ChatGPT shapes) parse into human_prompt/model_response events (REPORTED).
  case.json records mode, source reference and SHA-256. Docs:
  `docs/container-ci-collection.md`.

## [0.10.0] — 2026-09-02

### Added
- **Instruction & memory provenance** (`agentdfir provenance <pkg> [file] [--json] [--all-lines]`):
  per-line attribution of instruction/memory/config files (CLAUDE.md, AGENTS.md,
  .cursorrules, .clinerules, GEMINI.md, settings, hooks, memory) to the write that
  produced each line — session, agent, tool, time, evidence ref — and its TRIGGER:
  human prompt vs tool result (web/file/MCP content → the injection → persistence
  path); nearest human prompt kept as context. Content is re-read from the sealed
  transcript line: Claude Write/Edit/MultiEdit/NotebookEdit, Codex apply_patch,
  Cline/Roo write_to_file/replace_in_file, generic path+content tool inputs
  (incl. stringified OpenAI arguments), shell redirects and heredocs. Writes to
  instruction-like paths whose file was not collected are listed with snippets.
  Findings: INSTRUCTION_FROM_TOOL_RESULT, INSTRUCTION_INJECTION_PHRASE,
  INSTRUCTION_WRITTEN_BY_SUBAGENT, INSTRUCTION_FILE_WRITTEN_BY_AGENT.
  Output: console, `--json`, `detections/provenance.json`. Docs: `docs/provenance.md`.
- Claude parser: MultiEdit and NotebookEdit recognized as file edits.

## [0.9.0] — 2026-09-02

### Added
- **Real-time detection** (`monitor --detect [--alert <target>]...`): the read-only
  transcript tail now normalizes each new line (Claude Code, Codex, genericchat/
  pack JSONL products; product inferred from root, path or line shape) and runs
  the streaming per-event and sequence rules live — sensitive reads, exfil
  sequences, destructive commands, network destinations, self-modification, log
  deletion, MCP result poisoning, cross-session messaging, spawn explosion,
  trace gaps — plus honeytokens and injection phrases in live content. Findings
  are pushed within one poll interval to webhook (JSON POST, 5 s timeout, retry,
  bounded queue), syslog (RFC 5424 UDP/TCP), JSONL file or stdout; repeatable
  `--alert`, `--min-severity`, `--honeytokens`, `--known-destinations`, `--quiet`.
  Existing content never alerts; evidence refs carry real line numbers.
  `detect.NewLive` / `Live.Eval` expose the single-pass evaluator; parsers gain
  `NewLive(...).Line(...)`. Docs: `docs/realtime-detection.md`.

## [0.8.0] — 2026-09-02

### Added
- **Endpoint corroboration** (`agentdfir correlate <pkg> <os-log>...`, `triage --endpoint`):
  OS telemetry as the second witness. Adapters: auditd (SYSCALL/EXECVE/CWD/PATH/
  SOCKADDR grouped by msg id, hex args, AF_INET/6), Sysmon XML export (events 1/3/
  11/23/2), generic JSONL/CSV exports (Velociraptor, osquery, evtx_dump JSON, macOS
  eslogger — nested JSON flattened, field aliases). Format sniffed per file.
  Tool calls matched to process/file/network records within ±3 s (equality,
  shell-wrapper containment, program + token overlap, compound segments) →
  CORROBORATED with an evidence note; unmatched commands inside process-telemetry
  coverage → CONTRADICTED + ENDPOINT_CONTRADICTED_COMMAND; agent-lineage records
  (parent image or pid-tree ancestor is an agent binary) with no transcript
  counterpart → UNLOGGED_AGENT_ACTIVITY (grouped per program) and
  UNLOGGED_AGENT_NETWORK (non-allowlisted destinations). Outside coverage → UNKNOWN,
  never contradicted. States persisted to `normalized/events.jsonl`; summary +
  findings in `detections/corroboration.json`; `triage` merges them.
  Docs: `docs/endpoint-corroboration.md`.

### Changed
- Findings now carry `endpoint_corroboration` = the event's state when correlation
  raised or contradicted it (was always UNKNOWN).
- `triage` accepts the package before or after flags.

### Fixed
- `triage --shell-history` corroboration states were computed but never written
  back to the overlay; they are now persisted.

## [0.7.0] — 2026-09-02

### Added
- **MCP supply-chain audit** (`agentdfir mcp audit [<pkg>|--profile <root>]`):
  read-only inventory of every MCP server configured for Claude Code, Claude
  Desktop, Cursor, VS Code/Copilot Chat, Copilot CLI, Cline, Roo Code, Gemini CLI,
  OpenCode and Codex (JSON, JSONC and a TOML subset), normalized to transport,
  command/URL, package reference + pinning, resolved binary hash (live mode),
  env/header key names (values never recorded), auto-approve lists and declared
  tools. Structural findings: UNPINNED_MCP_PACKAGE, INSECURE_MCP_TRANSPORT,
  MCP_AUTO_APPROVE, MCP_SECRET_IN_CONFIG, MCP_REMOTE_FETCH_COMMAND,
  MCP_NAME_COLLISION, MCP_PROJECT_SCOPED_SERVER, MCP_TOOL_DESCRIPTION_POISONING
  (declared and cached tool manifests), MCP_ALL_PROJECT_SERVERS_TRUSTED,
  MCP_WILDCARD_TOOL_PERMISSION. `--write-baseline` / `--baseline` add
  MCP_SERVER_ADDED / REMOVED / CHANGED. Package mode writes
  `detections/mcp-audit.json`; exit code 3 when non-INFO findings exist.
- **MCP gateway correlation** (`--gateway-log <jsonl> [--gateway-map] [--gateway-server]`):
  the gateway's own log becomes a second witness — calls matched by id or tool+time
  (±2 s) are CORROBORATED; MCP_GATEWAY_UNLOGGED_CALL, MCP_GATEWAY_CONTRADICTED_CALL
  (status CONTRADICTED), MCP_GATEWAY_DENIED_CALL, MCP_GATEWAY_BACKEND_ERRORS; summary
  with backends seen and p95 latency. Any vendor export fits via a field map.
- `detect.InjectionPhrase` and `detect.SecretKind` exported so the audit shares the
  same conservative vocabularies as transcript detections.
  Docs: `docs/mcp-audit.md`.

## [0.6.0] — 2026-09-02

### Added
- **Product packs** (`agentdfir packs list|validate|add|remove|init`): add a new AI
  agent product with one signed JSON file — detection entry, collector manifest and
  parser binding — no Go change. Optional `field_map` (dot-paths) normalizes custom
  transcript shapes through the tolerant `genericchat` engine; roles map to the
  REPORTED/OBSERVED split, tool calls yield the command every rule inspects,
  epoch timestamps are converted. Packs load only when their detached ed25519
  signature verifies against `trusted.pub`; `AGENTDFIR_ALLOW_UNSIGNED_PACKS=1`
  permits unsigned packs for development, and `case.json` records the pack path,
  SHA-256 and signed state. Unknown keys, `..`/absolute paths, unrooted paths and
  built-in ID shadowing are rejected with author-facing messages.
  Docs: `docs/product-packs.md`.
- **SIEM/SOC interop**: `report --format ocsf` writes OCSF 1.3 JSON lines
  (Process Activity / File System Activity / API Activity for events, Detection
  Finding for findings, forensic fields under `unmapped.agentdfir.*`);
  `report --format sarif` writes SARIF 2.1.0 with per-rule MITRE properties and
  evidence path/line locations; `rules export --sigma <dir>` converts declarative
  rule packs to Sigma YAML (command rules → `process_creation`/`CommandLine`,
  portable to EDR telemetry). `report` now accepts the package before or after
  flags. Docs: `docs/siem-interop.md`.
- **DFIR-tool interop**: `collect --import <tree>` discovers every user profile in a
  KAPE / Velociraptor / CyLR / image tree and collects all products for all users
  into one sealed package (all-platform manifests, per-profile user attribution,
  `mode=import-tree`). `report --format timesketch` (Timesketch JSONL) and
  `--format l2tcsv` (17-column log2timeline CSV) export the unified timeline for
  Timesketch, Plaso workflows, Autopsy and Magnet; undated events are counted, not
  dropped silently. `report` rejects unknown formats instead of writing nothing.
  Docs: `docs/dfir-interop.md`.
- **PDF report** (`report --format pdf`): self-contained `report.pdf` from a
  standard-library PDF 1.4 writer (core fonts, no embedding, no dependencies).
  Sections: case summary, package integrity (verify result + seal signature state),
  findings sorted by severity with MITRE IDs, corroboration status and evidence
  references, timeline excerpt, artifact inventory, chain-of-custody records.
  Evidence strings are sanitized then PDF-escaped; runes outside the core-font set
  are shown as `?` and counted in the report and on the console, never dropped
  silently. Structure verified by re-parsing the xref table in tests and by
  `qpdf --check`.
- Community rule pack v2: 37 rules (was 12), 26 HIGH/CRITICAL, 14 high-confidence.
  New coverage: bind shells, sudoers NOPASSWD, account creation, EDR/audit
  disable, OS-log tampering, LD_PRELOAD injection, cloud/kube/git/browser/shadow/
  lsass credential access, credential-dir archiving, webhook/collaborator and
  DNS-tunnel exfil, Tor/proxychains, port scanning, Terraform state, clipboard,
  insecure MCP transport, MCP auto-approve, remote-fetching config hooks,
  unpinned MCP packages. Every rule carries MITRE ATT&CK where a valid technique
  exists and OWASP LLM/Agentic references; none shadow built-in detect rules.
- Regression test: shipped packs must load, have unique IDs, and never collide
  with built-in rule IDs.

## [0.5.1] — 2026-09-02

Streaming analysis pipeline. Closes the memory gap noted in 0.5.0: analysis
memory is now bounded by session/agent/artifact count, not event count.

### Changed
- Parsers emit events through a sink instead of accumulating them; normalize
  streams events straight to the overlay; `triage` detection re-reads the
  overlay in two bounded passes (`detect.RunStream`).
- Measured: full 24-rule triage of a 400k-event / 100 MB package went from
  ~1.23 GB RSS to ~18 MB RSS (collection was already streaming). Wall time is
  unchanged (~20 s) — it is rule-CPU-bound, not memory-bound, and multi-GB
  packages no longer risk OOM.
- A stream/in-memory equivalence test guarantees `RunStream` produces exactly
  the same findings as the in-memory `RunAll`.

### Notes
- Optional `triage --shell-history` and `--rules` still load full events on
  demand (they need them); the default path stays bounded.

## [0.5.0] — 2026-09-02

Analysis hardening. Completes the plan §14 detection set, fixes a large-
evidence scanning blind spot, and deepens MITRE mapping.

### Added
- 17 detection rules completing §14: UNEXPECTED_AGENT_RESUME, UNEXPECTED_TASK,
  AGENT_IDENTITY_MISMATCH, AGENT_CONTEXT_POISONING, TOOL_POISONING_INDICATOR,
  MCP_TOOL_POISONING, PERMISSION_ESCALATION, SENSITIVE_FILE_READ,
  UNEXPECTED_NETWORK_DESTINATION, POTENTIAL_DATA_EXFILTRATION (sequence-aware),
  AGENT_GENERATED_COMMIT, AGENT_GENERATED_PUSH, AGENT_SPAWN_EXPLOSION,
  LOG_DELETION, SESSION_TAMPERING, AGENT_SELF_MODIFICATION, TIMESTOMP_INDICATOR.
  Full §14 coverage: 36/36.
- `internal/netdest`: network-destination extraction from agent commands;
  normalize enriches events with `network_destination`; cloud-metadata
  endpoint detection.
- `agentdfir rules validate <dir>` — loader-based rule-pack validation.
- Community rule pack (12 mapped rules: reverse shells, curl|sh, base64|sh,
  cloud metadata, ssh key writes, cron/persistence, history clearing, chmod
  777, firewall disable, package publish, disk wipe, env exfil).
- `triage --spawn-threshold` and `--known-destinations`.

### Changed
- Content scans (secrets, injection, invisible-Unicode, honeytokens,
  poisoning) now STREAM in bounded memory — previously any artifact over
  16 MiB was silently skipped. Verified against a 20 MB transcript with a
  tail-end secret.
- `triage` parses the package once (was twice).
- HTML reports cap timeline/inventory rows (default 2000) with a pointer to
  the full JSONL/CSV — large cases no longer produce unusable reports.
- MITRE depth: added AML.T0053 (plugin/tool compromise), AML.T0057 (LLM data
  leakage), and precise ATT&CK IDs (T1041, T1070.x, T1552.x, T1562.x, T1565,
  T1071). Mappings only where a valid technique exists.

### Performance
- Collection remains streaming (100 MB in ~1.2 s, ~7 MB RSS). Full 24-rule
  triage of a 400k-event / 100 MB package is a batch operation (~20 s,
  ~1.1 GB RSS); the SQLite analysis cache (design D6) remains the documented
  path for multi-GB packages.

## [0.4.0] — 2026-09-01

Broadens product coverage to twelve AI agents. Adds OpenCode, VS Code
Copilot Chat, Aider and Warp — full detect/collect/normalize/detection
support.

### Added
- **OpenCode** (SST): storage/session, storage/message and storage/part
  files (per-message and per-part JSON); tool parts extract shell
  commands; auth.json collected as critical.
- **Copilot Chat (VS Code)**: workspaceStorage `chatSessions` /
  `chatEditingSessions` — the `requests[]` request/response format; the
  important Copilot surface beyond the CLI we already covered.
- **Aider**: repo-local evidence — `.aider.chat.history.md` (markdown
  chat log: `#### ` user turns vs assistant narrative) and
  `.aider.input.history` (timestamped prompts). Collect with
  `--path <repo>`.
- **Warp**: `warp.sqlite` AI blocks via JSON-fragment carving.
- Collector now globs directories mid-pattern (e.g.
  `workspaceStorage/*/chatSessions/**`), enabling per-workspace VS Code
  layouts.

### Notes
- OpenCode/Copilot-Chat parse structured JSON; Warp uses carving
  (content presence, not DB ordering). Same evidence-vs-claims discipline
  throughout: REPORTED narrative, OBSERVED tool records, TRACE_GAP for
  unparseable input.

## [0.3.0] — 2026-09-01

Every supported product now has a full parsing pipeline — detect,
collect, normalize, timeline, detections and reports work end to end for
all eight AI agent products.

### Added
- `genericchat` parser: Gemini CLI (API-style `parts` with
  `functionCall`/`functionResponse`, `logs.json`, checkpoints), Cline and
  Roo Code (Anthropic-style `api_conversation_history.json`, XML-style
  `<execute_command>` tool extraction, `ui_messages.json`), Copilot CLI
  (OpenAI-style `tool_calls`), OpenClaw (JSONL messages).
- Cursor `store.db` support via deterministic JSON fragment carving —
  recovered messages are explicitly marked `carved` so analysts can
  weigh them; carving proves content presence, not database ordering.
- Shell-command extraction across all styles (`run_shell_command`,
  `execute_command`, `bash`, XML tool text), feeding the same
  DESTRUCTIVE_COMMAND / rule-pack / correlation machinery.

### Notes
- The same evidence-vs-claims discipline applies to every product:
  model narrative is REPORTED, tool records are OBSERVED, and
  unparseable regions become TRACE_GAP evidence — never silent skips.

## [0.2.0] — 2026-09-01

Completes the OSS plan surface: analyst interaction, live monitoring,
declarative rule packs, signed knowledge packs, and injection-surface
detections.

### Added
- `investigate` — interactive, read-only case explorer (findings, agents,
  sessions, tools, MCP, timeline pivots, per-event detail).
- `replay` — step through a session's prompt → tool call → result → claim
  sequence with corroboration states inline.
- `monitor` — live, read-only watch of agent session directories: emits
  tool calls and messages as they land; flags truncation/rewrites; never
  touches the observed agents.
- `explain` — deterministic case digest (no AI, nothing transmitted);
  `--prompt-out` writes a reviewed-before-use analysis prompt for an
  analyst's own LLM.
- Declarative JSON rule packs (`triage --rules <dir>`): community-shareable
  detections over commands, summaries, configs and transcripts; mandatory
  false-positive notes; starter pack in `rules/`; companion repo
  [agentdfir-rules](https://github.com/efij/agentdfir-rules).
- Signed knowledge-pack overrides (`update-packs`, `sign --file`): collector
  manifests updatable without a binary release; ed25519-verified against a
  pinned trusted key; invalid packs are never loaded.
- Detections: `PROMPT_INJECTION_INDICATOR` (MITRE ATLAS AML.T0051),
  `INVISIBLE_UNICODE_INSTRUCTION` (tag/bidi/zero-width smuggling),
  honeytoken `SECRET_ACCESS` (`triage --honeytokens`).

### Fixed
- Parsers now recover past oversized transcript lines (bounded line reader);
  previously a single over-long line aborted the whole parse.


## [0.1.0] — 2026-09-01

First public release. Establishes the evidence foundation, the Claude Code
and Codex CLI collectors, deterministic analysis and detections, reporting,
and interoperability exports.

### Added

**Evidence foundation**
- Sealed `.adfir` evidence package: content-addressed `raw/<sha256>` storage
  with cross-user dedupe, `manifest.json`, `case.json`.
- Hash-chained `collection.jsonl` and `chain-of-custody.jsonl` (tamper-evident
  by construction).
- `SHA256SUMS` sealing the evidence zone; `agentdfir verify` detects any
  modification of evidence, manifests, planted blobs, or hash-chain breaks.
- ed25519 detached package signatures (`keygen`, `sign`, `verify --pubkey`).
- Full-package encryption: AES-256-GCM + PBKDF2-HMAC-SHA256, standard library
  only (`encrypt`/`decrypt`, passphrase via `AGENTDFIR_PASSPHRASE`).

**Acquisition**
- Manifest-driven collector, hardened for hostile hosts: symlinks never
  followed, irregular files skipped-and-recorded, per-artifact/total size
  bounds, hash-while-copy with torn-read detection, every failure recorded.
- `detect` (never executes suspect binaries), `collect` with `--current-user`,
  `--path` (offline image), `--live` (RFC 3227 order of volatility), `--sign`.
- Collectors: Claude Code, Codex CLI; declarative manifests for Cursor,
  Gemini CLI, Copilot CLI, Cline, Roo Code, OpenClaw.

**Analysis**
- Unified, vendor-neutral forensic schema (events, entities, relationships)
  with per-source corroboration states.
- Parsers: Claude Code JSONL, Codex CLI rollout JSONL. Malformed regions
  become `TRACE_GAP` evidence; unparsed artifacts are preserved, never dropped.
- `normalize`, `timeline`, `triage`, `inspect` (secrets redacted by default,
  `--reveal-sensitive` for explicit disclosure).
- Agent relationship graph with evidence-backed edges.
- Endpoint correlation with a pluggable `Adapter` interface; shell-history
  reference adapter upgrades `OBSERVED` tool calls to `CORROBORATED`.

**Detection**
- Deterministic rule engine (no LLM in the analysis path): `ORPHAN_AGENT`,
  `CROSS_SESSION_MESSAGE`, `DESTRUCTIVE_COMMAND`, `SHELL_EXECUTION` (info),
  `TRACE_GAP`, `PERMISSION_BYPASS_ENABLED`, `POTENTIAL_SECRET_EXPOSURE`.
- `diff` and `baseline create|check`: config-drift detection mapped to
  `HOOK_CHANGED`, `SKILL_CHANGED`, `PLUGIN_CHANGED`, `MCP_CONFIG_CHANGED`,
  `UNEXPECTED_MCP_SERVER`, `AGENT_DEFINITION_CHANGED`.

**Reporting & interoperability**
- `report`: self-contained, network-silent HTML (CSP `default-src 'none'`,
  all evidence strings sanitized and escaped), JSON, CSV.
- `export`: STIX 2.1 indicator bundles, OpenTelemetry GenAI log records
  (`gen_ai.*` + `agentdfir.*` namespaces).
- `export --support`: derived redacted support packages with a
  `redaction-manifest.json` (categories/counts/hash bindings, never values);
  originals unmodified, both packages independently verifiable.

**Adversary emulation**
- `simulate --scenario orphan-agent`: synthetic rogue-agent incident generator.

**Deployment & docs**
- KAPE Target/Module and Velociraptor artifact in `deploy/`.
- Published JSON Schemas (event, finding), `.adfir` format spec, and
  compliance capability mappings (ISO/IEC 27037, NIST AI RMF, GDPR, EU AI Act).
- Artifact-reference documentation and a static docs site.

### Security
- Evidence treated as hostile throughout: ANSI/invisible-Unicode neutralization
  on all evidence-derived output; bounded parsers; zip-slip defense on archive
  extraction; secrets never printed by default.

[Unreleased]: https://github.com/efij/AgentDFIR/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/efij/AgentDFIR/compare/v0.16.0...v1.0.0
[0.16.0]: https://github.com/efij/AgentDFIR/compare/v0.15.0...v0.16.0
[0.15.0]: https://github.com/efij/AgentDFIR/compare/v0.14.0...v0.15.0
[0.14.0]: https://github.com/efij/AgentDFIR/compare/v0.13.0...v0.14.0
[0.13.0]: https://github.com/efij/AgentDFIR/compare/v0.12.1...v0.13.0
[0.12.1]: https://github.com/efij/AgentDFIR/compare/v0.12.0...v0.12.1
[0.12.0]: https://github.com/efij/AgentDFIR/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/efij/AgentDFIR/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/efij/AgentDFIR/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/efij/AgentDFIR/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/efij/AgentDFIR/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/efij/AgentDFIR/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/efij/AgentDFIR/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/efij/AgentDFIR/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/efij/AgentDFIR/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/efij/AgentDFIR/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/efij/AgentDFIR/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/efij/AgentDFIR/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/efij/AgentDFIR/releases/tag/v0.1.0
