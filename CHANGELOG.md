# Changelog

All notable changes to AgentDFIR are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/efij/AgentDFIR/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/efij/AgentDFIR/compare/v0.5.1...v0.6.0
[0.5.1]: https://github.com/efij/AgentDFIR/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/efij/AgentDFIR/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/efij/AgentDFIR/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/efij/AgentDFIR/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/efij/AgentDFIR/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/efij/AgentDFIR/releases/tag/v0.1.0
