# Changelog

All notable changes to AgentDFIR are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and the project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/efij/AgentDFIR/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/efij/AgentDFIR/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/efij/AgentDFIR/releases/tag/v0.1.0
