<div align="center">

# 🔍 AgentDFIR

**Open-source digital forensics and incident response for AI agents.**

*Collect, preserve, reconstruct and investigate activity from Claude Code, Codex CLI, Cursor, Gemini CLI, Copilot and other AI agents.*

[![CI](https://github.com/efij/AgentDFIR/actions/workflows/ci.yml/badge.svg)](https://github.com/efij/AgentDFIR/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-%E2%89%A51.22-00ADD8?logo=go&logoColor=white)](go.mod)
[![Zero deps](https://img.shields.io/badge/runtime%20deps-zero-brightgreen)](go.mod)

[Website](https://efij.github.io/AgentDFIR/) · [Quick start](#-quick-start) · [Evidence format](#-the-adfir-evidence-package) · [Contributing](CONTRIBUTING.md)

</div>

---

AI coding agents execute shell commands, edit files, spawn subagents, call MCP servers and push code. When something goes wrong — a prompt injection, a poisoned MCP tool, a rogue subagent, quiet data exfiltration — the transcripts and configs they leave on the endpoint are **primary forensic evidence**. Almost no tooling exists to acquire and analyze them properly.

**AgentDFIR is that tooling.** Think KAPE / Velociraptor for the agentic-AI layer. It lets an incident responder answer:

> *Who instructed which AI agent/subagent to perform what action, through which tool/MCP/identity, against which resource — and what evidence proves it?*

## ⚖️ Evidence vs. claims — the core principle

AI-generated text is **never** automatically treated as proof of execution. Every action gets a corroboration state:

| State | Meaning |
|---|---|
| `REQUESTED` | a human asked for it |
| `REPORTED` | the model *said* it happened — narrative, not proof |
| `OBSERVED` | a tool-call record exists in the transcript |
| `CORROBORATED` | independent endpoint/network evidence confirms it |
| `CONTRADICTED` | endpoint evidence shows it did **not** occur |
| `UNKNOWN` | insufficient evidence |

An agent claiming *"I executed curl example.com"* with no matching tool call stays `REPORTED` — and AgentDFIR shows you exactly that.

## ⚡ Quick start

```sh
go build -trimpath -o agentdfir ./cmd/agentdfir

# Discover installed AI tooling — never executes suspect binaries
./agentdfir detect

# Forensic acquisition (lossless, sealed, hash-chained)
./agentdfir collect --product claude --operator "Your Name"

# From an offline image / copied home directory
./agentdfir collect --product claude --path /mnt/image/Users/suspect \
    --case-id CASE-2026-042 --authorization "IR-TICKET-123"

# From a KAPE / Velociraptor / CyLR tree: every product, every user, one package
./agentdfir collect --import /cases/host42/kape-output --case-id CASE-2026-042

# From a container (read-only docker export) or a CI artifact / support bundle / vendor export
./agentdfir collect --docker devcontainer-3a1f
./agentdfir collect --archive copilot-run-9921.zip

# Tamper-evident verification — one flipped byte anywhere fails
./agentdfir verify CASE-2026-042.adfir

# Investigate
./agentdfir timeline CASE-2026-042.adfir     # unified, evidence-linked timeline
./agentdfir triage   CASE-2026-042.adfir     # detections + IR-ready findings
./agentdfir report   CASE-2026-042.adfir --format pdf   # one-file PDF: findings, timeline, custody, integrity

# Train / test / demo with synthetic incidents
./agentdfir simulate --scenario orphan-agent --out demo-profile

# Browser case explorer — agent tree, timeline scrubber, raw evidence, findings (127.0.0.1 only)
./agentdfir serve CASE-2026-042.adfir --open

# Live watch — or a real-time sensor: detections pushed to your SOC within one poll interval
./agentdfir monitor
./agentdfir monitor --detect --alert https://soc.example/hook --honeytokens canaries.txt
./agentdfir investigate CASE-2026-042.adfir
./agentdfir replay --session 9b2d CASE-2026-042.adfir

# Org rule packs + honeytokens
./agentdfir triage --rules ./rules --honeytokens canaries.txt CASE-2026-042.adfir

# Second witness: corroborate the transcript against OS telemetry (auditd / Sysmon / EDR exports)
./agentdfir correlate CASE-2026-042.adfir /var/log/audit/audit.log
./agentdfir triage    CASE-2026-042.adfir --endpoint sysmon.xml

# Who wrote each line of CLAUDE.md / .cursorrules — and did it come from a tool result?
./agentdfir provenance CASE-2026-042.adfir CLAUDE.md

# MCP supply-chain audit: every server, every agent, read-only — plus gateway-log correlation
./agentdfir mcp audit
./agentdfir mcp audit CASE-2026-042.adfir --gateway-log gw.jsonl --gateway-server gateway

# Add a brand-new AI agent product with one signed JSON file — no Go
./agentdfir packs init foo-agent --config-dir .foo && ./agentdfir packs add foo-agent.product.json
```

Example finding:

```
HIGH — Unexpected Agent Activity [ORPHAN_AGENT]
  Session: 9b2d7e3a-…
  Agent:   adad4e2c    Parent: UNKNOWN
  Finding: Agent appeared without a verified parent invocation.
  Related: SendMessage/resume interaction with agent a7c3f19b
  Evidence: .claude/projects/…/agent-adad4e2c.jsonl:1 (artifact 6443bed58e63)
  Status: OBSERVED    Endpoint corroboration: UNKNOWN
```

No auto-escalation to "compromise" or "exfiltration" — findings state exactly what the evidence shows, with clickable references to the raw artifact behind every claim.

## 📦 The `.adfir` evidence package

Every acquisition produces a sealed, self-describing, independently parseable package:

```
case.adfir/
├── raw/<sha256>            content-addressed evidence bytes (deduped)
├── manifest.json           per-artifact metadata + logical paths
├── collection.jsonl        hash-chained collection log
├── chain-of-custody.jsonl  hash-chained custody log
├── case.json               case, operator, timezone/clock metadata
├── SHA256SUMS              covers the sealed zone exactly
├── normalized/             events / entities / relationships (regenerable)
└── detections/             findings.json
```

**Acquisition guarantees:**

- 🔒 **Lossless** — nothing redacted or rewritten at collection time
- #️⃣ **Hash-while-copy** — hashes describe exactly the preserved bytes; torn-read detection for files a live agent is still writing
- 🔗 **Symlinks never followed** — a planted symlink can't pull `~/.ssh` into evidence
- 📝 **Every failure recorded** — access denied, size bounds, irregular files
- 🧾 **Tamper-evident** — hash-chained logs detect edits, deletions and forged appends; `verify` catches a single flipped byte

## 🛡️ Built for hostile evidence

AI incident evidence may *intentionally* contain prompt injection and anti-analysis payloads. Therefore:

- Suspect binaries are **never executed** — not even for `--version`
- Transcript parsers are size-bounded; malformed regions become `TRACE_GAP` findings, never silent skips
- ANSI escapes and invisible Unicode (bidi overrides, zero-width, tag smuggling) are neutralized in **all** evidence-derived output — your terminal is part of the attack surface
- Model text is data, never instructions

## 🚀 Deploy with your existing stack

Ships with wrappers for tools IR teams already run:

- **KAPE** — [`deploy/kape/`](deploy/kape): Target (raw files) + Module (sealed `.adfir` package)
- **Velociraptor** — [`deploy/velociraptor/`](deploy/velociraptor): client artifact invoking `agentdfir collect`
- **Containers, CI, exports** — `collect --docker <container|export.tar>` and `collect --archive <zip|tar|tgz>` ([docs](docs/container-ci-collection.md))
- **Triage-tree import** — `collect --import <tree>` turns any KAPE/Velociraptor/CyLR output or mounted image into one sealed package (all products, all users)
- **Timesketch / Plaso** — `report --format timesketch|l2tcsv` puts the agent timeline next to your host timeline ([docs](docs/dfir-interop.md))

## 🗺️ Roadmap

| Status | Capability |
|---|---|
| ✅ | Sealed `.adfir` packages, hash-chained custody, `verify` |
| ✅ | Claude Code: detect, collect, normalize, timeline, triage |
| ✅ | 36 deterministic detections (full plan set): rogue/orphan agents, exfiltration, context/tool/MCP poisoning, secret & sensitive-file access, self-modification, log deletion, timestomping, session tampering… with MITRE ATLAS/ATT&CK mapping |
| ✅ | `simulate` — synthetic incident generation (adversary emulation for AI agents) |
| ✅ | Full parsers for 12 products: Claude Code, Codex, Gemini CLI, Cursor, Copilot CLI, Copilot Chat (VS Code), Cline, Roo, OpenClaw, OpenCode, Aider, Warp |
| ✅ | [Endpoint corroboration](docs/endpoint-corroboration.md) — auditd, Sysmon XML, Velociraptor/osquery/eslogger/EDR exports: tool calls → CORROBORATED / CONTRADICTED, unlogged agent processes and connections surfaced |
| ✅ | Reports: network-silent HTML, self-contained PDF (stdlib writer, no renderer deps), JSON, CSV, STIX 2.1, OTel · [OCSF 1.3, SARIF 2.1, Sigma export](docs/siem-interop.md) for SIEM/SOC pipelines |
| ✅ | [`serve`](docs/serve.md) — local browser case explorer: agent tree, density-scrubber timeline, raw evidence pane, findings, topology; loopback-only, zero external resources |
| ✅ | `monitor` live watch · [`--detect --alert`](docs/realtime-detection.md) real-time sensor (webhook / syslog / file) · `replay` session step-through · `investigate` explorer |
| ✅ | Declarative rule packs ([agentdfir-rules](https://github.com/efij/agentdfir-rules)) + signed knowledge packs |
| ✅ | Package signing (ed25519), full-package encryption (AES-256-GCM) |
| ✅ | Injection-surface detections: prompt-injection indicators, invisible-Unicode smuggling, honeytokens |
| ✅ | [Instruction provenance](docs/provenance.md) — per-line attribution of CLAUDE.md / AGENTS.md / rules / settings to the session, agent, tool and trigger (human prompt vs tool output) that wrote it |
| ✅ | [MCP supply-chain audit](docs/mcp-audit.md) — inventory of every MCP server across 9 hosts (JSON/JSONC/TOML), unpinned packages, plaintext transports, auto-approve, tool-description poisoning, baseline drift, gateway-log corroboration |
| ✅ | [Product packs](docs/product-packs.md) — add any new AI agent with one signed JSON file (detect + collect + parse), no Go |
| 🔜 | Raw-NTFS/VSS locked-file fallback, EDR/DNS adapters, fleet integrations |

## 🤝 Contributing

Adding a new AI agent product = one [product pack](docs/product-packs.md) (JSON: detection + collector manifest + parser binding) plus a synthetic fixture. No core changes needed. See [CONTRIBUTING.md](CONTRIBUTING.md).

Zero third-party runtime dependencies in the collector core, by policy — a forensic tool should be auditable in an afternoon.

## 📄 License

[MIT](LICENSE) — free forever. Use it, embed it, build on it.
