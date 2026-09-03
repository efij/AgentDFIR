<div align="center">

# 🔍 AgentDFIR

**Open-source digital forensics and incident response for AI agents.**

*Collect, preserve, reconstruct and investigate activity from Claude Code, Codex CLI, Cursor, Gemini CLI, Copilot and other AI agents.*

[![CI](https://github.com/efij/AgentDFIR/actions/workflows/ci.yml/badge.svg)](https://github.com/efij/AgentDFIR/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-%E2%89%A51.22-00ADD8?logo=go&logoColor=white)](go.mod)
[![Zero deps](https://img.shields.io/badge/runtime%20deps-zero-brightgreen)](go.mod)

[Website](https://efij.github.io/AgentDFIR/) · [Install](docs/install.md) · [Quick start](#-quick-start) · [Evidence format](#-the-adfir-evidence-package) · [Contributing](CONTRIBUTING.md)

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

## ⚡ Quick start — four steps

**Install** — one static binary, zero runtime dependencies. Full guide with air-gap,
checksum and Sigstore verification steps: [docs/install.md](docs/install.md).

```sh
# Portable, air-gap friendly: grab the raw binary for your OS from the releases page
#   https://github.com/efij/AgentDFIR/releases/latest
# macOS: browser downloads are quarantined; unsigned binaries need this once per file
xattr -d com.apple.quarantine agentdfir-v*-darwin-arm64 && chmod +x agentdfir-v*-darwin-arm64

# Online macOS / Linux, no dialogs (verifies SHA256, installs to ~/.local/bin)
curl -fsSL https://raw.githubusercontent.com/efij/AgentDFIR/main/install.sh | sh

# Homebrew
brew install efij/agentdfir/agentdfir

# Go toolchain
go install github.com/efij/AgentDFIR/cmd/agentdfir@latest

# From source
go build -trimpath -o agentdfir ./cmd/agentdfir
```


```sh
./agentdfir detect                                   # 1. what AI agents are on this machine (never runs them)
./agentdfir collect --product claude                 # 2. sealed, hash-chained evidence package
./agentdfir analyze CASE-2026-042.adfir              # 3. every analysis stage, one command
./agentdfir serve   CASE-2026-042.adfir --open       # 4. browse: agent tree, timeline, raw evidence, findings
```

Add a second witness and the same commands upgrade every finding from *the agent says* to *the OS confirms*:

```sh
./agentdfir analyze CASE-2026-042.adfir --endpoint /var/log/audit/audit.log   # auditd / Sysmon XML / EDR exports
./agentdfir analyze CASE-2026-042.adfir --gateway-log mcp-gateway.jsonl        # your MCP gateway's own log
```

Other ways in: `collect --path <copied home>`, `--import <KAPE/Velociraptor tree>`, `--docker <container>`, `--archive <zip|tar>`.
Other ways out: `report --format pdf|html|ocsf|sarif|timesketch|…`, `rules list --packs rules` (every detection → [MITRE ATLAS / ATT&CK](docs/detection-coverage.md)), `rules export --sigma`. Before an incident: `monitor --detect --alert <url>`, `mcp audit`.
Every command is listed by workflow step in `agentdfir help`.

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
| ✅ | [132 deterministic detections](docs/detection-coverage.md) (51 built-in + 81 pack rules; 88 HIGH/CRITICAL, every one mapped to MITRE ATLAS 5.6 / ATT&CK — 27 ATLAS and 65 ATT&CK techniques): rogue/orphan agents, exfiltration via tool invocation, context/memory/tool/MCP poisoning, agent credential-store theft, agent config modification, jailbreak & system-prompt extraction, secret & sensitive-file access, persistence (rc files, services, run keys, git hooks), credential dumping, bulk encryption, self-modification, log deletion, timestomping, session tampering… `agentdfir rules list` prints the matrix |
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
