# AgentDFIR

**Open-source digital forensics and incident response for AI agents.**

Collect, preserve, reconstruct and investigate activity from Claude Code, Codex, Cursor, Gemini, Copilot, OpenClaw and other AI agents.

Think KAPE / Velociraptor for the agentic-AI forensic layer. AgentDFIR lets an incident responder answer:

> Who instructed which AI agent/subagent to perform what action, through which tool/MCP/identity, against which resource, what actually happened on the endpoint, and what evidence proves it?

## Status

Early development. Working today: sealed evidence packages (`.adfir`), product detection, the Claude Code collector, and tamper-evident verification.

## Quick start

```sh
go build -trimpath -o agentdfir ./cmd/agentdfir

# Discover installed AI tooling (never executes suspect binaries)
./agentdfir detect

# Forensic acquisition of Claude Code artifacts for the current user
./agentdfir collect --product claude --operator "Your Name"

# Acquisition from an offline home directory / mounted image
./agentdfir collect --product claude --path /mnt/image/Users/suspect \
    --case-id CASE-2026-042 --authorization "IR-TICKET-123"

# Verify package integrity — detects any modification of evidence,
# manifests, or the hash-chained collection/custody logs
./agentdfir verify CASE-2026-042.adfir
```

## Evidence package (`.adfir`)

Every acquisition produces a sealed, self-describing package:

```
case.adfir/
├── raw/<sha256>            content-addressed evidence bytes (deduped)
├── manifest.json           per-artifact metadata incl. logical paths
├── collection.jsonl        hash-chained collection log
├── chain-of-custody.jsonl  hash-chained custody log
├── case.json               case, operator, timezone/clock metadata
└── SHA256SUMS              covers the sealed zone exactly
```

Acquisition guarantees:

- **Lossless** — nothing is redacted or rewritten at collection time
- **Hash-while-copy** — hashes describe exactly the bytes preserved, with torn-read detection for files being written by live agents
- **Symlinks are never followed** — recorded as metadata (a planted symlink cannot pull outside files into evidence)
- **Every failure recorded** — access denied, size bounds, irregular files
- **Tamper-evident** — one flipped byte anywhere in the sealed zone fails `verify`; hash-chained logs detect record edits, deletions and insertions

## Core Principle

AgentDFIR always distinguishes:

1. what the **human requested**
2. what the **model said**
3. what the **agent/tool attempted**
4. what the **endpoint actually executed**
5. what **independent evidence corroborates**

AI-generated text is never automatically treated as factual evidence of execution.

## License

Apache-2.0
