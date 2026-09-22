# Case explorer — `agentdfir serve`

```sh
agentdfir serve CASE-42.adfir              # prints http://127.0.0.1:<port>/
agentdfir serve CASE-42.adfir --port 8437 --open
agentdfir run                              # detect → collect → analyze → serve, in one go
```

A browser UI for one sealed package, from the same single binary. **Binds 127.0.0.1 only**, loads **no external resources** (CSP `default-src 'none'`, like the HTML report), rejects non-loopback `Host` headers (DNS-rebinding defence), and **never writes to the sealed evidence**. The one thing it writes is the analyst case file, `notes/notes.jsonl`, outside the sealed zone (see below). Every evidence string is sanitized server-side and rendered as text — the analyst's browser is part of the attack surface too.

## Views

- **Sessions** (landing) — a case strip (sessions, agents, events, critical + high findings, attack chains, contradicted events, findings reviewed) and one card per session, worst first: product, the first prompt, start and duration, prompts / tool calls / agents / spawns / files / destinations / MCP servers, an evidence bar (DISPROVED · CONFIRMED · RECORDED · CLAIMED · UNKNOWN), worst severity, attack-chain titles, tags. Add a tag or a note on the card. Click the card: the timeline opens filtered to that session with the same metadata as a header.
- **Timeline** — left: sessions → agents with *orphan* / *subagent* badges; centre: paginated timeline with text/type/state filters and a per-minute **density scrubber**; right: the selected event's fields, the **raw transcript line** it came from, *pin as key evidence*, *what led here* (the prompt before it, the tool result it consumed, the spawn that created its agent), analyst notes, and the findings on that event. Keyboard: `j`/`k` move, `Enter` open, `Esc` clear.
- **Findings** — filter by severity, *attack chains only*, verdict, text. Chain findings show their steps inline (`1. injection in tool result → 2. agent wrote its own instructions/config → 3. shell command executed`). Select one to get **How it happened**: the investigation tree (below), then **Your verdict** (true positive / false positive / needs review + note), MITRE badges, evidence references, false-positive notes.
- **Search** — `Ctrl+K` / `Cmd+K` from anywhere. Literal or RE2 regex, optional case-sensitivity, over every field of every event, every finding, and — when *raw evidence* is on — the bytes of every sealed artifact (parallel streaming scan, bounded to 20 s and 500 hits, binary and oversize artifacts skipped and counted). Raw hits map back to the normalized event on that line when one exists; click to see the evidence.
- **Topology** — sessions → main agents → subagents as an SVG tree; spawn edges highlighted, orphans outlined in red.
- **MCP · Provenance · Corroboration** — shown when `mcp audit`, `provenance` or `correlate` results exist in `detections/`.

State badges follow the corroboration model: REPORTED (model words), OBSERVED (agent log), CORROBORATED (OS/gateway agrees), CONTRADICTED (OS says no).

## The investigation tree

For an attack-chain finding the root's children are the matched steps in order. For any other finding they are the events its evidence references resolve to. Under every event node, the explorer adds what led there, each one a real transcript line:

| Role | What it is |
|---|---|
| tool result the agent had just consumed | the nearest earlier `tool_result` for the same agent — the input the model acted on |
| instruction delivered to this subagent | the `agent_message` a parent sent to a subagent |
| spawned this agent | the `agent_spawn` whose task id is this agent |
| human prompt before this | the nearest earlier `human_prompt` in the session |
| result returned to the agent | the `tool_result` of this tool call |

Nothing in the tree is inferred without an evidence line. *What led here* on any node fetches its own context (`/api/chain?event=<id>`), so the analyst can walk back as far as the evidence goes.

## The case file (`notes/notes.jsonl`)

Verdicts, notes, pins and tags are appended to `<pkg>/notes/notes.jsonl` as a hash chain (each record carries the SHA-256 of the previous line, like the custody log), with the OS user and a UTC timestamp. Editing, deleting or reordering a record breaks the chain and the explorer says so. The file lives outside the sealed zone, so `verify` still passes and the evidence is untouched. `report --format html|pdf|json` renders the case file as an *Analyst Investigation* section: verdicts per finding, pinned evidence with its raw reference, session tags, notes.

`POST /api/notes` is the only write endpoint. It requires the `X-AgentDFIR-Notes: 1` header, a loopback `Origin` (or none) and a same-origin `Sec-Fetch-Site`, so no page in another tab can forge entries. Everything else stays `GET`.

## Deep links

`#sessions` · `#timeline` · `#findings/<index>` · `#search/<query>` · `#session/<id>` · `#event/<id>`

## API

All JSON, loopback only: `/api/case`, `/api/sessions`, `/api/events?session=&agent=&type=&state=&q=&from=&to=&offset=&limit=`, `/api/event/{id}`, `/api/raw?artifact=&offset=`, `/api/findings`, `/api/chain?finding=<i>` | `?event=<id>`, `/api/search?q=&mode=text|regex&case=1&scope=events,findings,raw&limit=`, `/api/notes` (GET; POST as above), `/api/graph`, `/api/buckets`, `/api/extras`. Events are held in memory (`--max-events`, default 500 000; a truncation flag is shown in the header when exceeded).

Multi-user, hosted or remote access is deliberately out of scope for the open-source tool.
