# Case explorer — `agentdfir serve`

```sh
agentdfir serve CASE-42.adfir              # prints http://127.0.0.1:<port>/
agentdfir serve CASE-42.adfir --port 8437 --open
```

A browser UI for one sealed package, from the same single binary. **Binds 127.0.0.1 only**, loads **no external resources** (CSP `default-src 'none'`, like the HTML report), rejects non-loopback `Host` headers (DNS-rebinding defence), answers only `GET`, and **never writes to the package** (it normalizes into the analysis overlay if that has not happened yet). Every evidence string is sanitized server-side and rendered as text — the analyst's browser is part of the attack surface too.

## Views

- **Timeline** — left: sessions → agents with *orphan* / *subagent* badges (click to filter); centre: paginated timeline with text/type/state filters and a per-minute **density scrubber** (click a bar to zoom to that minute); right: the selected event's fields plus the **raw transcript line** it came from, pretty-printed. Keyboard: `j`/`k` move, `Enter` open, `Esc` clear.
- **Findings** — sorted by severity, MITRE ATT&CK/ATLAS badges, status + endpoint corroboration, evidence refs, false-positive notes; *Open evidence event in timeline* jumps to the exact line.
- **Topology** — sessions → main agents → subagents as an SVG tree; spawn edges highlighted, orphans outlined in red; click a node to filter the timeline.
- **MCP · Provenance · Corroboration** — shown when `mcp audit`, `provenance` or `correlate` results exist in `detections/`.

State badges follow the corroboration model: REPORTED (model words), OBSERVED (agent log), CORROBORATED (OS/gateway agrees), CONTRADICTED (OS says no).

## API

All JSON, loopback only: `/api/case`, `/api/events?session=&agent=&type=&state=&q=&from=&to=&offset=&limit=`, `/api/event/{id}`, `/api/raw?artifact=&offset=`, `/api/findings`, `/api/graph`, `/api/buckets`, `/api/extras`. Events are held in memory (`--max-events`, default 500 000; a truncation flag is shown in the header when exceeded).

Multi-user, hosted or remote access is deliberately out of scope for the open-source tool.
