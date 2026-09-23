# Case explorer — `agentdfir serve`

```sh
agentdfir serve CASE-42.adfir              # prints http://127.0.0.1:<port>/
agentdfir serve CASE-42.adfir --port 8437 --open
agentdfir run                              # detect → collect → analyze → serve, in one go
```

A browser UI for one sealed package, from the same single binary. **Binds 127.0.0.1 only**, loads **no external resources** (CSP `default-src 'none'`, like the HTML report), rejects non-loopback `Host` headers (DNS-rebinding defence), and **never writes to the sealed evidence**. The one thing it writes is the analyst case file, `notes/notes.jsonl`, outside the sealed zone (see below). Every evidence string is sanitized server-side and rendered as text — the analyst's browser is part of the attack surface too.

## Views

Written for someone who is not a security analyst: every severity, confidence and evidence state is said in words, and the rule ids, MITRE mappings and raw references are one click away under *Technical details*. Light and dark themes (follows the OS; the toggle pins one).

- **Overview** (landing) — the answer first: *"4 alerts need action now"*, what was read (conversations, computer, date range, recorded actions), four tiers (**Act now · Serious · Worth a look · Minor or routine**), **Start here** (the most serious kinds of issue, each with how often and in how many conversations), the **accounts** in the case, and whether the evidence is intact.
- **Findings** — grouped by *kind of issue* (rule × severity) instead of listed one by one: 1,237 findings on a real machine are about sixty kinds. Filter by tier, words or account; hide kinds you have finished. A kind opens to:
  - a plain title, one **verdict line** that reads severity and confidence together (*"Act now if real · Needs your check"*), **What happened / Why it matters / Ask yourself**, and *What the detector saw here*;
  - *Time 1 of N* with the conversation, the time and the **account** it ran under;
  - **Most likely start** — the root cause, read off the evidence: your request, an automatic (skill/plugin) message, something the agent read that itself carries injected instructions, or a helper agent. The card it points at is marked **Start** in the story;
  - **The story** — a swimlane diagram in three lanes (*You · The AI agent · Tools & outside world*), one card per evidence line in time order, arrows for every hand-off, gaps longer than ten minutes labelled, the flagged steps in red and numbered, the outside addresses a step reaches. *In short* sums the flagged steps up in one line first. Every card has **Show proof** and **What led to this?**;
  - **What to do**, with **Copy a note for your IT contact**, and **Your decision** — *Real problem · Expected · Detection mistake · Not sure yet* (stored as true positive / benign / false positive / needs review), optionally applied to every other time the same thing happened.
- **Activity** — conversations on the left, named by what the person first asked (skill and harness text skipped), each with its account; on the right, what happened, oldest first: when, who (*You · AI agent · Helper agent · Tool · Automatic*), what, flagged or not. Show *Everything · What was asked · Agent actions · Tool answers · Helper agents started · Only flagged*; words, account and time-range filters; a busy-ness strip to jump to a minute. Background bookkeeping records are left out. Keyboard: `j`/`k`.
- **Proof** (a side panel, from anywhere) — the record in plain fields (when, who, conversation, account, command, file, address, result, evidence status), *What stands out* (safety prompts off, a helper agent wrote this, the tool reported an error or a refused login, invisible characters), the findings on it, *Mark as key evidence*, *What led to this*, and the exact sealed log line.
- **More**
  - **Search everything** — `Ctrl+K` / `Cmd+K`. Literal or RE2, optional case, over every event, every finding and — when ticked — the raw bytes of every sealed artifact (bounded to 20 s / 500 hits).
  - **Plugin (MCP) activity** — every MCP tool call in time order: time, account, plugin, tool, *what the agent sent* (read out of the sealed line) and *what came back* (the matching tool result), filterable per plugin.
  - **Plugins installed** — one row per plugin: used by, account, runs on this computer or online, fixed version or not, what it is, where it is set.
  - **Memory files** — instruction and memory files, with the lines an agent wrote and why (copied from a tool answer, after your request…).
  - **Cross-check** — the OS/gateway corroboration summary when `correlate` ran, or the command to run it.
  - **Agent map** — conversations → main agents → helpers for the conversations with findings; agents with no known parent outlined in red.
  - **About the evidence** — computer, collection time, integrity (quick check on open, *Re-check every file now* for the full re-hash), signature, version.

Evidence states in words: *Written in the agent’s own log* (OBSERVED), *Claimed by the agent* (REPORTED), *Confirmed by the computer’s own records* (CORROBORATED), *The computer’s records disagree* (CONTRADICTED), *Not cross-checked* (UNKNOWN). The stored values are unchanged.

## Accounts

One person often runs agents under more than one login — a work Claude seat and a personal ChatGPT plan, or two Claude config directories. Every record, conversation, finding and plugin carries the account it ran under. The login is not on the events; it is read from the product's own settings in each profile directory that was collected — `~/.claude.json` (`oauthAccount`: email, organisation) for a Claude profile, `<CODEX_HOME>/auth.json` (the `id_token` claims: email, ChatGPT plan) for Codex — and an event belongs to the profile directory its transcript sits in. Claude desktop (Cowork) sessions stored under a Claude account id are matched to that account. Only the identity is read; tokens and keys never leave the server. A profile whose login file was not collected is shown as *login not recorded*.

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

`#overview` · `#findings/<rule>~<severity>/<index>` · `#activity/<conversation id>` · `#event/<id>` · `#more/search/<query>` · `#more/mcp` · `#more/plugins` · `#more/memory` · `#more/crosscheck` · `#more/map` · `#more/evidence`. The old links (`#sessions`, `#timeline`, `#findings/<index>`, `#search/<q>`, `#session/<id>`, `#topology`, `#extras`) still land in the right place.

## API

All JSON, loopback only: `/api/case`, `/api/sessions`, `/api/events?session=&agent=&type=&state=&q=&from=&to=&account=&mcp=1|<server>&flagged=1&nometa=1&sort=time&offset=&limit=` (rows carry `account`, `flags`, and for MCP calls `sent` / `answer`), `/api/accounts`, `/api/event/{id}`, `/api/raw?artifact=&offset=`, `/api/findings`, `/api/chain?finding=<i>` | `?event=<id>`, `/api/search?q=&mode=text|regex&case=1&scope=events,findings,raw&limit=`, `/api/notes` (GET; POST as above), `/api/graph`, `/api/buckets`, `/api/extras`. Events are not held in memory: `<pkg>/index/events.idx` records each event's byte offset in `normalized/events.jsonl` plus the fields the lists filter on, and the full event is read by offset when a detail view asks for it. The index is derived data — outside the sealed zone, not covered by `SHA256SUMS`, safe to delete, rebuilt on load when missing or stale. There is no event cap; `--max-events` is accepted and ignored.

Multi-user, hosted or remote access is deliberately out of scope for the open-source tool.
