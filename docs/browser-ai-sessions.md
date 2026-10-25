# Browser AI-service sessions (opt-in)

Many AI conversations never touch an agent's transcript: they happen in a
browser tab. Browser history cannot tell you what was said, but it can tell
you that a ChatGPT conversation titled "Deploy key rotation" was opened 14
times between two dates, from which browser profile, and whether someone
opened a public share link.

AgentDFIR reads that from the browser's own history database. It is
**off by default**: browser history is broad personal data, not agent
evidence, and it is collected only when you ask for it.

## Usage

```sh
agentdfir collect --product claude --include-browser          # this user: the agent plus browser history
agentdfir collect --product browser                            # browser history only
agentdfir collect --product claude --path /mnt/img/Users/x --include-browser
agentdfir collect --import <triage-tree> --include-browser     # also finds profiles that hold only a browser
agentdfir collect --docker <ctr> --include-browser             # --archive works the same way
agentdfir run --include-browser
```

Without the flag (or `--product browser`) no history file is opened, listed
or sealed. `detect` and a default `run` never probe browsers. When history is
collected, `case.json` records it in `notes.browser_history`.

## What is collected

The history database and its `-wal` / `-journal` companions, sealed
losslessly like every other artifact and subject to the same size bounds
(`--max-file-mb`). Category `browser_history`: transcript rules, secret scans
and content scans do not read these files.

| Browser | macOS | Linux | Windows |
|---|---|---|---|
| Chrome | `~/Library/Application Support/Google/Chrome/<profile>/History` | `~/.config/google-chrome/<profile>/History` | `AppData/Local/Google/Chrome/User Data/<profile>/History` |
| Edge | `…/Microsoft Edge/<profile>/History` | `~/.config/microsoft-edge/…` | `AppData/Local/Microsoft/Edge/User Data/…` |
| Brave | `…/BraveSoftware/Brave-Browser/<profile>/History` | `~/.config/BraveSoftware/Brave-Browser/…` | `AppData/Local/BraveSoftware/Brave-Browser/User Data/…` |
| Arc | `…/Arc/User Data/<profile>/History` | — | `AppData/Local/Packages/TheBrowserCompany.Arc_*/LocalCache/Local/Arc/User Data/…` |
| Vivaldi | `…/Vivaldi/<profile>/History` | `~/.config/vivaldi/…` | `AppData/Local/Vivaldi/User Data/…` |
| Opera / Opera GX | `…/com.operasoftware.Opera[GX]/History` | `~/.config/opera/History` | `AppData/Roaming/Opera Software/Opera [GX ]Stable/History` |
| Chromium | `…/Chromium/<profile>/History` | `~/.config/chromium/…`, snap | `AppData/Local/Chromium/User Data/…` |
| Firefox | `…/Firefox/Profiles/*/places.sqlite` | `~/.mozilla/firefox/*/`, snap, flatpak | `AppData/Roaming/Mozilla/Firefox/Profiles/*/` |
| Safari | `~/Library/Safari/History.db` | — | — |

`<profile>` is `Default`, `Profile N` and `Guest Profile`.

## What is parsed

The databases are read with AgentDFIR's own read-only SQLite reader out of
the sealed package (never the live file), with the write-ahead log applied.

Only rows whose URL belongs to a service in the table below become events.
Every other URL and title is discarded at classification and never written
to the overlay, the explorer or a report; the per-database summary event
reports only how many other rows there were. Hosts match exactly or as a
dot-suffix (`www.perplexity.ai`), never by substring:
`chatgpt.com.evil.example` and `evil.example/?q=chatgpt.com` match nothing.

| Service | Hosts | IDs taken from the URL |
|---|---|---|
| ChatGPT | chatgpt.com, chat.openai.com | `/c/<id>`, `/g/<gpt>/c/<id>` (conversation), `/share/<id>`, `/g/<gpt>`, `/g/g-p-…/project` |
| Claude | claude.ai | `/chat/<uuid>`, `/share/<uuid>`, `/project/<uuid>`, `/settings` |
| Gemini | gemini.google.com, g.co/gemini/share | `/app/<id>`, `/gem/<gem>`, `/share/<id>` |
| Microsoft Copilot | copilot.microsoft.com | `/chats/<id>`, `/shares/<id>` |
| Microsoft 365 Copilot | m365.cloud.microsoft/chat, copilot.cloud.microsoft | none (the URL carries no conversation id) |
| Perplexity | perplexity.ai | `/search/<slug>`, `/page/<slug>`, `/spaces/<slug>` |
| DeepSeek | chat.deepseek.com | `/a/chat/s/<id>`, `/share/<id>` |
| Grok | grok.com, x.com/i/grok | `/chat/<id>`, `/share/<id>`, `?conversation=<id>` |
| Le Chat (Mistral) | chat.mistral.ai | `/chat/<uuid>` |
| Poe | poe.com | `/chat/<id>`, `/s/<id>` (share) |
| HuggingChat | huggingface.co/chat | `/chat/conversation/<id>`, `/chat/r/<id>` (share) |
| Meta AI | meta.ai | `/c/<id>`, `/prompt/<id>` |
| Character.AI | character.ai | `/chat/<id>` |
| NotebookLM | notebooklm.google.com | `/notebook/<uuid>` |
| Google AI Studio | aistudio.google.com | `/prompts/<id>`, `/apikey` |
| OpenAI Platform | platform.openai.com | `/playground`, `/api-keys`, settings/usage |
| Anthropic Console | console.anthropic.com, platform.claude.com | `/workbench[/<id>]`, settings/usage |

The table lives in `internal/parsers/browser/services.go`; each entry has a
test URL in `services_test.go`.

### Events

Product `browser`, evidence class **browser-history**. Every event is
`session_meta` (actor `human` for visits); none is a prompt, a response or a
tool call.

- `browser_visit` (one per visit row): service, page kind, conversation or
  share id, the page title the browser stored (for most services the
  conversation title), visit time in UTC **and** the raw stored value with
  its clock (WebKit µs since 1601, PRTime µs since 1970, Cocoa seconds since
  2001), Chromium transition / Firefox visit type, the typed flag, the URL's
  own visit counter, browser and profile, and the source row
  (`visits:<rowid> → urls:<rowid>`; `source_offset` is the row id).
- `browser_session` (one per group): e.g. `ChatGPT conversation "Deploy key
  rotation" visited 14 time(s) between … and … (chrome/Default, brave/Profile
  2)`. Visits are grouped by service + kind + id across browsers; pages with
  no id in the URL are grouped per service, kind and browser profile. The
  session entity carries the same facts as attributes.
- `browser_db_read` (one per database): rows read, AI-service rows kept,
  other rows not extracted (count only), whether the WAL was applied.

Chromium expires visit rows after about 90 days but keeps the URL row with
its counter and last-visit time; such URLs are reported once, dated by the
last visit, with transition `url-row-only`. Safari keeps no time on the URL
row, so a Safari URL without visit rows is reported undated.

## What it proves, and what it does not

A history row proves the browser recorded a visit to a URL at a time. It
does **not** prove what was typed, what the model answered, that the page
loaded fully, or who sat at the keyboard. AgentDFIR never produces prompt or
response text from history. To read the conversations themselves, use the
provider's data export.

No rule links a browser visit to agent activity by time proximity.

## Detection

| Rule | Severity | Fires when |
|---|---|---|
| `AI_WEB_SHARE_LINK_VISITED` | LOW | the history holds a visit to a public share link of an AI conversation (ChatGPT, Claude, Gemini, Copilot, DeepSeek, Grok, Poe, HuggingChat). One finding per share link. Opening someone else's link looks the same as viewing one's own. |

## Reported as problems, never skipped

| Situation | Result |
|---|---|
| Database unreadable, over the 512 MiB parse bound, or not SQLite | `trace_gap` (`read_failed` / `malformed_database`) |
| SQLite, but no known history schema | `session_meta` `unsupported`, summary starts `UNSUPPORTED:` |
| WAL present but unreadable | note; database read as last checkpointed |
| Non-empty rollback journal | note; preserved, not applied |
| More than 200,000 AI-service visit rows in one database | rows past the bound not emitted; the summary says so |
| Implausible timestamp (before 1995, after 2200, zero) | event undated, raw value kept |

## Not covered

- Conversation content (history has none).
- Other browser stores: cookies, cache, session restore, local storage,
  IndexedDB, downloads, bookmarks, autofill, Login Data, Top Sites,
  Favicons. Not collected.
- Browsers installed with a custom data directory (`--user-data-dir`,
  portable installs) or a non-default Firefox profile location.
- Browsers not listed above (Firefox forks such as LibreWolf/Zen, Orion,
  DuckDuckGo, Samsung Internet, mobile browsers).
- Services not in the table. Unknown AI hosts are not guessed.

## Fixtures

All test databases are synthetic, written by
`internal/parsers/browser/testdata/make_fixtures.sh` with the sqlite3 CLI in
each browser's column layout. The Firefox fixture has rows that exist only in
its `-wal` file. Corpus cases: `attack/browser-ai-share-link`,
`benign/browser-ai-visits-no-share`.
