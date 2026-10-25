# Continue and Windsurf

Two IDE agents with built-in collectors. Both are detected by their
configuration directory (nothing is executed) and collected by `run`,
`collect --product continue|windsurf` and `collect --import`.

## Continue (continue.dev)

Detected by `~/.continue`. Collector rules (`internal/products/tier23_manifests.json`):

| Rule | Path (under `~/.continue`) | Category |
|---|---|---|
| `continue.config` | `config.json`, `config.yaml`, `config.ts`, `.continuerc.json` | product_config |
| `continue.sessions` | `sessions/**` (one JSON per session + `sessions.json` index) | agent_session |
| `continue.rules` | `rules/**` | agent_instructions |
| `continue.prompts` | `prompts/**` | agent_instructions |
| `continue.mcp` | `mcpServers/**` | product_config |
| `continue.assistants` | `assistants/**` | product_config |
| `continue.env` | `.env` | credentials |
| `continue.dev_data` | `dev_data/**` | debug_logs |
| `continue.logs` | `logs/**` | debug_logs |

The codebase index (`~/.continue/index`, embeddings) is not collected.

### Sessions

`sessions/<id>.json` holds `{sessionId, title, workspaceDirectory, mode,
chatModelTitle, history: [{message, contextItems, toolCallState(s)}]}`.
Parsed into:

| History item | Event | State |
|---|---|---|
| session header | `session_meta` (title, workspace, mode, model) | OBSERVED |
| `user` message | `human_prompt` | OBSERVED |
| `assistant` text | `model_response` | REPORTED |
| `thinking` | `model_response`, result `thinking` | REPORTED |
| assistant `toolCalls` / `toolCallStates` | `tool_call` (one per call id, deduplicated) | OBSERVED |
| tool call state (`done`, `errored`, `canceled`, …) | `tool_result` with that status | OBSERVED |
| `tool` message | `tool_result` (tool output text) | OBSERVED |
| context items | `session_meta` `context_item` (provider, name, URI only) | OBSERVED |
| `sessions.json` entry | `session_meta` `session_index`, dated by `dateCreated` | OBSERVED |

Built-in tools map onto the fields the rules read:
`builtin_run_terminal_command` → shell command; `builtin_read_file` and
friends → `read_file` + path; `builtin_create_new_file` → `write_file`;
`builtin_edit_existing_file` / `single_find_and_replace` → `edit_file`;
`builtin_fetch_url_content` → network destination; `builtin_search_web` →
`web_search`. Other tools (MCP tools) keep their name and arguments. A
history item that is not a message, or a session that is not JSON, is a
`trace_gap`.

Continue writes no per-message timestamps; session events are undated
except the index entries.

### MCP

`agentdfir mcp audit` and the analysis read Continue's MCP servers from
`config.json` (`experimental.modelContextProtocolServers`, or `mcpServers`
as a list or a name-keyed map), `config.yaml` and `mcpServers/*.yaml`
(`mcpServers:` list: `name`, `command`, `args`, `env`, `type`, `url`; hub
`uses:` blocks are recorded with package manager `continue-hub`, unpinned
because the launch line is not in the file), and `mcpServers/*.json`
(Claude-style `{"mcpServers": {…}}`). The YAML reader is a small subset
(block/flow lists and maps, quoted scalars, comments); a server entry it
cannot read is listed in the inventory's problems. Anchors, aliases,
multi-line scalars and `${{ secrets.X }}` resolution are not supported.

## Windsurf (Codeium)

Detected by `~/.codeium/windsurf`, `~/.windsurf` or the app data directory.

| Rule | Path | Category |
|---|---|---|
| `windsurf.mcp` | `~/.codeium/windsurf/mcp_config.json` | product_config |
| `windsurf.rules` | `~/.codeium/windsurf/memories/*.md` (incl. `global_rules.md`) | agent_instructions |
| `windsurf.memories` | `~/.codeium/windsurf/memories/*.pb` | agent_session |
| `windsurf.cascade` | `~/.codeium/windsurf/cascade/**` | agent_session |
| `windsurf.workflows` | `~/.codeium/windsurf/global_workflows/**` | agent_instructions |
| `windsurf.implicit` | `~/.codeium/windsurf/implicit/**` | product_state |
| `windsurf.settings_<os>` | `<app>/User/settings.json` | product_config |
| `windsurf.state_<os>` | `<app>/User/globalStorage/state.vscdb`, `workspaceStorage/*/state.vscdb` | product_state |
| `windsurf.logs_<os>` | `<app>/logs/**` | debug_logs |

`<app>` is `~/Library/Application Support/Windsurf` (macOS),
`~/.config/Windsurf` (Linux), `AppData/Roaming/Windsurf` (Windows).
Extensions under `~/.windsurf/extensions` are not collected here.

### What is parsed

- **Global rules, memories (`*.md`) and workflows**: fully, by the
  instruction-file rules (e.g. `AGENT_CONTEXT_POISONING`) and provenance.
- **MCP**: `mcp_config.json` (`mcpServers`, including `serverUrl`) in the MCP
  audit, live and from packages. Project `.windsurf/mcp.json` was already
  covered by `scan-repo`.
- **Cascade conversations and memory stores (`*.pb`)**: **UNSUPPORTED
  content.** They are protobuf with no published schema, and current builds
  encrypt them. Each file is collected and sealed, and reported as one
  `session_meta` event: session id from the file name (`cascade:<id>`), size,
  modification time (timestamp source `file_mtime`), and the reason, from
  the entropy of its first 64 KiB: `unsupported:encrypted` (≥ 7.5
  bits/byte) or `unsupported:undocumented_format`. Nothing is carved out of
  them; such files do not raise `TRACE_GAP`.
- **`state.vscdb`**: collected and sealed (`product_state`); its key/value
  contents are not interpreted. When it is under 4 MiB, the MCP audit's
  cached-tool scan still looks inside it for declared tool descriptions.

## Fixtures

All synthetic. Parser tests: `internal/parsers/genericchat/continue_windsurf_test.go`,
`internal/mcpaudit/continue_test.go`. Corpus cases:
`attack/continue-secret-then-exfil`, `attack/windsurf-global-rules-poisoning`,
`benign/continue-routine-session`, `benign/windsurf-encrypted-cascade`.
