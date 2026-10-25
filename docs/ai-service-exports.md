# AI-service account exports — ChatGPT, Claude.ai, DeepSeek, Gemini (Takeout), UFDR layout

When the evidence is a user's data export from a chat service rather than an agent on a disk, AgentDFIR seals it into a case and reconstructs the conversations as ordinary events and sessions. The existing rules (credential exposure, injection phrases, invisible Unicode, honeytokens, …), the timeline, the explorer and every report format then work on them unchanged.

```sh
agentdfir collect --ai-export chatgpt-export.zip --case-id CASE-7 --operator "Your Name"
agentdfir collect --ai-export ./unpacked-export/  --out CASE-7.adfir
agentdfir analyze CASE-7.adfir
```

`--ai-export` takes a zip / tar / tar.gz, or an unpacked directory. `collect --archive` and `collect --import` recognize the same exports when they are present (see below).

## Evidence class: a provider's record, not endpoint execution

An export is produced on the provider's side. It says what the service recorded, not what ran on the examined machine. The evidence states say exactly that:

| Export content | Event | State (label) |
|---|---|---|
| user message | `human_prompt` | REQUESTED (ASKED) |
| assistant text, reasoning summaries | `model_response` | REPORTED (CLAIMED) |
| tool call the export records (code interpreter, browsing, search, Claude `tool_use`) | `tool_call`, `action=provider_tool` | OBSERVED (RECORDED) |
| tool output the export records | `tool_result` | OBSERVED (RECORDED) |
| system/custom instructions, attachments, feedback, share links, account record | `session_meta` | OBSERVED (RECORDED) |

Tool calls from an export never carry `command`, `file` or `network_destination`. The code ran in the provider's sandbox, not on the host, and leaving those fields empty means endpoint or cloud correlation can never mark an export tool call CONFIRMED against activity on the examined machine. Nothing in an export becomes CONFIRMED on its own.

Every export event has a `timestamp_source` that starts with `provider_export`, followed by the original field and value, e.g. `provider_export:create_time=1788084010.25` or `provider_export:inserted_at=2026-09-01T18:00:01+08:00`. The `timestamp` itself is always UTC. The per-artifact integrity rules (AGENT_IDENTITY_MISMATCH, SESSION_TAMPERING) skip these events: one export file normally holds every conversation of the account, with branches that interleave in time.

## Provenance

Every artifact is sealed under its **in-export path** (`conversations.json`, `Takeout/My Activity/Gemini Apps/MyActivity.json`, …). Every event points back to the exact place it was read from:

- `source_artifact`: the sealed artifact (content SHA-256)
- `source_offset` / `source_line`: byte offset and line of the JSON value in that artifact
- `source_json_path`: an RFC 6901 JSON Pointer to the value, e.g. `/0/mapping/u-2/message` or `/3/chat_messages/1/content/1`. Exports are often one line, so the pointer is what locates the message.

The case notes (`case.json`) record `mode=ai-export`, the export file's SHA-256 (`ai_export_sha256`; for a directory input, the per-file hashes in the manifest stand in), the detected services, and each recognized file with its service, kind and schema variant (`ai_export_detected`, e.g. `conversations.json=chatgpt/conversations/mapping-tree`).

## Recognition by structure

Files are classified by their content, never by name: the first MiB is summarized (keys present at each level) and matched against the known schemas. A ChatGPT export renamed to `data.json`, or found inside a UFDR, is still recognized. Names are used for one thing only: a file named like an export file (`conversations.json`, `conversations-000.json`, `user.json`, `users.json`, `projects.json`, `message_feedback.json`, `shared_conversations.json`, a Gemini `MyActivity.json/.html`) whose structure matches no known schema produces one explicit finding instead of being ignored:

```
MEDIUM — Unsupported Evidence Format [TRACE_GAP]
  UNSUPPORTED conversations.json (unknown): conversation objects match no known export schema
  (keys present: thread_id, turns); expected keys missing: mapping (ChatGPT/DeepSeek), uuid+chat_messages (Claude.ai).
  The file is sealed and preserved unparsed; nothing was inferred from it.
```

A truncated or malformed region inside a known schema is a regular TRACE_GAP naming the byte offset and the element; everything before it is still parsed.

## Coverage

| Service | How to request the export | Parsed | Sealed, not parsed | Reported UNSUPPORTED |
|---|---|---|---|---|
| **ChatGPT** (OpenAI) | Settings → Data controls → Export data; a download link arrives by e-mail | `conversations.json` and split `conversations-NNN.json`: the full `mapping` message tree. The active branch is the parent chain of `current_node`; every other branch (regenerated answers, edited prompts) is still emitted, marked `result=export:alternate-branch`. Content types `text`, `multimodal_text` (image parts listed by asset id), `code`, `execution_output`, `tether_browsing_display`, `tether_quote`, `system_error`, `user_editable_context` (custom instructions), `thoughts`, `reasoning_recap`; a message addressed to a recipient other than `all` (python, browser, …) is a tool call. Model slug, attachment names/ids, conversation title. `user.json` (account), `message_feedback.json` (ratings), `shared_conversations.json` (share links) | `chat.html`, images, audio, DALL·E files, any other file | conversation files in an unknown schema |
| **Claude.ai** (Anthropic) | Settings → Privacy → Export data; link by e-mail | `conversations.json`: `chat_messages` with `sender`, content blocks `text`, `thinking`, `tool_use`, `tool_result` (older text-only exports: `text`), attachment and file names, conversation name. `users.json` (account), `projects.json` (project names, instructions present, knowledge-document names) | attachment `extracted_content` and project document bodies are not turned into events (they are in the sealed file and the content rules scan them) | unknown schema |
| **DeepSeek** | Settings → Data → Export data | `conversations.json`: the `mapping` tree with `fragments` — `REQUEST` (prompt), `RESPONSE`, `THINK` (reasoning), `SEARCH` (tool call with result titles/URLs); model, file names. DeepSeek records no `current_node`, so at a fork both branches are marked `result=export:branch-unresolved` rather than guessing | other files | unknown fragment types become metadata events naming the type; unknown file schema |
| **Gemini Apps** (Google Takeout) | takeout.google.com → My Activity → activity records: Gemini Apps → format **JSON** (the default is HTML) | `My Activity/Gemini Apps/MyActivity.json`: "Prompted …" records become prompt + response (response HTML reduced to text), other activity becomes metadata; attached file names. Activity has no conversation id: one session per file | Gems, saved info and other Takeout files | `MyActivity.html` only (HTML export): one UNSUPPORTED finding asking for the JSON format |
| **Cellebrite UFDR** | — | **Layout import only.** A UFDR is a zip with `report.xml` and an extracted file tree. `report.xml` is recognized by content (an XML `<project>` naming Cellebrite) and sealed as `ufdr.report`; every file is sealed under its in-archive path as `ufdr.file`. Any AI-service export found inside the tree is parsed as above | everything else | `report.xml` semantics are **not parsed** (case note: "UFDR layout import — report.xml semantics not parsed"); no claims are made about its contents |

Not covered:

- **Microsoft Copilot (consumer) and Perplexity** have no stable bulk conversation export. Their use is visible only through browser history (visit times, conversation URLs and titles), which is a different evidence class: browser history is not conversation content. See the opt-in browser-history collection.
- **ChatGPT desktop app cache (macOS)** is stored encrypted; it is not read. Collect the account export instead.
- Anything an export does not contain (deleted conversations, temporary chats, server-side logs) cannot be reconstructed from it.

## `--archive` and `--import`

- `collect --archive <zip|tar|tgz>`: when the unpacked archive holds a recognized export file or a UFDR `report.xml`, the whole archive is sealed the way `--ai-export` seals it (it is the export), and those files are no longer also kept as loose `archive.sessions` artifacts.
- `collect --import <tree>`: the tree is additionally searched for export files (`.json` / `.html` files, recognized by content, outside the product directories the profile collectors already read). Only recognized files are sealed. A tree with neither agent profiles nor export files still fails as before.

## Artifacts in the manifest

| collector_rule | artifact_type | product | What |
|---|---|---|---|
| `aiexport.conversations` | `agent_session` | `chatgpt`, `claude-ai`, `deepseek`, `gemini-apps` | conversations, projects, Gemini activity (parsed; scanned by the content rules) |
| `aiexport.metadata` | `ai_export_metadata` | as above | account, feedback, share-link records (parsed) |
| `aiexport.file` | `ai_export_file` | `ai-export` | every other file of an export (sealed only) |
| `ufdr.report` | `ufdr_report` | `ufdr` | UFDR `report.xml` (sealed only) |
| `ufdr.file` | `ufdr_file` | `ufdr` | UFDR file tree (sealed only) |

## Limits on hostile input

Exports are streamed: the top-level array is walked one element (one conversation) at a time with the JSON token decoder, never decoded whole; memory follows the largest single conversation, not the file. One conversation is bounded at 64 MiB, a mapping at 200,000 nodes, a message list at 200,000 messages; over-bound regions become TRACE_GAP findings. Parent-chain cycles and dangling node references in a mapping are reported, never followed.

## Fixtures

All fixtures (`internal/parsers/aiexport/testdata`, the corpus cases `attack/ai-export-pasted-credential` and `benign/ai-export-ordinary-chats`) are **synthetic**: realistic structure, invented content. Credential-shaped strings are built at test time, not stored. None of these export formats is formally documented by its provider; the readers follow the structure the exports have had through 2025-2026. A service that changes its format produces the UNSUPPORTED finding above rather than wrong events. Menu paths for requesting an export change over time; the export itself is what matters.
