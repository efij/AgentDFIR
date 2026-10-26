# MCP Forensics

*Investigating Model Context Protocol (MCP) server configuration and tool
activity in AI-agent incidents. Verified 2026-10-26.*

Part of [AgentDFIR](https://efij.github.io/AgentDFIR/), open-source DFIR
for AI agents.

## Why MCP matters forensically

MCP servers extend an AI agent with external tools. A malicious or
compromised MCP server can exfiltrate data, poison tool descriptions
(prompt injection delivered through tool metadata), or add capabilities
the operator never approved. MCP configuration and MCP tool calls are
therefore first-class evidence.

## Where MCP configuration lives

| Product | MCP config location |
|---|---|
| Claude Code | `~/.claude.json` (`mcpServers` object); project `.mcp.json` |
| Codex CLI | `~/.codex/config.toml` (`mcp_servers`) |
| Cursor | `~/.cursor/mcp.json` |
| Copilot CLI | `~/.copilot/mcp-config.json` |

A server entry typically declares a `command`, `args` and `env`. The
**server name** is the forensically stable identifier; commands and env
may carry secrets and are treated as sensitive.

## MCP activity in transcripts

MCP tool calls appear in session transcripts as tool-use records whose
tool name is namespaced. AgentDFIR normalizes these into events with
`mcp_server` and `mcp_tool` populated and `action: mcp_call`, and adds
graph edges `agent → tool → mcp_server`, each linked to the source event.

## What a normalized tool call retains

Raw tool arguments and results are **not** copied into normalized events.
They stay in the sealed source artifact, and every event points at the
exact record (`source_artifact` + `source_offset` / `source_line`, or
`source_json_path` for one-document exports). What the event does carry,
for MCP calls and every other tool call:

| Field | What it holds | What it never holds |
|---|---|---|
| `args_digest` | SHA-256 (hex) of the arguments' canonical JSON: keys sorted, whitespace removed, numbers as written. Arguments that are not JSON (a patch, a script), over 4 MiB, or nested past the decoder's limit are hashed as raw bytes. | the arguments |
| `arg_keys` | sorted top-level argument names, comma-separated, at most 64 (a cut list ends in `…`), each at most 64 bytes | values |
| `safe_args` | at most 16 allowlisted values, by argument name: paths (`file_path`, `path`, `cwd`, `notebook_path`, `workdir`, `directory`), URLs reduced to scheme + host (`url`, `uri`, `endpoint`, `base_url`), HTTP `method`, ARNs (`arn`, `resource_arn`, `role_arn`), cloud resource identifiers (`resource_id`, `resource_name`, `bucket`, `instance_id`, `project_id`, `subscription_id`, `region`, `cluster`, `namespace`), repository and branch names (`repo`, `repository`, `owner`, `branch`, `ref`), tool and server names (`tool`, `tool_name`, `server`, `server_name`, `subagent_type`). Camel case and dashes match too. Only string values; identifiers must not contain spaces; anything with a newline or control character is dropped as free text; every value is at most 256 bytes and passes through the `secrets` redaction category, so a credential becomes `[REDACTED:secret:<8 hex>]`. | prompts, file contents, message bodies, command text (the shell command stays in `command` as before), URL paths and query strings, URL userinfo, any key not on the list |
| `result_digest` | SHA-256 of the recorded result (canonical JSON when the result is JSON, the raw string otherwise) | the result |
| `result_status` | `ok`, `error` or `denied`, only as the transcript records it (below) | an outcome inferred from what happened next |
| `result_ref` | the `event_id` of the paired result on a call, and of the call on a result | |
| `tool_def_digest` | SHA-256 of the canonical JSON of the tool's `name`, `description`, `inputSchema` and `annotations` from the newest `tools/list` result the gateway logged before the call | the description text |
| `mcp_server_version` | `serverInfo` `name/version` from the newest `initialize` result the gateway logged before the call | |
| `approval_state` | from an explicit record only (below). The vocabulary is `approved`, `denied`, `auto_approved`, `not_recorded`; the sources read today produce `denied` and `auto_approved`, because none of them writes down a person saying yes. | an approval inferred from the call completing |

A secret that appears in an argument therefore leaves at most its
redaction marker in `safe_args` (and only when it sits in an allowlisted
key) and changes `args_digest`. The digests let an analyst check that two
calls had identical arguments, or recompute the digest from the sealed
record, without the events carrying the values.

### Result status, approval and pairing, by source

| Source | `result_status` | `approval_state` |
|---|---|---|
| Claude Code / Cowork transcripts | `ok` for a `tool_result` not flagged `is_error`; `error` when flagged; `denied` when flagged and the text is Claude Code's own rejection (`The user doesn't want to proceed with this tool use…`, `The user doesn't want to take this action right now…`, `User rejected tool use`, `Permission to use … has been denied`, `… requested permissions to use …, but you haven't granted it yet`). The same text in an unflagged result (a file that contains the sentence) stays `ok`. | `denied` on a denied result and on its call; `auto_approved` on a call when the recorded permission mode is `bypassPermissions` (every tool) or `acceptEdits` (Write, Edit, MultiEdit, NotebookEdit). The mode is the call line's own, or the last mode a line of that session and agent recorded earlier in the same file (Claude Code writes it on user lines). Otherwise empty. |
| Codex CLI rollouts | `denied` for Codex's `exec command rejected by user` / `patch rejected by user` outputs; `ok` / `error` from `metadata.exit_code` in an exec output; empty for any other output | `denied` on a rejected call and its output; `auto_approved` when the last `turn_context` recorded `approval_policy: never`. Per-call approval decisions under other policies are not written to the rollout, so the state stays empty. |
| Generic chat (Cline/Roo, Anthropic-style) | `ok` / `error` from `is_error`; Continue `done` / `errored` | empty |
| Claude.ai account export | `ok` / `error` from `is_error` | empty |
| MCP gateway log (`--gateway-log`) | not changed | `denied` for a `deny` / `denied` / `blocked` / `reject` decision (it overrides an `auto_approved` read from the mode); `auto_approved` for `allow` / `permit` when nothing else is recorded. A policy allow is an automatic decision, not a person's approval. |

Calls and results are paired by `tool_call_id` within one session of one
source file; a call whose result never arrives has an empty `result_ref`.
Pairing never crosses files, so the incremental overlay can renumber a
file's events without leaving stale references.

### Gateway runtime identity

When a gateway log is passed to `agentdfir analyze --gateway-log`, lines
that carry a JSON-RPC response (`result`, or `response.result`) with
`serverInfo` or `tools` are read as the backend's runtime identity. Each
MCP call the gateway matched (by call id, or the same tool within ±2 s)
gets the backend's newest `serverInfo` version and the newest `tools/list`
definition digest of that tool recorded at or before the call. A tool
missing from the newest listing gets no digest, even if an older listing
had it. Calls the gateway did not match use the backend whose name equals
the transcript's server name. These annotations are written to the events
before detection, so rules read them.

Tool definitions found only in client-side config or cached manifests are
not attached to calls: nothing in them says they were the definition in
force when the call was made. They are fingerprinted in the MCP audit
inventory (`definition_sha256`) and compared against baselines there.

### Related structured fields

- **`permission_change` events.** When a line records a permission mode
  different from the last one recorded for the same session and agent in
  the same file (Claude Code `permissionMode`; Codex `turn_context`
  `approval_policy`), an event with `event_type: permission_change`,
  `permission_from` (old) and `permission_mode` (new) is emitted at that
  line. Codex `turn_context` events now also carry the policy in
  `permission_mode`.
- **`parent_tool_call_id`** on subagent events: the Cowork / Agent SDK
  `parent_tool_use_id` of the line, or, for a CLI sidechain line, the
  Agent/Task call whose result in the same file named that agent id. A
  subagent transcript in its own file does not record its launching call,
  so it stays empty there.
- **`input_modality`** (`image`, `document`, `audio`): Claude `image` /
  `document` content blocks on a prompt or tool result, Codex
  `input_image` / `input_file` / `input_audio`, and account-export
  attachments (by MIME type, or file extension when none is recorded).
- **`principal` / `resource_id`** on a tool call a cloud audit record
  corroborated: CloudTrail `userIdentity.arn` (or `principalId` /
  `userName`) and the first ARN the record names; GCP
  `authenticationInfo.principalEmail` and `resourceName`; Azure `caller`
  and `resourceId`. Credential formats are masked, values bounded.
- **`exec_env`** on a tool call an endpoint process record corroborated,
  when that record attributes the process to a container
  (`container:<id>`) or Kubernetes pod (`pod:<namespace>/<name>`).

## Investigation workflow

```sh
# 1. Acquire and verify
agentdfir collect --product claude
agentdfir verify <case>.adfir

# 2. Establish a known-good baseline (once, from a trusted host)
agentdfir baseline create <trusted>.adfir --out org-baseline.json

# 3. Check a suspect host against it
agentdfir baseline check <case>.adfir --baseline org-baseline.json
#   -> UNEXPECTED_MCP_SERVER for any server not in the baseline
#   -> MCP_CONFIG_CHANGED when an existing config's hash changed

# 4. Review MCP calls on the timeline
agentdfir timeline <case>.adfir | grep mcp_call
```

## Detections

- `UNEXPECTED_MCP_SERVER` — a server present on the host but not in the
  org baseline.
- `MCP_CONFIG_CHANGED` — the MCP configuration artifact's hash differs
  from baseline.
- `POTENTIAL_SECRET_EXPOSURE` — credential material observed in a
  transcript that also invoked MCP tools (possible exfil path).

## Interpreting MCP tool poisoning

A poisoned MCP server delivers malicious instructions through **tool
descriptions**, which the agent reads as context. Evidence of the *call*
(`OBSERVED`) does not by itself prove the *description* was malicious —
acquire the server's declared command and, where possible, the tool
schema it served, and correlate with any resulting agent behavior. Do not
label an incident "tool poisoning" without that supporting evidence.

## Limitations

- The live tool *schemas* a server served are not always persisted on the
  endpoint; only the client-side config and the resulting calls may be
  recoverable. Claude Code and Codex transcripts do not record
  `initialize` or `tools/list` results, so `tool_def_digest` and
  `mcp_server_version` are filled only from a gateway log that does.
- An empty `approval_state` means the evidence records no decision for
  that call. It is not evidence that the call was unauthorized, and a
  completed call is not evidence that it was approved.
- `safe_args` is an allowlist, not a search index of arguments: a value
  under any other key, or a free-text value, is reachable only through the
  sealed record the event points at.
- Server names are attacker-controlled strings; treat them as data
  (AgentDFIR sanitizes them before display).

## References

- [`.adfir` package spec](adfir-spec.md)
- [Claude Code Forensic Artifacts](claude-code-forensic-artifacts.md)
