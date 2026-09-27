# Claude Code Forensic Artifacts

*Where Claude Code stores evidence, what each artifact means, and how to
acquire it. Verified against Claude Code 2.x on 2026-09-01.*

Part of [AgentDFIR](https://efij.github.io/AgentDFIR/), open-source DFIR
for AI agents.

## Artifact locations

Claude Code stores per-user state under `~/.claude/` (overridable by the
`CLAUDE_CONFIG_DIR` environment variable) plus a global config file at
`~/.claude.json`.

| Artifact | Path | Forensic value |
|---|---|---|
| Session transcripts | `~/.claude/projects/<project-slug>/<session-id>.jsonl` | Primary evidence: every prompt, model response, tool call and result |
| Subagent transcripts | same dir, `isSidechain:true` lines / `agent-*.jsonl` | Subagent activity, spawn provenance |
| Prompt history | `~/.claude/history.jsonl` | Human prompts across sessions |
| Global config | `~/.claude.json` | MCP servers, project list, startup counts |
| Settings | `~/.claude/settings.json`, `settings.local.json` | Permission rules, default mode |
| Memory | `~/.claude/CLAUDE.md`, project `.claude/` | Standing instructions (context-poisoning surface) |
| Hooks | `~/.claude/hooks/` | Shell commands run on events (high-value tampering target) |
| Skills / Plugins / Agents / Commands | `~/.claude/{skills,plugins,agents,commands}/` | Extension definitions |
| Task / todo state | `~/.claude/{todos,tasks,plans}/` | Task orchestration state |
| File-history checkpoints | `~/.claude/file-history/` | Pre-edit file snapshots |
| Shell snapshots | `~/.claude/shell-snapshots/` | Captured shell environment |
| Debug logs | `~/.claude/logs/` | Diagnostic timeline |
| Managed settings | macOS: `/Library/Application Support/ClaudeCode/`; Linux: `/etc/claude-code/` | Org-enforced policy |

## Session transcript (JSONL) schema

Each line is a JSON object. Forensically relevant fields:

- `type`: `user` \| `assistant` \| `system` \| `summary`
- `uuid`, `parentUuid`: message linkage (reconstructs the conversation DAG)
- `sessionId`, `agentId`: session and (sub)agent identity
- `isSidechain`: `true` for subagent-side messages
- `timestamp`: RFC 3339 event time
- `message.content[]`: text, `tool_use` (with `name`, `input`, `id`),
  and `tool_result` (with `tool_use_id`) items
- `version`: Claude Code version that wrote the line

## Interpretation: evidence vs claims

An `assistant` **text** item saying "I ran the deploy" is a *claim*
(`REPORTED`). Only a `tool_use` item named `Bash` with that command is
`OBSERVED`. Endpoint evidence (process/DNS/EDR) is required for
`CORROBORATED`. Never treat model narrative as confirmed host activity.

## Collection

```sh
# Current user
agentdfir collect --product claude

# All users / offline image
agentdfir collect --product claude --path /mnt/image/Users/suspect

# Verify integrity afterwards
agentdfir verify <case>.adfir
```

AgentDFIR acquires every artifact above losslessly into a sealed,
hash-chained package — following symlinks is refused, and the `claude`
binary is never executed (its hash is recorded instead).

## Detection ideas

- **Orphan subagent**: an `agent-*.jsonl` transcript with no `Task`
  spawn record linking a parent (`ORPHAN_AGENT`).
- **Cross-agent messaging**: `SendMessage` to an agent in another session
  (`CROSS_SESSION_MESSAGE`).
- **Permission bypass**: `settings.json` with
  `"defaultMode":"bypassPermissions"` (`PERMISSION_BYPASS_ENABLED`).
- **Config drift**: compare `~/.claude/hooks/` and MCP servers against an
  org baseline (`agentdfir baseline check`).

## Limitations

- Transcripts are user-writable files; a lone `OBSERVED` from a single
  JSONL is weaker than one corroborated by endpoint evidence, and is
  downgraded when `TRACE_GAP`/tampering indicators fire.
- Deleted sessions may leave no artifact; absence is not proof of absence.
- Format fields drift across Claude Code versions; AgentDFIR records the
  `version` and preserves unparsed lines as opaque evidence.

## References

- [`.adfir` package spec](adfir-spec.md)
- [Event schema](schema/event.schema.json)
