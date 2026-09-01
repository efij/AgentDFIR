# MCP Forensics

*Investigating Model Context Protocol (MCP) server configuration and tool
activity in AI-agent incidents. Verified 2026-09-01.*

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
  recoverable.
- Server names are attacker-controlled strings; treat them as data
  (AgentDFIR sanitizes them before display).

## References

- [`.adfir` package spec](adfir-spec.md)
- [Claude Code Forensic Artifacts](claude-code-forensic-artifacts.md)
