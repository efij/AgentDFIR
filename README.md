# AgentDFIR

**Open-source digital forensics and incident response for AI agents.**

Collect, preserve, reconstruct and investigate activity from Claude Code, Codex, Cursor, Gemini, Copilot, OpenClaw and other AI agents.

Think KAPE / Velociraptor for the agentic-AI forensic layer. AgentDFIR lets an incident responder answer:

> Who instructed which AI agent/subagent to perform what action, through which tool/MCP/identity, against which resource, what actually happened on the endpoint, and what evidence proves it?

## Status

Early development. Phase 1 in progress: sealed evidence packages (`.adfir`), product detection, and the Claude Code collector (`detect`, `collect`, `verify`).

## Core Principle

AgentDFIR always distinguishes:

1. what the **human requested**
2. what the **model said**
3. what the **agent/tool attempted**
4. what the **endpoint actually executed**
5. what **independent evidence corroborates**

AI-generated text is never automatically treated as factual evidence of execution.

## License

Apache-2.0
