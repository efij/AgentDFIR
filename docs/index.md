# AgentDFIR

**Open-source digital forensics and incident response for AI agents.**

Last updated: 2026-09-01 · Status: early development (evidence packages + Claude Code collector in progress)

## What is AI agent forensics?

AI agent forensics is the discipline of collecting, preserving and analyzing the evidence left behind by agentic AI tools — Claude Code, OpenAI Codex CLI, Cursor, Gemini CLI, GitHub Copilot CLI and similar — so an incident responder can answer:

> Who instructed which AI agent/subagent to perform what action, through which tool/MCP/identity, against which resource, what actually happened on the endpoint, and what evidence proves it?

AI coding agents execute shell commands, edit files, spawn subagents, call MCP servers and push code. When something goes wrong — a prompt injection, a poisoned MCP tool, a rogue subagent, data exfiltration — the session transcripts, configuration files and tool-call logs on the endpoint are the primary evidence. Almost no tooling exists to acquire and analyze them forensically. AgentDFIR is that tooling.

## Core principle: evidence vs claims

AI-generated text is never automatically treated as factual evidence of execution. Every significant action is classified:

| State | Meaning |
|---|---|
| `REQUESTED` | a human asked for it |
| `REPORTED` | the model *said* it happened |
| `OBSERVED` | a tool-call record exists in the transcript |
| `CORROBORATED` | independent endpoint/network evidence supports it |
| `CONTRADICTED` | endpoint evidence shows it did not occur |
| `UNKNOWN` | insufficient evidence |

Model narrative is never presented as confirmed host activity.

## What AgentDFIR will do

- `agentdfir detect` — discover installed AI tooling and versions on a host
- `agentdfir collect` — lossless, hash-verified forensic acquisition of agent artifacts (sessions, subagents, MCP configs, hooks, skills, permissions) across macOS, Windows and Linux
- `agentdfir verify` — tamper detection over sealed evidence packages
- `agentdfir triage` / `timeline` / `investigate` — deterministic parsing, unified timeline, agent relationship graph
- `agentdfir report` — self-contained, network-silent HTML/JSON reports with evidence-linked findings
- `agentdfir simulate` — synthetic rogue-agent incident generation for detection validation and training

Artifact-reference pages (Claude Code forensic artifacts, MCP forensics, prompt injection investigation, and more) will be published here as each collector ships — every page verified against a real product version, with exact paths, schemas and interpretation guidance.

## License

Apache-2.0 · [GitHub repository](https://github.com/efij/AgentDFIR)
