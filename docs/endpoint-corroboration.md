# Enrich — the second witness

An agent's transcript is witness #1: the agent's own diary. It can be wrong (the model narrated something that never ran), incomplete (a hidden subprocess), or edited. `agentdfir correlate` brings in witness #2 — the operating system's own telemetry — and re-labels every tool call by how much proof exists:

| State | Meaning |
|---|---|
| **REPORTED** | model text only — "I deleted the build dir" |
| **OBSERVED** | the agent's log has a real tool call — still only witness #1 |
| **CORROBORATED** | the OS recorded the same process / file / connection at the same moment — two independent witnesses agree |
| **CONTRADICTED** | telemetry covered that moment and shows nothing matching — it did not happen the way the transcript says |
| **UNKNOWN** | no telemetry for that moment — absence of evidence is never a contradiction |

## One command

```sh
agentdfir correlate CASE-42.adfir /var/log/audit/audit.log            # Linux auditd
agentdfir correlate CASE-42.adfir sysmon.xml                           # Windows Sysmon (XML export)
agentdfir correlate CASE-42.adfir procs.jsonl netconns.csv             # Velociraptor / osquery / eslogger / EDR exports
agentdfir analyze   CASE-42.adfir --endpoint audit.log                 # same, inside the one-shot analysis
agentdfir analyze   CASE-42.adfir --endpoint cloudtrail.json           # cloud audit export: the agent's az / aws / gcloud commands
```

Format is sniffed per file (`--format auditd|sysmon-xml|jsonl|csv|cloud-audit` to override). `--window 3s` sets the match window. Results are written back to `normalized/events.jsonl` (states + an evidence note naming the confirming record) and to `detections/corroboration.json`; `triage` merges the findings so every downstream report, OCSF/SARIF export and PDF carries the upgraded states.

## Supported telemetry

| Source | How to get it | What it yields |
|---|---|---|
| **auditd** | `/var/log/audit/audit.log` (execve auditing: `-a always,exit -F arch=b64 -S execve`) | process (SYSCALL+EXECVE, hex args decoded, CWD), network (SOCKADDR AF_INET/6), file (PATH create/delete, write opens) |
| **Sysmon** | `wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml > sysmon.xml` | EventID 1 process, 3 network, 11/23/2 file |
| **Generic JSONL / CSV** | Velociraptor (`Linux.Events.ProcessExecutions`, `Windows.System.Pslist`…), osquery `process_events`, `evtx_dump -o jsonl`, macOS `eslogger exec open create unlink` | nested JSON flattened; ~90 field aliases cover pid/ppid/exe/cmdline/parent/user/dest ip+port/file path |

| **AWS CloudTrail** | the trail's S3 objects (`{"Records":[…]}`), `aws cloudtrail lookup-events` output, or events one per line | cloud: service and API call, principal ARN, source IP, request resource names, error code |
| **Azure Activity Log** | `az monitor activity-log list -o json`, the REST `{"value":[…]}` shape, or diagnostic-settings `{"records":[…]}` blobs | cloud: Resource Manager operation, caller, resource id, client IP, Failed status |
| **GCP Cloud Audit Logs** | `gcloud logging read 'logName:cloudaudit.googleapis.com' --format=json` | cloud: service and method, principal email, resource name, caller IP, status code |

Cloud exports are read from files only: nothing calls a cloud API.

Raw `.evtx` is not parsed — export first (documented limitation). macOS unified log lacks exec argv; use `eslogger` (Endpoint Security) output.

## What the engine does

1. **Tool call → record.** For each transcript tool call with a command, file or network destination, find endpoint records within ±window. Commands match by normalized equality, shell-wrapper containment (`/bin/zsh -c 'rm -rf build'`), truncated telemetry, or same program + ≥60 % token overlap; compound commands (`a && b | c`) match any segment. Files match by path suffix; network by IP or host.
2. **Agent lineage.** A record belongs to the agent if its parent image, or any ancestor in the pid tree, is an agent binary (Claude, Cursor, Codex, Gemini, Copilot, Aider, OpenCode, Warp, Code Helper…) or a `node …/@anthropic-ai/claude-code/cli.js`-style runtime invocation.
3. **Findings.**

| Rule | Severity | Fires when | Example |
|---|---|---|---|
| `ENDPOINT_CONTRADICTED_COMMAND` | HIGH | tool call inside telemetry coverage, no matching process | transcript `pytest -q`, model says "42 tests passed", auditd has no pytest → **CONTRADICTED** |
| `UNLOGGED_AGENT_ACTIVITY` | MEDIUM | agent-lineage process exec with no transcript tool call (grouped per program, runtime helpers filtered) | `nc 185.10.10.10 4444` spawned under the agent, not in any transcript |
| `UNLOGGED_AGENT_NETWORK` | HIGH | agent-lineage connection to a non-allowlisted destination with no transcript reference | Cursor's `node` child connects to `185.x.x.x:4444` |

| `CLOUD_DESTRUCTIVE_BURST` | HIGH | a cloud audit log shows one identity deleting 10+ distinct resources within 10 minutes (refused calls do not count) | a leaked service principal deletes a dozen storage accounts in six minutes |

Contradiction requires **process** telemetry covering that moment; with only network or file records, unmatched commands stay OBSERVED.

### Cloud audit logs

An agent's `az`, `aws` or `gcloud` command is **CORROBORATED** when the control plane recorded the same operation within ±2 minutes, on the same resource when the command names one: `az storage account delete -n acct1` matches `Microsoft.Storage/storageAccounts/delete` on `…/storageAccounts/acct1`, `aws s3 rb s3://b` matches `s3:DeleteBucket` for `b`, `gcloud sql instances delete db1` matches `cloudsql.instances.delete` on `…/instances/db1`. When the cloud refused the call, the note says so and names the error.

A cloud log never **contradicts** a command. The export may be for a different account, subscription or project, so a missing record means nothing. Cloud records also do not count as host telemetry: a cloud-only export gives no process coverage.

## Example

```
Endpoint log audit.log: auditd, 7 records
Endpoint correlation: 3 tool calls checked — 2 CORROBORATED, 1 CONTRADICTED, 0 outside telemetry coverage; 4 agent-lineage records, 2 unlogged.
Telemetry coverage: 2026-08-30T09:59:00Z → 2026-08-30T10:01:30Z

HIGH — Transcript Command Not Seen by the Operating System [ENDPOINT_CONTRADICTED_COMMAND]
  Finding: Transcript records tool Bash running "pytest -q" at 2026-08-30T10:00:20Z, but endpoint telemetry covering that time shows no matching process…
HIGH — Agent Process Connected to a Destination Not in the Transcript [UNLOGGED_AGENT_NETWORK]
  Finding: … nc (pid 4430, under the agent's process tree) connecting to 185.10.10.10:4444 …
```

See also: [MCP audit](mcp-audit.md) (`--gateway-log` is the same idea for MCP calls), [SIEM interop](siem-interop.md).
