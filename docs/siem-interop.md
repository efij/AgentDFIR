# SIEM / SOC interop — OCSF, SARIF, Sigma

AgentDFIR findings and timelines drop into the pipelines security teams already run. Nothing is transmitted; every exporter writes local files you ship yourself.

## OCSF 1.3 (`agentdfir report <pkg> --format ocsf`)

Writes `events.ocsf.jsonl` and `findings.ocsf.jsonl` — one [OCSF](https://schema.ocsf.io/) object per line, ready for Amazon Security Lake, Splunk/Sentinel OCSF normalizers, or any lake that speaks OCSF.

| AgentDFIR | OCSF class | Notes |
|---|---|---|
| `tool_call` with a shell command | Process Activity (1007, Launch) | `process.cmd_line`, `process.name` |
| `tool_call` touching a file | File System Activity (1001) | activity from action: create/read/update/delete |
| every other event | API Activity (6003) | `api.operation` = event type or tool name |
| finding | Detection Finding (2004) | `finding_info.analytic.name` = rule ID, `attacks[]` carry ATT&CK / ATLAS technique IDs |

`time` is epoch milliseconds; `severity_id`/`confidence_id` follow the OCSF enums (confidence derives from corroboration state: CORROBORATED → High, OBSERVED → Medium, REPORTED → Low). Network destinations become `dst_endpoint` plus a Hostname/IP observable. Everything forensic that OCSF has no field for — corroboration state, agent lineage, MCP server, evidence artifact/line/offset — travels under `unmapped.agentdfir.*`, so a downstream analyst can always get back to the sealed evidence.

## SARIF 2.1.0 (`--format sarif`)

`findings.sarif.json` loads in the GitHub code-scanning tab, the VS Code SARIF viewer and SARIF-aware pipelines. Each rule appears once under `tool.driver.rules` with MITRE IDs in `properties`; each result points at the evidence's logical path and line via `physicalLocation`. Severity → level: HIGH/CRITICAL `error`, MEDIUM `warning`, else `note`. Results carry a stable `partialFingerprints` value so re-exports de-duplicate.

## Sigma (`agentdfir rules export --sigma <pack-dir> --out sigma/`)

Converts declarative rule packs (the shipped `rules/` directory or [agentdfir-rules](https://github.com/efij/agentdfir-rules)) to one Sigma YAML per rule:

- `match.type: command` → `logsource.category: process_creation`, field `CommandLine` — **portable to EDR/Sysmon/auditd process telemetry**, so a behavior first seen in an agent transcript becomes a fleet-wide hunt through sigmac/pySigma.
- `summary`, `config`, `transcript` → `logsource.product: agentdfir` — run against the OCSF/OTel feed above.
- `contains` → `|contains`, `regex` → `|re`; ATT&CK IDs become `attack.tXXXX` tags; severity maps to Sigma `level`.

Built-in Go rules (orphan agents, session tampering, exfiltration sequences…) are stateful and multi-event; they are not expressible as Sigma selections and are not exported.
