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
agentdfir correlate CASE-42.adfir Sysmon.evtx Security.evtx            # raw Windows event logs, no export step
agentdfir correlate CASE-42.adfir procs.jsonl netconns.csv             # Velociraptor / osquery / eslogger / EDR exports
agentdfir analyze   CASE-42.adfir --endpoint audit.log                 # same, inside the one-shot analysis
agentdfir analyze   CASE-42.adfir --endpoint cloudtrail.json           # cloud audit export: the agent's az / aws / gcloud commands
```

Format is sniffed per file (`--format auditd|sysmon-xml|evtx|jsonl|csv|cloud-audit` to override). `--window 3s` sets the match window. Results are written back to `normalized/events.jsonl` (states + an evidence note naming the confirming record) and to `detections/corroboration.json`; `triage` merges the findings so every downstream report, OCSF/SARIF export and PDF carries the upgraded states.

## Supported telemetry

| Source | How to get it | What it yields |
|---|---|---|
| **auditd** | `/var/log/audit/audit.log` (execve auditing: `-a always,exit -F arch=b64 -S execve`) | process (SYSCALL+EXECVE, hex args decoded, CWD), network (SOCKADDR AF_INET/6), file (PATH create/delete, write opens) |
| **Sysmon** | `wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml > sysmon.xml` | EventID 1 process, 3 network, 11/23/2 file |
| **Windows .evtx** | the raw files: `C:\Windows\System32\winevt\Logs\*.evtx` (or a KAPE/triage copy) | Sysmon, Security 4688, PowerShell 4104 and more — see [Native .evtx files](#native-evtx-files) |
| **Generic JSONL / CSV** | Velociraptor (`Linux.Events.ProcessExecutions`, `Windows.System.Pslist`…), osquery `process_events`, `evtx_dump -o jsonl`, macOS `eslogger exec open create unlink` | nested JSON flattened; ~90 field aliases cover pid/ppid/exe/cmdline/parent/user/dest ip+port/file path |

| **AWS CloudTrail** | the trail's S3 objects (`{"Records":[…]}`), `aws cloudtrail lookup-events` output, or events one per line | cloud: service and API call, principal ARN, source IP, request resource names, error code |
| **Azure Activity Log** | `az monitor activity-log list -o json`, the REST `{"value":[…]}` shape, or diagnostic-settings `{"records":[…]}` blobs | cloud: Resource Manager operation, caller, resource id, client IP, Failed status |
| **GCP Cloud Audit Logs** | `gcloud logging read 'logName:cloudaudit.googleapis.com' --format=json` | cloud: service and method, principal email, resource name, caller IP, status code |

Cloud exports are read from files only: nothing calls a cloud API.

macOS unified log lacks exec argv; use `eslogger` (Endpoint Security) output.

## Native .evtx files

Raw Windows event log files are read directly by a parser written for AgentDFIR (Go standard library only, no Windows API, no third-party code). Pass the file as is: the `ElfFile` signature is sniffed, or force it with `--format evtx`. One file per argument; `--endpoint` does not take directories.

| Provider (channel) | Event ID | Becomes | Fields used |
|---|---|---|---|
| Microsoft-Windows-Sysmon (Sysmon/Operational) | 1 | process | Image, CommandLine, ProcessId, ParentProcessId, ParentImage, User |
| | 3 | network | DestinationIp, DestinationPort, DestinationHostname |
| | 11 / 2 / 23 / 26 | file (create / modify / delete / delete) | TargetFilename |
| | 22 | network (DNS query) | QueryName → destination host, Image, ProcessId |
| Microsoft-Windows-Security-Auditing (Security) | 4688 | process; process-image when no command line was audited | NewProcessName, CommandLine, NewProcessId / ProcessId (hex), ParentProcessName, user |
| Microsoft-Windows-PowerShell (PowerShell/Operational) | 4104 | script | ScriptBlockText, Execution ProcessID, MessageNumber/MessageTotal, Path |
| Service Control Manager (System) | 7045 | service + operator notice | ServiceName, ImagePath, AccountName |
| Microsoft-Windows-Eventlog (Security / System) | 1102 / 104 | log-clear + operator notice | SubjectUserName, SubjectDomainName, Channel |

Sysmon events go through the same mapping as the XML export, so the same events read from `Sysmon.evtx` or from `wevtutil … /f:xml` give identical records, notes and states.

Script blocks (4104) are a weaker witness. They can **corroborate** a command, but only on an exact match (whitespace collapsed, case ignored) or when the whole command appears inside the block with a token boundary on both sides. Containment needs at least 12 characters and two tokens. For `powershell|pwsh -c|-Command <script>`, the inner script is tried as well. Only the first 64 KiB of a block is considered. Script blocks are not complete process telemetry, so they never contradict a command and never extend the telemetry's coverage window. A match is recorded in the event's `witness_note` with the basis `script-block:`. If a command was already CONTRADICTED by process telemetry and a matching script block exists, the state stays CONTRADICTED and the block is named in the evidence note (an in-process PowerShell host runs scripts without starting a process).

Security 4688 records with no command line (command-line auditing off) become `process-image` records. They name only the program, so the most they give is **PARTLY CONFIRMED** (`PARTIALLY_CORROBORATED`): a command, or one of its `&&` / `|` / `;` segments, must start with a program whose name equals the record's image basename (`.exe` ignored) within the window. They never contradict a command and never widen coverage, and a match is marked `process-image:` in `witness_note`. 4688 records that do carry a command line, including ones in the same file, are ordinary process telemetry and behave like Sysmon event 1.

Service installs and cleared logs are not correlation input. They are listed as `notice:` lines under the log's summary (`agentdfir correlate`, and the `analyze` / `run` log). No new detection rule is attached to them.

What the parser checks and how it handles damage:

| Check | On failure |
|---|---|
| File signature `ElfFile` | not an .evtx file: format error (other formats are then not tried) |
| File header CRC32 (first 120 bytes) | noted; chunks are still read |
| Format version 3.x | other versions noted as `UNSUPPORTED evtx format version …`; parsing is attempted |
| Chunk signature `ElfChnk` | chunk skipped and counted; all-zero (preallocated) chunks are skipped silently |
| Chunk header CRC32 and event-records CRC32 | noted; the chunk's records are still read, and each one's reference ends in `chunk checksum mismatch` |
| Record signature, size and trailing size copy | rest of that chunk skipped, next chunk read |
| Binary XML inside a record | that record skipped and counted, next record read |
| Truncated file or last chunk | what is present is read; the truncation is noted |

Binary XML support: fragment headers, elements with and without the dependency identifier, attributes, value text, CDATA, character and entity references, processing instructions (ignored as content), template instances with inline or back-referenced definitions (cached per chunk), normal and optional substitutions, names inline or by chunk offset, and all value types (strings UTF-16 and ANSI, signed/unsigned 8–64-bit integers, hex integers, reals, bool, binary, GUID, size_t, FILETIME, SYSTEMTIME, SID, arrays of these, nested BinXml).

Not read, by design: records left in chunk slack space after the free-space offset (counted and noted, not parsed), the header's dirty flag (noted; records are read as found), registry events (Sysmon 12–14), process termination (Sysmon 5), logons (Security 4624/4625) and every other provider/event ID (a single note counts them and names the most common). Message strings from provider DLLs are not resolved; only the event's own data is used.

Bounds: files up to 2 GiB, read one 64 KiB chunk at a time; nesting depth 32; per-chunk and per-record caps on parsed nodes, rendered nodes and rendered text (attribute values included); a fault inside one record is converted to a recorded problem.

Fixtures are synthetic. The tests build .evtx files with a test-only writer (`internal/endpoint/evtx/evtxtest`) that emits valid headers, chunks with correct CRCs and string/template tables, and templates with substitution arrays; no real Windows logs are committed. A fuzz test (`FuzzChunk`) mutates chunks seeded from that writer.

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

---

## DNS, proxy and authentication logs (partial witnesses)

These sources each see part of what happened. They can **corroborate** a tool call; they **never contradict** one, never count as telemetry coverage (a DNS log next to an auditd log does not stretch the auditd window), and never raise `UNLOGGED_*` findings: a lookup or a proxied request names a client IP, not a process, so nothing ties it to the agent's process tree. Unmatched lookups and requests are therefore not reported as unexplained; that would need process lineage these logs do not carry.

| Witness | Matches a tool call when | State |
|---|---|---|
| proxy request (Squid, Zeek http.log / ssl.log SNI, proxy exports) | same host as a URL or destination in the call (or a subdomain of it), within ±2 min | **CORROBORATED**, like a host network record; **PARTLY CONFIRMED** when both sides carry a URL path and the paths differ |
| sudo `COMMAND=` line, journal `_CMDLINE` | same command (the leading `sudo [flags]` is ignored), within `--window` | **CORROBORATED** |
| DNS query | a lookup of exactly the host the call contacted (curl/wget/scp/ssh destinations, URLs in the command, an MCP tool's URL), within ±2 min | **PARTLY CONFIRMED** only: a lookup shows intent to connect, not a connection |
| sshd `Accepted … for <user>` | an `ssh user@host` command with that user, within ±2 min | **PARTLY CONFIRMED** only: the log does not name the host it came from |

Why a miss means nothing: resolvers cache, programs use hard-coded IPs, traffic can go around the proxy, and the log may be from another machine. `detections/corroboration.json` carries `witness_records`, `witness_corroborated` and `witness_partial`.

### DNS query logs — `--format dns-log` / `zeek`

| Log | Lines read | Record |
|---|---|---|
| Zeek `dns.log` (TSV with `#fields` header, or JSON lines) | every row with a `query` | `dns`: query name, client (`id.orig_h`), `qtype_name`, answers |
| BIND query log (`querylog yes`, file or syslog) | `client … 10.0.0.5#53514 (name): query: name IN A …` | `dns`: name, client, type |
| dnsmasq / Pi-hole `pihole.log` | `query[A] name from 10.0.0.5`; the following `reply`/`cached`/`gravity blocked … is …` lines become the answers | `dns` (source `dnsmasq` or `pihole`) |
| Unbound (`log-queries: yes`) | `[epoch] unbound[pid:0] info: 10.0.0.5 name. A IN` | `dns` |
| Windows DNS Server debug log | `PACKET … UDP Rcv <client> <xid>   Q [...] A (7)example(3)com(0)` (client queries only; responses and recursion are skipped) | `dns` |

Not read: Pi-hole `FTL.log` (diagnostics, no queries; use `pihole.log`), DNS-over-HTTPS from the client (no resolver log exists), Zeek logs other than dns/http/ssl (reported as `UNSUPPORTED`).

### Web proxy / secure web gateway — `--format squid` / `zeek` / `jsonl` / `csv`

| Log | Record |
|---|---|
| Squid `access.log`, native (`epoch elapsed client CODE/status bytes method URL user hierarchy/peer type`) and common (`client - user [time] "METHOD URL HTTP/1.1" status bytes TCP_…:HIER_…`) | `network`: host, port, `url`, method, client, user; `TCP_DENIED` and HTTP ≥ 400 kept as `failed` |
| Zeek `http.log` | `network`: `host`, `uri`, method, server IP/port, status ≥ 400 as `failed` |
| Zeek `ssl.log` | `network`: SNI `server_name`, server IP/port (no path) |
| Generic JSONL / CSV with a `url` field (`url`, `request_url`, `url.full`, `url.original`, `http.url`, `cs-uri`, …) and no command line | `network` (source `proxy-export`) |

HTTPS through a forward proxy is a `CONNECT host:443`: the host is known, the path is not, so such a record corroborates by host. A common-format access log from a web server (relative URLs, no Squid result codes) is not taken for a proxy log.

### Linux authentication logs — `--format authlog` / `journald`

| Source | Lines read | Record |
|---|---|---|
| `/var/log/auth.log`, `/var/log/secure` (classic syslog or RFC 3339 timestamps) | sudo `… ; USER=root ; COMMAND=…` (including refusals such as `command not allowed`) | `process`: the command, invoking user, `failed` |
| | sshd `Accepted` / `Failed` / `Invalid user` | `auth`: method, user, source IP |
| | su (`pam_unix(su:session): session opened …`, `Successful su …`, `FAILED SU …`) | `auth`: target in `resource`, invoking user |
| `journalctl -o json` | `__REALTIME_TIMESTAMP`, `_PID`, `_EXE`, `_CMDLINE`, `_UID`, `MESSAGE` (string or byte array), `SYSLOG_IDENTIFIER` | one `process` per pid + command line; sudo/sshd/su messages parsed as above |

Classic syslog timestamps have no year and no zone: the year comes from the file's modification time and the zone is UTC, the same rule as every other zone-less timestamp here. Lines from other programs (cron sessions and the like) are counted as skipped, not as problems.

## Kubernetes, Git hosting and object storage audit logs (cloud-like witnesses)

These follow the cloud audit logs above, with one stricter rule: a command is **CORROBORATED** only when the service recorded the same operation on the resource the command names, within ±2 minutes. A command that names no resource (`kubectl apply -f manifest.yaml`, `git push origin main`, `aws s3 ls`), or a record that names none, matches by operation alone and gets **PARTLY CONFIRMED** (`cloud_partial` in `corroboration.json`). A refusal is noted; a miss changes nothing, nothing is ever contradicted, and the records give no host coverage. Full matches are counted in the `Cloud audit correlation` line.

### Resource name matching (all cloud and cloud-like audit sources)

A resource name from a command matches a record only on whole segments: the record's resource (or one of its space-separated ids) equals the name, or the name's `/`-separated segments appear as whole, consecutive segments of it (ARN `:` counts as a separator, an `s3://`/`gs://` scheme is ignored). `prod` matches `…/storageAccounts/prod` and `prod/db`, never `nonprod-db` or `acctprod`; names shorter than three characters match only the whole resource. This also applies to the CloudTrail / Azure Activity / GCP pass above, where earlier versions matched any substring. The documented cloud behaviour is otherwise unchanged: an `az`/`aws`/`gcloud` command that names no resource is still CORROBORATED by an operation match. For kubectl, `-n <namespace>` makes the compared name `<namespace>/<name>`.

### Host extraction

Hosts are taken from each URL with a URL parser, never with a pattern: in `curl https://trusted.com@evil.com/x` the host is `evil.com` (what curl contacts), and the userinfo part is never used. URLs that do not parse, or whose host is percent-encoded (clients disagree on decoding it), are dropped rather than guessed at. IPv6 literals (`http://[2001:db8::5]:8080/`) keep their address without brackets or port. The same parser fills every tool call's network destination at normalization (`netdest.Extract`), so the host network matching of auditd and Sysmon records is protected as well. For these witnesses a call with a command line is read from the command itself; the stored destination is used for calls without one (MCP and fetch tools).

### Kubernetes audit log — `--format k8s-audit`

`audit.k8s.io/v1` Event JSON lines (or an EventList). Only the final stage of each request (`ResponseComplete`/`Panic`) becomes a record; earlier stages are counted as skipped. Record: `operation` = `<verb> <resource>[/<subresource>]`, `resource` = `<namespace>/<name>`, user `user.username`, first `sourceIPs`, `failed` = HTTP status ≥ 400.

`kubectl` (and `oc`) verbs map to audit verbs: `get`/`describe` → get/list, `delete` → delete/deletecollection, `apply` → create/patch/update, `edit`/`patch`/`label`/`scale`/`rollout` → patch/update, `exec`/`cp`/`port-forward` → create on `pods/…`, `logs` → get `pods/log`. Short names (`po`, `deploy`, `svc`, `cm`, …) and `type/name` arguments are understood; `-f manifest.yaml` matches by verb alone since the command line does not show the resources. Kubernetes records do not feed `CLOUD_DESTRUCTIVE_BURST` (controllers delete pods all day).

### GitHub / GitLab audit exports — `--format git-audit`

| Export | Fields read |
|---|---|
| GitHub audit log, JSON (array or lines) or CSV | `action`, `actor`, `repo`, `@timestamp`/`created_at` (epoch ms or RFC 3339), `actor_ip`, and `branch`/`name`/`team`/`user`/`org` into `resource` |
| GitLab audit events JSON | `event_name` (or `details.custom_message`, `details.add`/`remove`/`change`), `details.author_name`, `details.entity_path`/`target_details`, `details.ip_address`, `created_at` |

Matched commands: `gh repo create|delete|archive|rename|edit …`, `gh pr|release|secret|variable|workflow … <verb>`, `gh api -X POST|PUT|PATCH|DELETE repos/<owner>/<repo>/…` (reads are not audited and are not matched), `git push` (`git.push`; the repository is only known when the push names a URL), `glab repo create|delete`. GitHub and GitLab records do feed `CLOUD_DESTRUCTIVE_BURST`: one identity destroying ten repositories in ten minutes is rare.

### Object-storage access logs — `--format storage-access`

| Log | Record |
|---|---|
| S3 server access log | `operation` = S3 operation (`REST.DELETE.OBJECT`, `REST.PUT.OBJECT`, …), `resource` = `bucket/key`, requester ARN, remote IP, error code |
| GCS usage logs (CSV with header) | `operation` = `cs_method cs_operation`, `resource` = `cs_bucket/cs_object`, `c_ip`; usage logs name no principal |
| Azure Storage Analytics logging (`$logs`, format 1.0 and 2.0) | `operation` = operation type (`DeleteBlob`, `PutBlob`, …), `resource` = requested object key, requester account, IP |

Matched commands: `aws s3 rm|rb|mb|ls|cp|mv|sync`, `aws s3api delete-object|put-object|get-object|delete-bucket|create-bucket|list-objects…`, `gsutil` / `gcloud storage rm|cp|mv|ls|mb|rb|buckets …`, `az storage blob delete|upload|download|list`, `az storage container delete|create|list`. Storage records do not feed `CLOUD_DESTRUCTIVE_BURST` (object churn is routine). Not read: S3 CloudTrail data events (use `--format cloud-audit`), Azure Monitor resource logs for storage (`StorageBlobLogs`), GCS Cloud Audit data-access logs (`cloud-audit`).

### What these adapters never do

None of the DNS, proxy, auth-log, journal, Kubernetes, Git-hosting or storage adapters can produce **CONTRADICTED** or `ENDPOINT_CONTRADICTED_COMMAND`: their coverage of what an agent did is unknown, so the absence of a record is not evidence of anything. All test fixtures for these formats are synthetic.
