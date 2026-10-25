# Black-box recorder (`monitor --record`)

An agent transcript collected after an incident proves nothing about
whether it was edited, and the OS telemetry that would contradict it is
often rotated away by then. The black-box recorder keeps both, on the
host, from before the incident: agent transcripts, MCP config changes and
OS telemetry, every byte range in the monitor's hash-chained journal.

It is the existing `agentdfir monitor`, not a second engine. The
transcript watch, live detection (`--detect`, `--alert`) and the journal
(`--journal`, `--journal-anchor`) work as before; `--record` turns the
journal on and adds the sources below.

```sh
# Linux: agent transcripts + auditd + a Falco JSON export, kept 7 days / 2 GB
sudo agentdfir monitor --record --auditd /var/log/audit/audit.log \
     --tail /var/log/falco/events.json --retain 7d,2GB --journal-anchor /root/anchor.log

# macOS: agent transcripts + Endpoint Security through Apple's eslogger
sudo agentdfir monitor --record --es --retain 7d

agentdfir monitor status            # collection health, offline, from the state dir
agentdfir journal verify            # chain + every capture: intact, pruned (journaled) or deleted
agentdfir replay ~/.agentdfir/monitor          # step through the recording
agentdfir run --endpoint ~/.agentdfir/monitor  # investigate: correlate transcripts with the recording
```

## What it records

| Source | Flag | What is read | Capture | Sequence numbers (gap detection) | Needs |
|---|---|---|---|---|---|
| Agent transcripts | always (watched dirs, or every detected agent) | appended bytes of `*.jsonl` session files, in place | none: the transcript itself; each append range is journaled | none | the user who runs the agent |
| MCP invocations | (part of transcripts) | MCP tool calls are transcript lines, so they are journaled with them. An MCP gateway's own JSONL log can be recorded with `--tail` | as transcripts / `tail-<name>-*.jsonl` | none | read access to the gateway log |
| MCP config changes | on with `--record` (`--no-mcp-config` turns it off) | every MCP host config location `mcp audit` knows (`~/.claude.json`, `.cursor/mcp.json`, Claude Desktop, VS Code, Cline, Roo, Gemini, Codex, Windsurf, Continue, managed settings…): appear / change / disappear | `mcp-config-*.jsonl`: path, size, mtime, SHA-256 per change | none | the user |
| Endpoint Security (macOS) | `--es` | Apple's `/usr/bin/eslogger` as a child process | `eslogger-*.jsonl` (raw eslogger JSON) | `global_seq_num` | root, macOS 13+, Full Disk Access for the terminal |
| auditd (Linux) | `--auditd <path>` | the audit log, tailed read-only from its current end | `auditd-*.log` (raw records) | audit serial (`msg=audit(…:serial)`) | root (audit.log is `root:root 0600`) or a group with read access |
| Any endpoint export | `--tail <file>` (repeatable) | a growing file the endpoint importer reads: Tetragon JSON export, Falco JSON output, Sysmon XML export, bpftrace JSON lines, journald JSON, Zeek… The format is sniffed by content | `tail-<name>-*.jsonl`, `.log` or `.xml` | eslogger and auditd formats as above; others none | read access to the file |

Captures are the raw bytes the source wrote, unchanged, so each one is
importable later with `--endpoint` and its hash means something. They roll
over at 64 MiB or one hour (at a line boundary), which is what lets
retention prune old data while recording continues.

Tailing is rotation-aware: when the file is renamed away (logrotate
`create`), the old file is read to its end and the new one from its first
byte; a file truncated in place (`copytruncate`) restarts at 0, and the
status notes that bytes written between the last poll and the truncation
are not captured. `--tail-from-start` also records what the file held when
the monitor started; by default that history is left for `--endpoint` to
read directly.

### UNSUPPORTED and limits

- A `--tail` file the endpoint importer does not recognize is still
  recorded and journaled byte for byte; its status shows format
  `UNSUPPORTED` with the importer's reason, and `run --endpoint <state dir>`
  / `replay` list it as UNSUPPORTED rather than importing it.
- Binary `.evtx` files are not tailed (records are not appended as lines);
  the status says so. Export them, or pass the file to `--endpoint`.
- Sources without sequence numbers (Tetragon, Falco, Sysmon XML exports,
  transcripts) cannot show drops; `monitor status` says "drops cannot be
  detected" for them. A missing record there is never evidence that
  nothing happened.
- Audit serials can skip for reasons other than loss (events suppressed by
  exclude rules after a serial was assigned). A gap in `auditd` is a reason
  to look, not proof of tampering. Records of neighbouring events that
  arrive out of order fill their holes and are not counted; a serial that
  jumps far back is counted as a reset (reboot, auditd restart).
- eslogger's own drop counters are not exposed by eslogger; drops are seen
  only as `global_seq_num` gaps.
- The recorder does not load eBPF programs or run an Endpoint Security
  client of its own (both would need third-party code or an Apple
  entitlement). It records what auditd, eslogger, Tetragon and Falco
  produce.

## Tamper evidence

Every flushed range of every capture goes into the same journal the
transcript appends use (`~/.agentdfir/monitor/journal.jsonl`): offset,
length, SHA-256 of the range, running SHA-256 of the whole file, and the
file's device:inode, in a hash chain whose head is sent off-file at each
seal (system log, stderr, `--journal-anchor`). See the honest-scope note
in `internal/journal`: a same-user attacker who knows about the journal
can rebuild it; the anchor kept elsewhere is what defeats that.

`agentdfir journal verify [journal.jsonl] [--anchor <head>]` checks the
chain, then every capture file the journal recorded (looked up next to the
journal, so a copied state dir verifies offline):

| State | Meaning | Fails verify |
|---|---|---|
| OK | every journaled range still hashes to what was recorded | no |
| PRUNED | deleted by retention; the prune record is journaled and its full-file hash matches the journaled content | no |
| DELETED | journaled, now missing, and no prune record accounts for it | yes |
| REWRITTEN / TRUNCATED | edited or cut after it was journaled | yes |
| REPLACED | swapped for another file or shrank while monitored | yes |
| PRUNE_MISMATCH | pruned, but its content at pruning differed from the journal (edited, then deleted) | yes |

Agent transcripts are not part of this file check (agents delete old
sessions on their own); they are checked at analysis, where a collected
case runs the journal against the collected transcripts and captures:
`TRANSCRIPT_REWRITTEN`, `TRANSCRIPT_TRUNCATED`, `TRANSCRIPT_REPLACED`,
and `TRANSCRIPT_DELETED` (INFO for a transcript, HIGH "Recorded Capture
Deleted Without a Prune Record" for a capture). A pruned capture raises no
finding.

## Retention

`--retain 7d`, `--retain 2GB` or `--retain 7d,2GB` (sizes are binary:
1 GB = 2^30 bytes; ages take s, m, h, d, w). Once a minute the recorder:

1. journals every capture range written so far;
2. considers only capture files the journal recorded (a capture-named file
   it never recorded is reported, not counted or deleted); picks those whose
   creation stamp (file name, or first journal record if earlier; never the
   mtime) is older than the age bound, then, oldest first, as
   many more as it takes to bring the total under the size bound — never a
   file still being written, never `journal.jsonl` or `status.json`;
3. for each, hashes the whole file and appends a `prune` record (path,
   size, SHA-256, the journaled size and running hash, reason) to the
   journal, then deletes the file. If the delete fails, a `prune_failed`
   record follows and the file stays verifiable.

Journal entries are never pruned. Without a journal nothing is deleted.

## `monitor status`

Reads `~/.agentdfir/monitor/status.json` (rewritten every 10 s while the
monitor runs, and once more on a clean stop) and the journal. No running
daemon is needed; `--dir <path>` reads a state directory copied off a host.

- monitor: RUNNING (status fresh), STOPPED (clean stop recorded), or NOT
  RUNNING (stale status without a stop: killed, crashed, host down);
- per source: state (running, waiting for the input to appear, error,
  stopped, not-started), last event time (when the recorder last captured
  data from it), records (lines; journaled ranges for transcripts), bytes,
  sequence gaps and missing count with the first few jumps, drops,
  rotations, permission and other problems;
- retention: policy, capture files and bytes on disk, files and bytes
  pruned, the last prune and its reason;
- journal: record count, chain intact or broken, head, last seal time, and
  whether the newest head in the `--journal-anchor` file is still in the
  chain.

`--json` prints the same as one object. Exit code 1 when there is no status
file or the journal chain is broken.

## Recorded → investigate

- `agentdfir run --endpoint ~/.agentdfir/monitor` (or `analyze <case>
  --endpoint <state dir>`): a directory given to `--endpoint` is expanded
  to the OS-telemetry captures in it (MCP config records and
  empty/UNSUPPORTED captures are listed on stderr and left out). `run`
  collects the agent transcripts and, through the same product manifest
  that already collects the journal, the journal and the captures into the
  case; it checks the transcripts against the journal, and correlates every
  tool call with the recorded telemetry (CORROBORATED / CONTRADICTED inside
  the coverage window), with all detection rules on top.
- `agentdfir replay <state dir> [--all] [--session <text>]`: verifies the
  journal and the captures, then steps through every recorded OS record in
  time order (`--session` filters on text in the line).

## Privacy

Everything stays on the host, under `~/.agentdfir/monitor` (mode 0700,
files 0600). Nothing is sent anywhere; the only thing that leaves the
journal file is the chain head (a hash) written to the system log and the
optional anchor file.

What is recorded is sensitive: transcripts contain prompts and tool
output; auditd and eslogger record every command line (which can include
secrets passed as arguments) and file paths. MCP config changes are
recorded as hashes only, never content, because MCP configs carry API keys.
Bound what you keep with `--retain`, restrict event types with
`--es-events`, and collect only with authorization. A collected case seals
the captures with the rest of the evidence (`agentdfir.monitor_capture`,
`agentdfir.monitor_es`, `agentdfir.monitor_journal` artifacts).

## Open source and Pro

The open-source recorder is single-host and local: one machine, one user's
state directory, policy given on the command line, verification and
investigation on that machine or on a copied state dir. Fleet deployment,
central policy and retention, off-host anchoring as a service, and
managed/signed collectors are not in the open-source tool.

## Fixtures

Tests use injectable sources and run without root: synthetic auditd lines
written to temporary files (rotated by rename and by truncation, with a
serial gap), a synthetic Falco line, synthetic MCP configs, and the
existing synthetic eslogger fixture (`internal/endpoint/testdata/macos`)
through a stand-in eslogger. No real-host captures are committed.
