# macOS telemetry and host state

AgentDFIR reads three kinds of macOS evidence. None of them needs an Apple
entitlement or native code: Endpoint Security events come from Apple's own
`/usr/bin/eslogger`, which is already entitled.

| Source | How to get it | Privileges | Role in correlation |
|---|---|---|---|
| Endpoint Security (eslogger JSON) | `sudo eslogger exec fork exit create close rename unlink btm_launch_item_add tcc_modify … > es.jsonl`, or `sudo agentdfir monitor --es` | root, macOS 13+, Full Disk Access for the terminal | full host witness for the event types captured: corroborates, can contradict a command inside its coverage, drives lineage rules |
| Unified log | `log show --style ndjson --last 1h > ul.ndjson` (or `--style json`) | none for the default store; private arguments show as `<private>` | partial witness: corroborates ssh logins, never contradicts, never widens coverage |
| Host state | `agentdfir collect --include-macos-host` or `collect --product macos-host` | user for LaunchAgents and the keychain listing; Full Disk Access for TCC.db; root for the system BTM store | inventory plus the TCC time-overlap check |

Import either log with `agentdfir analyze <case> --endpoint es.jsonl --endpoint ul.ndjson`
(the format is detected by content; `agentdfir correlate --format eslogger|unifiedlog` forces it).

## eslogger

Each line has `schema_version`, `version` (ES message version), `time`,
`seq_num`, `global_seq_num`, the acting process and an `event` object whose
single key is the event type. The type comes from that key, not from the
numeric `event_type`, which is not stable across releases.

| Record kind | ES event types |
|---|---|
| process | exec (new image, argv bounded to 256 args and 32 KiB, cwd) |
| process-fork / process-exit | fork, exit |
| file | open, create, write, close (only when `modified`), rename, unlink, truncate, clone, link |
| auth | authentication, openssh_login/logout, login_login/logout, lw_session_*, screensharing_attach/detach, sudo, su |
| persistence | btm_launch_item_add, btm_launch_item_remove (the instigator is the actor when ES names one) |
| tcc | tcc_modify (macOS 15+; instigator, else responsible process) |
| av | xp_malware_detected, xp_malware_remediated |
| ipc | uipc_connect, uipc_bind (UNIX-domain sockets) |
| signal | signal, proc_suspend_resume |

Process identity is recorded as the optional Record fields `orig_ppid`,
`resp_pid`, `audit_token`, `signing_id`, `team_id`, `cdhash`,
`platform_binary`, `uid`, `euid`, `proc_session`, `tty`, `cwd`. Sequence
numbers go to `seq` + `seq_domain` (`eslogger/<event type>`, since ES
numbers each type separately) and `global_seq`, so a gap in the stream
can be detected.

Not covered, said plainly:

- **Endpoint Security has no IP network events.** eslogger shows UNIX-socket
  connects, not TCP or UDP connections. It never yields a network record and
  never confirms or contradicts a claimed network destination. Use a proxy,
  Zeek or DNS log for that.
- Event types without a mapping (for example `mmap`, `lookup`, or a type a
  newer macOS adds) are counted per type and reported as UNSUPPORTED in the
  load summary. They are never dropped silently.
- `close` events without modification are counted and not imported.
- A `schema_version` other than 1 is reported UNSUPPORTED and read
  best-effort.
- The parent image on an exec record is the image last seen for that pid
  earlier in the same capture, or empty. Nothing is guessed.

## monitor --es

`sudo agentdfir monitor --es [--es-events exec,fork,…] [--journal]` checks
that it runs on macOS 13+, as root, with `/usr/bin/eslogger` present, then
asks `eslogger --list-events` and subscribes only to the requested types
this macOS offers. The raw stream is written to
`~/.agentdfir/monitor/eslogger-<UTC>.jsonl` (mode 0600). With `--journal`
every flushed range of that file goes into the hash-chained journal like a
transcript append. The Claude Code collector takes the capture file with the
profile. If eslogger cannot start (not root, no Full Disk Access, old macOS)
the monitor says why and keeps watching transcripts. eslogger is local only,
and the child is killed when the monitor stops.

## Unified log

The mapping is short on purpose. A record is auth or tcc only when
`processImagePath` is the exact path of the system binary that writes it
**and** the subsystem is one that binary uses. Any process can log under any
subsystem name and pick any basename:

| Kind | Sender (exact image path, subsystem) |
|---|---|
| auth | /usr/sbin/sshd, /usr/libexec/sshd-session (com.openssh.sshd or none): Accepted/Failed/Invalid user parsed like auth.log. /usr/bin/sudo, su, login; opendirectoryd (com.apple.opendirectoryd); authd (com.apple.Authorization); loginwindow (com.apple.loginwindow.logging): kept raw |
| tcc | tccd (com.apple.TCC); the `kTCCService…` name only when the message contains it |
| log | everything else, raw (bounded to 200 000 records per export). A sudo `COMMAND=` line is kept as log with the command in `cmdline`: a log line is not execution evidence and never corroborates |

`lossEvent` entries are counted and reported: the log itself says messages
were dropped.

## Host state (`--include-macos-host`)

Opt-in, like browser history. Collected read-only:

- `~/Library/LaunchAgents`, `/Library/LaunchAgents`, `/Library/LaunchDaemons` (`*.plist`)
- `/private/var/db/com.apple.backgroundtaskmanagement/BackgroundItems-v*.btm`
- login items: `backgrounditems.btm`, `com.apple.loginitems.plist`
- `TCC.db` (+ `-wal`), user and system
- keychains: a **metadata listing only** (path, size, mtime from lstat) of
  `~/Library/Keychains` and `/Library/Keychains`. Keychain files are never
  opened and no secret is read.

At analysis: XML plists are parsed (Label, Program, ProgramArguments,
RunAtLoad, KeepAlive). Binary plists and the BTM store (an NSKeyedArchiver
binary plist) are sealed losslessly and reported **UNSUPPORTED**. The TCC
`access` table is read with the built-in SQLite reader (service, client,
client_type, auth_value or the older `allowed`, last_modified). A file the
collector could not read (no Full Disk Access, root-only) stays in the
manifest as `ACCESS_DENIED` with the reason and is listed as not readable.

## Rules

| Rule | Severity | Fires on | ATT&CK |
|---|---|---|---|
| `MACOS_LAUNCHD_PERSISTENCE_BY_AGENT` | HIGH | a LaunchAgents/LaunchDaemons plist created, modified or renamed into place, or a BTM launch item added, by a process descended from the agent | T1543.001 |
| `MACOS_TCC_MODIFIED_BY_AGENT` | HIGH / MEDIUM | HIGH: tcc_modify instigated by, or a TCC.db write from, an agent-descended process. MEDIUM: a TCC change with no process attribution (a TCC.db row's last_modified, or a tcc_modify from another process) inside an agent session window. That is time overlap, not attribution | T1548.006 |
| `MACOS_KEYCHAIN_ACCESS_BY_AGENT` | HIGH | an agent-descended process running `security find-generic-password`/`find-internet-password` with `-w`/`-g`, `dump-keychain` or `export`, or opening a keychain database directly (securityd and other keychain daemons excluded) | T1555.001 |

The rule pack's transcript-side rule on `security find-*-password` stays.
The keychain rule here sees the same act from the OS side, including when
the transcript does not log it.

## Fixture origin

- `internal/endpoint/testdata/macos/eslogger_synthetic.jsonl`: **synthetic**,
  built to the eslogger JSON shape and ES structures. eslogger needs root and
  Full Disk Access, which the build host does not grant.
- `internal/endpoint/testdata/macos/unifiedlog_scrubbed.ndjson`: **real**
  `log show --style ndjson` output from a macOS 26 host, with names scrubbed.
- `internal/endpoint/testdata/macos/unifiedlog_synthetic.json`: synthetic
  messages in the real field layout.
- `internal/macoshost/testdata/TCC.db`: built with `/usr/bin/sqlite3` using
  the real `access` schema. The binary plist was made with `plutil`.
- Corpus cases `macos-agent-persistence-keychain-tcc` (attack) and
  `macos-user-launchagent-keychain-outside-agent` (benign): synthetic eslogger
  captures.
