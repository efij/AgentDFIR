# Linux telemetry: eBPF tools, containers, privilege changes, persistence

AgentDFIR does **not** load eBPF programs. Loading eBPF from Go needs a
third-party library or cgo, and AgentDFIR is stdlib-only. It imports what
eBPF tools already recorded, with `--endpoint <file>` (format sniffed, or
forced with `--format`). auditd stays the built-in baseline. Kernel
compatibility is those tools' job; AgentDFIR reports which witness is
present and what it could not read.

## Importers

| `--format` | Input | Records | Role |
|---|---|---|---|
| `tetragon` | `tetra getevents -o json`, or the agent's JSON export file | `process_exec` → process; `process_kprobe` / `process_lsm` → network (`*connect` hooks with a `sock_arg`), file (file hooks with a path: `security_file_permission` with MAY_WRITE → modify, otherwise open; `fd_install` → open; unlink → delete; truncate/rename → modify), syscall (any other hook: setns, mount, `bpf_check`, …); `process_tracepoint` → syscall `<subsys>/<event>` | **coverage**, like auditd: it can corroborate and contradict |
| `falco` | Falco alerts with `json_output: true` | by `output_fields["evt.type"]`: execve → process; connect/sendto → network, or file for a unix socket path such as `/var/run/docker.sock`; open/openat/creat/unlink/rename/chmod → file; other types → syscall. No `evt.type` but `proc.cmdline` → process | sighting: corroborates, never contradicts |
| `bpftrace` | `bpftrace -f json` | printf events that follow the field contract below | sighting |
| `docker-events` | `docker events --format '{{json .}}'` | kind `container`, Operation `docker <action>`; exec events carry the command run inside the container | sighting; exec events corroborate `docker exec …` |
| `podman-events` | `podman events --format json` | kind `container`, Operation `podman <status>` (podman does not log the exec command) | sighting |

Falco emits only when a rule matched. bpftrace scripts filter and lose
events under load. A container runtime sees only its own API calls. So
those records never widen telemetry coverage and never turn a miss into
CONTRADICTED. Tetragon's exec stream covers every exec on the node while
its agent runs, so its time span counts as process coverage.

### Falco rule names

The Falco rule name and priority travel with each record in `detection`,
for example `falco rule "Terminal shell in container" priority Notice
(third-party detection)`. AgentDFIR also prints one notice per distinct
rule. These are Falco's detections, never AgentDFIR findings. AgentDFIR's
own rules read only the record fields.

### bpftrace field contract

Only `printf` output can describe single events. A line is read when its
`data` is a JSON object (or a string that holds one JSON object per
line) with:

| Field | Required | Meaning |
|---|---|---|
| `time` | yes | wall clock: an RFC 3339 string, or epoch **nanoseconds** as a number (≥ 1.5e18). Raw `nsecs` is boot-relative and is refused. Use `strftime("%Y-%m-%dT%H:%M:%SZ", nsecs)`. |
| `pid` | yes | > 0 |
| `comm` / `exe` (or `filename`) / `args` | at least one | `args` may be a string or an array |
| `ppid`, `uid`, `cwd` | no | |
| `cgroup` | no | a `/proc/<pid>/cgroup` path; gives the container id |
| `event` | no | `exec` (default) → process; `connect` + `daddr`, `dport` → network; `open` + `path` → file |

Example (execsnoop-style):

```
tracepoint:syscalls:sys_enter_execve {
  printf("{\"time\":\"%s\",\"pid\":%d,\"ppid\":%d,\"comm\":\"%s\",\"args\":\"%s\"}\n",
    strftime("%Y-%m-%dT%H:%M:%SZ", nsecs), pid, curtask->real_parent->tgid, comm, str(args.filename));
}
```

### Reported as UNSUPPORTED or incomplete (counted, never silently dropped)

- Tetragon `process_uprobe`, `process_loader` and unknown event types.
  `rate_limit_info` and `process_throttle` say that Tetragon itself dropped
  events, so coverage is incomplete for that period. `process_exit` is
  folded into its exec and counted.
- Falco alerts from plugin sources (`k8s_audit`, `aws_cloudtrail`, `okta`,
  …). These are not host telemetry. Import that source's own log instead.
- bpftrace `map`, `hist`, `lhist`, `stats` and other aggregate output;
  printf text that is not a contract object; objects missing `time` or
  `pid`. `lost_events` lines are summed and reported.
- Docker / podman events about images, networks, volumes and the daemon.
  `health_status` events are counted as skipped noise.
- containerd (`ctr events`) and CRI-O event streams print text, not JSON,
  and are not read.

## Container and namespace attribution

New `omitempty` fields on every endpoint record: `container_id`,
`container_name`, `container_image`, `pod`, `k8s_namespace`, `pid_ns`,
`mnt_ns`, `net_ns` (namespace inode numbers), `exec_id`,
`parent_exec_id`, `cwd`, `caps`, `tty`, `priv_from`, `priv_to`,
`detection`.

- Tetragon fills all of them: `pod.container`, `ns.*.inum`,
  `cap.effective`, exec ids.
- Falco fills container, image, pod and namespace from `container.*` and
  `k8s.*`. `host` means no container. Falco gives the 12-character short
  id.
- auditd fills `container_id` only from kernel-written fields. That means
  `contid=` on `CONTAINER_ID` / `CONTAINER_OP` records, which only kernels
  with the audit container-id patch set emit (authoritative), or a
  dedicated `cgroup=` field. exe, comm, argv and paths are never scanned,
  because a binary can be named after a container scope. Stock kernels log
  neither field. auditd does not log namespace inodes either, so on stock
  kernels auditd records carry no container.

## sudo, su, PAM and polkit (auth.log, secure, journald)

The existing mappings are unchanged. New records sit beside them:

| Line | Records |
|---|---|
| `sudo: dev : TTY=pts/0 ; PWD=/x ; USER=root ; COMMAND=…` | the existing process record (now with cwd, tty, priv_from/priv_to), **plus** kind `auth`, Operation `sudo`, priv_from → priv_to, command, tty, cwd, failure reason |
| `pam_unix(su:session): session opened for user root by dev` | the existing auth `su` record, now with priv_from `dev`, priv_to `root` |
| `pam_unix(<svc>:auth): authentication failure; … ruser=dev … user=root` | auth `pam-auth-fail <svc>` (sshd is excluded: its `Failed password` line is already an auth record) |
| `pkexec: dev: Executing command [USER=root] … [COMMAND=…]` (and `Error executing command …`) | a process record for the command, like sudo, plus auth `pkexec` |
| `polkitd: Operator of … authenticated as unix-user:root to gain … authorization for action A` | auth `polkit A` |

## Linux persistence collection (`collect`, `run`)

On a live Linux host, and on an offline tree that has `etc/os-release`,
collection also reads, read-only:

- systemd units and timers: `/etc/systemd/system`, `~/.config/systemd/user`
- cron: `/etc/crontab`, `/etc/anacrontab`, `/etc/cron.d`,
  `/etc/cron.{hourly,daily,weekly,monthly}`, `/var/spool/cron`
- shell init: `~/.bashrc`, `~/.bash_profile`, `~/.bash_login`,
  `~/.profile`, `~/.zshrc`, `~/.zprofile`, `~/.zshenv`, `/etc/profile`,
  `/etc/profile.d`, `/etc/bash.bashrc`
- `/etc/ld.so.preload`
- `~/.ssh/authorized_keys`, `authorized_keys2`

The files are collected through the normal manifest collector (product
`linux-persistence`). Symlinks such as `*.wants/` links are recorded and
never followed. An unreadable file or directory is an `ACCESS_DENIED`
record carrying the error. `host/linux-persistence.json` is an inventory:
unit `ExecStart` / `OnCalendar` / `WantedBy` lines, crontab entries,
ld.so.preload entries, and each authorized key by type, `SHA256:`
fingerprint (as `ssh-keygen -l` prints it) and comment. Paths that could
not be read are listed with the reason. Not read: `/usr/lib/systemd`
vendor units, other users' homes, `/etc/rc.local`, udev rules, PAM
configuration, XDG autostart.

## Rules

These rules fire only for activity that the telemetry ties to the agent's
process tree. The tie can be pid ancestry, Tetragon `exec_id` ancestry, or
the parent executable the record names. They run over every source that
carries process identity: auditd, Tetragon, Falco, bpftrace, journald.

| Rule | Severity | ATT&CK | Fires on |
|---|---|---|---|
| `AGENT_SYSTEMD_PERSISTENCE` | HIGH | T1543.002 (T1053.006 for timers / `systemd-run --on-*`) | unit/timer written under a systemd unit directory; `systemctl [opts] enable/link/preset/reenable`; `systemd-run --on-*` |
| `AGENT_CRONTAB_MODIFIED` | HIGH | T1053.003 | cron files written; `crontab` installing, editing or removing (`-l` / `-T` do not count) |
| `AGENT_NAMESPACE_ESCAPE` | CRITICAL | T1611 | nsenter with target pid 1; setns naming `/proc/1/ns` (or any setns from a container); block-device or host mount from a container; container runtime socket used from a container |
| `AGENT_BPF_LOAD` | HIGH | T1014 | `bpftool prog load/loadall/attach`, `net/cgroup attach`; a bpf program load seen by a kprobe or Falco |

Command lines in endpoint records are exec argv joined with spaces. They
are tokenized on whitespace, with quotes and escapes removed, the way a
shell would. A script passed to a shell with `-c` is parsed as shell text.
The whole line is also read a second time as shell text. The original
regular expressions remain as a fallback, so each extra reading can only
add detections.

## Fixtures

All fixtures under `internal/endpoint/testdata/linuxtel` and the corpus
cases `attack/linux-agent-host-tampering` and
`benign/linux-agent-routine-ops` are **synthetic**. They were written by
hand from each tool's documented JSON schema, because Tetragon, Falco and
bpftrace need a privileged eBPF-capable kernel that the build host lacks.
They include malformed lines and unknown event types. Replace them with
real captures when available.
