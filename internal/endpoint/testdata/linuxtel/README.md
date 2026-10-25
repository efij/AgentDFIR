# Linux eBPF / container-runtime fixtures (synthetic)

Every file here is **hand-made (synthetic)**. Tetragon, Falco and bpftrace
need a privileged Linux kernel with eBPF support, which the build host does
not have, so these lines were written by hand, field by field, from each
project's documented JSON output:

| File | Schema followed |
|---|---|
| `tetragon.jsonl` | Tetragon `GetEventsResponse` JSON (`tetra getevents -o json`, export file): `process_exec`, `process_exit`, `process_kprobe` (`tcp_connect`, `security_file_permission`, `fd_install`, `bpf_check`, `__x64_sys_mount`), `process_tracepoint` (`syscalls/sys_enter_setns`), `rate_limit_info`, `process_uprobe`, `process_loader` |
| `falco.jsonl` | Falco alert with `json_output: true` (`time`, `rule`, `priority`, `source`, `output`, `output_fields`, `tags`, `hostname`) |
| `bpftrace.jsonl` | `bpftrace -f json` envelopes (`attached_probes`, `printf`, `map`, `hist`, `lost_events`) with printf objects that follow the AgentDFIR event field contract (docs/linux-telemetry.md) |
| `docker-events.jsonl` | `docker events --format '{{json .}}'` |
| `podman-events.jsonl` | `podman events --format json` |

Each file deliberately also contains malformed (truncated) lines, objects
that are not events of that tool, and recognized-but-unmapped event types,
so the tests prove those are counted and reported (UNSUPPORTED with a
reason) rather than silently dropped.

Process ids, container ids, IPs (RFC 5737 / example.org) and users are
invented. When real captures become available they should replace or join
these files.
