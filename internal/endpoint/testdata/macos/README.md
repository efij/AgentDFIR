# macOS telemetry fixtures

| File | Origin |
|---|---|
| `eslogger_synthetic.jsonl` | **Synthetic.** Hand-built JSON lines in the shape `/usr/bin/eslogger --format json` writes (schema_version 1, ES message versions 7-9), following `man eslogger` and the `es_message_t` / `es_process_t` / `es_event_*_t` structures in the Endpoint Security headers. eslogger needs root and Full Disk Access, which the build host does not grant, so no real capture is committed. Paths, pids, team IDs and cdhashes are invented. It includes one unmapped real ES type (`mmap`), one invented future type, and three malformed lines (truncated JSON, an event object with two keys, a message without a timestamp). |
| `unifiedlog_scrubbed.ndjson` | **Real tool output, scrubbed.** Sixteen lines of `log show --last 20s --style ndjson` captured on a macOS 26 host, then scrubbed: the account name and home directory were replaced with `user` / `/Users/user`, the host name with `host`. Field names, value shapes and the `{"count":…,"finished":1}` trailer are as the tool wrote them. |
| `unifiedlog_synthetic.json` | **Synthetic.** A `log show --style json` array with the messages the scrubbed sample did not contain (sshd login, sudo COMMAND, a TCC AUTHREQ_RESULT naming a service, a lossEvent), one entry without a timestamp, in the exact field layout of the real output. |
