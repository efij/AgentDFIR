# v4.5 rule fixtures

**All synthetic, machine-written.** The files of the cases below are the
output of `TestGenerateV45RuleFixtures` (`internal/corpus/gen_v45_test.go`):

    AGENTDFIR_REGEN_V45=1 go test ./internal/corpus -run TestGenerateV45RuleFixtures

Nothing was copied from a real host. Paths, pids, users and buckets are invented.

| Format | How it is written |
|---|---|
| eslogger JSON lines | `es_message_t` shape of `/usr/bin/eslogger --format json` (schema_version 1), as in `internal/endpoint/testdata/macos` |
| `.evtx` | `internal/endpoint/evtx/evtxtest` (real BinXML chunks; Sysmon 1, PowerShell 4104, Eventlog 1102 field layouts). One file mixes channels. |
| Tetragon JSON lines | `tetra getevents -o json` shape, event-type key first |
| Claude Code transcripts | JSONL user/assistant/tool_use/tool_result records |

| Rule | Attack | Benign twin | Incomplete telemetry |
|---|---|---|---|
| AGENT_PRIVILEGE_ELEVATION, AGENT_LOGGING_DISRUPTED, AGENT_EVIDENCE_SOURCE_DELETED | `macos-agent-sudo-unloads-auditd-deletes-transcript` | `macos-human-sudo-logrotate-during-agent` | `macos-incomplete-no-exec-events` |
| WIN_AGENT_SUSPICIOUS_POWERSHELL, AGENT_LOGGING_DISRUPTED | `windows-agent-encoded-powershell-log-clear` | `windows-agent-powershell-routine` | `windows-incomplete-script-blocks-only` |
| PACKAGE_SCRIPT_TOUCHED_AGENT | `package-postinstall-launches-agent` | `package-install-agent-cli-and-native-build` | `package-script-file-events-only` |
| CHAIN_STAGED_DATA_TO_TRANSFER | `source-archived-to-tmp-then-bucket` | `build-artifact-archived-then-deploy-bucket` | `transfer-after-lost-history` |
| CHAIN_SECRET_TO_NEW_REMOTE_PUSH | `env-read-new-remote-push` | `fork-upstream-remote-then-push` | `secret-read-push-after-lost-history` |

Incomplete-telemetry cases are benign cases: any finding they produce that
is not in their `allow` list fails the corpus, including a false
`ENDPOINT_CONTRADICTED_COMMAND` (DISPROVED).
