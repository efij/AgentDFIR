# v5 rule and chain fixtures

**All synthetic, machine-written.** The files of the cases below are the
output of `TestGenerateV5RuleFixtures` (`internal/corpus/gen_v5_test.go`):

    AGENTDFIR_REGEN_V5=1 go test ./internal/corpus -run TestGenerateV5RuleFixtures

Nothing was copied from a real host. Paths, users, buckets, servers and
session ids are invented; the one credential (in `credential-in-mcp-message`)
is a JWT built from harmless parts.

| Format | How it is written |
|---|---|
| Claude Code transcripts | JSONL user / assistant / tool_use / tool_result lines with `permissionMode`, `isSidechain` + `agentId` (subagent lines), `toolUseResult` (rejections, Task results) and image content blocks where the client writes them. The structured tool-call fields (`arg_keys`, `args_digest`, `safe_args`, `result_status`, `approval_state`, `permission_from`, `input_modality`, …) are filled by the real parser. |
| MCP gateway log | JSON lines in the default gateway map's field names: `initialize` results (serverInfo) and `tools/list` results per backend, one record per call (`call_id` = the transcript's tool_use id). Read with `--gateway-log` (`"gateway"` in case.json). |
| MCP client log | a `tools/list` JSON-RPC response in `.claude/logs/`, the cached tool declaration MCP_ARGUMENT_BEHAVIOR_MISMATCH compares calls with. |
| Agent definition | `.claude/agents/docs-writer.md` front matter with a `tools:` list. |

Every attack case names its benign twin in `twin`, and the twin names it
back; `TestEveryCaseExplainsItself` checks the pairing.

| Rule or chain | Attack | Benign twin |
|---|---|---|
| MCP_ARGUMENT_BEHAVIOR_MISMATCH | `mcp-call-undeclared-argument` | `mcp-call-declared-arguments` |
| MCP_TOOL_IDENTITY_DRIFT | `mcp-server-version-drift-midsession` | `mcp-server-stable-identity` |
| CHAIN_MCP_RUG_PULL_TO_ACTION | `mcp-rug-pull-then-credential-read` | `mcp-upgrade-then-routine-work` |
| AGENT_PERMISSION_STATE_DRIFT | `permission-mode-widened-without-prompt` | `permission-mode-widened-by-person` |
| AGENT_UNAUTHORIZED_RESOURCE_CHANGE | `plan-mode-file-edited` | `plan-mode-plan-approved-then-edit` |
| AGENT_CREDENTIAL_TO_EXTERNAL_TOOL | `credential-in-mcp-message` | `mcp-message-without-credential` |
| AGENT_AUTONOMOUS_RECON_SEQUENCE | `agent-autonomous-recon-burst` | `person-directed-diagnostics` |
| CHAIN_AGENT_RECON_TO_IMPACT | `recon-then-destroy-same-bucket` | `recon-then-cleanup-other-bucket` |
| AGENT_ADAPTIVE_ATTACK_SEQUENCE | `adaptive-keychain-method-switch` | `edit-failed-then-same-tool-fixed` |
| CHAIN_ADAPTIVE_RETRY_TO_BYPASS | `write-denied-then-shell-copy` | `write-failed-then-same-tool-retry` |
| AGENT_DELEGATION_SCOPE_EXPANSION | `subagent-tool-outside-definition` | `subagent-within-definition` |
| AGENT_RESOURCE_EXHAUSTION | `tool-call-loop-burst` | `slow-poll-under-threshold` |
| AGENT_MULTIMODAL_TRIGGER_CHAIN | `image-result-then-shell-post` | `prompt-with-image-then-fix` |
| CHAIN_SKILL_POISON_TO_EXEC | `skill-written-from-fetched-page-then-run` | `skill-written-at-request-then-run` |
| CHAIN_TOOL_RESPONSE_TO_SECRET_EXFIL | `tool-response-injection-then-key-upload` | `clean-tool-response-then-credential-check` |
| CHAIN_SHARED_MEMORY_TO_SUBAGENT | `memory-file-written-then-subagent-acts` | `memory-file-written-subagent-reads-other` |
| CHAIN_BROWSER_TOKEN_TO_ACCOUNT_ACTION | `browser-cookies-then-authenticated-post` | `project-cookie-jar-then-health-check` |

A twin's `allow` list names the other rules its activity correctly raises
(a requested credential read, a requested deletion, an agent writing its
own instruction file at the person's request, a real server upgrade); the
twin exists to show the v5 rule or chain stays silent, not that the
activity is invisible.
