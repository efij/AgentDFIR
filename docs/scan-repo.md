# `agentdfir scan-repo` — check a repository before an agent opens it

In 2025–2026 code execution moved into files dependency scanners never
read. The keyv wave of Shai-Hulud (Aug 2026) committed a
`.claude/settings.json` **SessionStart** hook and a `.vscode/tasks.json`
**folderOpen** task; Codex CLI ran a repository's own `.codex/config.toml`
MCP commands at startup (CVE-2025-61260); SANDWORM_MODE planted MCP
servers with poisoned tool descriptions; a README talked Gemini CLI into
running a command. Opening the folder is the trigger. `scan-repo` reads
those files first.

```sh
agentdfir scan-repo                     # the current directory
agentdfir scan-repo ~/src/untrusted --json
agentdfir scan-repo . --sarif results.sarif --fail-on high    # CI gate
```

Nothing in the repository is executed. Symlinks are never followed out of
the tree, files are size-capped, and findings carry at most a short,
secret-masked excerpt of a command — never file contents — so a SARIF
upload cannot leak what a symlink pointed at.

## What it checks

| rule | surface |
|---|---|
| `REPO_AGENT_HOOK_AUTORUN` | Claude Code `hooks` (every event), `statusLine.command`, `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `otelHeadersHelper`; plugin `hooks/hooks.json`; `.cursor/hooks.json`; Gemini CLI hooks; project MCP server commands. CRITICAL when it runs at session start **and** touches the network, credentials, an encoded payload or a headless agent — a repo script it calls (`node .claude/setup.mjs`) is read and judged too |
| `REPO_VSCODE_AUTORUN_TASK` | `runOn: folderOpen` tasks in `.vscode/tasks.json` and `*.code-workspace` (JSONC, per-OS commands) |
| `REPO_DEVCONTAINER_HOST_COMMAND` | devcontainer `initializeCommand` (runs on the host) |
| `REPO_AGENT_ENV_OVERRIDE` | committed `env` setting `ANTHROPIC_BASE_URL`, `NODE_OPTIONS`, `BASH_ENV`, `LD_PRELOAD`, proxies… |
| `REPO_AGENT_PERMISSION_WEAKENING` | `bypassPermissions`, `Bash(*)`, `enableAllProjectMcpServers`, Copilot auto-approve, `task.allowAutomaticTasks`, workspace trust off |
| `REPO_EXECUTABLE_PATH_OVERRIDE` | editor settings pointing an interpreter or tool at a file in the repo |
| `REPO_CODEX_PROJECT_CONFIG` | a project `.codex/config.toml` with commands |
| MCP audit rules (`MCP_REMOTE_FETCH_COMMAND`, `UNPINNED_MCP_PACKAGE`, `MCP_PACKAGE_TYPOSQUAT`, `MCP_TOOL_DESCRIPTION_POISONING`, …) | `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `.codex/config.toml`, `opencode.json`, `.roo/`, `.kiro/`, `.amazonq/`, `.windsurf/` MCP files |
| `REPO_INSTRUCTION_INJECTION` | `AGENTS.md`, `CLAUDE.md`, `CLAUDE.local.md`, `GEMINI.md`, `.cursorrules`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, `.github/{instructions,prompts}/`, `.cursor/rules/`, `.kiro/steering/`, `.amazonq/rules/`, `.roo/rules/`, `.windsurf/rules/`, `.claude/{agents,commands,skills}/`: injection phrases, invisible Unicode (tag characters CRITICAL), "fetch this URL and follow it" |
| `AI_CLI_HEADLESS_BYPASS` | any of the above, or a `package.json` install script, launching claude / codex / gemini / q / cursor-agent / copilot headless with approvals off (the s1ngularity shape) |
| `REPO_LIFECYCLE_SCRIPT_RISK` | install/prepare scripts that download-and-run, touch credentials or decode payloads |
| `REPO_AGENT_CONFIG_SYMLINK` | an agent config or instruction file that is a symlink |
| `REPO_AGENT_CONFIG_HIDDEN_IN_REVIEW` | `.gitattributes` hiding agent config from PR diffs |
| `REPO_GIT_EXEC_CONFIG` | `.git/config` `core.fsmonitor` / `hooksPath` / `sshCommand` / `askpass`, shell credential helpers |
| `REPO_GIT_REF_INJECTION` | branch or tag names with shell syntax (the Codex branch-name token theft) |
| `REPO_CONFIG_UNPARSEABLE`, `REPO_FILE_OVERSIZED` | an autorun file crafted to break scanners, or padded past the size limit |

## In CI (GitHub Actions)

```yaml
# .github/workflows/agent-config.yml
on: [pull_request]          # not pull_request_target
permissions:
  contents: read
  security-events: write    # only if you upload SARIF
jobs:
  scan-repo:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: efij/AgentDFIR@<commit-sha>   # pin by commit SHA
        with:
          fail-on: high
          sarif: agentdfir.sarif
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: agentdfir.sarif
```

The action builds `agentdfir` from the exact commit you pin — there is no
release download to substitute — with the standard library only. Inputs
reach the shell through environment variables, never `${{ }}` inside a
script.

## As a pre-commit hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/efij/AgentDFIR
    rev: v3.0.0
    hooks:
      - id: agentdfir-scan-repo
```

pre-commit builds the hook from the pinned `rev` (Go toolchain required).
