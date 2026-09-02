# Container, CI and cloud-agent collection

Agents increasingly run where `$HOME` is not a laptop: devcontainers and Docker, CI runners (GitHub Actions with the Copilot coding agent, self-hosted pipelines), and vendor clouds whose only trace is a data export. Two flags on `collect` bring that evidence into the same sealed `.adfir` package; everything downstream — `triage`, `correlate`, `provenance`, `report`, `mcp audit` — works unchanged.

```sh
agentdfir collect --docker devcontainer-3a1f --case-id CASE-42          # running or stopped container
agentdfir collect --docker /cases/host42/container-export.tar            # saved `docker export`
agentdfir collect --archive copilot-run-9921.zip --case-id CASE-43       # GitHub Actions artifact
agentdfir collect --archive support-bundle.tar.gz                        # support bundle
agentdfir collect --archive claude-data-export.zip                       # vendor account export
```

## `--docker <container | export.tar>`

Runs `docker export <container>` — a read-only snapshot of the container filesystem as a tar stream. **Nothing is executed inside the container**; no `docker exec`, no signals, no writes. Set `AGENTDFIR_DOCKER=podman` (or any compatible CLI) to use another runtime; a saved export tar is accepted directly for offline work.

The stream is filtered on the fly: only files under a user or workspace home (`/root`, `/home/*`, `/workspaces/*`, `/workspace`, `/app`, `/Users/*`, `/srv`, `/opt`) that belong to a known agent product's config dir or file — plus repo-scoped agent files such as `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.mcp.json`, `.cursor/rules` — are kept. The result is fed to the import-tree collector (all products, all users) and sealed. `case.json` records `mode=docker`, the container reference or export file + SHA-256.

## `--archive <zip | tar | tar.gz>`

Format is sniffed by magic bytes. Extraction is defensive: paths that would escape the destination are refused and counted, symlinks/hardlinks/devices are skipped, every entry and the total are size-bounded (`--max-file-mb`). Then:

1. **Profile layout present** (e.g. an artifact that captured `~/.claude`): the import-tree collector runs as for `--import`.
2. **No profile layout** (typical CI artifact, support bundle, vendor export): every `*.json` / `*.jsonl` file is preserved as an `archive.sessions` artifact (product `ci-archive`) so the tolerant parser still yields events — tool calls, prompts, model text — and detections run on them.

Vendor **chat exports** are understood: `conversations.json` in the Claude.ai shape (`chat_messages[]` with `sender`) and the ChatGPT shape (`mapping{}` with `author.role` and `content.parts`) become `human_prompt` / `model_response` events. Exports carry no tool telemetry, so model text stays **REPORTED** — a claim, not proof.

`case.json` records `mode=archive`, the file, its SHA-256 and kind.

## Example

```
Docker container: devcontainer-3a1f (docker export — read-only, nothing runs inside the container)
Kept 12 agent-related file(s), 5208 bytes (10 skipped/filtered, 0 refused paths)
  profile home/dev     products: [codex-cli]
  profile root         products: [claude-code]
Acquired:  10 artifacts (4882 bytes)
Sealed:    SHA256SUMS written; run `agentdfir verify` to confirm integrity.
```

```
Archive: copilot-run-9921.zip (zip)
Extracted 2 file(s), 183 bytes (0 skipped, 1 refused paths)
  no profile layout found — preserved 1 loose JSON/JSONL file(s) as archive.sessions
```
