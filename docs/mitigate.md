# `agentdfir mitigate` — stop it happening again

Everything else in AgentDFIR is read-only. `mitigate` is the one command that
changes files outside a case: it writes guardrails into the AI agents' own
permission settings so what a case found cannot happen again, and fixes
config that is unsafe right now.

```sh
agentdfir mitigate                     # the plan: what it would change, nothing written
agentdfir mitigate --apply             # default packs + fixes, asks per file
agentdfir mitigate --status            # every change, verified against the file now
agentdfir mitigate --revert <id>       # one file back, byte-exact
agentdfir mitigate --revert-all        # everything back, newest first
```

The explorer's **Protect** tab does the same from the browser: on the
machine the case came from, *Preview changes* shows every file and the
exact diff, *Apply* makes the changes, and each applied change has *Undo*.
It goes through the same backup, ledger and revert as the command. For a
case from another computer the tab builds the command to run there.

## What can be done about a finding

A case is cumulative: every scan re-reads every transcript ever collected,
so a finding about a command that ran in March fires in every scan for the
life of the case. That splits findings into four groups:

| Group | Fires on | What `mitigate` does | Next scan shows |
|---|---|---|---|
| **Fix now** | a config file as it is right now | edits it | the finding is gone |
| **Prevented** | something the agent already did | adds a guardrail so it cannot recur | `N since <date>`: only what happened after |
| **Needs a person** | past behaviour with no config control | says what to do (rotate a key, review a file) | your verdict in the case notes |
| **Not fixable by settings** | the quality of the evidence | says what collection would help | unchanged |

Findings the analyst marked *benign* or *false positive* leave every count
and every plan.

## Guardrail packs

`--select` takes pack ids, `default` (the two marked ✓), `all`, and `fix`.
The default selection is `default,fix`.

| Pack | Level | Friction | Default | Stops |
|---|---|---|---|---|
| `log-protect` | block | 0 | ✓ | the agent deleting or rewriting its own transcripts |
| `secret-paths` | block | 0 | ✓ | the agent's Read tool on cloud keys, SSH keys, tokens, browser password stores |
| `outbound-upload` | ask | 1 | | sending files or data to another machine (`curl -d/-F/-T`, `scp`, `rclone`, `aws s3 cp` …) |
| `download-exec` | ask | 1 | | `curl … \| sh` and friends |
| `cloud-destructive` | ask | 1 | | deleting cloud storage, databases, key vaults, apps or projects, removing resource locks or backup protection, stopping cloud logging (`az`, `aws`, `gcloud`, `terraform destroy`) |
| `persistence` | ask | 1 | | cron jobs, launch agents, shell startup lines, `authorized_keys` |
| `self-modify` | ask | 2 | | the agent editing its own permissions, hooks or MCP servers |
| `no-bypass` | block | 2 | | `--dangerously-skip-permissions` (sets `disableBypassPermissionsMode`) |
| `destructive` | ask | 3 | | `rm -rf`, force-push, hard reset |

**Ask** makes the agent stop and ask you; nothing is blocked. `--deny <pack>`
turns an ask pack into a block. Friction is how often the pack gets in the
way of legitimate work (0 = never). Every pack cites the MITRE ATLAS
mitigations it implements.

**Fix now** (`fix`):

- **MCP pin** — `npx pkg@latest` (or no version) becomes `pkg@<version>`,
  where the version is the one already running on this machine, read from
  the npx cache (`~/.npm/_npx`). Nothing is executed or downloaded. With no
  cached copy, the plan prints the `npm view` command to run by hand.
- **MCP auto-approve** — a non-empty `autoApprove` / `alwaysAllow` list is
  emptied, so each tool call is shown to you again.

## Where each pack is written

| Agent | File | How |
|---|---|---|
| Claude Code | `~/.claude/settings.json` | `permissions.deny` / `permissions.ask`, one `PreToolUse` hook, `permissions.disableBypassPermissionsMode` |
| Codex CLI | `~/.codex/rules/agentdfir.rules` | a file agentdfir owns; `prefix_rule(…, decision = "forbidden" \| "prompt")`. `default.rules` is never touched |
| Cursor CLI | `~/.cursor/cli-config.json` (only if it exists) | `permissions.deny`; Cursor has no ask list, so ask packs are recommended, not written |
| MCP configs | `~/.claude.json`, `~/.cursor/mcp.json`, `~/.kiro/settings/mcp.json`, `~/.gemini/settings.json`, Claude desktop config | pins and auto-approve only |

The **log guard** is a hook, not a pattern: glob denies are trivially
rewritten (`rm -rf ~/.cl*`). Claude Code runs `agentdfir guard log` before
every Bash, Write and Edit call; it refuses commands that delete, truncate
or overwrite agent transcripts and history (exit 2, the reason goes back to
the model). Claude's memory files under `~/.claude/projects/*/memory/` are
not covered. Malformed input is allowed, so a payload format change cannot
stop every tool call.

What cannot be written is printed under **By hand**: Codex has no per-path
read rule (keep `sandbox_mode = "workspace-write"`), Warp has no local
policy file, and managed settings are an administrator's change —
`--export managed` prints the JSON to put in
`/Library/Application Support/ClaudeCode/managed-settings.json`
(`/etc/claude-code/` on Linux, `C:\ProgramData\ClaudeCode\` on Windows).
Managed settings are the one layer an agent cannot edit away.

## Safety

- **Never inside `run` or `serve`.** Only a command you typed changes files.
- **Plan first.** Without `--apply` nothing is written and the exit code is
  3 when there is something to apply (CI can fail on it). With `--apply`
  you are asked per file unless `--yes`.
- **Re-read before write.** Each file is read again immediately before it is
  written and the change recomputed on those bytes, so an agent that rewrote
  `~/.claude.json` a second ago does not lose its edit.
- **Backup, atomic write.** A byte-exact copy goes to
  `~/.agentdfir/mitigations/backups/<utc>/<sha256>/`; the file is written to
  a temp file and renamed. Key order, number formatting and every key
  agentdfir does not know are preserved.
- **Refuses** symlinks, files owned by another user, root-owned or managed
  settings, and anything that is not valid JSON.
- **Never executes an agent binary** (no `claude config set`, no `defaults
  write`).

## The ledger

`~/.agentdfir/mitigations/ledger.jsonl` — one hash-chained record per file
written (who, when, which packs and pack version, sha256 before and after,
the backup), plus one per revert. Editing or deleting a record breaks every
record after it, and `--status` says so. The next `agentdfir run` collects
the ledger into the case, so the evidence package records the intervention.

`--status` re-reads every file: **in place**, **DRIFTED** (a guardrail was
removed after it went in — check the case for `AGENT_SELF_MODIFICATION`),
**FILE GONE** or **reverted**. `--revert` refuses when the file changed after
agentdfir wrote it, because restoring the backup would discard that edit;
`--force` restores anyway.

## Limits, said up front

- Past findings stay: a guardrail stops the next one, it does not rewrite a
  transcript. The "since" count is the measure.
- A user-level `settings.json` is a file the agent's own Write tool could
  edit. That is why `self-modify` exists and why `--status` reports drift;
  managed settings are the layer an agent cannot touch.
- Guardrails apply to agents started after the change: restart running ones.
