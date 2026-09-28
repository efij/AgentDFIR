# `agentdfir hunt` — was this machine hit by a known incident?

After every public AI-agent or developer-supply-chain incident the first
question is the same: *did it touch us?* `hunt` answers it for the
incidents shipped in the binary and for any STIX 2.1 or MISP feed you
add, offline and read-only.

```sh
agentdfir hunt                                  # this machine's case (run `agentdfir run` first)
agentdfir hunt case.adfir --incident s1ngularity,keyv-wave
agentdfir hunt --path ~/projects                # + lockfiles, installed files, shell rc files on disk
agentdfir hunt --iocs feed.stix.json --json     # add a STIX 2.1 bundle or MISP event
agentdfir hunt --list                           # incidents, indicator counts, sources
```

Exit status is `1` when an incident's indicators are present, `0`
otherwise, so it drops into scripts and CI.

## Incidents shipped (pack `agentdfir-incidents` v1)

Every indicator is copied from the cited write-up; nothing is inferred.
`--list` prints the sources.

| id | incident | indicators |
|---|---|---|
| `s1ngularity` | Nx npm compromise, Aug 2025 — postinstall ran the victim's `claude`/`gemini`/`q` headless to inventory secrets | malicious `nx` / `@nx/*` versions, `/tmp/inventory.txt`, `s1ngularity-repository`, rc-file shutdown line |
| `shai-hulud-1` | npm worm wave 1, Sep 2025 | `bundle.js` SHA-256, `shai-hulud-workflow.yml`, webhook.site endpoint |
| `shai-hulud-2` | "The Second Coming", Nov 2025 | `setup_bun.js` / `bun_environment.js` hashes and names, `SHA1HULUD` runner, `truffleSecrets.json` |
| `postmark-mcp` | first malicious MCP server, Sep 2025 | `postmark-mcp` ≥ 1.0.16, `giftshop.club` |
| `sandworm-mode` | SANDWORM_MODE worm, Feb 2026 — rogue MCP server injected into agent configs | the 19 typosquatted packages and versions, C2 domains, `.dev-utils/` |
| `codexui-android` | Codex token theft, Apr–May 2026 | `codexui-android`, `@friuns/codexui`, `sentry.anyclaw.store`, XOR key |
| `keyv-wave` | Shai-Hulud keyv / cacheable wave, Aug 2026 — committed SessionStart hook + folderOpen task | `keyv@6.0.0` and siblings, `npm-cache.com`, payload file names, repo description |
| `amazon-q-wiper` | Amazon Q VS Code 1.84.0 wiper prompt, Jul 2025 | the extension install directory |

Incidents without host indicators (Anthropic's GTG-1002 / GTG-2002 reports,
the OpenAI–Hugging Face agent intrusion, Replit, PocketOS) are covered by
`agentdfir simulate` reproductions and behavioural rules, not by IOCs.

## Where a hit was seen decides what it proves

| label | meaning | severity |
|---|---|---|
| `OBSERVED` | a command the agent ran, a file it touched, a configured MCP package, a lockfile entry, a file on disk or a matching SHA-256 | CRITICAL (HIGH for medium-confidence indicators) |
| `SEEN_IN_OUTPUT` | in the output of a shell command (`npm ls` printing `nx@21.5.0`) | one level lower |
| `MENTIONED` | in a user question, the model's prose, a web page or file the agent read, a `grep`/`cat`/`echo` argument, or a heredoc body the agent wrote | context only, never a finding |
| context | a low-confidence indicator (public infrastructure the payload used and legitimate software also uses, such as Ethereum RPC nodes) | never a finding on its own |

A security engineer who researches an incident with an agent gets
mentions, not a compromise verdict: commands are split into shell stages
with quoted prose and heredoc bodies removed before matching.

## Verdicts are bounded by the evidence

| verdict | meaning |
|---|---|
| `HIT` | at least one OBSERVED / SEEN_IN_OUTPUT indicator |
| `SIMULATED` | indicators found in a case built by `agentdfir simulate` (the profile carries `.agentdfir-simulated`) |
| `NO EVIDENCE` | nothing found on the surfaces listed under *Searched* |
| `INCONCLUSIVE` | the case's agent activity starts after the incident ended — transcripts from then are gone (Claude Code deletes sessions after `cleanupPeriodDays`), so only current-state checks ran |

Every hit carries first/last seen, the timestamp's source (transcript time
or file mtime), a count, the evidence location and whether it falls inside
the incident window.

## Surfaces

`analyze` (and `run`) check the embedded incidents on every case: agent
commands and files, shell-tool output, collected configs, instructions and
shell history, MCP packages, collected file paths and hashes. `hunt` adds
the raw transcript bytes and, with `--path`, a bounded read-only walk
(symlinks never followed; `node_modules` read through npm's hidden
lockfile) for `package-lock.json`, `npm-shrinkwrap.json`, `yarn.lock`,
`pnpm-lock.yaml`, `bun.lock`, `requirements*.txt`, `poetry.lock`,
`uv.lock`, top-level shell rc files, named payload files (hashed) and
extension directories.

## Feeds

`--iocs` (and `analyze --iocs`) accept:

- an agentdfir incident pack (`{"pack":…,"incidents":[…]}` — the format of `internal/ioc/packs/incidents.json`);
- a STIX 2.1 bundle — `indicator` objects whose pattern uses `domain-name`, `ipv4-addr`, `url`, `file:name`, `file:hashes.'SHA-256'` or `process:command_line` comparisons; other forms are counted as skipped, never silently dropped;
- a MISP event or `/events/restSearch` response — `domain`, `hostname`, `ip-dst`, `url`, `sha256`, `filename`, `filename|sha256`, `email-dst`, `github-repository` attributes.

Defanged values (`hxxp`, `[.]`) are refanged. Limits: 16 MB per feed,
50,000 indicators, regexes ≤ 1 KiB, literal strings ≥ 8 characters.
