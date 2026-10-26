# Supply-chain fixtures

Hand-made (synthetic) home directories, written to reproduce the shapes
Claude Code leaves on disk: `plugins/known_marketplaces.json`,
`plugins/installed_plugins.json`, a plugin cache directory with
`.claude-plugin/plugin.json`, `hooks/hooks.json` and a skill, `~/.claude.json`
MCP servers with declared tools, `settings.json`, and transcripts with a
stream-json `system/init` record (tool list), a `hook_success` attachment,
a `Skill` tool call, an MCP tool call and a Bash command. No real
transcript or credential is included.

- `chain/round1`, `chain/round2`: two collection rounds of the same home.
  Between them the plugin skill from the third-party marketplace
  `attacker/agent-tools` is modified, the `docs` MCP server gains a
  `write_file` tool, an env key and a `/` path argument, and settings gain
  an allow rule and a PostToolUse hook. Round 2 adds a session in which the
  skill runs, the new MCP tool is called and `cat ~/.aws/credentials`
  follows within a minute: untrusted repository → modified skill → MCP
  invocation → behaviour change → executed command.
- `benign/round1`, `benign/round2`: the same home collected twice with no
  change. No drift and no supply-chain finding is expected.
