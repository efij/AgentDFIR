# Product packs — add a new AI agent without writing Go

A **product pack** is one JSON file that teaches AgentDFIR a new AI agent product:

1. **how to detect it** (config dirs/files, binaries),
2. **what to collect** (a collector manifest, KAPE-Targets style),
3. **how to normalize its transcripts** (a parser binding, optionally with a field map for a custom message shape).

Install it, and `detect`, `collect`, `normalize`, `timeline`, `triage` and every detection rule work on the new product exactly as they do for the built-ins. This is how the 12 built-in products would have been added if packs had existed first.

## 60-second start

```sh
agentdfir packs init foo-agent --name "Foo Agent" --config-dir .foo   # starter file
$EDITOR foo-agent.product.json                                          # paths + field_map
agentdfir packs validate foo-agent.product.json                         # same checks the loader runs

# Development: unsigned packs load only when explicitly allowed
export AGENTDFIR_ALLOW_UNSIGNED_PACKS=1
agentdfir packs add foo-agent.product.json
agentdfir collect --product foo-agent --path /mnt/image/Users/suspect

# Distribution: sign it, ship pack + .sig, recipients put your public key in trusted.pub
agentdfir keygen --priv me.key --pub me.pub
agentdfir sign --key me.key --file foo-agent.product.json
agentdfir packs add foo-agent.product.json --sig foo-agent.product.json.sig
```

Packs live in `~/.agentdfir/packs/products/` (or `$AGENTDFIR_PACKS_DIR/products/`).

## Pack format (`pack_format: "1"`)

```json
{
  "pack_format": "1",
  "version": "0.1.0",
  "author": "you",
  "homepage": "https://…",
  "product": {
    "id": "foo-agent",
    "name": "Foo Agent",
    "config_dirs": [".foo"],
    "config_files": [],
    "config_env": "FOO_HOME",
    "binaries": ["foo"]
  },
  "manifest": {
    "product": "foo-agent",
    "entries": [
      {"id": "foo.config",   "paths": ["${CONFIG_ROOT}/config.json"], "category": "product_config", "sensitivity": "medium"},
      {"id": "foo.sessions", "paths": ["${CONFIG_ROOT}/sessions/**"], "category": "agent_session",  "sensitivity": "high"},
      {"id": "foo.mcp",      "paths": ["${PROFILE_ROOT}/.foo/mcp.json"], "category": "product_config", "sensitivity": "high",
       "platforms": ["darwin", "linux"]}
    ]
  },
  "parser": {
    "engine": "genericchat",
    "rule_prefix": "foo.",
    "vendor": "foocorp",
    "field_map": {
      "messages_key": "conversation_log",
      "role": "who",
      "text": "msg",
      "timestamp": "ts",
      "session_id": "sid",
      "tool_name": "call.name",
      "tool_args": "call.args",
      "model_roles": ["bot"],
      "human_roles": ["person"]
    }
  }
}
```

### `product`
Detection only. Paths are relative to the user profile; `detect` never executes a discovered binary (it records path + SHA-256).

### `manifest`
Declarative collector rules. Each path must start with `${PROFILE_ROOT}`, `${CONFIG_ROOT}` or `${SYSTEM_ROOT}`; `..` is refused. `**` collects a tree; `*` globs one level. `platforms` filters by OS. Categories: `agent_session`, `prompt_history`, `agent_definitions`, `agent_instructions`, `product_config`, `managed_config`, `product_state`, `task_state`, `credentials`, `debug_logs`, `file_checkpoints`, `shell_state`. Sensitivity: `low|medium|high|critical`.

Only `agent_session` and `prompt_history` artifacts are parsed into events; everything else is preserved as sealed evidence and scanned by content rules.

### `parser`
`engine` is `genericchat` — the tolerant engine that already understands Gemini, Anthropic, OpenAI-chat and plain `{role, content}` message shapes, JSON arrays, JSONL, common wrapper keys and SQLite string-carving. Omit `field_map` if your product uses one of those.

`field_map` is for everything else. Values are dot-paths into each message object (`meta.author.role`, `calls[0].name`). The engine rewrites each message into its canonical shape before normalization, so:

- roles listed in `model_roles` become **REPORTED** model narrative; `human_roles` become **OBSERVED** human input;
- `tool_name`/`tool_args` produce `tool_call` events; a `command`/`cmd`/`script` argument becomes the shell command every detection rule inspects;
- `timestamp` accepts RFC 3339 strings or epoch seconds/milliseconds;
- messages that match nothing become `trace_gap` events — never silent skips.

## Trust model

A pack drives *what gets collected* on a suspect host, so it is treated like code:

- A pack loads only if `<pack>.sig` (ed25519, detached) verifies against `trusted.pub` in the packs directory.
- `AGENTDFIR_ALLOW_UNSIGNED_PACKS=1` allows unsigned packs for development. The evidence package records `product_pack_path`, `product_pack_sha256` and `product_pack_signed` in `case.json`, so an unsigned pack can never masquerade as a vetted one later.
- Unknown JSON keys are rejected (typos cannot silently disable an entry). A pack cannot shadow a built-in product ID.
- Rejections are printed to stderr and never abort a command.

## Contributing a pack

Open a PR in [agentdfir-rules](https://github.com/efij/agentdfir-rules) under `products/` with the pack, a synthetic session fixture, and the expected event counts. CI validates with `agentdfir packs validate`. Once a pack is stable and widely used it can be promoted to a built-in.
