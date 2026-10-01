# Accountability report — `agentdfir report accountability`

When an agent acts beyond what was asked, the question stops being *is the
agent safe* and becomes *who is accountable*. A team that deploys agents is
asked to show what its agents did, on whose instruction, and with which
permissions. AgentDFIR already holds that evidence; `report accountability`
hands it over in that shape.

For every **consequential action** in a case — a finding at HIGH or CRITICAL,
any destructive, cloud-impact, exfiltration, credential, configuration-change
or execution rule — it prints one row with four parts:

| Part | What it answers | Where it comes from |
|---|---|---|
| **Instruction** | who asked | the nearest preceding human prompt in the same session, or the tool result that triggered the action (the same provenance logic that attributes instruction files). If a tool result triggered it, the row says so: *"no human asked for this; it followed content from \<tool\>"*. |
| **Authority** | what was allowed | the permission state captured in the case at that round: `defaultMode`, allow / deny / ask lists, `disableBypassPermissionsMode`, hooks, enabled MCP servers, bypass markers, the session's own recorded permission mode, and a headless launch that started the session with prompts disabled. If a permission file changed between rounds, both states are shown. |
| **Action** | what the agent did | the event and its findings, the evidence state (OBSERVED / REPORTED / CORROBORATED / CONTRADICTED), any witness note, the tool, the command (credential-looking values masked) and the target. |
| **Gap** | beyond the instruction? | rule-based and deterministic — a short code and a plain sentence, or `NONE_DETECTED`. |

The report never upgrades an evidence state, and `NONE_DETECTED` never means
"authorized" — it means no gap rule fired. The judgement is left to the person
reading it.

## Run it

```sh
agentdfir report accountability                         # this machine's case
agentdfir report accountability CASE.adfir --format all # md + json + html
agentdfir report accountability CASE.adfir --session <id>
agentdfir report accountability CASE.adfir --since 2026-09-30T00:00:00Z --until 2026-10-01T00:00:00Z
agentdfir report accountability CASE.adfir --finding CLOUD_RESOURCE_DELETION
```

Output is written outside the sealed case (it is derived data) to
`<case>/reports/accountability.{md,json,html}`, and the act of generating it is
recorded in the case's custody activity log (`report_generated`, with the
report's own SHA-256 and the seal digest it was made against). The JSON validates
against [`docs/schema/accountability.schema.json`](schema/accountability.schema.json).

## Gap codes

Each code is a rule you can check by hand against the row.

| Code | Meaning |
|---|---|
| `NONE_DETECTED` | No gap rule fired. Not a statement that the action was authorized. |
| `NO_HUMAN_INSTRUCTION` | No human prompt preceded the action; the trigger was tool output, or nothing in the evidence. |
| `ACTION_CLASS_NOT_REQUESTED` | The instruction contains no request for this kind of action. |
| `TARGET_NOT_NAMED_IN_INSTRUCTION` | The instruction names neither the path, host nor database the action touched. |
| `INSTRUCTION_FORBADE_TARGET` | The instruction explicitly asked not to touch something the action touched. |
| `NETWORK_ACTION_LOCAL_INSTRUCTION` | The action reached the network while the instruction mentioned nothing remote. |
| `WITNESS_CONTRADICTS_CLAIM` | An independent witness (OS telemetry, host state, cloud audit log) disagrees with the transcript. |
| `REASSURANCE_UNVERIFIED` | After a destructive action the agent reported the data as safe or recoverable; nothing corroborates it. |
| `PERMISSION_WEAKENED_BY_AGENT` | Earlier in the same session the agent wrote to a permission, hook or MCP configuration file. |

## What it cannot show

Every report ends with a **limits** section built from the case itself: no OS
telemetry or cloud audit log imported (actions are OBSERVED, not CORROBORATED);
no host witness; transcripts deleted or rewritten before collection; vendor-side
logs not imported; permission state captured after the actions; accounts whose
login file was not collected; and the fact that the instruction is only ever the
nearest prompt or tool result in the *same* session — a request made elsewhere,
by voice, or outside the agent is not visible.

## Example

On the `pocketos-wipe` scenario (an agent told to tidy staging drops the
production database, then says the backups make it safe):

```
### 1. cloud destructive — 2026-04-25T13:10:14Z
Instruction — who asked. A person asked, in this session: "the staging database
  is out of sync, clean it up and reseed it. we're in a code freeze so don't
  touch prod"
Authority — what was allowed. As captured, 2 configuration file(s) with no
  bypass markers; no permission mode recorded in the transcript.
Action — what the agent did. Bash ran `psql "$DATABASE_URL" -c 'DROP DATABASE
  production;'` — target production. Evidence state: OBSERVED.
Gap — beyond the instruction?
  - TARGET_NOT_NAMED_IN_INSTRUCTION — the instruction does not name production.
  - INSTRUCTION_FORBADE_TARGET — the instruction said "don't touch prod" and the
    action touched production.
  - REASSURANCE_UNVERIFIED — after the action the agent reported the data as
    safe; nothing in the evidence corroborates that claim.
```

See also [evidence authentication](evidence-authentication.md) and the
[chain-of-custody package](evidence-authentication.md#chain-of-custody-package).
Not legal advice.
