# The `.adfir` Evidence Package Specification

Version: `0.2` · Document revision: 0.2.2 · Status: draft · License: MIT

An `.adfir` package is an **open, self-describing, independently parseable**
container for AI-agent forensic evidence. Any tool can read it without
AgentDFIR. This document is the normative reference.

## Design: two zones

An `.adfir` package has a **sealed zone** (written once at acquisition,
never modified) and an **analysis overlay** (regenerable, excluded from
the seal).

```
case.adfir/
├── raw/<sha256>[.gz]       # sealed: content-addressed evidence bytes
├── manifest.jsonl          # sealed: append-only per-artifact metadata
├── collection.jsonl        # sealed: hash-chained collection log
├── chain-of-custody.jsonl  # sealed: hash-chained custody log
├── case.json               # sealed: case / operator / clock metadata, rounds
├── seals/SHA256SUMS.<n>    # sealed: the seal each earlier round was closed with
├── seals/SEAL.sig.<n>      # sealed: the signature over that seal, when it was signed
├── SHA256SUMS              # sealed: covers the sealed zone exactly
├── SEAL.sig                # ed25519 signature over SHA256SUMS (every round, by default)
├── .lock                   # transient: held during a collect→seal cycle; not sealed
├── normalized/             # overlay: events / entities / relationships (JSONL)
│   ├── events.jsonl        #   uncompressed: index/ addresses it by byte offset
│   ├── events/<parser>/    #   per-artifact segments (.jsonl.gz), the parse cache
│   ├── lineage.json        #   the action graph (0.2.2 rules below)
│   ├── state.json          #   which artifact each segment holds, at what offset, with what hash
│   └── state.mac           #   HMAC of state.json under the machine's cache key, when it has one
├── detections/             # overlay: findings.json, analysis-manifest.json (0.2.2)
├── index/                  # overlay: events.idx, the explorer's offset index
├── reports/                # overlay: HTML/JSON/CSV/STIX/OTel
└── redaction-manifest.json # present only in derived support packages
```

`SHA256SUMS` covers exactly: `case.json`, the manifest, `collection.jsonl`,
`chain-of-custody.jsonl`, every file in `seals/`, and every file in
`raw/`. Regenerating the overlay never changes the seal.

`SHA256SUMS` is UTF-8 text, one line per covered file, each line
terminated by LF: the lowercase hex SHA-256 of the file's bytes, two
spaces, and the file's path relative to the package root with `/` as the
separator (the format `sha256sum -c` reads). AgentDFIR sorts the whole
lines by byte value (so by hash); a verifier MUST NOT depend on the
order, and a path listed twice is malformed. A path is never absolute and never contains a `..` or `.`
component; a verifier MUST treat such a line as a problem and MUST NOT
read the file it names.

The overlay is derived and rebuildable, but it is reused across rounds, so
it is not trusted blindly: `state.json` records the sha256 of every cached
segment and of `events.jsonl`, and the code fingerprint and evidence digest
it was built from. A segment or `events.jsonl` that no longer matches, or a
`state.json` whose `state.mac` does not verify, is discarded and rebuilt
from the sealed zone.

Everything in the overlay is gzipped except `normalized/events.jsonl`,
which stays plaintext because `index/events.idx` records a byte offset per
event and a gzip stream cannot be seeked. The segments under
`normalized/events/` hold the same events, split per source artifact, so a
new collection round re-parses only the transcripts whose content address
changed. `normalized/retired.json` lists source paths the current
collection policy excludes (`node_modules`, git object storage) together
with the last round that collected each; `Current()` leaves those records
out of the scan set while the manifest keeps them as evidence, and a later
round that collects the path again (`run --full-plugins`) puts it back. All
of it is derived: `agentdfir compact` deletes it, and
`agentdfir analyze --renormalize` rebuilds it from the sealed evidence.

## Content addressing

`artifact_id` is the lowercase hex SHA-256 of an artifact's **plaintext**
content. It is the artifact's identity and never depends on how the bytes
are stored. Identical content across users or sessions is stored once
(dedupe); the manifest carries one record per logical occurrence. This
eliminates case-folding, Unicode-normalization and path-length hazards
inside the package — original paths live only in manifest metadata
(`logical_path`).

A record describes its storage separately from its identity:

| Field | Meaning |
|---|---|
| `artifact_id` | SHA-256 of the plaintext — the content address |
| `status` | `OK` when the content was acquired; anything else (`NOT_PRESENT`, `ACCESS_DENIED`, `ERROR`, `SKIPPED_*`, …) records an attempt with no stored content |
| `size` | plaintext length in bytes |
| `codec` | `none` (absent = `none`) or `gzip` |
| `stored_sha256` | SHA-256 of the bytes on disk |
| `stored_size` | length of the bytes on disk |
| `chunks[]` | present when the artifact is stored in parts (see below) |

Only records with `status` `OK` and a non-empty `artifact_id` have
stored content; the integrity checks below apply to those. A blob is
stored at `raw/<sha256>` when `codec` is `none`, and at
`raw/<sha256>.gz` when it is `gzip`. The suffix is part of the file name
so an analyst can identify and decompress one blob with `gunzip` alone.
A reader MUST NOT infer content from a blob's name: `SHA256SUMS` covers
the stored bytes and `artifact_id` covers the plaintext, and both are
checked.

Producers SHOULD store plaintext when compression does not pay.
AgentDFIR samples the first 256 KiB and compresses only artifacts over
4 KiB that reach a ratio of 1.15 or better.

Readers MUST bound decompression by the record's `size` and fail rather
than continue past it.

## Chunked artifacts

Agent transcripts grow by appending. When a later round finds a file whose
first `size` bytes still hash to what an earlier round preserved, it stores
only the new tail and records the artifact as an ordered `chunks` list:

```json
"chunks": [
  {"id": "<sha256 of part 1 plaintext>", "size": 41231, "codec": "gzip",
   "stored_sha256": "…", "stored_size": 7714, "round": 1},
  {"id": "<sha256 of part 2 plaintext>", "size": 8102,  "codec": "gzip",
   "stored_sha256": "…", "stored_size": 1503, "round": 2}
]
```

Concatenating the chunks' plaintext in order reproduces the artifact, and
its SHA-256 MUST equal `artifact_id`. Each chunk is stored as an ordinary
blob under its own content address, so `SHA256SUMS` covers it like any
other. A chunked artifact's `artifact_id` is therefore not the name of any
single file, and a verifier MUST hash the concatenation rather than skip
the artifact.

## Rounds

A package may be collected into more than once. Each collection is a
**round**, and a round only ever appends:

- Every artifact record carries `round` (the round that wrote the record)
  and, when the bytes came from an earlier round, `acquired_in_round`.
- `manifest.jsonl` is a header line (the manifest without `artifacts`)
  followed by one artifact record per line, appended in discovery order
  within each round.
- Both hash chains continue from their previous last line. A producer MUST
  verify the whole existing chain before appending: extending a broken
  chain would hide the break behind valid-looking records.
- Before writing a new `SHA256SUMS`, the previous one is copied to
  `seals/SHA256SUMS.<n>` where `n` is the round it closed, and the previous
  `SEAL.sig`, if any, to `seals/SEAL.sig.<n>`. Both are covered by the new
  `SHA256SUMS`, so every seal commits to all earlier seals and signatures.
- `case.json` gains a `rounds` array summarizing each round. A round records
  `prev_seal_sha256` (the sha256 of the `SHA256SUMS` it replaced), `signer`
  (the hex ed25519 public key it was sealed for) and `prior_integrity`:
  what checking the earlier rounds found before this round was added —
  `verified`, `unsigned`, or `FAILED` with `prior_integrity_problems`.
- A producer MUST hold an exclusive lock (`.lock`) for a collect→seal
  cycle. `.lock` is not evidence and is not covered by `SHA256SUMS`.
- Rounds are transactional. Before a round writes anything, the producer
  records the sealed state it starts from (the lengths of the manifest and
  both chains, and `case.json`) in `.round-pending.json`. A round that is
  not sealed — abandoned or crashed — is rolled back to exactly that state,
  by the producer on exit or by the next round before it checks or extends
  the package; the next round records each one as a `round_aborted` custody
  event with what was discarded. A round is sealed once its new
  `SHA256SUMS` is in place (written atomically, last); it is never rolled
  back after that. `.round-pending.json` and `.round-aborted.json` are not
  evidence and are not covered by `SHA256SUMS`.

A file a later round did not re-read is recorded with
`collection_method: "carried_forward"` and the `acquired_in_round` that
did read it. Consumers MUST NOT present carried-forward evidence as freshly
acquired. A producer MUST decide "unchanged" on properties an unprivileged
writer cannot forge (inode plus change time); modification time alone is
not sufficient.

## Round integrity

Before a producer adds a round to an existing package, and after taking
the lock but before writing anything, it SHOULD check the earlier rounds:

1. `SEAL.sig` verifies over the current `SHA256SUMS`, with the public key
   the last signed round recorded as its `signer`;
2. the current `SHA256SUMS` matches the producer's last recorded anchor for
   this case (below);
3. a quick verification (steps 1, 2, 4, 5 of the next section) passes.

A failure MUST NOT stop the new round, and MUST NOT be repaired: the round
is sealed with `prior_integrity: "FAILED"` and the problems listed, so the
failure is part of the record from then on. A `SEAL.sig` that does not
match when no round recorded a `signer` predates signed rounds (earlier
`run --sign` signed before sealing); it is reported and not trusted, and it
is not evidence of tampering.

A producer SHOULD sign every round (AgentDFIR uses a per-machine key under
its home, `keys/seal.ed25519`, unless `--sign` names another or `--no-sign`
is given) and SHOULD record each sealed round's `SHA256SUMS` digest in an
anchor log outside the package (AgentDFIR: `anchors.jsonl` in its home, a
hash chain of its own) and print it. A signature proves a round was sealed
by the holder of the key; the anchor, and the printed digest kept somewhere
else, are what show a package was not rewritten and re-signed, or rolled
back to an earlier copy, by someone who controls the machine.

## Compatibility

Readers MUST accept both manifest forms: `manifest.jsonl` (0.2) and a
`manifest.json` JSON array with an `artifacts` key (0.1). Readers MUST
accept records with no `codec`, `stored_sha256`, `chunks` or `round`
fields; such an artifact is an uncompressed, whole blob at
`raw/<artifact_id>` from round 1. A 0.1 package is a valid 0.2 package
that has not been added to.

## Hash chaining

`collection.jsonl` and `chain-of-custody.jsonl` are JSONL where each line
is a JSON object with a `prev` field equal to the SHA-256 (hex) of the
previous line's exact bytes, excluding the terminating LF. The first
record's `prev` is 64 zeros. Any edit, deletion, insertion or reorder
breaks the chain from that point on. Each record also carries `seq`,
equal to its zero-based position in the file (0, 1, 2, …), and a UTC
`ts_utc`. Every line is a record: a blank line is a break.

The chains alone do not detect a record appended at the end with a
correct `prev` and `seq`, or the last records being removed; the file's
line in `SHA256SUMS` does.

## Integrity verification

`agentdfir verify` (or any third-party implementation) MUST:

1. recompute SHA-256 for every path listed in `SHA256SUMS` and compare,
   and confirm `case.json`, both chains and one manifest form are listed;
2. flag any file in the sealed zone that `SHA256SUMS` does not cover
   (planted evidence): any file in `raw/` or `seals/`, and a
   `manifest.json` or `manifest.jsonl` that is present but not listed.
   The second manifest form matters because readers prefer
   `manifest.jsonl`: one planted next to a sealed `manifest.json` would
   otherwise replace the manifest every consumer reads;
3. confirm each manifest artifact's **plaintext** hashes to its
   `artifact_id` — decoding its codec, and concatenating its chunks in
   order when it has them;
4. walk both hash chains and report the first break;
5. if `SEAL.sig` is present, verify the ed25519 signature over the SHA-256
   of `SHA256SUMS` (the signed message is the 32-byte digest itself, not
   its hex form). If `SEAL.sig` is absent, that is a problem when the
   verifier was given a key to require, or when the last entry in
   `case.json`'s `rounds` records a `signer`: deleting the signature
   must not turn a signed package into an "unsigned" one. If `case.json`
   cannot be read, whether a signature was expected cannot be decided,
   and that is a problem too.

`SEAL.sig` is UTF-8 text of `key: value` lines:

```
algorithm: ed25519
sha256sums_digest: <hex SHA-256 of SHA256SUMS>
signature: <hex, 64 bytes>
public_key: <hex, 32 bytes>
```

The signature proves who sealed the package only as far as the public
key is trusted. Without a pinned key (`agentdfir verify --pubkey`) a
valid signature by a different key is not a problem: re-signing is
legitimate (`agentdfir sign`), and someone who controls the package can
rewrite it, re-seal it, edit the `signer` recorded in `case.json` and
re-sign it with their own key. The signer-downgrade check in step 5 also
relies on `case.json`, which is itself in the sealed zone. Detecting a
full rewrite needs a key or a seal digest kept outside the package (see
Round integrity).

A verifier MAY also check the round history: for each round in
`case.json` with a `prev_seal_sha256`, `seals/SHA256SUMS.<round-1>`
hashes to it; every `raw/` entry that archived seal lists is still listed
with the same hash (blobs are never rewritten); and
`seals/SEAL.sig.<n>`, when present, verifies over `seals/SHA256SUMS.<n>`
(a mismatch is a problem when round `n` recorded a `signer`, and only a
note otherwise).

Step 3 is what compression and chunking must never be allowed to weaken:
`stored_sha256` proves the bytes on disk are the ones that were sealed, and
`artifact_id` proves they decode to the evidence that was collected.

A verifier MAY offer a **quick** depth that performs steps 1, 2, 4 and 5,
substituting a presence-and-length check for step 3, so that opening a
large case is not gated on re-reading every byte. It MUST report which
depth it ran. `agentdfir verify` runs the full check by default.

## Encryption (optional)

A package directory may be archived and encrypted to a single
`case.adfir.enc` file using AES-256-GCM with a PBKDF2-HMAC-SHA256 derived
key. The public envelope header (`ADFIRENC` magic, version, iteration
count, salt, nonce) is authenticated as GCM additional data and contains
no secrets. Encryption hides logical paths, which can leak confidential
project/repository names.

## Versioning

- `adfir_version` — this container format (independent). `0.2` adds the
  append-only manifest, storage codecs, chunked artifacts and rounds; `0.1`
  packages remain readable, verifiable and extensible.
- `schema_version` — the normalized event/entity/relationship schema.
- `collector_version` — the producing tool version.

## Schemas

- Event: [`schema/event.schema.json`](schema/event.schema.json)
- Finding: [`schema/finding.schema.json`](schema/finding.schema.json)
- Analysis manifest (0.2.2): [`schema/analysis-manifest.schema.json`](schema/analysis-manifest.schema.json)
- Action graph (0.2.2): [`schema/action-graph.schema.json`](schema/action-graph.schema.json)

## Analysis files (0.2.2, optional)

Three overlay files let a third party check what an analysis concluded,
and reproduce it, without trusting the tool's interface. All are
optional: a package without them is exactly as valid as before, and a
verifier MUST NOT require them. They are derived data outside the seal,
so they prove nothing about the evidence; a verifier that finds them
SHOULD check them and report their problems separately from integrity.
Readers MUST accept either stored form (`<name>` or `<name>.gz`) and
MUST ignore properties they do not know.

### Reproducible analysis manifest

`detections/analysis-manifest.json` (schema:
[`schema/analysis-manifest.schema.json`](schema/analysis-manifest.schema.json),
`"schema": "agentdfir.analysis-manifest/1"`) records what produced
`detections/findings.json`:

- `tool`: name, version, Go version, OS/arch, and `analysis_fingerprint`,
  the hash of the code that turns evidence into findings (parsers,
  built-in rules, embedded packs);
- `rule_set`: the built-in rules' fingerprint, whether the embedded packs
  ran, every loaded pack with its SHA-256, and the SHA-256 of every file
  in an analyst-supplied rules directory;
- `input`: `seal_sha256` (the SHA-256 of `SHA256SUMS`, which commits to
  the whole sealed zone), the manifest file's SHA-256 and the inputs
  digest;
- `options`: every option that changes findings, naming each input file
  (endpoint logs, IOC feeds, shell history, gateway log and map) by path,
  size and SHA-256. Honeytokens are recorded by **count only**: any
  digest of planted secrets stored in the package would let its holder
  confirm guessed tokens. `reused_correlation` and `overlay_reused` say
  when the analysis carried forward results of an earlier run (event
  states, endpoint-correlation findings) that a run from the sealed zone
  cannot reproduce;
- `analyzed_utc` (not part of any fingerprint) and `findings` (count,
  file, algorithm, fields);
- `findings_fingerprint`.

**Findings fingerprint** (`adfir-findings-sha256/1`). For each finding in
`detections/findings.json` (a JSON array; `null` is empty), build an
entry: the netstrings (`<decimal byte length>:<bytes>,`) of the UTF-8
values of `rule_id`, `severity`, `status`, `endpoint_corroboration`,
`session_id`, `agent_id` (absent = empty string), then the netstring of
the decimal count of `evidence_refs`, then the netstring of each
reference, the references sorted by byte value. Sort the entries by byte
value, keeping duplicates. The fingerprint is `sha256:` followed by the
lowercase hex SHA-256 of the concatenated netstrings of the sorted
entries. Titles, descriptions, timestamps and order are deliberately
excluded: the fingerprint covers what a finding asserts about the
evidence, not how it is worded or when the analysis ran.

A verifier recomputes the fingerprint from `findings.json` and compares
it, and the finding count, with the manifest; a mismatch means one of
the two was changed after the analysis and is a problem. A `seal_sha256`
that differs from the package's current `SHA256SUMS` means a later round
was added after the analysis; that is a note (re-analyze), not a
problem.

**Reproduction.** `agentdfir verify --reproduce <pkg> [--manifest f]`
copies the sealed zone (and `normalized/retired.json`, an input to the
scan set) to a scratch directory, re-runs the analysis with the recorded
options and input files (refusing when one is missing or its SHA-256
changed, and requiring `--honeytokens` again when honeytokens were used,
since only their count was recorded), and compares fingerprints. On a
mismatch it lists what differed and whether that can change findings
(tool code, packs, rules files, evidence, options, carried-forward
results) or should not (version string, Go toolchain, platform), and the
findings only one side has. A mismatch with nothing finding-relevant
different is a determinism defect.

### Action graph

`normalized/lineage.json` (schema:
[`schema/action-graph.schema.json`](schema/action-graph.schema.json)) is
who did what through whom: nodes (`human`, `agent`, `subagent`,
`tool_call`, `process`, `file`, `network`, `cloud_resource`,
`mcp_server`; `tool`, `resource` and `outcome` are reserved) and edges
with `basis`, `evidence_state`, `source_refs` and, from 0.2.2,
`limitations`. Kinds and relations are open sets; consumers MUST accept
unknown values. A verifier MUST check that:

1. node ids are unique and every edge's `from` and `to` is a node in the
   graph;
2. every edge cites at least one source reference, and each reference
   names an `artifact_id`, an `event_id` or a `telemetry_ref`;
3. an edge with `confidence` (a correlation) cites both an agent record
   and the `telemetry_ref` it was paired with;
4. in a graph that declares `"adfir_spec": "0.2.2"` or later, an edge
   whose `evidence_state` is `CORROBORATED` cites a `telemetry_ref` or
   carries a non-empty `limitations` saying why not. An edge's
   `evidence_state` is the state of the recorded step it derives from; an
   `invoked` edge of a corroborated tool call cites the transcript and
   says so in `limitations`. Graphs from earlier versions do not declare
   `adfir_spec` and are checked against rules 1–3 only.

`limitations` are written conservatively from the edge itself: a named
destination is not a connection, a lookup is not a connection, a
correlation is not a shared identifier, narrative is not execution, and
so on.

### STIX 2.1 export

`report --format stix` writes `reports/findings.stix.json`, a
self-contained STIX 2.1 bundle: one `identity` (AgentDFIR, id
`identity--` + uuid5(N, `identity|agentdfir`)), one `report` for the case
referencing every other object, one `note` per finding (abstract = title;
content = description, rule, severity, both evidence states, evidence
references; `external_references` to `mitre-attack` / `mitre-atlas`
technique ids), and, only for known-incident indicators the evidence
actually holds (hunt hits, not mentions or low-confidence context): an
`indicator` with a STIX pattern, the observable (`domain-name`,
`ipv4-addr`, `ipv6-addr`, or `file` by SHA-256), an `observed-data` when
the evidence dates the sighting, and a `relationship` (`based-on` the
observed-data, or `related-to` the observable). Indicator kinds with no
STIX observable stay in the notes; a URL indicator is a prefix without a
scheme, so it gets a `LIKE` pattern and no `url` object.

Ids are UUIDv5: AgentDFIR's objects in namespace
N = `6a44158c-b5d0-56ae-8976-a8dc20c62f96` (= uuid5(NAMESPACE_URL,
`https://efij.github.io/AgentDFIR/stix`)) over
`<type>|<case id>|<identity>`; observables in the STIX 2.1 SCO namespace
`00abedb4-aa42-466c-9c01-fed23315a9b7` over their ID-contributing
properties (RFC 8785 JSON). `created`, `modified`, `published` and
`valid_from` are the case's creation time (observation times come from
the evidence), so a re-export is byte-identical. A verifier checks the properties STIX
2.1 requires for each object type present, id form and uniqueness,
`spec_version` 2.1, timestamp form and order, `number_observed` range,
and that every `*_ref`/`*_refs` resolves inside the bundle. A bundle
without the identity above predates 0.2.2 and is not checked by default.

### Production sets

`export --production` writes a production set beside the package whose
`production-manifest.json` lists every produced file with its SHA-256
and size. From 0.2.2 the manifest is signed:
`production-manifest.json.sig` is the detached signature format of
`agentdfir sign --file` (`algorithm: ed25519`, `file_sha256`,
`signature`, `public_key`), an ed25519 signature over the 32-byte
SHA-256 of the manifest. A verifier (`agentdfir verify <production-dir>`
or `adfir_verify.py`) checks every listed file, that nothing unlisted is
present, and the signature (pinned with `--pubkey`). A missing signature
is a problem only when a key is pinned; productions written before 0.2.2
are unsigned. `production-manifest.csv` is a convenience copy and is not
covered.

## Corroboration states

`REQUESTED` → `REPORTED` → `OBSERVED` → `PARTIALLY_CORROBORATED` →
`CORROBORATED`, plus `CONTRADICTED` and `UNKNOWN`. Aggregate precedence:
`CONTRADICTED > CORROBORATED > PARTIALLY_CORROBORATED > OBSERVED >
REPORTED > REQUESTED > UNKNOWN`. Model narrative alone is never higher
than `REPORTED`.

## Conformance

`testdata/conformance/` holds one valid package and one invalid package
per tamper case, each with an `expected.json` giving the verdict
(`VERIFIED` or `FAILED`) and, where the case needs it, the public key to
pin. The `analysis-*` fixtures (`"kind": "analysis"`, spec 0.2.2) cover
the analysis files: valid ones (including a pre-0.2.2 graph) and one per
inconsistency (edited or dropped findings, an edited fingerprint, missing
findings, a malformed manifest, a dangling edge, an edge with no source,
a CORROBORATED edge with no witness, a correlated edge without its
telemetry record, a STIX indicator with no pattern, a dangling STIX
reference, a malformed STIX id); their sealed zones verify. A conforming
verifier reaches the expected verdict on every one.
`tools/adfir-verify/adfir_verify.py` is an independent verifier written
from this document with the Python 3 standard library only (including a
pure-Python ed25519 verifier); `agentdfir verify` and it are both tested
against the fixtures and against packages written by released versions.

## Specification changelog

| Revision | Date | Changes |
|---|---|---|
| 0.2.2 | 2026-10-25 | Optional analysis files, no change to the sealed zone (0.2 and 0.2.1 packages verify unchanged): the reproducible analysis manifest and the `adfir-findings-sha256/1` findings fingerprint, with `verify --reproduce`; honeytokens recorded by count only; the action graph schema, its verifier rules and edge `limitations` (`adfir_spec` marks graphs that follow rule 4); the STIX 2.1 export profile with UUIDv5 ids; signed production manifests. JSON Schemas for the manifest and the graph; conformance fixtures for all three. |
| 0.2.1 | 2026-10-25 | Clarifications, no format change: the `SHA256SUMS` line format and path rules; `status` and which records have stored content; chain `prev` excludes the LF, `seq` is the zero-based position, blank lines are breaks; verification step 2 covers `seals/` and an unlisted second manifest form, not only `raw/`; the signed message is the 32-byte digest; the `SEAL.sig` file format; a missing `SEAL.sig` is a problem when a key is pinned or the last round recorded a signer (and when `case.json` is unreadable); what a signature does and does not prove without a pinned key; optional round-history checks; conformance fixtures. Verifiers written to 0.2 that only checked `raw/` for unlisted files missed planted manifests and seals. |
| 0.2 | 2026-09-19 | Append-only `manifest.jsonl`, storage codecs (`gzip`), chunked artifacts, rounds, archived seals and signatures, round integrity, transactional rounds. |
| 0.1 | 2026-09-01 | Content-addressed `raw/`, `manifest.json`, two hash chains, `SHA256SUMS`, optional `SEAL.sig`. |
