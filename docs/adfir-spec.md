# The `.adfir` Evidence Package Specification

Version: `0.2` · Status: draft · License: MIT

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
├── SHA256SUMS              # sealed: covers the sealed zone exactly
├── SEAL.sig                # optional: ed25519 detached signature
├── .lock                   # transient: held during a collect→seal cycle; not sealed
├── normalized/             # overlay: events / entities / relationships (JSONL)
├── detections/             # overlay: findings.json
├── reports/                # overlay: HTML/JSON/CSV/STIX/OTel
└── redaction-manifest.json # present only in derived support packages
```

`SHA256SUMS` covers exactly: `case.json`, the manifest, `collection.jsonl`,
`chain-of-custody.jsonl`, every `seals/SHA256SUMS.<n>`, and every file in
`raw/`. Regenerating the overlay never changes the seal.

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
| `size` | plaintext length in bytes |
| `codec` | `none` (absent = `none`) or `gzip` |
| `stored_sha256` | SHA-256 of the bytes on disk |
| `stored_size` | length of the bytes on disk |
| `chunks[]` | present when the artifact is stored in parts (see below) |

A blob is stored at `raw/<sha256>` when `codec` is `none`, and at
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
  `seals/SHA256SUMS.<n>` where `n` is the round it closed. Earlier sealed
  states stay provable.
- `case.json` gains a `rounds` array summarizing each round.
- A producer MUST hold an exclusive lock (`.lock`) for a collect→seal
  cycle. `.lock` is not evidence and is not covered by `SHA256SUMS`.

A file a later round did not re-read is recorded with
`collection_method: "carried_forward"` and the `acquired_in_round` that
did read it. Consumers MUST NOT present carried-forward evidence as freshly
acquired. A producer MUST decide "unchanged" on properties an unprivileged
writer cannot forge (inode plus change time); modification time alone is
not sufficient.

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
previous line's exact bytes. The first record's `prev` is 64 zeros. Any
edit, deletion, insertion or reorder breaks the chain from that point on.
Each record also carries a monotonic `seq` and a UTC `ts_utc`.

## Integrity verification

`agentdfir verify` (or any third-party implementation) MUST:

1. recompute SHA-256 for every path listed in `SHA256SUMS` and compare;
2. flag any `raw/` file not covered by `SHA256SUMS` (planted evidence);
3. confirm each manifest artifact's **plaintext** hashes to its
   `artifact_id` — decoding its codec, and concatenating its chunks in
   order when it has them;
4. walk both hash chains and report the first break;
5. if `SEAL.sig` is present, verify the ed25519 signature over the SHA-256
   of `SHA256SUMS`.

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

## Corroboration states

`REQUESTED` → `REPORTED` → `OBSERVED` → `PARTIALLY_CORROBORATED` →
`CORROBORATED`, plus `CONTRADICTED` and `UNKNOWN`. Aggregate precedence:
`CONTRADICTED > CORROBORATED > PARTIALLY_CORROBORATED > OBSERVED >
REPORTED > REQUESTED > UNKNOWN`. Model narrative alone is never higher
than `REPORTED`.
