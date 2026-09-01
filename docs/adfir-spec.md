# The `.adfir` Evidence Package Specification

Version: `0.1` · Status: draft · License: MIT

An `.adfir` package is an **open, self-describing, independently parseable**
container for AI-agent forensic evidence. Any tool can read it without
AgentDFIR. This document is the normative reference.

## Design: two zones

An `.adfir` package has a **sealed zone** (written once at acquisition,
never modified) and an **analysis overlay** (regenerable, excluded from
the seal).

```
case.adfir/
├── raw/<sha256>            # sealed: content-addressed evidence bytes
├── manifest.json           # sealed: per-artifact metadata
├── collection.jsonl        # sealed: hash-chained collection log
├── chain-of-custody.jsonl  # sealed: hash-chained custody log
├── case.json               # sealed: case / operator / clock metadata
├── SHA256SUMS              # sealed: covers the sealed zone exactly
├── SEAL.sig                # optional: ed25519 detached signature
├── normalized/             # overlay: events / entities / relationships (JSONL)
├── detections/             # overlay: findings.json
├── reports/                # overlay: HTML/JSON/CSV/STIX/OTel
└── redaction-manifest.json # present only in derived support packages
```

`SHA256SUMS` covers exactly: `case.json`, `manifest.json`,
`collection.jsonl`, `chain-of-custody.jsonl`, and every `raw/<sha256>`.
Regenerating the overlay never changes the seal.

## Content addressing

Each acquired blob is stored at `raw/<sha256>` where `<sha256>` is the
lowercase hex SHA-256 of its bytes. Identical content across users or
sessions is stored once (dedupe); the manifest carries one record per
logical occurrence. This eliminates case-folding, Unicode-normalization
and path-length hazards inside the package — original paths live only in
manifest metadata (`logical_path`).

## Hash chaining

`collection.jsonl` and `chain-of-custody.jsonl` are JSONL where each line
is a JSON object with a `prev` field equal to the SHA-256 (hex) of the
previous line's exact bytes. The first record's `prev` is 64 zeros. Any
edit, deletion, insertion or reorder breaks the chain from that point on.
Each record also carries a monotonic `seq` and a UTC `ts_utc`.

## Integrity verification

`agentdfir verify` (or any third-party implementation) MUST:

1. recompute SHA-256 for every path listed in `SHA256SUMS` and compare;
2. flag any `raw/` blob not covered by `SHA256SUMS` (planted evidence);
3. confirm each manifest artifact's blob hashes to its `artifact_id`;
4. walk both hash chains and report the first break;
5. if `SEAL.sig` is present, verify the ed25519 signature over the SHA-256
   of `SHA256SUMS`.

## Encryption (optional)

A package directory may be archived and encrypted to a single
`case.adfir.enc` file using AES-256-GCM with a PBKDF2-HMAC-SHA256 derived
key. The public envelope header (`ADFIRENC` magic, version, iteration
count, salt, nonce) is authenticated as GCM additional data and contains
no secrets. Encryption hides logical paths, which can leak confidential
project/repository names.

## Versioning

- `adfir_version` — this container format (independent).
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
