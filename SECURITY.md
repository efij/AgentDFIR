# Security Policy

AgentDFIR is a forensic tool: it runs on compromised hosts and parses hostile evidence. Security reports are treated with priority.

## Reporting a vulnerability

Please report vulnerabilities privately via GitHub Security Advisories ("Report a vulnerability" on the repository's Security tab). Do not open public issues for exploitable bugs.

Of particular interest:

- collector weaponization (symlink/path tricks causing over-collection or writes outside the package)
- evidence-package tamper-detection bypasses (hash chain, SHA256SUMS, content addressing)
- parser vulnerabilities (memory exhaustion, path traversal, archive bombs)
- analyst-targeting output injection (terminal escapes, invisible Unicode, HTML report injection)

## Scope notes

AgentDFIR never bypasses OS permissions, EDR, encryption or sandboxes by design — reports that a permission boundary blocks acquisition are expected behavior, not vulnerabilities.

## Where collected evidence lives

Since v1.5.0, `agentdfir run` writes to one case per host/user under the
AgentDFIR home — `$AGENTDFIR_HOME`, else `~/.agentdfir`
(`%LOCALAPPDATA%\AgentDFIR` on Windows) — and identical blobs are shared
between cases there.

That directory therefore aggregates **every agent transcript collected on
the machine**: prompts, tool output, source code, and whatever secrets
passed through a session. Treat it as you would any evidence store.

- The home, the case directories and the shared store are created `0700`
  and are refused if they are a symlink, are not a directory, are not owned
  by the current user, or are group/world-writable. Stored blobs are `0400`.
- Nothing in the package is encrypted at rest by default. For evidence
  leaving the machine, use `agentdfir encrypt <pkg>` (full-package
  encryption to a single `.adfir.enc`, which also hides logical paths) and
  `export --support` for a redacted copy.
- Reclaim space with `agentdfir store gc --delete`, which removes only
  blobs no case links to any more. Deleting a case directory is safe: every
  other case holds its own real link to the bytes it needs.
- `--no-share` keeps a case's bytes entirely inside its own directory.

### Signed rounds and what they prove

Every round is signed with this machine's key (`keys/seal.ed25519` in the
home, `0600`, created on first use) unless `--sign` names another key or
`--no-sign` is given, and each sealed round's digest is appended to
`anchors.jsonl` in the home and printed at the end of the run. Before a
new round is added, the previous signature, the anchor and the sealed
files are checked; a failure is recorded in the new round permanently and
the run exits 4.

Limits, stated plainly: the key and the anchor log sit on the same machine,
under the same account, as the evidence. They stop anyone who can only
reach the case directory (a share, a copy, a backup restore), and they
catch accidental corruption, but someone who controls the account can
rewrite a case, re-sign it and edit the anchor log. The digest printed at
the end of each run — pasted into a ticket or case notes somewhere else —
is what that attacker cannot reach. Sign with an external key (`--sign`)
when that matters.

The analysis overlay is reused across rounds. It is authenticated with a
key derived from the machine key and every cached file is hashed; anything
that does not match is rebuilt from the sealed evidence, never trusted.

### Resource use

`agentdfir run` is gentle by default: lowered CPU priority, at most half the
CPUs (4 workers), a soft heap limit, acquisition reads capped at 200 MB/s,
a pause while the machine is under load, and a free-disk floor (2 GiB, or
1% of the volume up to 5 GiB) it will not cross — it refuses to start, or
stops cleanly, instead. `--priority background` also lowers I/O priority;
`--priority normal` restores full speed.

A collect→seal cycle holds an exclusive lock on the package. If a run is
killed, the next run reports and reclaims the stale lock; a lock held by a
live process is never stolen.
