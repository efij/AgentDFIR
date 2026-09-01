# Contributing to AgentDFIR

Thanks for helping build open-source DFIR for AI agents.

## Ground rules

- **Forensic coding rules are non-negotiable:**
  - never execute discovered/suspect binaries (not even `--version`)
  - never follow symlinks during acquisition
  - hash while copying, never after
  - record every failure — nothing is silently swallowed
  - sanitize evidence-derived strings before terminal output
  - treat all acquired evidence as hostile (see the parser safety rules)
- **Zero third-party dependencies in the collector core** (`detect`, `collect`, `verify`). Exceptions need explicit justification in the PR.
- `gofmt` and `go vet` must be clean; all tests pass with `-race`.
- **Never commit real evidence.** Test fixtures are synthetic only.

## Adding support for a new AI agent product

One PR should contain:

1. Product entry in `internal/products/products.json` (detection knowledge)
2. Collector manifest (`internal/products/<product>_manifest.json`)
3. Synthetic test fixtures + collector tests
4. A docs page describing the product's forensic artifacts (locations, schemas, timestamp semantics, limitations)

No changes to the acquisition core should be required — if they are, open an issue first.

## Branching & releases

- `main` is always releasable and protected; all work lands via pull request.
- Feature branches: `feat/<slug>`; fixes: `fix/<slug>`; docs: `docs/<slug>`.
- Conventional-style commit subjects; every PR must pass CI (build, `gofmt`,
  `go vet`, `go test -race`) on Linux, macOS and Windows.
- Releases are tagged `vX.Y.Z` (SemVer). Pushing a tag triggers the release
  workflow, which cross-compiles static binaries for linux/darwin/windows
  (amd64+arm64), publishes checksummed archives, and attaches release notes.
  Update `CHANGELOG.md` before tagging.

## Development

```
go build ./...
go test -race ./...
```

## Sign-off

By contributing you certify the [Developer Certificate of Origin](https://developercertificate.org/). Add `Signed-off-by: Your Name <email>` to commits (`git commit -s`).
