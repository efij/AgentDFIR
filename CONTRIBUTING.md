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
- Releases are `vX.Y.Z` (SemVer). **A release is cut by bumping
  `internal/version/version.go` — there is no tagging step to remember.**
  When that file lands on `main` with an exact `X.Y.Z` version,
  `.github/workflows/auto-release.yml` tags it and starts `release.yml`,
  which cross-compiles static binaries for linux/darwin/windows
  (amd64+arm64), signs every asset with Sigstore, publishes the release,
  verifies all four install paths on three operating systems, and updates
  the Homebrew tap. Update `CHANGELOG.md` in the same commit.
- A version between releases carries a suffix (`2.4.0-dev`). Anything that is
  not exactly `X.Y.Z` is ignored by the release automation.
- `.github/workflows/release-drift.yml` runs daily and **fails if the version
  on `main` is not the version people can install** — no tag, no release, a
  release still in draft, an incomplete asset upload, or a published release
  that is not the latest one. Run it on demand with
  `gh workflow run release-drift.yml`.

  This exists because v2.1.0, v2.2.0 and v2.2.1 were merged to `main` and
  never tagged. No release was cut for any of them, every install path kept
  serving v2.0.1, and nothing anywhere said so — including a fix for Codex
  CLI sessions being invisible to every detection. Neither workflow is
  optional scaffolding; they are the reason that cannot repeat.

## Development

```
go build ./...
go test -race ./...
```

## Sign-off

By contributing you certify the [Developer Certificate of Origin](https://developercertificate.org/). Add `Signed-off-by: Your Name <email>` to commits (`git commit -s`).
