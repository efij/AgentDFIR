# Install

AgentDFIR is a single static binary with zero runtime dependencies. Pick the path
that fits the machine you are on. Every path ends with the same file.

| You are… | Use | Dialogs |
|---|---|---|
| on an **air-gapped / offline** box, or want **one file on a USB stick** | [Portable binary](#1-portable-binary-air-gap-first) | macOS: one command once. Windows: one click once. |
| on an online macOS / Linux box | [`install.sh`](#2-installsh-macos--linux) | none |
| a Homebrew user | [`brew install`](#3-homebrew-macos--linux) | none |
| a Go developer | [`go install`](#4-go-install) | none |

All release assets are checksummed (`SHA256SUMS.txt`) and signed with Sigstore.
See [Verify what you downloaded](#5-verify-what-you-downloaded).

---

## 1. Portable binary (air-gap first)

Release page: <https://github.com/efij/AgentDFIR/releases/latest>

Per-platform **raw binaries** are published uncompressed, so one download is the
whole tool. Archives (`.tar.gz`, `.zip`) carry the same binary for people who
prefer them.

| Platform | Asset |
|---|---|
| macOS Apple Silicon | `agentdfir-vX.Y.Z-darwin-arm64` |
| macOS Intel | `agentdfir-vX.Y.Z-darwin-amd64` |
| Linux x86-64 | `agentdfir-vX.Y.Z-linux-amd64` |
| Linux ARM64 | `agentdfir-vX.Y.Z-linux-arm64` |
| Windows x86-64 | `agentdfir-vX.Y.Z-windows-amd64.exe` (or `.zip`) |

### macOS

```sh
cd ~/Downloads
shasum -a 256 -c <(grep darwin-arm64 SHA256SUMS.txt)      # optional but recommended
chmod +x agentdfir-vX.Y.Z-darwin-arm64
xattr -d com.apple.quarantine agentdfir-vX.Y.Z-darwin-arm64
./agentdfir-vX.Y.Z-darwin-arm64 version
```

**Why the `xattr` line.** Browsers stamp every download with a quarantine flag.
On first run Gatekeeper checks the file for an Apple Developer ID signature plus
notarization and, finding neither, shows *"Apple could not verify 'agentdfir' is
free of malware"* and kills the process. AgentDFIR release binaries are built on
GitHub's Linux runners and are not Apple-signed. The `xattr -d` command removes
the quarantine flag, which is exactly what Apple's own *System Settings →
Privacy & Security → Open Anyway* button does. You need it once per downloaded
file. Homebrew, `install.sh`, `curl` and `go install` never set the flag, so
those paths show no dialog.

The same is true for every unsigned command-line tool on macOS, including the
ones Homebrew installs. Nothing about this is specific to AgentDFIR.

### Windows

1. Download the `.exe` (or the `.zip` and extract it).
2. On first run Windows SmartScreen may show *"Windows protected your PC"*
   because the binary carries no Authenticode signature. Click **More info →
   Run anyway**. Once per file.
3. `agentdfir-vX.Y.Z-windows-amd64.exe version`

Verify the checksum first with PowerShell:

```powershell
(Get-FileHash .\agentdfir-vX.Y.Z-windows-amd64.exe -Algorithm SHA256).Hash.ToLower()
Select-String windows-amd64.exe .\SHA256SUMS.txt
```

### Linux

```sh
sha256sum -c <(grep linux-amd64 SHA256SUMS.txt)
chmod +x agentdfir-vX.Y.Z-linux-amd64
./agentdfir-vX.Y.Z-linux-amd64 version
```

No execution gate on Linux.

### Air-gap note

The macOS quarantine flag and the Windows mark-of-the-web live in filesystem
metadata (an extended attribute, an alternate data stream). A copy through a
FAT/exFAT USB stick usually drops both, so on the actual offline machine the
dialog often never appears. Carry `SHA256SUMS.txt` and the `.sigstore.json`
bundle alongside the binary so you can still [verify](#5-verify-what-you-downloaded)
it there.

---

## 2. `install.sh` (macOS / Linux)

```sh
curl -fsSL https://raw.githubusercontent.com/efij/AgentDFIR/main/install.sh | sh
```

Detects OS and architecture, downloads the raw binary and `SHA256SUMS.txt`,
verifies the checksum, installs to `~/.local/bin/agentdfir`. Read it first if
you like: it is 100 lines of plain `sh`.

Options via environment:

```sh
AGENTDFIR_VERSION=v0.12.1 AGENTDFIR_INSTALL_DIR=/usr/local/bin sh install.sh
```

---

## 3. Homebrew (macOS / Linux)

```sh
brew install efij/agentdfir/agentdfir
```

Formula lives in <https://github.com/efij/homebrew-agentdfir> and builds the
tagged source with the Homebrew Go toolchain. `brew upgrade agentdfir` follows
new releases.

---

## 4. `go install`

```sh
go install github.com/efij/AgentDFIR/cmd/agentdfir@latest
```

Builds locally, lands in `$(go env GOPATH)/bin`. Reports its version without
the `v` prefix (from Go module metadata).

---

## 5. Verify what you downloaded

### Checksum

`SHA256SUMS.txt` covers every asset.

```sh
sha256sum -c --ignore-missing SHA256SUMS.txt      # Linux
shasum -a 256 -c --ignore-missing SHA256SUMS.txt  # macOS
```

### Provenance (Sigstore)

Every asset and `SHA256SUMS.txt` itself is signed keylessly by the release
workflow using GitHub's OIDC identity. The signature and certificate ship as a
`<asset>.sigstore.json` bundle next to the asset. With
[cosign](https://github.com/sigstore/cosign) installed:

```sh
V=v0.12.1; A=agentdfir-$V-darwin-arm64
cosign verify-blob --bundle "$A.sigstore.json" \
  --certificate-identity "https://github.com/efij/AgentDFIR/.github/workflows/release.yml@refs/tags/$V" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --offline "$A"
```

`--offline` works because the bundle embeds the Rekor transparency-log entry,
so the check runs on an air-gapped machine. A pass proves the file was produced
by *this repository's* release workflow for *that* tag, and has not been
modified since. It does not, and cannot, satisfy Gatekeeper or SmartScreen;
those look only for Apple and Microsoft-rooted certificates.

---

## Why the binaries are not Apple/Microsoft signed

Removing the macOS dialog for a raw browser download requires an Apple
Developer ID certificate and notarization, available only through the paid
Apple Developer Program. Removing the Windows one requires an Authenticode
certificate. Neither changes what the binary does, and both are on the
roadmap. Until then the paths above give you either zero dialogs (Homebrew,
`install.sh`, `go install`) or one honest, documented step (portable binary),
plus cryptographic provenance that is stronger than either platform's
signature check.

## What the release pipeline checks

Every tag runs `.github/workflows/release.yml`: build, sign, publish, then a
separate `verify` job on macOS, Linux and Windows downloads the *published*
assets and performs the exact steps on this page, including stamping the
quarantine flag on macOS and the mark-of-the-web on Windows, before the
release is considered good. The same `verify` job can be re-run at any time
against an already-published tag from the Actions tab (*Run workflow* →
enter the tag), which skips the build and checks only what users download.


## Release checklist (maintainers)

A tag push builds, signs and publishes assets, then updates the Homebrew tap. The tap step **fails the release**
if the `HOMEBREW_TAP_TOKEN` repository secret is missing (fine-grained PAT, `contents: write` on
`efij/homebrew-agentdfir`) and verifies the formula now serves the tag. Manual fallback: `scripts/update-tap.sh vX.Y.Z`.
After every release check all four paths report the new version: `brew upgrade agentdfir`, `install.sh`,
`go install github.com/efij/AgentDFIR/cmd/agentdfir@latest`, raw binary from the releases page.
