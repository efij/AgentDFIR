#!/usr/bin/env sh
# AgentDFIR installer for macOS and Linux.
#
#   curl -fsSL https://raw.githubusercontent.com/efij/AgentDFIR/main/install.sh | sh
#
# What it does, in order:
#   1. detects OS/arch, 2. downloads the raw release binary and SHA256SUMS.txt,
#   3. verifies the checksum, 4. installs to $AGENTDFIR_INSTALL_DIR (default ~/.local/bin).
# It downloads with curl/wget, which never set the macOS quarantine flag or the
# Windows mark-of-the-web, so the installed binary runs without any OS dialog.
#
# Environment:
#   AGENTDFIR_VERSION      tag to install (default: latest release), e.g. v0.11.1
#   AGENTDFIR_INSTALL_DIR  target directory (default: ~/.local/bin)
#   AGENTDFIR_BASE_URL     asset base URL override (tests use file:///…/dist)
#
# Windows: download agentdfir-<ver>-windows-amd64.zip from the releases page instead.
set -eu

REPO="efij/AgentDFIR"
INSTALL_DIR="${AGENTDFIR_INSTALL_DIR:-$HOME/.local/bin}"
VERSION="${AGENTDFIR_VERSION:-}"

say()  { printf '%s\n' "$*" >&2; }
die()  { say "install.sh: error: $*"; exit 1; }

fetch() { # fetch <url> <out>
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL --retry 3 -o "$2" "$1"
  elif command -v wget >/dev/null 2>&1; then
    wget -q -O "$2" "$1"
  else
    die "need curl or wget"
  fi
}

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1
  else die "need sha256sum or shasum"; fi
}

case "$(uname -s)" in
  Darwin) OS=darwin ;;
  Linux)  OS=linux ;;
  *) die "unsupported OS $(uname -s). On Windows download the .zip from https://github.com/$REPO/releases" ;;
esac
case "$(uname -m)" in
  x86_64|amd64)  ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) die "unsupported architecture $(uname -m)" ;;
esac

if [ -z "$VERSION" ]; then
  command -v curl >/dev/null 2>&1 || die "set AGENTDFIR_VERSION when curl is unavailable"
  VERSION="$(curl -fsSLI -o /dev/null -w '%{url_effective}' "https://github.com/$REPO/releases/latest")"
  VERSION="${VERSION##*/}"
  [ -n "$VERSION" ] || die "could not resolve latest release"
fi

BASE_URL="${AGENTDFIR_BASE_URL:-https://github.com/$REPO/releases/download/$VERSION}"
ASSET="agentdfir-${VERSION}-${OS}-${ARCH}"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

say "agentdfir $VERSION ($OS/$ARCH)"
say "downloading $ASSET"
fetch "$BASE_URL/$ASSET" "$TMP/$ASSET"
fetch "$BASE_URL/SHA256SUMS.txt" "$TMP/SHA256SUMS.txt"

EXPECTED="$(grep -E "[[:space:]]\*?${ASSET}\$" "$TMP/SHA256SUMS.txt" | head -n1 | cut -d' ' -f1)"
[ -n "$EXPECTED" ] || die "$ASSET not listed in SHA256SUMS.txt"
ACTUAL="$(sha256_of "$TMP/$ASSET")"
[ "$EXPECTED" = "$ACTUAL" ] || die "checksum mismatch for $ASSET
  expected $EXPECTED
  actual   $ACTUAL"
say "checksum ok  $ACTUAL"

mkdir -p "$INSTALL_DIR"
chmod 755 "$TMP/$ASSET"
# curl/wget never set com.apple.quarantine; remove it anyway if present so the
# result is identical to what the docs promise (no Gatekeeper dialog).
if [ "$OS" = darwin ] && command -v xattr >/dev/null 2>&1; then
  xattr -d com.apple.quarantine "$TMP/$ASSET" 2>/dev/null || true
fi
mv -f "$TMP/$ASSET" "$INSTALL_DIR/agentdfir"

say "installed $INSTALL_DIR/agentdfir"
"$INSTALL_DIR/agentdfir" version >&2

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) say ""; say "note: $INSTALL_DIR is not on your PATH. Add it, e.g.:"
     say "  export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
esac
