#!/usr/bin/env sh
# Render the Chocolatey package source for a released tag and publish it to
# the package-source repository.
#
#   scripts/update-choco.sh v2.5.1                   render + push source to $CHOCO_REPO
#   scripts/update-choco.sh v2.5.1 --render-only DIR render into DIR (the release
#                                                    job then runs `choco pack` /
#                                                    `choco push` on Windows)
#
# Renders scripts/chocolatey/*.tmpl with the Windows zip hashes taken from the
# release's SHA256SUMS.txt. The community-feed push itself needs choco.exe,
# so it lives in the Windows release job; this script only produces the
# auditable source. Auth for the source repo, first match wins:
#   $CHOCO_REPO_SSH_KEY   private key of a write deploy key on the source repo
#                         (CI secret CHOCO_REPO_SSH_KEY)
#   $CHOCO_REPO_TOKEN     a token with contents:write on the source repo
#   otherwise             your local git credentials (gh auth) when run by hand
# The community-feed API key is never read here.
set -eu

VERSION="${1:?usage: update-choco.sh vX.Y.Z [--render-only DIR]}"
REPO="efij/AgentDFIR"
CHOCO_REPO="${CHOCO_REPO:-efij/chocolatey-agentdfir}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TPL="$HERE/chocolatey"

case "$VERSION" in v*) ;; *) echo "version must start with v" >&2; exit 1 ;; esac
BARE="${VERSION#v}"
RENDER_ONLY=""
if [ "${2:-}" = "--render-only" ]; then
  RENDER_ONLY="${3:?--render-only needs a directory}"
fi
SUMS_URL="https://github.com/$REPO/releases/download/${VERSION}/SHA256SUMS.txt"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

echo "fetching $SUMS_URL"
curl -fsSL --retry 3 -o "$WORK/SHA256SUMS.txt" "$SUMS_URL"
sha_for() { grep -E " \*?agentdfir-${VERSION}-windows-$1\.zip\$" "$WORK/SHA256SUMS.txt" | cut -d' ' -f1; }
SHA_AMD64="$(sha_for amd64)"
SHA_ARM64="$(sha_for arm64)"
if [ -z "$SHA_AMD64" ] || [ -z "$SHA_ARM64" ]; then
  echo "SHA256SUMS.txt lacks a windows zip entry (amd64='$SHA_AMD64' arm64='$SHA_ARM64')" >&2
  exit 1
fi
echo "sha256 amd64 $SHA_AMD64"
echo "sha256 arm64 $SHA_ARM64"

render() {
  # $1 = destination directory; writes agentdfir.nuspec and tools/chocolateyinstall.ps1
  mkdir -p "$1/tools"
  sed -e "s|@VERSION@|$BARE|g" -e "s|@TAG@|$VERSION|g" \
      -e "s|@SHA_AMD64@|$SHA_AMD64|g" -e "s|@SHA_ARM64@|$SHA_ARM64|g" \
    "$TPL/agentdfir.nuspec.tmpl" > "$1/agentdfir.nuspec"
  sed -e "s|@VERSION@|$BARE|g" -e "s|@TAG@|$VERSION|g" \
      -e "s|@SHA_AMD64@|$SHA_AMD64|g" -e "s|@SHA_ARM64@|$SHA_ARM64|g" \
    "$TPL/chocolateyinstall.ps1.tmpl" > "$1/tools/chocolateyinstall.ps1"
  if grep -q '@[A-Z_]*@' "$1/agentdfir.nuspec" "$1/tools/chocolateyinstall.ps1"; then
    echo "unrendered placeholder left in the package source" >&2
    exit 1
  fi
}

if [ -n "$RENDER_ONLY" ]; then
  render "$RENDER_ONLY"
  echo "rendered into $RENDER_ONLY"
  exit 0
fi

if [ -n "${CHOCO_REPO_SSH_KEY:-}" ]; then
  KEY="$WORK/deploy_key"
  umask 077; printf '%s\n' "$CHOCO_REPO_SSH_KEY" > "$KEY"; umask 022
  export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
  CLONE_URL="git@github.com:${CHOCO_REPO}.git"
elif [ -n "${CHOCO_REPO_TOKEN:-}" ]; then
  CLONE_URL="https://x-access-token:${CHOCO_REPO_TOKEN}@github.com/${CHOCO_REPO}.git"
else
  CLONE_URL="https://github.com/${CHOCO_REPO}.git"
fi
git clone -q "$CLONE_URL" "$WORK/src"
render "$WORK/src"

cd "$WORK/src"
git add agentdfir.nuspec tools/chocolateyinstall.ps1
if git diff --cached --quiet; then
  echo "package source already at $VERSION"
  exit 0
fi
git -c user.name="agentdfir-release" -c user.email="release@agentdfir.invalid" \
  commit -q -m "agentdfir ${VERSION}"
git push -q origin HEAD
echo "package source updated: https://github.com/${CHOCO_REPO}"
