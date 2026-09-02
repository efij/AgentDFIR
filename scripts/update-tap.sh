#!/usr/bin/env sh
# Publish/refresh the Homebrew formula in the tap repository for a released tag.
#
#   scripts/update-tap.sh v0.11.1
#
# Renders scripts/agentdfir.rb.tmpl with the tag's source-tarball sha256 and
# pushes Formula/agentdfir.rb to $TAP_REPO (default efij/homebrew-agentdfir).
# Auth: $TAP_TOKEN (CI, a token with contents:write on the tap repo) or your
# local git credentials (gh auth) when run by hand.
set -eu

VERSION="${1:?usage: update-tap.sh vX.Y.Z}"
REPO="efij/AgentDFIR"
TAP_REPO="${TAP_REPO:-efij/homebrew-agentdfir}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$HERE/agentdfir.rb.tmpl"

case "$VERSION" in v*) ;; *) echo "version must start with v" >&2; exit 1 ;; esac
BARE="${VERSION#v}"
SRC_URL="https://github.com/$REPO/archive/refs/tags/${VERSION}.tar.gz"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM

echo "fetching $SRC_URL"
curl -fsSL --retry 3 -o "$WORK/src.tar.gz" "$SRC_URL"
if command -v sha256sum >/dev/null 2>&1; then SHA="$(sha256sum "$WORK/src.tar.gz" | cut -d' ' -f1)"
else SHA="$(shasum -a 256 "$WORK/src.tar.gz" | cut -d' ' -f1)"; fi
echo "sha256 $SHA"

if [ -n "${TAP_TOKEN:-}" ]; then
  CLONE_URL="https://x-access-token:${TAP_TOKEN}@github.com/${TAP_REPO}.git"
else
  CLONE_URL="https://github.com/${TAP_REPO}.git"
fi
git clone -q "$CLONE_URL" "$WORK/tap"
mkdir -p "$WORK/tap/Formula"
sed -e "s|@VERSION@|$BARE|g" -e "s|@TAG@|$VERSION|g" -e "s|@SHA256@|$SHA|g" \
  "$TEMPLATE" > "$WORK/tap/Formula/agentdfir.rb"

cd "$WORK/tap"
git add Formula/agentdfir.rb
if git diff --cached --quiet; then
  echo "tap already at $VERSION"
  exit 0
fi
git -c user.name="agentdfir-release" -c user.email="release@agentdfir.invalid" \
  commit -q -m "agentdfir ${VERSION}"
git push -q origin HEAD
echo "tap updated: brew install ${TAP_REPO%%/homebrew-*}/${TAP_REPO#*/homebrew-}/agentdfir"
