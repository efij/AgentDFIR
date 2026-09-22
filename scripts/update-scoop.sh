#!/usr/bin/env sh
# Publish/refresh the Scoop manifest in the bucket repository for a released tag.
#
#   scripts/update-scoop.sh v2.4.0
#
# Renders scripts/agentdfir.scoop.json.tmpl with the Windows zip hashes taken
# from the release's SHA256SUMS.txt and pushes bucket/agentdfir.json to
# $BUCKET_REPO (default efij/scoop-agentdfir). Same auth contract as
# update-tap.sh, first match wins:
#   $BUCKET_SSH_KEY   private key of a write deploy key on the bucket repo
#                     (CI secret SCOOP_BUCKET_SSH_KEY)
#   $BUCKET_TOKEN     a token with contents:write on the bucket repo
#   otherwise         your local git credentials (gh auth) when run by hand
set -eu

VERSION="${1:?usage: update-scoop.sh vX.Y.Z}"
REPO="efij/AgentDFIR"
BUCKET_REPO="${BUCKET_REPO:-efij/scoop-agentdfir}"
HERE="$(cd "$(dirname "$0")" && pwd)"
TEMPLATE="$HERE/agentdfir.scoop.json.tmpl"

case "$VERSION" in v*) ;; *) echo "version must start with v" >&2; exit 1 ;; esac
BARE="${VERSION#v}"
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

if [ -n "${BUCKET_SSH_KEY:-}" ]; then
  KEY="$WORK/deploy_key"
  umask 077; printf '%s\n' "$BUCKET_SSH_KEY" > "$KEY"; umask 022
  export GIT_SSH_COMMAND="ssh -i $KEY -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new"
  CLONE_URL="git@github.com:${BUCKET_REPO}.git"
elif [ -n "${BUCKET_TOKEN:-}" ]; then
  CLONE_URL="https://x-access-token:${BUCKET_TOKEN}@github.com/${BUCKET_REPO}.git"
else
  CLONE_URL="https://github.com/${BUCKET_REPO}.git"
fi
git clone -q "$CLONE_URL" "$WORK/bucket"
mkdir -p "$WORK/bucket/bucket"
sed -e "s|@VERSION@|$BARE|g" -e "s|@TAG@|$VERSION|g" \
    -e "s|@SHA_AMD64@|$SHA_AMD64|g" -e "s|@SHA_ARM64@|$SHA_ARM64|g" \
  "$TEMPLATE" > "$WORK/bucket/bucket/agentdfir.json"

cd "$WORK/bucket"
git add bucket/agentdfir.json
if git diff --cached --quiet; then
  echo "bucket already at $VERSION"
  exit 0
fi
git -c user.name="agentdfir-release" -c user.email="release@agentdfir.invalid" \
  commit -q -m "agentdfir ${VERSION}"
git push -q origin HEAD
echo "bucket updated: scoop bucket add agentdfir https://github.com/${BUCKET_REPO} && scoop install agentdfir"
