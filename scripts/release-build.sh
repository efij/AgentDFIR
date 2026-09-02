#!/usr/bin/env sh
# Build every release asset into dist/.
#
#   scripts/release-build.sh v0.12.1 [dist]
#
# Produces, per target:
#   agentdfir-<ver>-<os>-<arch>[.exe]       raw portable binary (air-gap / USB)
#   agentdfir-<ver>-<os>-<arch>.tar.gz      archive (darwin, linux)
#   agentdfir-<ver>-<os>-<arch>.zip         archive (windows)
# plus SHA256SUMS.txt over all of the above.
#
# Used by .github/workflows/release.yml and by the CI smoke test, so the
# artifact layout that install.sh expects is defined in exactly one place.
set -eu

VERSION="${1:?usage: release-build.sh <version> [dist-dir]}"
DIST="${2:-dist}"
MODULE="github.com/efij/AgentDFIR"
TARGETS="${TARGETS:-linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64}"

rm -rf "$DIST"
mkdir -p "$DIST"
LDFLAGS="-s -w -X ${MODULE}/internal/version.Version=${VERSION}"

for t in $TARGETS; do
  os="${t%/*}"; arch="${t#*/}"
  base="agentdfir-${VERSION}-${os}-${arch}"
  bin="agentdfir"; raw="$base"
  if [ "$os" = "windows" ]; then bin="agentdfir.exe"; raw="${base}.exe"; fi
  echo "building $raw"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$DIST/$raw" ./cmd/agentdfir
  # The archive carries the plain name so extraction yields `agentdfir[.exe]`.
  cp "$DIST/$raw" "$DIST/$bin"
  if [ "$os" = "windows" ]; then
    (cd "$DIST" && zip -q -j "${base}.zip" "$bin")
  else
    (cd "$DIST" && tar -czf "${base}.tar.gz" "$bin")
  fi
  rm -f "$DIST/$bin"
done

cd "$DIST"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum agentdfir-* > SHA256SUMS.txt
else
  shasum -a 256 agentdfir-* > SHA256SUMS.txt
fi
echo "---- $DIST"
ls -la
