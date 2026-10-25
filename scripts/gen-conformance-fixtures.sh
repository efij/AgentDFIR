#!/usr/bin/env bash
# Regenerates testdata/conformance (the .adfir conformance fixtures).
#
# The fixtures are produced by the benchmark package's generator test, run
# inside a throwaway Linux container so the packages record a neutral host
# (conformance-host), user (root) and temporary paths instead of the
# machine that generated them. Content is synthetic.
#
# Usage: scripts/gen-conformance-fixtures.sh
# Needs: go, docker. Tests never need either; they read the committed files.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
arch=$(docker info --format '{{.Architecture}}' 2>/dev/null || uname -m)
case "$arch" in
aarch64 | arm64) goarch=arm64 ;;
*) goarch=amd64 ;;
esac
bin=$(mktemp -d)/benchmark.test
(cd "$repo" && CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go test -c -o "$bin" ./internal/benchmark)
docker run --rm --hostname conformance-host -v "$repo":/w -v "$(dirname "$bin")":/b -w /w/internal/benchmark \
	debian:stable-slim /b/benchmark.test -test.run 'TestConformanceGoVerify$' -update-conformance
du -sh "$repo/testdata/conformance"
