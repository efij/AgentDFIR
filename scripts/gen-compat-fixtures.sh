#!/usr/bin/env bash
# Regenerates the historical .adfir packages under internal/compat/testdata.
#
# Each package is produced by the RELEASED binary of that tag, not by the
# current code: the source of the tag is exported with `git archive`, built
# for Linux, and run inside a throwaway container so the package records a
# neutral host (compat-host) and user (root) instead of the machine that
# generated it. The scenario is the synthetic orphan-agent profile, so the
# packages contain no real evidence.
#
# Usage: scripts/gen-compat-fixtures.sh [work-dir] [tag ...]
# Needs: git, go, docker. Tests never need any of them; they read the
# committed .tar.gz files.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
work=${1:-$(mktemp -d)}
shift || true
tags=("$@")
if [ ${#tags[@]} -eq 0 ]; then
	tags=(v2.0.0 v2.7.0 v3.0.0 v3.2.0)
fi
out="$repo/internal/compat/testdata"
arch=$(docker info --format '{{.Architecture}}' 2>/dev/null || uname -m)
case "$arch" in
aarch64 | arm64) goarch=arm64 ;;
*) goarch=amd64 ;;
esac

mkdir -p "$work"
for tag in "${tags[@]}"; do
	src="$work/src-$tag"
	rm -rf "$src" "$work/run-$tag"
	mkdir -p "$src" "$work/run-$tag"
	git -C "$repo" archive "$tag" | tar -x -C "$src"
	(cd "$src" && CGO_ENABLED=0 GOOS=linux GOARCH=$goarch go build -trimpath -o "$work/run-$tag/agentdfir" ./cmd/agentdfir)
	docker run --rm --hostname compat-host -v "$work/run-$tag":/w -w /w debian:stable-slim sh -euc '
		./agentdfir simulate --scenario orphan-agent --out /w/profile >/dev/null
		./agentdfir collect --product claude --path /w/profile --out /w/pkg \
			--case-id COMPAT-'"$tag"' --operator compat >/dev/null
		./agentdfir verify /w/pkg >/dev/null
	'
	# Deterministic archive: sorted names, fixed owner and mtime (GNU tar),
	# or the bsdtar equivalent. No AppleDouble ._ entries: verify would
	# rightly report them as files planted in raw/.
	(cd "$work/run-$tag" && tar --sort=name --owner=0 --group=0 --numeric-owner \
		--mtime=2026-10-25T00:00:00Z -czf "$out/$tag-package.tar.gz" pkg 2>/dev/null ||
		COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata --uid 0 --gid 0 --uname root --gname root \
			-czf "$out/$tag-package.tar.gz" pkg)
	ls -l "$out/$tag-package.tar.gz"
done
