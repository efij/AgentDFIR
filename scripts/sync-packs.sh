#!/usr/bin/env sh
# Copy the shipped rule packs into the Go package that embeds them.
#
# rules/ is the authoring location and what github.com/efij/agentdfir-rules
# mirrors. internal/rulepack/packs/ is the same bytes, where //go:embed can
# reach them, so a portable binary carries the packs instead of needing a
# --rules directory that nobody has. TestEmbeddedPacksMatchRulesDir fails the
# build if the two ever drift.
#
#   scripts/sync-packs.sh
set -eu
cd "$(dirname "$0")/.."
rm -f internal/rulepack/packs/*.json
cp rules/*.json internal/rulepack/packs/
echo "synced $(ls -1 internal/rulepack/packs/*.json | wc -l | tr -d ' ') pack(s) into internal/rulepack/packs/"
