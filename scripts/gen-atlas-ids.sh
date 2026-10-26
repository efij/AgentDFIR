#!/usr/bin/env sh
# Regenerate the pinned MITRE ATLAS tables:
#   internal/mitre/data/atlas.json   (technique IDs, names, tactic membership)
#   internal/rulepack/atlas_ids.go   (the ID table the analysis path validates against)
#
#   scripts/gen-atlas-ids.sh [path/to/ATLAS-2026.09.yaml]
#
# The release is pinned (version, URL and SHA-256) in internal/mitre/gen.
# Without an argument the pinned release asset is downloaded; with one, the
# local file is used. Either way the bytes must match the pinned SHA-256 or
# nothing is written. A floating "latest" is never read: moving to a new
# ATLAS release is a reviewed change to the pin.
#
# The ATT&CK Enterprise table is regenerated the same way:
#   go run ./internal/mitre/gen -only attack -attack enterprise-attack-20.0.json -out internal/mitre/data
set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${1:-}"
if [ -n "$SRC" ]; then
  SRC="$(cd "$(dirname "$SRC")" && pwd)/$(basename "$SRC")"
fi
cd "$HERE/internal/mitre"
exec go run ./gen -only atlas -atlas "$SRC"
