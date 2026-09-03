#!/usr/bin/env sh
# Regenerate internal/rulepack/atlas_ids.go from the MITRE ATLAS data file.
#
#   scripts/gen-atlas-ids.sh [path/to/ATLAS.yaml]
#
# Without an argument the current dist/ATLAS.yaml is fetched from
# github.com/mitre-atlas/atlas-data. The table is used by tests to reject
# rule packs that cite a MITRE ATLAS technique ID that does not exist.
set -eu

HERE="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$HERE/internal/rulepack/atlas_ids.go"
SRC="${1:-}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT INT TERM

if [ -z "$SRC" ]; then
  SRC="$TMP/ATLAS.yaml"
  curl -fsSL -o "$SRC" https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml
fi

VERSION="$(awk '/^version:/{print $2; exit}' "$SRC")"
[ -n "$VERSION" ] || { echo "could not read version from $SRC" >&2; exit 1; }

# Technique entries look like:
#   - id: AML.T0051
#     name: LLM Prompt Injection
awk '/^ *- id: AML\.T[0-9]/{id=$3; getline; sub(/^ *name: */,""); print id "\t" $0}' "$SRC" \
  | grep -v 'use:' | sort -u > "$TMP/techniques.tsv"

N="$(wc -l < "$TMP/techniques.tsv" | tr -d ' ')"
[ "$N" -gt 100 ] || { echo "suspiciously few techniques ($N)" >&2; exit 1; }

{
  printf '// Code generated from MITRE ATLAS data (dist/ATLAS.yaml, version %s); DO NOT EDIT.\n' "$VERSION"
  printf '// Regenerate: scripts/gen-atlas-ids.sh\n\npackage rulepack\n\n'
  printf '// ATLASVersion is the ATLAS release the technique table was generated from.\n'
  printf 'const ATLASVersion = "%s"\n\n' "$VERSION"
  printf '// atlasTechniques lists every technique and sub-technique ID in that release.\n'
  printf 'var atlasTechniques = map[string]string{\n'
  awk -F'\t' '{ gsub(/"/, "\\\"", $2); printf "\t\"%s\": \"%s\",\n", $1, $2 }' "$TMP/techniques.tsv"
  printf '}\n'
} > "$OUT"

gofmt -w "$OUT"
echo "wrote $OUT: ATLAS $VERSION, $N techniques"
