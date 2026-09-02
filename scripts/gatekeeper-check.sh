#!/usr/bin/env bash
# Exercise the real macOS "downloaded in a browser" path against a release binary.
#
#   scripts/gatekeeper-check.sh <binary> <expected-version-string>
#
# 1. copies the binary and stamps the same com.apple.quarantine flag a browser sets
# 2. records Gatekeeper's verdict (spctl) and whether the quarantined copy runs
# 3. applies the documented fix (xattr -d com.apple.quarantine) and REQUIRES it to run
#
# Step 2 is logged, not asserted: GitHub macOS runners may have Gatekeeper
# enforcement off, and an unsigned binary is expected to be rejected anyway.
# Step 3 is the contract with users in docs/install.md.
set -euo pipefail

BIN="${1:?usage: gatekeeper-check.sh <binary> <expected-version-string>}"
WANT="${2:?usage: gatekeeper-check.sh <binary> <expected-version-string>}"
[[ "$(uname -s)" == Darwin ]] || { echo "gatekeeper-check: not macOS, skipping"; exit 0; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$BIN" "$WORK/agentdfir"
chmod 755 "$WORK/agentdfir"

xattr -w com.apple.quarantine "0081;00000000;Chrome;" "$WORK/agentdfir"
echo "quarantine: $(xattr -p com.apple.quarantine "$WORK/agentdfir")"
echo "codesign:   $(codesign -dvv "$WORK/agentdfir" 2>&1 | grep -E '^(Signature|TeamIdentifier)' | tr '\n' ' ')"
echo "spctl:      $(spctl --assess --type execute "$WORK/agentdfir" 2>&1 || true)"
set +e
out="$("$WORK/agentdfir" version 2>&1)"; rc=$?
set -e
echo "quarantined run: exit=$rc ${out:+output=$out}"
if [[ $rc -eq 0 ]]; then
  echo "note: runner allowed the quarantined binary (Gatekeeper not enforcing here)"
else
  echo "note: quarantined binary blocked, as documented for an unsigned download"
fi

xattr -d com.apple.quarantine "$WORK/agentdfir"
out="$("$WORK/agentdfir" version)"
echo "after xattr -d: $out"
[[ "$out" == *"$WANT"* ]] || { echo "FAIL: expected '$WANT' in '$out'"; exit 1; }
echo "OK: documented macOS path works"
