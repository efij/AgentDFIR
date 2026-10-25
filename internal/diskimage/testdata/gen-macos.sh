#!/usr/bin/env bash
# Regenerates the APFS / HFS+ / DMG / sparsebundle fixtures with Apple's own
# tools (hdiutil, diskutil, ditto) on a macOS host. No root needed.
#
# Every image is created by this script in a scratch directory, attached
# read-write ONLY at a mount point inside that directory to populate it,
# and detached again. No other disk is touched.
#
#   ./gen-macos.sh            # from internal/diskimage/testdata
#
# Outputs (gzipped):
#   ../apfs/testdata/apfs.img.gz           bare APFS container, one volume "T"
#   ../apfs/testdata/expected.txt          sha256 of regular files, from shasum on the source tree
#   ../hfsplus/testdata/hfsplus.img.gz     bare journaled HFS+ volume
#   ../hfsplus/testdata/hfsx.img.gz        bare case-sensitive HFSX volume
#   ../hfsplus/testdata/expected.txt
#   apfs-gpt.raw.gz                        GPT disk, one APFS partition (UDTO / .cdr = raw)
#   apfs-multi.dmg.gz                      UDZO of a bare APFS container: "Plain", "Enc" (encrypted), "Data2"
#   apfs-udzo.dmg.gz / apfs-udbz.dmg.gz    UDIF, zlib / bzip2 chunks
#   apfs-ulfo.dmg.gz                       UDIF, LZFSE chunks (reader reports UNSUPPORTED)
#   hfs-udzo.dmg.gz                        UDIF (zlib) of a GPT disk with one HFS+ partition
#   apfs.sparsebundle.tar.gz               sparsebundle directory (Info.plist + bands/), tarred
#   enc-head.dmg.gz                        first 8 KiB of an AES-128 encrypted UDIF (encrcdsa header)
set -euo pipefail
export TZ=UTC LC_ALL=C
here="$(cd "$(dirname "$0")" && pwd)"
apfsdir="$here/../apfs/testdata"
hfsdir="$here/../hfsplus/testdata"
mkdir -p "$apfsdir" "$hfsdir"
work=$(mktemp -d "${TMPDIR:-/tmp}/adfir-macos-gen.XXXXXX")
mnt="$work/mnt"
mkdir -p "$mnt"
trap 'hdiutil detach "$mnt" -force -quiet 2>/dev/null || true; rm -rf "$work"' EXIT

session='{"type":"user","uuid":"u1","sessionId":"s1","cwd":"/Users/alice/proj","timestamp":"2026-08-30T10:00:01Z","message":{"role":"user","content":"list the files"}}
{"type":"assistant","uuid":"a1","parentUuid":"u1","sessionId":"s1","cwd":"/Users/alice/proj","timestamp":"2026-08-30T10:00:02Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls -la"}}]}}
{"type":"user","uuid":"u2","parentUuid":"a1","sessionId":"s1","cwd":"/Users/alice/proj","timestamp":"2026-08-30T10:00:03Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"total 0"}]},"toolUseResult":"total 0"}'

# Source files built once, outside any image, so expected.txt comes from
# shasum and not from the reader under test.
src="$work/src"
mkdir -p "$src"
printf '%s\n' "$session" > "$src/session.jsonl"
# yes | head ends with SIGPIPE, which pipefail would treat as a failure.
pattern() { yes "$1" | head -c "$2" || true; }
pattern "agentdfir known content line" 300000 > "$src/known.bin"
pattern "agentdfir compressible line" 200000 > "$src/compressed.txt"
printf 'tiny compressed\n' > "$src/small-compressed.txt"

# attach <image>: mounts the only (or the first) volume at $mnt.
attach() { hdiutil attach -mountpoint "$mnt" -nobrowse -owners on "$1" >/dev/null; }
# detach retries: Spotlight or fseventsd may hold the fresh volume briefly.
detach() {
  for _ in 1 2 3 4 5; do hdiutil detach "$mnt" -quiet && return 0; sleep 2; done
  sync
  hdiutil detach "$mnt" -force
}

# populate_small <mountpoint>: the profile the end-to-end tests collect.
populate_small() {
  local h="$1/Users/alice"
  mkdir -p "$h/.claude/projects/-Users-alice-proj"
  cp "$src/session.jsonl" "$h/.claude/projects/-Users-alice-proj/session.jsonl"
  printf '{"model":"synthetic"}\n' > "$h/.claude/settings.json"
  cp "$src/known.bin" "$h/known.bin"
}

# populate <mountpoint> <apfs|hfs>: everything the reader tests look at.
populate() {
  local m=$1 kind=$2 h="$1/Users/alice"
  populate_small "$m"
  mkdir -p "$h/docs/sub" "$m/many"
  printf 'plain notes\n' > "$h/notes.txt"
  xattr -w com.example.zone 'ZoneId=3' "$h/notes.txt"
  # A 6000-byte xattr: APFS stores values over 3804 bytes as a data stream.
  xattr -w com.example.big "$(pattern x 6000)" "$h/notes.txt"
  printf 'nested\n' > "$h/docs/sub/nested.txt"
  ln "$h/notes.txt" "$h/hardlink.txt"
  ln -s docs/sub/nested.txt "$h/link"
  ditto --hfsCompression "$src/compressed.txt" "$h/compressed.txt"
  ditto --hfsCompression "$src/small-compressed.txt" "$h/small-compressed.txt"
  # Enough directory records to give the fs-tree / catalog index nodes.
  for i in $(seq -w 1 600); do printf 'file %s\n' "$i" > "$m/many/f$i"; done
  if [ "$kind" = apfs ]; then
    # A clone shares the original's extents; rewriting 14 bytes in its
    # middle gives it three extents (shared, private, shared).
    cp -c "$h/known.bin" "$h/clone.bin"
    printf 'PATCHED-MIDDLE' | dd of="$h/clone.bin" bs=1 seek=150000 conv=notrunc 2>/dev/null
  else
    # HFS+ allocates contiguously while it can: fill the volume with
    # 4 KiB files (leaving a little room so the journaled catalog can
    # still delete), free every other one, then write a file larger than
    # the remaining contiguous space, so it takes the holes (more than 8
    # extents → extents-overflow B-tree).
    mkdir -p "$m/fill"
    n=$(( $(df -k "$m" | awk 'NR==2{print $4}') / 4 * 85 / 100 ))
    for i in $(seq 1 "$n"); do head -c 4096 /dev/zero > "$m/fill/x$i"; done
    for i in $(seq 1 2 "$n"); do rm -f "$m/fill/x$i"; done
    pattern "fragmented payload line" 409600 > "$h/fragmented.bin"
    rm -rf "$m/fill"
    cp "$h/fragmented.bin" "$work/fragmented.bin"
  fi
  find "$h" -exec touch -h -t 202408301000.00 {} +
}

# ---- bare APFS container, one volume ----
hdiutil create -quiet -size 12m -fs APFS -volname T -layout NONE "$work/apfs.dmg"
attach "$work/apfs.dmg"
populate "$mnt" apfs
detach

# ---- APFS container: volumes "Plain", "Enc" (encrypted), "Data2" ----
# APFS allows one volume per started 512 MiB of container, so this one is
# 1100 MiB. It is built as a sparse image and committed as UDZO (zero
# chunks cost nothing), which the tests read through the DMG reader.
hdiutil create -quiet -size 1100m -fs APFS -volname Plain -layout NONE -type SPARSE "$work/multi.sparseimage"
attach "$work/multi.sparseimage"
populate_small "$mnt"
cdisk=$(diskutil info "$mnt" | awk -F': *' '/APFS Container:/{print $2}')
printf 'throwaway-fixture-passphrase' | diskutil apfs addVolume "$cdisk" APFS Enc -stdinpassphrase -nomount >/dev/null
data2=$(diskutil apfs addVolume "$cdisk" APFS Data2 -nomount | awk '/Disk from APFS operation:/{print $NF}')
mkdir -p "$work/mnt2"
diskutil mount -mountPoint "$work/mnt2" "$data2" >/dev/null
printf 'second volume\n' > "$work/mnt2/second.txt"
sync
diskutil unmount force "$work/mnt2" >/dev/null || true
detach
hdiutil convert -quiet "$work/multi.sparseimage" -format UDZO -o "$work/apfs-multi.dmg"

# ---- bare HFS+ (journaled) and HFSX ----
hdiutil create -quiet -size 6m -fs HFS+ -volname H -layout NONE "$work/hfsplus.dmg"
attach "$work/hfsplus.dmg"
populate "$mnt" hfs
detach
hdiutil create -quiet -size 2m -fs "Case-sensitive HFS+" -volname X -layout NONE "$work/hfsx.dmg"
attach "$work/hfsx.dmg"
populate_small "$mnt"
printf 'upper\n' > "$mnt/Users/alice/CASE.txt"
printf 'lower\n' > "$mnt/Users/alice/case.txt"
detach

# ---- GPT disks for the container formats ----
hdiutil create -quiet -size 8m -fs APFS -volname T "$work/apfs-gpt.dmg"
attach "$work/apfs-gpt.dmg"
populate_small "$mnt"
detach
hdiutil create -quiet -size 4m -fs HFS+ -volname H "$work/hfs-gpt.dmg"
attach "$work/hfs-gpt.dmg"
populate_small "$mnt"
detach
cv() { hdiutil convert -quiet "$1" -format "$2" -o "$3"; }
cv "$work/apfs-gpt.dmg" UDZO "$work/apfs-udzo.dmg"
cv "$work/apfs-gpt.dmg" UDBZ "$work/apfs-udbz.dmg"
cv "$work/apfs-gpt.dmg" ULFO "$work/apfs-ulfo.dmg"
cv "$work/hfs-gpt.dmg" UDZO "$work/hfs-udzo.dmg"
# UDTO (.cdr) is the raw disk; it must equal the UDRW source byte for byte.
cv "$work/apfs-udzo.dmg" UDTO "$work/apfs-gpt.raw"
mv "$work/apfs-gpt.raw.cdr" "$work/apfs-gpt.raw"
cmp "$work/apfs-gpt.raw" "$work/apfs-gpt.dmg"
hdiutil convert -quiet "$work/apfs-gpt.dmg" -format UDSB -imagekey sparse-band-size=2048 -o "$work/apfs.sparsebundle"
printf 'throwaway-fixture-passphrase' | hdiutil create -quiet -size 1m -fs HFS+ -volname E -encryption AES-128 -stdinpass "$work/enc.dmg"
head -c 8192 "$work/enc.dmg" > "$work/enc-head.dmg"

# ---- expected hashes (from the source files) ----
{
  (cd "$src" && shasum -a 256 session.jsonl known.bin compressed.txt small-compressed.txt)
  printf '%s  clone.bin\n' "$( (head -c 150000 "$src/known.bin"; printf 'PATCHED-MIDDLE'; tail -c +150015 "$src/known.bin") | shasum -a 256 | cut -d' ' -f1)"
} > "$apfsdir/expected.txt"
{
  (cd "$src" && shasum -a 256 session.jsonl known.bin compressed.txt small-compressed.txt)
  (cd "$work" && shasum -a 256 fragmented.bin)
} > "$hfsdir/expected.txt"

gz() { gzip -9 -n -c "$1" > "$2"; }
gz "$work/apfs.dmg" "$apfsdir/apfs.img.gz"
gz "$work/hfsplus.dmg" "$hfsdir/hfsplus.img.gz"
gz "$work/hfsx.dmg" "$hfsdir/hfsx.img.gz"
for f in apfs-gpt.raw apfs-multi.dmg apfs-udzo.dmg apfs-udbz.dmg apfs-ulfo.dmg hfs-udzo.dmg enc-head.dmg; do
  gz "$work/$f" "$here/$f.gz"
done
COPYFILE_DISABLE=1 tar -C "$work" -cf - apfs.sparsebundle | gzip -9 -n > "$here/apfs.sparsebundle.tar.gz"
ls -la "$apfsdir" "$hfsdir" "$here"/apfs* "$here"/hfs* "$here"/enc*
