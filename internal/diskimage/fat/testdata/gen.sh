#!/usr/bin/env bash
# Regenerates the synthetic FAT12/16/32 and exFAT fixtures in this directory.
# Run from the repository root. FAT images are populated with mtools (no
# mount). exFAT has no offline populate tool, so that part loop-mounts the
# image inside the container and needs --privileged:
#
#   docker run --rm --privileged -v "$PWD":/w -w /w debian:stable-slim \
#     /w/internal/diskimage/fat/testdata/gen.sh
#
# Outputs (gzipped raw filesystem images):
#   fat12.img.gz  fat16.img.gz  fat32.img.gz  exfat.img.gz
#   expected.txt  "sha256  path" computed by coreutils from the source tree.
# Every image holds home/alice/.claude/projects/p/session.jsonl, known.bin,
# a VFAT long name, a deleted file and a fragmented file.
set -eu
[ -n "${TRACE:-}" ] && set -x
export TZ=UTC LC_ALL=C MTOOLS_SKIP_CHECK=1
apt-get update -qq >/dev/null
apt-get install -y -qq dosfstools mtools exfatprogs coreutils gzip mount >/dev/null

OUT=/w/internal/diskimage/fat/testdata
W=$(mktemp -d)
S=$W/src
LONG="A very long file name that exceeds eight dot three.txt"
mkdir -p "$S/home/alice/.claude/projects/p" "$S/docs"
printf '{"type":"user","message":"hello","ts":"2024-03-15T12:34:56Z"}\n{"type":"assistant","message":"hi"}\n' \
  > "$S/home/alice/.claude/projects/p/session.jsonl"
yes "agentdfir known content line" | head -c 300000 > "$S/known.bin"
echo "long name" > "$S/docs/$LONG"
echo "short" > "$S/docs/SHORT.TXT"
yes "fragmented payload" | head -c 30000 > "$W/fragmented.bin"
for i in $(seq -w 1 20); do head -c 400 /dev/zero | tr '\0' a > "$W/f$i.dat"; done
echo "gone" > "$W/deleted.txt"
find "$S" "$W"/*.bin "$W"/*.dat "$W/deleted.txt" -exec touch -d '2024-03-15 12:34:56' {} +

populate_fat() { # image
  img=$1
  for d in home home/alice home/alice/.claude home/alice/.claude/projects home/alice/.claude/projects/p docs frag; do
    mmd -i "$img" "::/$d"
  done
  mcopy -m -i "$img" "$S/home/alice/.claude/projects/p/session.jsonl" ::/home/alice/.claude/projects/p/
  mcopy -m -i "$img" "$S/known.bin" ::/
  mcopy -m -i "$img" "$S/docs/$LONG" "$S/docs/SHORT.TXT" ::/docs/
  mcopy -m -i "$img" "$W/deleted.txt" ::/
  for i in $(seq -w 1 20); do mcopy -m -i "$img" "$W/f$i.dat" ::/frag/; done
  # Fill the volume except 50 clusters so the allocator has to wrap into the
  # holes left by the deleted frag files (FAT32's FSInfo hint otherwise
  # keeps new files contiguous at the end).
  free=$(mdir -i "$img" ::/ | grep 'bytes free' | tr -d ' ' | sed 's/bytesfree//')
  head -c $((free - 50 * 512)) /dev/zero > "$W/filler.bin"
  mcopy -i "$img" "$W/filler.bin" ::/
  for i in $(seq -w 1 2 20); do mdel -i "$img" "::/frag/f$i.dat"; done
  mdel -i "$img" ::/deleted.txt
  mcopy -m -i "$img" "$W/fragmented.bin" ::/
  mdel -i "$img" ::/filler.bin
}

rm -f "$W"/*.img
mkfs.fat -C -F 12 -s 1 -n ADFIRFAT12 -i 12121212 "$W/fat12.img" 1440 >/dev/null
mkfs.fat -C -F 16 -s 1 -n ADFIRFAT16 -i 16161616 "$W/fat16.img" 4096 >/dev/null
mkfs.fat -C -F 32 -s 1 -n ADFIRFAT32 -i 32323232 "$W/fat32.img" 34000 >/dev/null
for t in 12 16 32; do populate_fat "$W/fat$t.img"; done
mdir -i "$W/fat32.img" -/ ::/ | head -40

# exFAT: loop mount (privileged container only).
truncate -s 4M "$W/exfat.img"
mkfs.exfat -c 4K -L ADFIREXFAT "$W/exfat.img" >/dev/null
mkdir -p "$W/mnt"
mount -o loop,time_offset=0 "$W/exfat.img" "$W/mnt"
M=$W/mnt
mkdir -p "$M/home/alice/.claude/projects/p" "$M/docs" "$M/frag"
cp "$S/home/alice/.claude/projects/p/session.jsonl" "$M/home/alice/.claude/projects/p/"
cp "$S/known.bin" "$M/"
cp "$S/docs/$LONG" "$S/docs/SHORT.TXT" "$M/docs/"
cp "$W/deleted.txt" "$M/"
for i in $(seq -w 1 20); do cp "$W/f$i.dat" "$M/frag/"; sync; done
free=$(df -B1 --output=avail "$M" | tail -1 | tr -d ' ')
head -c $((free - 4 * 4096)) /dev/zero > "$M/filler.bin"
sync
for i in $(seq -w 1 2 20); do rm "$M/frag/f$i.dat"; done
rm "$M/deleted.txt"
sync
cp "$W/fragmented.bin" "$M/"
sync
rm "$M/filler.bin"
find "$M" -exec touch -d '2024-03-15 12:34:56' {} +
sync
umount "$M"

for t in fat12 fat16 fat32 exfat; do gzip -9n -c "$W/$t.img" > "$OUT/$t.img.gz"; done
{
  (cd "$S" && find . -type f | sort | sed 's|^\./||' | while read -r f; do sha256sum "$f"; done)
  echo "$(sha256sum < "$W/fragmented.bin" | cut -d' ' -f1)  fragmented.bin"
} > "$OUT/expected.txt"
ls -l "$OUT"
