#!/usr/bin/env bash
# Regenerates the synthetic ext2/ext4 fixtures in this directory.
# Run from the repository root (no loop mounts, no privileges needed):
#
#   docker run --rm -v "$PWD":/w -w /w debian:stable-slim \
#     bash internal/diskimage/ext4/testdata/gen.sh
#
# Outputs (all gzipped raw filesystem images):
#   ext4.img.gz         ext4, 64bit, extents, flex_bg, 256-byte inodes,
#                       journal, a fragmented file (extent tree with an index
#                       level), a sparse file, fast + slow symlinks, a long
#                       name, deleted entries and a directory flagged
#                       fscrypt-encrypted.
#   ext2.img.gz         ext2, 128-byte inodes, legacy block maps with single,
#                       double and triple indirect blocks.
#   ext4-inline.img.gz  ext4 with inline_data + meta_bg (no resize_inode) and
#                       the needs_recovery flag set.
#   expected.txt        "sha256  path" for the regular files, computed by
#                       coreutils from the source tree, not by the reader.
set -eu
[ -n "${TRACE:-}" ] && set -x
export TZ=UTC LC_ALL=C
apt-get update -qq >/dev/null && apt-get install -y -qq e2fsprogs coreutils gzip >/dev/null

OUT=/w/internal/diskimage/ext4/testdata
W=$(mktemp -d)
S=$W/src
mkdir -p "$S/home/alice/.claude/projects/p" "$S/docs/sub" "$S/secret"

printf '{"type":"user","message":"hello","ts":"2024-03-15T12:34:56Z"}\n{"type":"assistant","message":"hi"}\n' \
  > "$S/home/alice/.claude/projects/p/session.jsonl"
yes "agentdfir known content line" | head -c 300000 > "$S/known.bin"
echo "small" > "$S/docs/small.txt"
echo "nested" > "$S/docs/sub/nested.txt"
echo "encrypted in real life" > "$S/secret/hidden.txt"
LONG=$(printf 'n%.0s' $(seq 1 240)).txt
echo "long name" > "$S/docs/$LONG"
# Sparse: 8 KiB of data, a hole, then 4 KiB more data at 1 MiB.
yes "head" | head -c 8192 > "$S/sparse.bin"
yes "tail" | head -c 4096 | dd of="$S/sparse.bin" bs=1 seek=1048576 conv=notrunc status=none
ln -s docs/small.txt "$S/link-fast"
ln -s "docs/$LONG" "$S/link-slow"
ln -s /etc/passwd "$S/link-abs"
find "$S" -exec touch -h -d '2024-03-15 12:34:56' {} +

# ---- ext4 main image ----
rm -f "$W/ext4.img"
mkfs.ext4 -q -F -b 1024 -I 256 -O 64bit,extent,flex_bg,huge_file -J size=1 \
  -L adfir-ext4 -U 11111111-2222-3333-4444-555555555555 -E lazy_itable_init=0 \
  -d "$S" "$W/ext4.img" 6M
# Fragment: 40 one-block files, delete every other one, then write a file
# that has to fill the holes (the extent tree grows an index level).
for i in $(seq -w 1 40); do head -c 1000 /dev/zero | tr '\0' a > "$W/f$i"; done
CMDS=$W/cmds
: > "$CMDS"
echo "mkdir frag" >> "$CMDS"
for i in $(seq -w 1 40); do echo "write $W/f$i frag/f$i" >> "$CMDS"; done
for i in $(seq -w 1 2 40); do echo "rm frag/f$i" >> "$CMDS"; done
debugfs -w -f "$CMDS" "$W/ext4.img" >/dev/null 2>&1
yes "fragmented payload" | head -c 30000 > "$W/fragmented.bin"
debugfs -w -R "write $W/fragmented.bin fragmented.bin" "$W/ext4.img" >/dev/null 2>&1
# Mark /secret as fscrypt-encrypted (EXT4_ENCRYPT_FL 0x800 | EXTENTS_FL).
debugfs -w -R "set_inode_field secret flags 0x80800" "$W/ext4.img" >/dev/null 2>&1
debugfs -R "ex fragmented.bin" "$W/ext4.img" 2>/dev/null | head -8 || true

# ---- ext2 block-map image (1 KiB blocks) ----
S2=$W/src2
mkdir -p "$S2/home/alice/.claude/projects/p"
cp "$S/home/alice/.claude/projects/p/session.jsonl" "$S2/home/alice/.claude/projects/p/"
cp "$S/known.bin" "$S2/known.bin"        # 300000 bytes: double indirect
# Triple indirect: data beyond 12+256+65536 KiB, almost all of it a hole.
yes "deep" | head -c 2048 > "$S2/deep.bin"
yes "far" | head -c 3000 | dd of="$S2/deep.bin" bs=1024 seek=70000 conv=notrunc status=none
find "$S2" -exec touch -h -d '2024-03-15 12:34:56' {} +
rm -f "$W/ext2.img"
mkfs.ext2 -q -F -b 1024 -I 128 -L adfir-ext2 -d "$S2" "$W/ext2.img" 2M

# ---- ext4 inline_data + meta_bg image ----
S3=$W/src3
mkdir -p "$S3/home/alice/.claude/projects/p" "$S3/tiny"
cp "$S/home/alice/.claude/projects/p/session.jsonl" "$S3/home/alice/.claude/projects/p/"
echo "inline file" > "$S3/tiny/a.txt"
echo "b" > "$S3/tiny/b.txt"
cp "$S/known.bin" "$S3/known.bin"
find "$S3" -exec touch -h -d '2024-03-15 12:34:56' {} +
rm -f "$W/inline.img"
mkfs.ext4 -q -F -b 1024 -I 256 -O inline_data,meta_bg,^resize_inode,^has_journal \
  -L adfir-inline -d "$S3" "$W/inline.img" 3M
debugfs -w -R "feature needs_recovery" "$W/inline.img" >/dev/null 2>&1

gzip -9n -c "$W/ext4.img" > "$OUT/ext4.img.gz"
gzip -9n -c "$W/ext2.img" > "$OUT/ext2.img.gz"
gzip -9n -c "$W/inline.img" > "$OUT/ext4-inline.img.gz"
{
  (cd "$S" && find . -type f | sort | sed 's|^\./||' | while read -r f; do sha256sum "$f"; done)
  echo "$(sha256sum < "$W/fragmented.bin" | cut -d' ' -f1)  fragmented.bin"
  echo "$(sha256sum < "$S2/deep.bin" | cut -d' ' -f1)  ext2:deep.bin"
  echo "$(sha256sum < "$S3/tiny/a.txt" | cut -d' ' -f1)  inline:tiny/a.txt"
} > "$OUT/expected.txt"
ls -l "$OUT"
