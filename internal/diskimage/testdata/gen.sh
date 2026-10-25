#!/usr/bin/env bash
# Regenerates the synthetic disk-image fixtures in this directory.
#
# Everything here is synthetic: a tiny NTFS volume holding a fake home
# directory with a made-up agent session, wrapped in a partition table and
# then in every container format the reader supports. The tests never run
# this script; they read the committed, gzipped outputs.
#
# Requires docker. FUSE is used inside the container to populate the NTFS
# volume with ntfs-3g, so the container runs with /dev/fuse and SYS_ADMIN.
#
#   ./gen.sh            # from internal/diskimage/testdata
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"

docker build -q -t adfir-dimg-gen - >/dev/null <<'EOF'
FROM debian:stable-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      ntfs-3g qemu-utils ewf-tools gdisk fdisk attr fuse3 >/dev/null && rm -rf /var/lib/apt/lists/*
EOF

docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
  -v "$here":/out adfir-dimg-gen bash -euo pipefail -c '
work=$(mktemp -d)
cd "$work"

session='"'"'{"type":"user","uuid":"u1","sessionId":"s1","cwd":"/Users/alice/proj","timestamp":"2026-08-30T10:00:01Z","message":{"role":"user","content":"list the files"}}
{"type":"assistant","uuid":"a1","parentUuid":"u1","sessionId":"s1","cwd":"/Users/alice/proj","timestamp":"2026-08-30T10:00:02Z","message":{"role":"assistant","content":[{"type":"tool_use","id":"t1","name":"Bash","input":{"command":"ls -la"}}]}}
{"type":"user","uuid":"u2","parentUuid":"a1","sessionId":"s1","cwd":"/Users/alice/proj","timestamp":"2026-08-30T10:00:03Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"t1","content":"total 0"}]},"toolUseResult":"total 0"}'"'"'

# populate <mountpoint> <home-parent> <user>
populate() {
  m=$1; parent=$2; u=$3
  h="$m/$parent/$u"
  mkdir -p "$h/.claude/projects/-Users-$u-proj" "$h/compressed" "$h/links" "$h/Documents"
  printf "%s\n" "$session" > "$h/.claude/projects/-Users-$u-proj/session.jsonl"
  printf "{\"model\":\"synthetic\"}\n" > "$h/.claude/settings.json"
  printf "plain notes\n" > "$h/notes.txt"
  # Alternate data stream on notes.txt (listed as metadata, never a file).
  setfattr -n user.zone -v "ZoneId=3" "$h/notes.txt"
  # Non-resident file with a recognizable pattern.
  for i in $(seq 1 2000); do printf "line %05d of the non-resident file\n" $i; done > "$h/Documents/big.txt"
  # Sparse file: 1 MiB logical, 4 KiB of data in the middle.
  truncate -s 1048576 "$h/Documents/sparse.bin"
  printf "SPARSEDATA" | dd of="$h/Documents/sparse.bin" bs=1 seek=524288 conv=notrunc status=none
  # LZNT1-compressed file (compression attribute set on the directory first).
  setfattr -h -v 0x00000800 -n system.ntfs_attrib_be "$h/compressed"
  for i in $(seq 1 3000); do printf "compressible text block %d\n" $((i % 7)); done > "$h/compressed/comp.txt"
  # Many hard links with long names push the target record into an
  # $ATTRIBUTE_LIST.
  printf "hard link target\n" > "$h/links/target.txt"
  for i in $(seq 1 40); do ln "$h/links/target.txt" "$h/links/a-rather-long-hard-link-name-to-overflow-the-mft-record-$i.txt"; done
  # A deleted file (its MFT record stays, flagged not-in-use).
  printf "gone\n" > "$h/deleted.txt"; rm "$h/deleted.txt"
  # Fixed timestamps for the tests.
  find "$h" -exec touch -h -d "2026-08-30 10:00:00 UTC" {} +
  touch -d "2026-08-30 10:05:00 UTC" "$h/.claude/projects/-Users-$u-proj/session.jsonl"
}

mkntfs_img() { # file sizeMiB
  truncate -s ${2}M "$1"
  mkntfs -q -F -Q -s 512 -c 4096 -L ADFIRTEST "$1" >/dev/null
}

# ---- GPT disk, one NTFS partition (Windows-style home) ----
mkntfs_img part.ntfs 6
mkdir -p mnt
ntfs-3g -o compression,streams_interface=xattr part.ntfs mnt
populate mnt Users alice
umount mnt
truncate -s 8M disk-gpt.raw
sgdisk -n 1:2048:+6M -t 1:0700 -c 1:data disk-gpt.raw >/dev/null
dd if=part.ntfs of=disk-gpt.raw bs=512 seek=2048 conv=notrunc status=none

# ---- MBR disk: primary (empty) + extended with a logical NTFS (Linux-style home) ----
mkntfs_img logical.ntfs 4
ntfs-3g -o streams_interface=xattr logical.ntfs mnt
populate mnt home bob
umount mnt
truncate -s 8M disk-mbr.raw
printf "label: dos\nstart=2048, size=2048, type=83\nstart=4096, size=12288, type=5\nstart=6144, size=8192, type=7\n" | sfdisk -q disk-mbr.raw >/dev/null
dd if=logical.ntfs of=disk-mbr.raw bs=512 seek=6144 conv=notrunc status=none

# ---- containers of the GPT disk ----
qemu-img convert -q -f raw -O vpc -o subformat=fixed disk-gpt.raw disk-fixed.vhd
qemu-img convert -q -f raw -O vpc -o subformat=dynamic disk-gpt.raw disk-dynamic.vhd
qemu-img convert -q -f raw -O vhdx disk-gpt.raw disk.vhdx
qemu-img convert -q -f raw -O vmdk -o subformat=monolithicSparse disk-gpt.raw disk-sparse.vmdk
qemu-img convert -q -f raw -O vmdk -o subformat=streamOptimized disk-gpt.raw disk-stream.vmdk
qemu-img convert -q -f raw -O vmdk -o subformat=monolithicFlat disk-gpt.raw disk-flat.vmdk
ewfacquire -q -u -d sha1 -t disk -c deflate:best -f encase6 -S 1GiB -C case -D synthetic -E 1 -e examiner -N none -m fixed -M logical disk-gpt.raw >/dev/null
# Uncompressed, split into ~1.4 MiB segments: disk-split.E01 … .E06
ewfacquire -q -u -d sha1 -t disk-split -c none -f encase6 -S 1MiB -C case -D synthetic -E 1 -e examiner -N none -m fixed -M logical disk-gpt.raw >/dev/null

# ---- split raw ----
split -b 3M -d -a 3 --numeric-suffixes=1 disk-gpt.raw disk-gpt.raw.
split -b 3M -a 2 disk-gpt.raw disk-gpt-alpha.raw.

rm -f /out/*.gz
for f in disk-gpt.raw disk-mbr.raw disk-fixed.vhd disk-dynamic.vhd disk.vhdx disk-sparse.vmdk disk-stream.vmdk disk-flat.vmdk disk-flat-flat.vmdk disk.E01 disk-split.E* disk-gpt.raw.0* disk-gpt-alpha.raw.a*; do
  gzip -9 -n -c "$f" > "/out/$f.gz"
done
ls -la /out
'
