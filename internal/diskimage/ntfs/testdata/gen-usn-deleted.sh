#!/usr/bin/env bash
# Regenerates usn-deleted.ntfs.gz (a 4 MiB NTFS volume, no partition table).
#
# Step 1 (docker, ntfs-3g): mkntfs + a FUSE mount build the volume:
#   Users/alice/proj/{keep.txt, kept-big.bin, newcomer.txt} in use,
#   deleted-resident.txt  (resident $DATA, deleted),
#   deleted-big.txt       (non-resident, deleted last: clusters stay free),
#   deleted-overwritten.bin (non-resident, deleted, then the volume is
#                          filled by fill.bin so its clusters are reused),
#   $Extend/$UsnJrnl with a $J stream: a sparse 64 KiB hole + 8 KiB of 0xFF.
# ntfs-3g never writes a USN journal, so
# Step 2 (go test, TestGenerateUSNFixture) overwrites the 0xFF placeholder
# clusters in place with documented USN_RECORD_V2/V3/V4 records (synthetic)
# that reference the volume's real MFT records, then gzips the result.
#
#   ./gen-usn-deleted.sh     # from internal/diskimage/ntfs/testdata
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

docker build -q -t adfir-dimg-gen - >/dev/null <<'DOCKER'
FROM debian:stable-slim
RUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
      ntfs-3g qemu-utils ewf-tools gdisk fdisk attr fuse3 >/dev/null && rm -rf /var/lib/apt/lists/*
DOCKER

docker run --rm --device /dev/fuse --cap-add SYS_ADMIN --security-opt apparmor:unconfined \
  -v "$tmp":/out adfir-dimg-gen bash -eu -c '
work=$(mktemp -d); cd "$work"
truncate -s 4M v.ntfs
mkntfs -q -F -Q -s 512 -c 4096 -L USNTEST v.ntfs >/dev/null 2>&1
mkdir m
ntfs-3g -o streams_interface=windows v.ntfs m
p=m/Users/alice/proj
mkdir -p $p
printf "keep me\n" > $p/keep.txt
yes "kept non-resident line" | head -c 20480 > $p/kept-big.bin || true
printf "victim\n" > $p/victim.txt
rm $p/victim.txt
printf "newcomer\n" > $p/newcomer.txt
# $Extend refuses new names; a file made at the root can be moved in.
touch "m/\$UsnJrnl"
truncate -s 65536 "m/\$UsnJrnl:\$J"
head -c 8192 /dev/zero | tr "\0" "\377" >> "m/\$UsnJrnl:\$J"
mv "m/\$UsnJrnl" "m/\$Extend/"
printf "resident secret\n" > $p/deleted-resident.txt
yes "deleted line kept on free clusters" | head -c 12288 > $p/deleted-big.txt || true
yes "OVERWRITTEN-ORIGINAL" | head -c 12288 > $p/deleted-overwritten.bin || true
touch m/Users/alice/fill.bin
find m/Users -exec touch -h -d "2026-08-30 10:00:00 UTC" {} +
rm $p/deleted-overwritten.bin
yes F | tr -d "\n" > m/Users/alice/fill.bin 2>/dev/null || true   # until ENOSPC
rm $p/deleted-big.txt $p/deleted-resident.txt
umount m
cp v.ntfs /out/usn-deleted.ntfs
'
cd "$here/.."
ADFIR_GEN_USN="$tmp/usn-deleted.ntfs" go test -run TestGenerateUSNFixture -count=1 .
