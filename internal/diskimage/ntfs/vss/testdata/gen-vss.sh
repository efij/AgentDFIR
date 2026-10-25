#!/usr/bin/env bash
# Regenerates vss-synthetic.ntfs.gz (a 3 MiB NTFS volume, no partition table).
#
# Step 1 (docker, ntfs-3g): mkntfs + a FUSE mount make the volume with
#   Users/alice/report.txt (16 KiB, "CURRENT" text) and notes.txt (8 KiB),
#   and a shadow-copy store file in System Volume Information, named like
#   Windows names it ({guid}{3808876b-...}), filled with a marker pattern.
# A real shadow copy cannot be produced on a non-Windows host, so
# Step 2 (go test, TestGenerateVSSFixture) writes a SYNTHETIC store, built
# by hand from the libvshadow format documentation, into that file's
# clusters and the VSS volume header at offset 0x1e00 (see README.md).
#
#   ./gen-vss.sh     # from internal/diskimage/ntfs/vss/testdata
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
truncate -s 3M v.ntfs
mkntfs -q -F -Q -s 512 -c 4096 -L VSSTEST v.ntfs >/dev/null 2>&1
mkdir m
ntfs-3g v.ntfs m
mkdir -p m/Users/alice "m/System Volume Information"
for i in $(seq 1 512); do printf "CURRENT report %04d of 512 lines\n" $i; done | head -c 16384 > m/Users/alice/report.txt
for i in $(seq 1 256); do printf "CURRENT notes %04d of 256 rows\n" $i; done | head -c 8192 > m/Users/alice/notes.txt
yes "VSS-STORE-AREA!" | head -c 262144 > "m/System Volume Information/{6a3e1b07-5b2c-4d33-9f00-0123456789ab}{3808876b-c176-4e48-b7ae-04046e6cc752}" || true
find m/Users -exec touch -h -d "2026-08-30 10:00:00 UTC" {} +
umount m
cp v.ntfs /out/vss-base.ntfs
'
cd "$here/.."
ADFIR_GEN_VSS="$tmp/vss-base.ntfs" go test -run TestGenerateVSSFixture -count=1 .
