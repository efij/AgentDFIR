#!/usr/bin/env bash
# Regenerates the Linux filesystem / container fixtures (XFS, Btrfs, QCOW2,
# LVM2) with the real tools: mkfs.xfs, mkfs.btrfs, qemu-img, pvcreate /
# vgcreate / lvcreate. See README.md next to this script for what each
# fixture holds and which parts are made by mounting.
#
# The tests never run this script; they read the committed, gzipped
# outputs. Requires docker. The container is privileged because the Btrfs
# snapshot / zstd extents and the LVM volumes need loop devices and
# device-mapper; the XFS image and the Btrfs base image are populated
# without mounting (mkfs.xfs -p protofile, mkfs.btrfs --rootdir).
#
#   ./gen-linux.sh        # from internal/diskimage/testdata
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
pkg="$(cd "$here/.." && pwd)"

docker run --rm --privileged -v "$pkg":/pkg debian:stable-slim bash /pkg/testdata/gen-linux-inner.sh
