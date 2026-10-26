#!/usr/bin/env bash
# Runs inside the throwaway container started by gen-linux.sh; writes the
# fixtures under $PKG (the internal/diskimage directory, mounted).
set -euo pipefail
PKG=${PKG:-/pkg}

apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq xfsprogs btrfs-progs qemu-utils lvm2 thin-provisioning-tools e2fsprogs fdisk >/dev/null
grep -q "udev_sync = 0" /etc/lvm/lvm.conf || cat >> /etc/lvm/lvm.conf <<CONF
activation {
  udev_sync = 0
  udev_rules = 0
  verify_udev_operations = 1
}
devices {
  obtain_device_list_from_udev = 0
}
CONF
work=$(mktemp -d); cd "$work"
T="2026-08-30 10:00:00 UTC"

session="{\"type\":\"user\",\"uuid\":\"u1\",\"sessionId\":\"s1\",\"cwd\":\"/home/alice/proj\",\"timestamp\":\"2026-08-30T10:00:01Z\",\"message\":{\"role\":\"user\",\"content\":\"list the files\"}}
{\"type\":\"assistant\",\"uuid\":\"a1\",\"parentUuid\":\"u1\",\"sessionId\":\"s1\",\"cwd\":\"/home/alice/proj\",\"timestamp\":\"2026-08-30T10:00:02Z\",\"message\":{\"role\":\"assistant\",\"content\":[{\"type\":\"tool_use\",\"id\":\"t1\",\"name\":\"Bash\",\"input\":{\"command\":\"ls -la\"}}]}}"

# populate <dir>: the content every Linux fixture shares.
populate() {
  r=$1
  h=$r/home/alice
  mkdir -p "$h/.claude/projects/-home-alice-proj" "$r/deep/a/b/c/d/e/f" "$r/data" "$r/dirs/small" "$r/dirs/block" "$r/dirs/leaf" "$r/dirs/node"
  printf "%s\n" "$session" > "$h/.claude/projects/-home-alice-proj/session.jsonl"
  printf "{\"model\":\"fixture\"}\n" > "$h/.claude/settings.json"
  printf "AgentDFIR linux filesystem fixture\n" > "$h/notes.txt"
  ln -s notes.txt "$h/notes-link"
  ln -s "/$(printf "very-long-symlink-target-component-%02d/" $(seq 1 8))end" "$h/long-link"
  printf "deep leaf\n" > "$r/deep/a/b/c/d/e/f/leaf.txt"
  for i in $(seq 1 3000); do printf "line %05d of the multi-block text file\n" $i; done > "$r/data/big.txt"
  # frag.bin: 40 x (4 KiB data, 4 KiB hole) -> one extent per data chunk.
  : > "$r/data/frag.bin"
  for i in $(seq 0 39); do printf "%04096d" $i | dd of="$r/data/frag.bin" bs=4096 seek=$((i*2)) conv=notrunc status=none; done
  truncate -s $((80*4096)) "$r/data/frag.bin"
  for i in $(seq 1 5); do printf "s%d\n" $i > "$r/dirs/small/f$i"; done
  for i in $(seq 1 40); do : > "$r/dirs/block/entry-$i"; done
  for i in $(seq 1 300); do : > "$r/dirs/leaf/leaf-directory-entry-$i"; done
  for i in $(seq 1 2000); do : > "$r/dirs/node/node-directory-entry-with-a-long-name-$i"; done
  find "$r" -exec touch -h -d "$T" {} +
  touch -d "2026-08-30 10:05:00 UTC" "$h/.claude/projects/-home-alice-proj/session.jsonl"
}

# manifest <mountpoint> <out>: type size sha256 mtime path, sorted.
manifest() {
  (cd "$1" && find . -mindepth 1 \( -name lost+found -prune \) -o -print | sort | while read -r p; do
    t=$(stat -c %F "$p"); m=$(stat -c %Y "$p")
    case "$t" in
      "regular file"|"regular empty file") echo "f $(stat -c %s "$p") $(sha256sum < "$p" | cut -c1-64) $m ${p#./}";;
      directory) echo "d - - $m ${p#./}";;
      "symbolic link") echo "l - $(readlink "$p") $m ${p#./}";;
    esac
  done) > "$2"
}

# proto <dir> <indent>: an mkfs.xfs protofile body for dir.
proto() {
  local d=$1 ind=$2 e n
  for e in "$d"/* "$d"/.[!.]*; do
    [ -e "$e" ] || [ -L "$e" ] || continue
    n=$(basename "$e")
    if [ -L "$e" ]; then echo "$ind$n l--777 0 0 $(readlink "$e")"
    elif [ -d "$e" ]; then echo "$ind$n d--755 0 0"; proto "$e" "$ind "; echo "$ind\$"
    else echo "$ind$n ---644 0 0 $e"; fi
  done
}

mkdir root; populate root

# ---- XFS v5 (default mkfs: crc, finobt, bigtime, nrext64) ----
{ echo /dev/null; echo "0 0"; echo "d--755 0 0"; proto root " "; echo "\$"; } > xfs.proto
truncate -s 300M xfs.img
mkfs.xfs -q -p xfs.proto -L adfirxfs xfs.img
xfs_db -r -c "sb 0" -c "p versionnum features_incompat features_ro_compat" xfs.img
cp xfs.img m.img; mkdir -p mnt; mount -o loop,ro m.img mnt; manifest mnt xfs.manifest; umount mnt; rm m.img

# ---- XFS v4 (crc=0) ----
truncate -s 300M xfs4.img
mkfs.xfs -q -m crc=0 -p xfs.proto xfs4.img 2>/dev/null

# ---- Btrfs: --rootdir with a subvolume, zlib, then mount for snapshot + zstd + prealloc ----
cp -a root broot; mkdir -p broot/vol1/inner; printf "inside the subvolume\n" > broot/vol1/inner/sub.txt
touch -h -d "$T" broot/vol1 broot/vol1/inner broot/vol1/inner/sub.txt
truncate -s 128M btrfs.img
mkfs.btrfs -q -L adfirbtrfs --rootdir broot -u rw:vol1 --compress zlib btrfs.img
mount -o loop btrfs.img mnt
btrfs subvolume snapshot -r mnt/vol1 mnt/snap1 >/dev/null
mkdir mnt/zstd; btrfs property set mnt/zstd compression zstd
for i in $(seq 1 2000); do printf "zstd compressed line %05d\n" $i; done > mnt/zstd/z.txt
fallocate -l 65536 mnt/data/prealloc.bin
sync; umount mnt
cp btrfs.img m.img; mount -o loop,ro m.img mnt; manifest mnt btrfs.manifest; umount mnt; rm m.img

# ---- QCOW2 wrapping the Btrfs image (plain and deflate-compressed) ----
qemu-img convert -f raw -O qcow2 btrfs.img btrfs.qcow2
qemu-img convert -f raw -O qcow2 -c btrfs.img btrfs-c.qcow2
qemu-img convert -f raw -O qcow2 -o compat=0.10 xfs.img xfs-v2.qcow2
qemu-img create -q -f qcow2 -b btrfs.qcow2 -F qcow2 backed.qcow2
qemu-img create -q -f qcow2 -o compression_type=zstd zstd-type.qcow2 1M

# ---- LVM2: MBR with two 0x8e partitions -> two PVs -> VG "vgadfir" ----
# root: linear, two non-adjacent segments, holds an ext4 with the profile.
# striped: two stripes across both PVs (made by lvcreate -i2).
# The kernel in the generating VM has no thin/raid/snapshot dm targets, so
# lvcreate refuses those LV types. They are added to the metadata text
# (linux-lvm-extra-lvs.txt) and written back by LVM's own vgcfgrestore,
# which validates the result; their extents hold no data.
truncate -s 40M lvm.img
printf "label: dos\nstart=2048, size=36864, type=8e\nstart=38912, type=8e\n" | sfdisk -q lvm.img
# No udev in the container, so no partition nodes: loop each partition by offset.
losetup -D
A=$(losetup -f --show -o $((2048*512)) --sizelimit $((36864*512)) lvm.img)
B=$(losetup -f --show -o $((38912*512)) lvm.img)
pvcreate -q $A $B
vgcreate -q -s 1M vgadfir $A $B
lvcreate -q -y -L 4M -n root vgadfir $A
lvcreate -q -y -i2 -I64k -L 4M -n striped vgadfir
lvextend -q -L +2M vgadfir/root $A
mkfs.ext4 -q -F /dev/vgadfir/root
mkdir -p lmnt; mount /dev/vgadfir/root lmnt; cp -a root/home lmnt/; umount lmnt
vgchange -q -an vgadfir
vgcfgbackup -q -f vg.txt vgadfir
{ head -n -3 vg.txt; cat $PKG/testdata/linux-lvm-extra-lvs.txt; printf "\t}\n\n}\n"; } > vg-edited.txt
vgcfgrestore -q --force -f vg-edited.txt vgadfir
lvs -a -o lv_name,segtype,seg_start_pe,seg_size_pe,devices vgadfir
losetup -D

for f in xfs.img xfs4.img btrfs.img; do gzip -9 -c $f > $f.gz; done
cp xfs.img.gz xfs.manifest $PKG/xfs/testdata/
cp xfs4.img.gz $PKG/xfs/testdata/xfs4.img.gz
cp btrfs.img.gz btrfs.manifest $PKG/btrfs/testdata/
for f in btrfs.qcow2 btrfs-c.qcow2 xfs-v2.qcow2 backed.qcow2 zstd-type.qcow2 lvm.img; do gzip -9 -c $f > $PKG/testdata/linux-$f.gz; done
ls -la $PKG/xfs/testdata $PKG/btrfs/testdata $PKG/testdata/linux-*
