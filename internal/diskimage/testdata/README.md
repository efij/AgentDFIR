# Disk-image fixtures

## NTFS / container fixtures (`disk*`)

Synthetic content made by `gen.sh` (see the comments there).

## Linux fixtures (`linux-*`, `../xfs/testdata`, `../btrfs/testdata`)

These are made by the real tools. `gen-linux.sh` starts a throwaway privileged
`debian:stable-slim` container and runs `gen-linux-inner.sh` inside it, which writes
every file listed below:

```
./gen-linux.sh        # from this directory; needs docker
```

Tool versions at generation time: xfsprogs 6.13.0, btrfs-progs 6.14, qemu-img
10.0.13, LVM 2.03.31, e2fsprogs from Debian 13.

Shared content (`populate` in the script): `home/alice/.claude/projects/-home-alice-proj/session.jsonl`
(an agent session), `home/alice/.claude/settings.json`, `home/alice/notes.txt`
(SHA-256 `51a8d4dc…f026`), a short and a 308-byte symlink, a 7-level-deep
directory, `data/big.txt` (120000 bytes), `data/frag.bin` (40 × 4 KiB data, 4 KiB
holes → 40 extents), and directories with 5 / 40 / 300 / 2000 entries (XFS
shortform / block / leaf / node forms).

| File | Made by | Notes |
|---|---|---|
| `../xfs/testdata/xfs.img.gz` | `truncate -s 300M; mkfs.xfs -q -p xfs.proto -L adfirxfs` | v5 defaults (crc, finobt, bigtime, nrext64, reflink, rmapbt), **populated without mounting** from a protofile |
| `../xfs/testdata/xfs4.img.gz` | `mkfs.xfs -q -m crc=0 -p xfs.proto` | v4, 256-byte inodes (the long symlink is remote) |
| `../xfs/testdata/xfs.manifest` | coreutils over a read-only loop mount of a copy | `type size sha256\|target mtime path` |
| `../btrfs/testdata/btrfs.img.gz` | `truncate -s 128M; mkfs.btrfs -q -L adfirbtrfs --rootdir broot -u rw:vol1 --compress zlib`, then a loop mount for `btrfs subvolume snapshot -r vol1 snap1`, `btrfs property set zstd compression zstd` + a 54000-byte file, `fallocate -l 65536 data/prealloc.bin` | base content **populated without mounting**; the snapshot, the zstd extent and the prealloc extent need a mount |
| `../btrfs/testdata/btrfs.manifest` | coreutils over a read-only loop mount of a copy | |
| `linux-btrfs.qcow2.gz` | `qemu-img convert -f raw -O qcow2 btrfs.img` | v3 |
| `linux-btrfs-c.qcow2.gz` | `qemu-img convert -f raw -O qcow2 -c btrfs.img` | deflate-compressed clusters |
| `linux-xfs-v2.qcow2.gz` | `qemu-img convert -f raw -O qcow2 -o compat=0.10 xfs.img` | v2 header |
| `linux-backed.qcow2.gz` | `qemu-img create -f qcow2 -b btrfs.qcow2 -F qcow2` | backing file → UNSUPPORTED |
| `linux-zstd-type.qcow2.gz` | `qemu-img create -f qcow2 -o compression_type=zstd … 1M` | zstd compression type → UNSUPPORTED |
| `linux-lvm.img.gz` | `sfdisk` (two 0x8e partitions), `pvcreate`, `vgcreate -s 1M vgadfir`, `lvcreate -L 4M -n root`, `lvcreate -i2 -I64k -L 4M -n striped`, `lvextend -L +2M root` (second, non-adjacent segment), `mkfs.ext4` on root + copy of `home/`, `vgcfgbackup`, then `vgcfgrestore --force` of the backup with `linux-lvm-extra-lvs.txt` appended | **partially synthetic**, see below |

### LVM: what is synthetic

The LVM label, the PV headers, the metadata areas and the metadata text are
written by LVM's own tools. The `root` (linear, two segments, holding an ext4)
and `striped` (two stripes) LVs are real `lvcreate` output. The kernel in the
generating VM has no thin-pool, thin, raid1 or snapshot device-mapper targets,
so `lvcreate` refuses to make those. Their LV sections (`snap` + `snapshot0`,
`mirror` + its `_rmeta`/`_rimage` legs, `pool` + `_tmeta`/`_tdata`, `thin`)
were **written by hand** in `linux-lvm-extra-lvs.txt`, appended to the
`vgcfgbackup` text and written to disk with `vgcfgrestore --force`, which parses
and validates them. Their extents hold no data. They exist only so that the
UNSUPPORTED path is exercised against metadata LVM itself accepted.

Container quirks: the container has no udev, so the script sets
`udev_sync = 0`, `udev_rules = 0` and `verify_udev_operations = 1` in
`lvm.conf`, and it loops each partition by offset instead of using partition
nodes.
