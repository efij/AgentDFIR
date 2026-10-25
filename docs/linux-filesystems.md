# Linux filesystems and containers: XFS, Btrfs, QCOW2, LVM2

`agentdfir collect --image` reads XFS and Btrfs volumes, QCOW2 virtual disks and LVM2 linear
logical volumes in pure Go. Nothing is mounted, activated or executed, and the image is opened
read-only. Every reader limits its allocations and loops, checks for cycles, and returns typed
errors. Anything a reader does not understand is reported as **UNSUPPORTED** with a reason in the
volume notes. It is never skipped silently.

The layers stack the same way they do for other images: a QCOW2 container can hold an MBR/GPT
disk, a partition can be an LVM2 physical volume, and a linear LV can hold an XFS, Btrfs or ext4
filesystem.

## Coverage

| Format | Read | Reported, not decoded | UNSUPPORTED (with reason) |
|---|---|---|---|
| **XFS v5** (CRC) | superblock; every AG's superblock copy, AGF and AGI (magic + CRC32C); inodes located directly from the inode number (AG, AG block, slot); dinode v3 incl. `nrext64` extent counters, `bigtime` and creation time; data forks: local, extent list, B+tree (depth, bounds, ownership and cycle checks); directories: shortform, block, leaf, node (every data block below the 32 GiB leaf offset is scanned linearly); inline and remote symlinks (never followed); holes and unwritten extents read as zeros; reflinked files as plain extents | CRC32C mismatches on the superblock, AG headers, inodes, directory, bmap and symlink blocks are counted (`crc_errors`) and listed in the volume notes. The structure is still used if its magic and owner are right. A dirty log is ignored, and the volume is read as it is on disk. A `needsrepair` flag is noted | realtime-device files (listed, reads refused); `metadir`, `zoned` and unknown incompatible features (volume refused) |
| **XFS v4** | the same, with dinode v1/v2, v4 directory and bmap headers and the `ftype` feature bit | no CRCs exist on v4 | v4 without version-2 directories |
| **Btrfs** (single device) | primary superblock, plus mirrors at 64 MiB / 256 GiB when the primary's checksum is wrong (the newest valid mirror is used and the fallback is noted); `sys_chunk_array` bootstrap; chunk tree (SINGLE and DUP profiles; DUP reads the first copy); root tree; the top-level fs tree (id 5) and every subvolume and snapshot; `INODE_ITEM`, `INODE_REF`, `DIR_INDEX` (`DIR_ITEM` as fallback), `EXTENT_DATA`: inline, regular, preallocated (zeros), holes (zeros); zlib-compressed extents (inline and regular) | crc32c and sha256 tree-block checksums are verified, and mismatches are counted (`csum_errors`) and noted. xxhash64 / blake2b checksums are noted as not verified. Data checksums (csum tree) are not verified. A log tree is noted and not replayed. Subvolumes with zero references (being deleted) are noted | multi-device filesystems; RAID0/1/10/5/6/1C3/1C4 chunks (named); lzo and zstd extents (the file is listed and opening it fails); encrypted/encoded extents; `extent-tree-v2`, `raid-stripe-tree` and unknown incompatible features |
| **QCOW2** | v2 and v3 headers; L1/L2 cluster map; unallocated and zero clusters read as zeros; deflate-compressed clusters; refcounts are ignored (only writers need them) | the `dirty` and `corrupt` header flags and internal snapshots (counted; the active layer is read) go into the image metadata notes | backing files (the backing file's name is reported); AES/LUKS encryption (ENCRYPTED); external data files; extended L2 entries (subclusters); `zstd` compression type; QCOW v1 |
| **LVM2** | PV label (sectors 0–3, checksum), PV header data/metadata area lists, metadata area header (magic, checksum), the circular metadata text buffer (including wrap-around), the text format; **linear** LVs (`striped` segments with `stripe_count = 1`, one or more segments, segments on different PVs of the same image allowed). Each LV becomes a volume that the filesystem probe runs on | PV volumes are listed with status `LVM-PV` and point at their LVs. Hidden component LVs (raid images/metadata, pool data/metadata, snapshot exception headers) are counted in the partition-table notes. The newest metadata (highest seqno) across PVs wins. PVs the metadata names but the image lacks are noted | thin pools, thin LVs, snapshots (the copy-on-write store is listed under its name as the snapshot), raid*/mirror, striped over several devices, any other segment type, LVs touching a PV that is not in the image. Each of these is listed by `vg/lv` name with the reason. A PV whose metadata cannot be read falls back to the signature table (UNSUPPORTED, with the activation route) |

### Btrfs subvolume convention

The filesystem root shown is always the **top-level subvolume (id 5)**, even when another
subvolume is the default (`default_subvolume` in the root's `Sys()` metadata, plus a note).
Every other subvolume and snapshot appears where its directory entry sits, which is exactly what
a mount of `subvolid=5` shows. Its root directory carries `subvolume_id`, `subvolume_readonly`,
`subvolume_created` and, for snapshots, `snapshot_parent_uuid`. Inode numbers repeat across
subvolumes, so `Sys()["inode"]` is the subvolume-local inode number, while the directory identity
used for loop detection is `subvolume_id << 40 | inode`. A snapshot's files are read like any
other files. Unchanged files are byte-identical to their originals in the source subvolume.

### Volume numbering

LV volumes are numbered from 1001 upward (`partition_index` in `image-provenance.jsonl`), with
scheme `lvm` and name `vg/lv`. The `partition_offset` of an LV is the disk offset of its first
segment. A multi-segment LV lists every disk range in its `segments`.

## Fixture origin

Every fixture was made by the real tools inside a throwaway `debian:stable-slim` container (xfsprogs
6.13, btrfs-progs 6.14, qemu-img 10.0, LVM 2.03.31). The exact commands are in
`internal/diskimage/testdata/gen-linux-inner.sh`, and `internal/diskimage/testdata/README.md`
describes the fixtures.

- XFS v5 and v4: `mkfs.xfs -p protofile`, populated without mounting.
- Btrfs: `mkfs.btrfs --rootdir … -u rw:vol1 --compress zlib`, populated without mounting. A
  loop mount then added the read-only snapshot, the zstd file and the `fallocate`d file,
  because mkfs cannot make those.
- QCOW2: `qemu-img convert` (plain, `-c` deflate, `compat=0.10` for v2), `qemu-img create -b`
  (backing file) and `-o compression_type=zstd`.
- LVM2: `pvcreate`/`vgcreate`/`lvcreate` made the linear and striped LVs on two partitions of
  one disk. The generating VM's kernel has no thin, raid or snapshot device-mapper targets, so
  `lvcreate` refuses those types. They were added to the metadata text and written back by LVM's
  own `vgcfgrestore`, which validates the result. Those LVs' extents hold no data. **This part
  is partially synthetic**, and the README says so.

Expected file lists, sizes, SHA-256 hashes, link targets and mtimes (`*.manifest`) were taken with
coreutils from a read-only mount of a copy of each image. The tests compare whole trees against
those manifests. Damaged variants (bad CRCs, truncation, cyclic B-trees and directory entries,
broken LVM checksums, a missing PV) are built by mutation in the tests. Each reader has `Fuzz*`
targets.
