# Disk images: `collect --image`

```
agentdfir collect --image <path> [--out <dir>] [--case-id …] [--operator …] [--authorization …]
                  [--max-file-mb <n>] [--sign <key> | --no-sign] [--skip-image-verify]
```

`--image` reads a forensic disk image directly, without mounting it, and builds the same
sealed `.adfir` package `collect --import` builds from a triage tree. Everything is pure Go;
no libewf, no Sleuth Kit, no loop device, no FUSE. Nothing on the image is executed.

## What happens

1. The image is opened read-only and identified by its **magic bytes**, never its extension.
   Split raw (`.001/.002…`, `.aa/.ab…`) and E01 segments (`.E01…E99`, `.EAA…`) are found next
   to the first file. Sibling segments and VMDK extents must be regular files in the same
   directory; symlinks are refused.
2. Every segment file is SHA-256 hashed **before** anything else.
3. For E01, the stored acquisition MD5 and SHA-1 (`hash` / `digest` sections) are checked
   against a full re-read of the media: `match`, `mismatch`, or `absent`. `--skip-image-verify`
   skips the re-read and records `not verified`.
4. The partition table is read (GPT, or MBR with extended/logical partitions; no table means one
   whole-disk volume). Every volume is probed against the filesystem registry.
5. On each readable filesystem, user profiles holding a known AI agent product are discovered
   (the same product list and config-presence test `collect --import` uses), and the products'
   collector manifests (all platforms) are resolved against them. **Only those candidate files**
   are copied into a private `0700` staging directory, with their original mtime/atime set.
6. The existing import pipeline runs over the staging tree and seals the package; staging is
   removed afterwards.
7. The image is closed and **hashed again**. `unchanged` / `CHANGED` is written to the case
   notes and to the sealed, hash-chained `collection.jsonl` (`image_rehash` event). A changed
   image makes the command exit 1.

The package additionally holds a sealed **`image-provenance.jsonl`** artifact: one line per
candidate file with the image path, every segment's SHA-256, container type, partition
scheme/index/offset/type, filesystem type, inode (MFT record number on NTFS), original path,
size, SHA-256 of the extracted content, mtime/atime/ctime/btime in UTC, alternate data stream
names, the E01 verification result, and — for a file that could not be extracted — why.

Volumes that could not be read (encrypted, unsupported, unrecognized, corrupt) are printed in
the summary and written to the case notes (`image_volume_<n>`, `image_volumes_not_read`). They
are never skipped silently.

Exit codes follow `collect --import`: 0 sealed; 1 unreadable image, no agent evidence found,
or a partial/changed acquisition (sealed with what was taken); 2 the path is not a readable file.

## Coverage

| Layer | Read | Not read / reported UNSUPPORTED |
|---|---|---|
| raw / dd / img | yes | — |
| split raw | `.000/.001…`, `.aa/.ab…` | gaps in the series end it (a missing middle segment shortens the image; the segment list is recorded) |
| E01 (EWF-E01, EnCase 1–7 / libewf) | zlib and stored chunks, Adler-32 on stored chunks, `table`/`table2`, split segments, `header`/`header2` case fields, MD5 + SHA-1 verification | Ex01/Lx01 (EWF2), L01 logical evidence, SMART `.s01` |
| VHD | fixed, dynamic | differencing (parent name reported) |
| VHDX | BAT, payload blocks, metadata, 512/4096 logical sectors | non-empty log ("dirty log"), differencing (parent path reported), partially-present blocks |
| VMDK | monolithicSparse, streamOptimized (compressed grains, footer GD), monolithicFlat / twoGbMax* via descriptor, multi-extent descriptors (FLAT/SPARSE/ZERO extents next to the descriptor) | delta/snapshot disks (parent hint reported), ESX COWD / SESparse, extents outside the descriptor's directory |
| QCOW2 | v2/v3, L1/L2 cluster map, deflate-compressed clusters, zero clusters ([details](linux-filesystems.md)) | backing files (name reported), encryption (ENCRYPTED), external data files, extended L2, zstd compression type |
| DMG (UDIF), sparsebundle | raw / zero / zlib / bzip2 chunks; sparsebundle bands — see [macos-filesystems.md](macos-filesystems.md) | ADC / LZFSE / LZMA chunks, UDSP sparse images (UNSUPPORTED), encrypted images (ENCRYPTED) |
| other containers | — | VDI and compressed files (gzip/xz/zip/7z…) are named and refused |
| Partitions | MBR (incl. extended/logical, loop-guarded), GPT (header + entry CRC-32, backup compared; primary damaged → backup used), LVM2 linear logical volumes ([details](linux-filesystems.md)) | APM (Apple Partition Map), LVM2 thin/snapshot/raid/mirror/multi-device striped LVs (listed UNSUPPORTED with the reason), dynamic disks (LDM), Storage Spaces |
| NTFS | boot sector, `$MFT` via its own data runs, update-sequence fixups, `$STANDARD_INFORMATION` times, `$FILE_NAME` (Win32/POSIX over DOS), resident and non-resident `$DATA`, sparse runs, `$ATTRIBUTE_LIST`, LZNT1 compression, hard links | EFS-encrypted file content (per file, UNSUPPORTED), reparse points (recorded, not followed), `$I30` index slack, `$LogFile`/`$UsnJrnl` parsing, deleted files (skipped and counted), Volume Shadow Copies (presence of the store is noted, copies are not parsed) |
| ext2 / ext3 / ext4 | superblock (rev 0 and dynamic), 32/64-byte group descriptors, flex_bg, meta_bg, extent trees and legacy block maps, inline_data, htree directories (read linearly), sparse and large files, nanosecond and creation times; symlinks reported, never followed | journal never replayed (a volume that needs recovery is read as on disk and flagged), fscrypt-encrypted files (listed, UNSUPPORTED), deleted entries (skipped and counted), external journal devices and the compression/dirdata/unknown incompatible features (volume UNSUPPORTED) |
| FAT12 / FAT16 / FAT32, exFAT | BPB and FAT type by cluster count, VFAT long names (checksum-verified), exFAT entry sets with checksums, NoFatChain, ValidDataLength; FAT times as local wall-clock (`tz` = `local-unknown`), exFAT times with their recorded UTC offset | deleted entries (skipped and counted), exFAT up-case table and allocation bitmap, TexFAT; a FAT/exFAT/ext volume the reader cannot open is named by signature and reported UNSUPPORTED |
| BitLocker, LUKS | — | ENCRYPTED, with the unlock-then-mount route |
| XFS, Btrfs | see [linux-filesystems.md](linux-filesystems.md) | realtime XFS files, Btrfs lzo/zstd extents, multi-device/RAID Btrfs (UNSUPPORTED with the reason) |
| APFS, HFS+ / HFSX | see [macos-filesystems.md](macos-filesystems.md) | encrypted APFS volumes (FileVault), LZVN/LZFSE-compressed files: listed, UNSUPPORTED |
| ReFS, ZFS | — | UNSUPPORTED by signature, with the mount route |

### The mount-and-`--import` route

For anything listed as UNSUPPORTED or ENCRYPTED: mount (or unlock and mount) the volume
**read-only** with its native tools — e.g. `hdiutil attach -readonly` on macOS,
`cryptsetup open --readonly` / `dislocker` / `mount -o ro,norecovery` on Linux, or attach the VHD
read-only on Windows — and run `agentdfir collect --import <mountpoint>`. The package then
records `import-tree` mode; note the image hash and mount steps in `--authorization` or the case
notes yourself.

## NTFS details

* The directory tree is built from each `$FILE_NAME`'s parent reference; the `$I30` B-trees are
  not used. A directory is linked under exactly one parent, so the tree cannot loop. Parent
  loops and records naming themselves as parent are detected, counted and reported.
* In-use records whose parent is gone appear under `$OrphanFiles/<record>-<name>`.
* Names are matched case-insensitively (Win32 semantics), exact match first.
* Names that cannot be one path element on every host (`/`, `\`, `:`, NUL or other control
  characters) are refused and recorded, escaped, as problems.
* `FileInfo.Sys()` returns `map[string]any` with `inode`, `mtime`, `atime`, `ctime` (MFT
  change), `btime` (all `time.Time`, UTC), `fs` = `"ntfs"`, plus `ads`, `attributes`,
  `compressed`, `sparse`, `encrypted`, `reparse_point` when relevant.
* Alternate data streams are listed in metadata only, never extracted as files.

## NTFS artifacts: USN journal, deleted records, shadow copies

Sealed into the case for every NTFS volume `collect --image` reads (they sit beside the
import tree, not inside it, so they are preserved but not parsed as agent sessions):

| Logical path | Default | Content |
|---|---|---|
| `image/vol<N>/ntfs/usn.jsonl` | on (when the volume has a journal) | one line per `$Extend\$UsnJrnl:$J` record |
| `image/vol<N>/ntfs/deleted.jsonl` | on | one line per deleted MFT record that still has a name |
| `image/vol<N>/ntfs/recovered/<mft_ref>_<name>` | `--recover-deleted` | recoverable deleted content, labelled `RECOVERED_UNVERIFIED` |
| `vss/<n>-<creation time>/…` (inside the import tree) | `--include-vss` | agent evidence extracted from each shadow copy; provenance lines carry `vss_snapshot` |

A summary of each (record counts, skipped bytes, UNSUPPORTED snapshots) is in the volume's
`image_volume_<N>` case note. The case is still refused when no volume holds agent evidence:
these artifacts accompany agent evidence, they do not replace it.

One byte and file budget (`--max-file-mb` per file; 8 GiB and 200,000 files in total) covers
everything taken from one image, in this order: live agent evidence, then shadow-copy
extraction (at most 64 snapshots per volume, each given only what is left), then `usn.jsonl`,
recovered files and `deleted.jsonl`. Whatever the budget cuts is named in the volume note
(`TRUNCATED`, `not written`, or the list of snapshots NOT examined).

**USN journal.** `$J` is read through its data runs; sparse runs (the deallocated head of a
wrapped journal) are skipped by run, never scanned. USN_RECORD_V2 and V3 are decoded: file
and parent reference (record + sequence), USN, timestamp (UTC), reason flags, source info,
security id, file attributes and name, with flag names decoded (undocumented bits are kept as
hex). V4 range-tracking records are counted and emitted with `status: UNSUPPORTED`. Every
record's length, alignment, version and name bounds are checked; anything implausible is
skipped 8 bytes at a time until the scanner resynchronizes, and the skipped bytes and resync
count are reported. `path` is resolved from the parent reference against the current MFT:
`path_status` is `resolved`, `unresolved` (parent record not in use), or `reused-mft-entry`
when the parent record's sequence number no longer matches — the path then starts with
`(reused-mft-entry)` instead of naming the record's current occupant. A path reflects the
volume at acquisition time, not at the time of the journal entry.

**Deleted records.** MFT base records with IN_USE clear but a valid `FILE` signature and
update-sequence fixups (torn records are counted as corrupt, not listed). Each line has the
name, parent path (same resolution as above), size, `$STANDARD_INFORMATION` and `$FILE_NAME`
times, attributes, ADS names, whether `$DATA` is resident, and `content_state`:
`resident` or `clusters-unallocated` (recoverable), `overwritten-or-reallocated` (some
cluster is allocated again in `$Bitmap`; content is never returned), `no-data`,
`sparse-only`, or `UNSUPPORTED` with a reason (EFS, broken run list, unreadable `$Bitmap`).
Recovered content is labelled `RECOVERED_UNVERIFIED`: free clusters can have been rewritten
and freed again after the delete, so it is a lead, not proof. Records whose extension records
were reused are reported with a problem rather than stitched together.

**Volume Shadow Copies** (`internal/diskimage/ntfs/vss`). Read-only, per the libvshadow format
documentation: VSS volume header at 0x1e00, catalog (store information and store location
entries), store header, block list and current bitmap. Each snapshot is presented as a
read-only volume: a 16 KiB block described in its store comes from the store, otherwise from
the next newer store, otherwise from the current volume; overlay descriptors replace only the
sectors their bitmap names; forwarders redirect to another block in the newer layers. The
NTFS reader then opens that volume unchanged. UNSUPPORTED (with the reason, nothing
extracted): header or block version other than 1, unknown descriptor flags, offsets outside
the volume, a snapshot larger than the volume, broken or looping chains, and any read that
would have to pass through a newer store that is itself unsupported. Block range lists and
the previous bitmap are not used; bitmaps are counted only, never used to zero blocks.

**Fixture origin.** The USN/deleted fixture (`internal/diskimage/ntfs/testdata/`) is a real
ntfs-3g volume whose journal content is synthetic (ntfs-3g does not write one). The VSS
fixture (`internal/diskimage/ntfs/vss/testdata/`) is a real ntfs-3g volume carrying a
**synthetic, hand-built store**: it shows the reader matches our reading of the documented
layout, not that it matches every store Windows writes. Each directory's README says how it
was made.

## Hostile-input bounds

* Every size read from an image is checked against the file/volume size before it drives an
  allocation or loop (overflow-safe comparisons); E01 tables, VHD/VHDX BATs, VMDK grain
  directories and NTFS run lists are capped.
* VMDK grain-table cache is bounded by bytes (4 MiB per extent).
* Discovery and extraction dedupe directories by inode and cap directory entries visited
  (2,000,000), candidate files (200,000), per-file bytes (`--max-file-mb`, default 512 MiB) and
  total bytes (8 GiB). Hitting a cap stops the work with a recorded problem.
* Staging paths are checked by the extractor itself (authoritative for every filesystem reader):
  elements containing `\`, `:`, control characters, `..`, trailing dots/spaces, or Windows
  device names (`CON`, `NUL`, `COM1`…) are refused; the joined path must stay inside staging;
  files are created with `O_EXCL` and symlinks inside staging are never followed.
* Fuzz tests cover NTFS record parsing, whole-volume walks, USN record parsing and `$J` scanning,
  the USN/deleted readers on mutated volumes, the VSS catalog/block-list parser, E01 table
  parsing and E01 open/read.

## Fixtures

All test images are **synthetic**: a 6 MiB NTFS volume with a made-up home directory and a
three-line session, wrapped in GPT/MBR and converted to every supported container. They are
produced by `internal/diskimage/testdata/gen.sh` (docker: ntfs-3g, qemu-img, ewfacquire,
sgdisk/sfdisk) and committed gzipped. The tests never run docker.
