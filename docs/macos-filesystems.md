# macOS filesystems and disk images

`agentdfir collect --image` reads Apple disk images and filesystems in pure
Go, read-only: nothing is mounted, attached, decrypted, replayed or
written. What it cannot read is named, with a reason, in the case notes
(`image_volume_<n>`, `image_volumes_not_read`) and never silently skipped.

```
agentdfir collect --image Mac.dmg --out case.adfir
agentdfir collect --image Backup.sparsebundle --out case.adfir   # the bundle directory
agentdfir collect --image disk.raw --out case.adfir              # GPT with APFS / HFS+ partitions
```

## Coverage

| Layer | Read | Not read (reported) |
|---|---|---|
| UDIF `.dmg` | `koly` trailer, XML plist `resource-fork/blkx` `mish` tables; chunk types raw, zero-fill, ignore, zlib (UDZO), bzip2 (UDBZ); unlisted sectors read as zeros | ADC, LZFSE (ULFO), LZMA (ULMO) chunks → UNSUPPORTED naming the chunk type (the image is not opened, so no sector is guessed); segmented images; UDSP `.sparseimage` → UNSUPPORTED; AES-encrypted images (`encrcdsa` / `cdsaencr`) → ENCRYPTED |
| sparsebundle | `Info.plist` (`band-size`, `size`), `bands/<hex>`; missing bands and short bands read as zeros; every band file is hashed before and after like any segment | encrypted bundles (`token` holds an `encrcdsa` header) → ENCRYPTED; stray files in `bands/` are ignored and listed in `image_meta_bands_ignored` |
| GPT | Apple APFS (`7C3457EF-…`) and HFS+ (`48465300-…`) partitions, named | Apple Partition Map (APM) |
| APFS container | `NXSB`, newest checkpoint with a valid Fletcher-64 checksum in a contiguous descriptor area (older checkpoints and the block-0 copy as fallbacks; skipped ones are listed), container and volume object maps | Fusion containers, APFS version 1, a B-tree checkpoint descriptor area → UNSUPPORTED |
| APFS volumes | every `APSB`; fs-tree inode, directory-record (hashed and plain), xattr (embedded and stream), file-extent, dstream records; extents (clones are shared extents, holes read as zeros); sealed-volume fext tree; nanosecond create/modify/change/access times; owner, group, mode, BSD and internal flags | encrypted volumes (FileVault: `APFS_FS_UNENCRYPTED` clear, or encrypted object-map entries) → listed, UNSUPPORTED with the unlock-and-`--import` route; no key handling |
| APFS layout | one readable volume → the container root; several volumes → one top-level directory per volume, named after it (`Macintosh HD - Data/Users/…`; empty, duplicate or slash-bearing names become `volume-<n>`, `<name>-<n>`, `a_b`) | an encrypted volume's directory is listed; reading it fails UNSUPPORTED |
| APFS snapshots | listed (name, xid, creation time: `apfs.FS.Volumes()`), and readable as `.snapshots/<name>/` at the volume root by resolving the volume object map at the snapshot's xid. A real root entry always wins: the virtual directory takes the first of `.snapshots`, `.apfs-snapshots`, `.apfs-snapshots-2`… that no entry matches (case-insensitively) | — |
| HFS+ / HFSX | volume header, catalog B-tree, extents-overflow B-tree, data forks, resource forks (for decmpfs), xattrs from the attributes B-tree, dates (1904 epoch, GMT), owner/group/mode; case-insensitive lookups on HFS+, exact on HFSX; a stored `/` is presented as `:` (as macOS does) | journal never replayed: a dirty journal (start ≠ end) is reported (`journal: dirty (not replayed)`) and the volume is read as on disk; the two private metadata folders are not listed |
| Hard links | APFS: several directory records naming one inode. HFS+: `hlnk` records resolve to their `iNode<n>` file, directory links (`fdrp`) to `dir_<n>` (best effort) | — |
| Symlinks | listed with their target (`symlink_target`, `ReadLink`), never followed | — |
| Compressed files (`com.apple.decmpfs`) | zlib inline (type 3), zlib in the resource fork (type 4), uncompressed inline (type 1) | LZVN (7/8, what `ditto --hfsCompression` writes today), LZFSE (11/12), LZBITMAP and others: listed with their real size and `compression` type, reading returns UNSUPPORTED |

Inode numbers in the file metadata (`inode`) are unique across the whole
exposed tree: for APFS the volume/snapshot namespace is in bits 56–63 (0
for the first readable volume's live tree) and the raw APFS file id is in
`file_id`. Readers' problems (skipped checkpoints, encrypted volumes, a
dirty journal, malformed records) are copied into the case notes for the
volume.

## Hostile input

Every APFS object read is checked (checksum, type, the object id it was
reached by); a mismatch is damage, returned as an error and counted, never
a panic. B-tree walks are depth- and node-budget-bounded and detect cycles;
the HFS+ leaf chain is loop-guarded. Sizes from the image never drive an
allocation directly: decompression grows with the decoded data and must
produce exactly the declared size, declared sizes are capped by the
compression ratio and the container size, and stream xattrs / forks that
are mostly holes are refused. Per-file and total extraction limits apply as
for every other filesystem.

## Fixtures

All APFS, HFS+, DMG and sparsebundle fixtures are made by Apple's own
tools (`hdiutil`, `diskutil`, `ditto`) on a macOS host by
`internal/diskimage/testdata/gen-macos.sh` (see the `README.md` next to
each fixture set). The encrypted APFS volume is a real FileVault volume
added with `diskutil apfs addVolume -stdinpassphrase`. Damaged variants
(corrupted checksums, a damaged newest checkpoint, a B-tree pointing to
itself, looping HFS+ leaf chains, truncation) are made by mutating those
images in the tests.

Two things are synthetic and labelled so: APFS **snapshot** reading is
tested on a hand-built container (`internal/diskimage/apfs/synth_test.go`),
because creating a snapshot on a disk image needs root (`tmutil` only
snapshots the boot volume); and **zlib decmpfs** decoding is tested on
hand-built headers, because current `ditto` compresses with LZVN.
