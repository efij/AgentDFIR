# Volume Shadow Copy fixture — SYNTHETIC

`vss-synthetic.ntfs.gz` is a 3 MiB NTFS volume. The **volume** is real: mkntfs and an
ntfs-3g FUSE mount (`gen-vss.sh`, docker) create `Users/alice/report.txt`, `notes.txt` and a
store file in `System Volume Information` named the way Windows names it
(`{guid}{3808876b-c176-4e48-b7ae-04046e6cc752}`).

The **shadow-copy store is synthetic.** Windows is the only producer of real VSS stores and
none can be made on this project's build hosts, so `TestGenerateVSSFixture` writes one by hand
from the libvshadow format documentation (see `../build_test.go`): the volume header at offset
0x1e00, one catalog block, and for each of two snapshots a store header, a block list, the
preserved 16 KiB data blocks and a current bitmap, all inside the store file's clusters.

* Snapshot 1 (2026-08-01 09:00 UTC): `report.txt` reads "VERSION-1 …".
* Snapshot 2 (2026-08-15 09:00 UTC): `report.txt` reads "VERSION-2 …", and an overlay
  descriptor replaces only the first sector of `notes.txt`.
* Snapshot 1 has no copy of `notes.txt`, so it reads through store 2.
* The catalog lists the newer store first, to check ordering by creation time.

The fixture therefore proves that the reader matches **our reading** of the documented
layout. It does not prove compatibility with every store Windows writes; anything outside
that reading is reported UNSUPPORTED (see `docs/disk-images.md`).
