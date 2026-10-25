# NTFS reader fixtures

| File | Origin | What it exercises |
|---|---|---|
| `usn-deleted.ntfs.gz` | **Real ntfs-3g volume, synthetic journal content.** Made by `gen-usn-deleted.sh`: mkntfs and an ntfs-3g FUSE mount create the volume, the files, the deletions and a `$Extend\$UsnJrnl:$J` stream (sparse 64 KiB hole + 8 KiB placeholder). ntfs-3g does not write a USN journal, so the 8 KiB of placeholder clusters are then overwritten in place by `TestGenerateUSNFixture` with hand-built USN_RECORD_V2/V3/V4 records (layouts as documented for `FSCTL_READ_USN_JOURNAL`) that reference the volume's real MFT records, plus 24 bytes of deliberate garbage. | USN: sparse-hole skipping, V2/V3 decoding, V4 counted as UNSUPPORTED, resync after garbage, parent-path resolution with a stale sequence number (`(reused-mft-entry)`), a record on a second 4 KiB page. Deleted records: resident content, non-resident content on free clusters, non-resident content whose clusters were reallocated (`overwritten-or-reallocated`). |

The 6 MiB NTFS volume inside `../../testdata/disk-gpt.raw.gz` (made by `../../testdata/gen.sh`)
is also used: it has no journal (absent path) and one resident deleted file.

The Volume Shadow Copy fixture lives with its reader in `../vss/testdata/`.

Both fixtures are tiny (4–6 MiB volumes, gzipped to well under 2 MB). The tests never run docker.
