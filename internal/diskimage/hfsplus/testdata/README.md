# HFS+ fixtures

Made by `../../testdata/gen-macos.sh` with `hdiutil` on macOS (no root):

- `hfsplus.img.gz`: `hdiutil create -size 6m -fs HFS+ -volname H -layout NONE`,
  populated like the APFS volume (hard link, symlink, xattr, LZVN-compressed
  `ditto --hfsCompression` copies, 600 files) plus `fragmented.bin`: the
  volume is filled with 4 KiB files, every other one is deleted and a
  400 KiB file is written into the holes, so it needs the extents-overflow
  B-tree.
- `hfsx.img.gz`: `hdiutil create -size 2m -fs "Case-sensitive HFS+"`, with
  `CASE.txt` and `case.txt` side by side.
- `expected.txt`: SHA-256 from `shasum` on the source files.

The dirty-journal case is made in the test by mutating `hfsplus.img`.
