# APFS fixtures

Made by `../../testdata/gen-macos.sh` with `hdiutil` on macOS (no root):

- `apfs.img.gz`: `hdiutil create -size 12m -fs APFS -volname T -layout NONE`
  (a bare container), attached read-write in the script's scratch directory
  and populated: the agent profile, `known.bin` (300 000 bytes), a hard link
  (`hardlink.txt` → `notes.txt`), a symlink (`link` → `docs/sub/nested.txt`),
  an embedded xattr (`com.example.zone`) and a 5 999-byte stream xattr
  (`com.example.big`), a clone (`cp -c known.bin clone.bin`, then 14 bytes
  rewritten in the middle, giving three extents), `ditto --hfsCompression`
  copies (LZVN, the UNSUPPORTED path) and 600 files in `many/` (fs-tree index
  nodes). Times set with `touch -t 202408301000.00`.
- `expected.txt`: SHA-256 of the regular files, computed by `shasum` from the
  source files, not by the reader.

Synthetic (hand-built, see `synth_test.go`): the snapshot container. A
snapshot cannot be created on a disk image without root.
