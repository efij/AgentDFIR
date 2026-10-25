# Disk-image test fixtures

`gen.sh` builds the NTFS-based container fixtures (synthetic, in Docker).

`gen-macos.sh` builds the macOS fixtures with Apple's own tools on a macOS
host, without root. It creates every image in a scratch directory, attaches
only those images read-write at a mount point inside that directory to
populate them, and detaches them again. The exact commands are in the
script; in short:

| File | Made by |
|---|---|
| `apfs-gpt.raw.gz` | `hdiutil create -size 8m -fs APFS -volname T` (GPT, UDRW raw), populated, then `hdiutil convert -format UDTO` of the UDZO copy (checked byte-identical with `cmp`) |
| `apfs-udzo.dmg.gz`, `apfs-udbz.dmg.gz`, `apfs-ulfo.dmg.gz` | `hdiutil convert -format UDZO / UDBZ / ULFO` of that disk (zlib, bzip2, LZFSE chunks) |
| `hfs-udzo.dmg.gz` | `hdiutil create -size 4m -fs HFS+ -volname H`, populated, `hdiutil convert -format UDZO` |
| `apfs.sparsebundle.tar.gz` | `hdiutil convert -format UDSB -imagekey sparse-band-size=2048` of the APFS disk (1 MiB bands, several missing), tarred with `COPYFILE_DISABLE=1` |
| `apfs-multi.dmg.gz` | `hdiutil create -size 1100m -fs APFS -volname Plain -layout NONE -type SPARSE`, then `diskutil apfs addVolume <container> APFS Enc -stdinpassphrase` (a throwaway passphrase: a real FileVault volume) and `diskutil apfs addVolume <container> APFS Data2`, populated, `hdiutil convert -format UDZO` |
| `enc-head.dmg.gz` | the first 8 KiB of `hdiutil create -size 1m -fs HFS+ -encryption AES-128 -stdinpass` (the `encrcdsa` header is all the reader looks at) |

Each image holds `Users/alice/.claude/projects/-Users-alice-proj/session.jsonl`
(the same synthetic session as the other fixtures), `settings.json` and
`known.bin`. The fuller APFS / HFS+ test volumes are in
`../apfs/testdata` and `../hfsplus/testdata`.
