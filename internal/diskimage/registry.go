package diskimage

import (
	"bytes"
	"errors"
	"io"
	"io/fs"

	"github.com/efij/AgentDFIR/v4/internal/diskimage/apfs"
	"github.com/efij/AgentDFIR/v4/internal/diskimage/ext4"
	"github.com/efij/AgentDFIR/v4/internal/diskimage/fat"
	"github.com/efij/AgentDFIR/v4/internal/diskimage/hfsplus"
	"github.com/efij/AgentDFIR/v4/internal/diskimage/ntfs"
)

// Filesystem is one registered read-only filesystem reader.
type Filesystem struct {
	Name  string
	Probe func(r io.ReaderAt, size int64) bool
	Open  func(r io.ReaderAt, size int64) (fs.FS, error)
}

// filesystems is the reader registry, probed in order. Adding a reader is
// one line: a package exposing Probe and Open with these signatures.
var filesystems = []Filesystem{
	{"ntfs", ntfs.Probe, ntfs.Open},
	{"ext4", ext4.Probe, ext4.Open},
	{"fat", fat.Probe, fat.Open},
	{"apfs", apfs.Probe, apfs.Open},
	{"hfsplus", hfsplus.Probe, hfsplus.Open},
}

// Register adds a reader at the end of the registry (for readers that
// live outside this package's import graph, and for tests).
func Register(f Filesystem) { filesystems = append(filesystems, f) }

// Unrecognized filesystems: known by signature, not read. Each carries the
// documented workaround — mount read-only with the platform's own tools,
// then `agentdfir collect --import <mountpoint>`.
type signature struct {
	name   string
	match  func(head []byte) bool
	reason string
}

const mountWorkaround = "mount the volume read-only with its native tools and run `agentdfir collect --import <mountpoint>`"

var signatures = []signature{
	{"bitlocker", func(h []byte) bool { return at(h, 3, "-FVE-FS-") }, "BitLocker-encrypted volume; unlock it (manage-bde -unlock / dislocker) with the recovery key, then " + mountWorkaround},
	{"luks", func(h []byte) bool { return at(h, 0, "LUKS\xba\xbe") || at(h, 0, "SKUL\xba\xbe") }, "LUKS-encrypted volume; open it (cryptsetup open --readonly) with the passphrase, then " + mountWorkaround},
	{"apfs", func(h []byte) bool { return at(h, 32, "NXSB") }, "APFS container (FileVault-encrypted if the user enabled it); on macOS attach the image read-only (hdiutil attach -readonly -nomount, then diskutil apfs unlockVolume / mount -o rdonly), then " + mountWorkaround},
	{"hfs+", func(h []byte) bool { return at(h, 1024, "H+") || at(h, 1024, "HX") }, "HFS+ volume; " + mountWorkaround},
	{"hfs", func(h []byte) bool { return at(h, 1024, "BD") }, "classic HFS volume; " + mountWorkaround},
	{"refs", func(h []byte) bool { return at(h, 3, "ReFS\x00\x00\x00\x00") }, "ReFS volume; attach the image read-only on Windows Server / Windows 11 Pro, then " + mountWorkaround},
	{"xfs", func(h []byte) bool { return at(h, 0, "XFSB") }, "XFS volume; mount -o ro,norecovery, then " + mountWorkaround},
	{"btrfs", func(h []byte) bool { return at(h, 0x10040, "_BHRfS_M") }, "Btrfs volume; mount -o ro,rescue=nologreplay, then " + mountWorkaround},
	{"lvm2", func(h []byte) bool { return at(h, 0x218, "LVM2 001") || at(h, 0x018, "LVM2 001") }, "LVM2 physical volume; activate it read-only (vgchange -ay --readonly) and image or mount the logical volume, then " + mountWorkaround},
	{"zfs", func(h []byte) bool {
		return len(h) > 0x20000 && bytes.Contains(h[0x20000:], []byte{0x0c, 0xb1, 0xba, 0x00, 0x00, 0x00, 0x00, 0x00})
	}, "ZFS pool member; import it read-only (zpool import -o readonly=on), then " + mountWorkaround},
	{"ext", func(h []byte) bool { return len(h) > 1081 && h[1080] == 0x53 && h[1081] == 0xEF }, "ext2/3/4 volume the built-in reader could not open (unusual feature set or damage); " + mountWorkaround},
	{"exfat", func(h []byte) bool { return at(h, 3, "EXFAT   ") }, "exFAT volume the built-in reader could not open (unusual feature set or damage); " + mountWorkaround},
	{"fat", func(h []byte) bool { return at(h, 54, "FAT12") || at(h, 54, "FAT16") || at(h, 82, "FAT32") }, "FAT volume the built-in reader could not open (unusual feature set or damage); " + mountWorkaround},
	{"swap", func(h []byte) bool { return at(h, 4086, "SWAPSPACE2") || at(h, 4086, "SWAP-SPACE") }, "swap space; holds no filesystem"},
}

func at(h []byte, off int, sig string) bool {
	return len(h) >= off+len(sig) && string(h[off:off+len(sig)]) == sig
}

// FSResult is what OpenFS found on one volume.
type FSResult struct {
	Type   string // registered reader name, or the recognized-but-unsupported name
	FS     fs.FS  // nil unless a reader opened the volume
	Reason string // why FS is nil
	Err    error  // typed: ErrUnsupported / ErrEncrypted / ErrCorrupt / ErrUnknown
}

// OpenFS probes the volume with every registered reader, then with the
// unsupported-signature table. It never returns a nil result: an
// unrecognized volume is reported as such.
func OpenFS(r io.ReaderAt, size int64) FSResult {
	for _, f := range filesystems {
		if !f.Probe(r, size) {
			continue
		}
		fsys, err := f.Open(r, size)
		if err != nil {
			kind := ErrCorrupt
			if errors.Is(err, ntfs.ErrUnsupported) || errors.Is(err, ErrUnsupported) || errors.Is(err, errors.ErrUnsupported) {
				kind = ErrUnsupported
			}
			return FSResult{Type: f.Name, Reason: err.Error(), Err: &Error{Kind: kind, Format: f.Name, Reason: err.Error()}}
		}
		return FSResult{Type: f.Name, FS: fsys}
	}
	head := make([]byte, 0x40000)
	n, _ := r.ReadAt(head, 0)
	head = head[:n]
	for _, s := range signatures {
		if s.reason == "" || len(head) == 0 || !s.match(head) {
			continue
		}
		kind := ErrUnsupported
		if s.name == "bitlocker" || s.name == "luks" {
			kind = ErrEncrypted
		}
		return FSResult{Type: s.name, Reason: s.reason, Err: &Error{Kind: kind, Format: s.name, Reason: s.reason}}
	}
	reason := "no recognized filesystem signature (unformatted, unknown, or encrypted without a header, e.g. VeraCrypt); " + mountWorkaround
	if allZero(head) {
		reason = "volume starts with zeros: unformatted or wiped"
	}
	return FSResult{Type: "unknown", Reason: reason, Err: &Error{Kind: ErrUnknown, Format: "filesystem", Reason: reason}}
}
