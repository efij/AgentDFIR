// Package diskimage opens forensic disk images read-only and exposes the
// volumes and filesystems inside them. Everything is pure Go: no libewf,
// no loop mounts, nothing executed.
//
// Layers:
//
//	container  raw / split raw / E01 / VHD / VHDX / VMDK  → one io.ReaderAt (logical disk)
//	partition  MBR (+ extended) / GPT / none              → volumes (offset + size)
//	filesystem registry (NTFS here; ext4, FAT plug in)     → io/fs.FS
//
// Inputs are hostile. Every size read from an image is bounded before it
// drives an allocation or a loop, and every failure is a typed *Error, so
// the caller can report "encrypted", "unsupported" and "corrupt"
// distinctly instead of silently skipping a volume.
package diskimage

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Error kinds. Use errors.Is(err, diskimage.ErrUnsupported) and friends.
var (
	ErrUnsupported = errors.New("unsupported")
	ErrEncrypted   = errors.New("encrypted")
	ErrCorrupt     = errors.New("corrupt")
	ErrUnknown     = errors.New("unrecognized format")
)

// Error is a typed failure: what kind, which format, and why.
type Error struct {
	Kind   error  // one of the Err* sentinels above
	Format string // e.g. "ewf", "vhdx", "gpt", "ntfs"
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s: %s", e.Format, strings.ToUpper(e.Kind.Error()), e.Reason)
}

// Is matches the sentinel kind.
func (e *Error) Is(target error) bool { return target == e.Kind }

func unsupported(format, reason string, args ...any) error {
	return &Error{Kind: ErrUnsupported, Format: format, Reason: fmt.Sprintf(reason, args...)}
}

func corrupt(format, reason string, args ...any) error {
	return &Error{Kind: ErrCorrupt, Format: format, Reason: fmt.Sprintf(reason, args...)}
}

// Container formats reported in Image.Format.
const (
	FormatRaw        = "raw"
	FormatSplitRaw   = "split-raw"
	FormatEWF        = "ewf"
	FormatVHDFixed   = "vhd-fixed"
	FormatVHDDynamic = "vhd-dynamic"
	FormatVHDX       = "vhdx"
	FormatVMDK       = "vmdk"
)

// maxSegments bounds how many files one image may span.
const maxSegments = 4096

// Image is an opened disk image: the logical disk as an io.ReaderAt.
type Image struct {
	r        io.ReaderAt
	size     int64
	Format   string
	Segments []string          // every file the image is read from, in order
	Meta     map[string]string // container metadata (EWF case fields, VMDK create type …)
	closers  []io.Closer
	ewf      *ewfImage
}

// ReadAt reads the logical disk. Reads past the end return io.EOF.
func (im *Image) ReadAt(p []byte, off int64) (int, error) {
	if off < 0 {
		return 0, errors.New("negative offset")
	}
	if off >= im.size {
		return 0, io.EOF
	}
	want := len(p)
	if int64(want) > im.size-off {
		p = p[:im.size-off]
	}
	n, err := im.r.ReadAt(p, off)
	if err == nil && n < want {
		err = io.EOF
	}
	return n, err
}

// Size is the logical disk size in bytes.
func (im *Image) Size() int64 { return im.size }

// Close releases every segment file.
func (im *Image) Close() error {
	var first error
	for _, c := range im.closers {
		if err := c.Close(); err != nil && first == nil {
			first = err
		}
	}
	im.closers = nil
	return first
}

// Open sniffs path by its magic bytes (never its extension) and opens the
// container read-only. Split raw and EWF segment siblings are found next
// to path; VMDK extents are resolved relative to the descriptor.
func Open(path string) (*Image, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	head := make([]byte, 4096)
	n, _ := io.ReadFull(f, head)
	head = head[:n]
	var tail []byte
	if fi.Size() >= 512 {
		tail = make([]byte, 512)
		if _, err := f.ReadAt(tail, fi.Size()-512); err != nil {
			tail = nil
		}
	}
	kind := sniff(head, tail)
	switch kind {
	case "ewf":
		f.Close()
		return openEWF(path)
	case "ewf2":
		f.Close()
		return nil, unsupported("ewf", "EWF2 (Ex01/Lx01) segment files are not supported; convert to E01 (ewfexport -f encase6) or raw")
	case "lvf":
		f.Close()
		return nil, unsupported("ewf", "L01 logical evidence files hold files, not a disk; export the files and use collect --import")
	case "vhdx":
		return openVHDX(f, fi.Size(), path)
	case "vhd":
		return openVHD(f, fi.Size(), path)
	case "vmdk-sparse":
		return openVMDKSparseFile(f, fi.Size(), path)
	case "vmdk-descriptor":
		f.Close()
		return openVMDKDescriptor(path)
	case "vmdk-cowd", "vmdk-sesparse":
		f.Close()
		return nil, unsupported("vmdk", "ESX %s extents are not supported; convert with qemu-img convert -O raw", strings.TrimPrefix(kind, "vmdk-"))
	case "qcow":
		f.Close()
		return nil, unsupported("qcow2", "QCOW images are not supported; convert with qemu-img convert -O raw")
	case "vdi":
		f.Close()
		return nil, unsupported("vdi", "VirtualBox VDI images are not supported; convert with qemu-img convert -O raw")
	case "dmg":
		f.Close()
		return nil, unsupported("dmg", "Apple disk images are not supported; convert to raw (hdiutil convert -format UDTO) first")
	case "gzip", "xz", "bzip2", "zstd", "zip", "7z":
		f.Close()
		return nil, unsupported(kind, "compressed file, not a disk image; decompress it first")
	}
	f.Close()
	return openRaw(path)
}

// sniff classifies a file by its first bytes (and last sector, for VHD).
func sniff(head, tail []byte) string {
	has := func(off int, sig string) bool {
		return len(head) >= off+len(sig) && string(head[off:off+len(sig)]) == sig
	}
	switch {
	case has(0, "EVF\x09\x0d\x0a\xff\x00"):
		return "ewf"
	case has(0, "EVF2\x0d\x0a\x81\x00"), has(0, "LEF2\x0d\x0a\x81\x00"):
		return "ewf2"
	case has(0, "LVF\x09\x0d\x0a\xff\x00"):
		return "lvf"
	case has(0, "vhdxfile"):
		return "vhdx"
	case has(0, "KDMV"):
		return "vmdk-sparse"
	case has(0, "COWD"):
		return "vmdk-cowd"
	case len(head) >= 8 && bytes.Equal(head[:8], []byte{0xbe, 0xba, 0xfe, 0xca, 0, 0, 0, 0}):
		return "vmdk-sesparse"
	case has(0, "# Disk DescriptorFile"), isVMDKDescriptorText(head):
		return "vmdk-descriptor"
	case has(0, "QFI\xfb"):
		return "qcow"
	case has(64, "\x7f\x10\xda\xbe"):
		return "vdi"
	case has(0, "\x1f\x8b"):
		return "gzip"
	case has(0, "\xfd7zXZ\x00"):
		return "xz"
	case has(0, "BZh"):
		return "bzip2"
	case has(0, "\x28\xb5\x2f\xfd"):
		return "zstd"
	case has(0, "PK\x03\x04"):
		return "zip"
	case has(0, "7z\xbc\xaf\x27\x1c"):
		return "7z"
	}
	if len(tail) == 512 {
		if string(tail[:8]) == "conectix" {
			return "vhd"
		}
		if string(tail[:4]) == "koly" {
			return "dmg"
		}
	}
	if len(tail) >= 511 && string(tail[1:9]) == "conectix" { // 511-byte footer variant
		return "vhd"
	}
	if has(0, "conectix") { // dynamic disks carry a footer copy at offset 0
		return "vhd"
	}
	return "raw"
}

func isVMDKDescriptorText(head []byte) bool {
	s := string(head)
	return strings.Contains(s, "createType=") && strings.Contains(s, "# Extent description") ||
		strings.HasPrefix(strings.TrimLeft(s, " \t\r\n"), "version=") && strings.Contains(s, "createType=")
}

// sameDirFile resolves an extent/segment name relative to the image's
// directory and refuses anything that would leave it, and anything that
// is not a plain regular file there (symlinks included).
func sameDirFile(dir, name string) (string, error) {
	if name == "" || filepath.IsAbs(name) || strings.ContainsAny(name, "/\\:\x00") || name == "." || name == ".." || !filepath.IsLocal(name) {
		return "", unsupported("vmdk", "extent %q is outside the image directory; only extents next to the descriptor are read", name)
	}
	p := filepath.Join(dir, name)
	if fi, err := os.Lstat(p); err == nil && !fi.Mode().IsRegular() {
		return "", unsupported("vmdk", "extent %q is a symlink or not a regular file; not followed", name)
	}
	return p, nil
}

// openRegular opens a sibling file (segment, extent) that the image
// itself names. It must be a regular file, not a symlink, and the opened
// descriptor must be the same file the Lstat saw, so nothing can be
// swapped in between the check and the open.
func openRegular(p string) (*os.File, error) {
	before, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if !before.Mode().IsRegular() {
		return nil, corrupt("image", "%s is a symlink or not a regular file; not followed", filepath.Base(p))
	}
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, corrupt("image", "%s changed between check and open; not read", filepath.Base(p))
	}
	return f, nil
}

// multiReader concatenates fixed-size parts into one io.ReaderAt.
type multiReader struct {
	parts []part
	size  int64
}

type part struct {
	r     io.ReaderAt
	start int64
	size  int64
}

func (m *multiReader) ReadAt(p []byte, off int64) (int, error) {
	total := 0
	for len(p) > 0 {
		if off >= m.size {
			return total, io.EOF
		}
		// Find the part holding off (parts are few; linear is fine).
		var pt *part
		for i := range m.parts {
			if off >= m.parts[i].start && off < m.parts[i].start+m.parts[i].size {
				pt = &m.parts[i]
				break
			}
		}
		if pt == nil {
			return total, io.EOF
		}
		n := len(p)
		if rem := pt.start + pt.size - off; int64(n) > rem {
			n = int(rem)
		}
		got, err := pt.r.ReadAt(p[:n], off-pt.start)
		total += got
		if got < n {
			if err == nil || err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return total, err
		}
		p = p[n:]
		off += int64(n)
	}
	return total, nil
}

// zeroReader reads as zeros (VMDK ZERO extents).
type zeroReader struct{}

func (zeroReader) ReadAt(p []byte, off int64) (int, error) {
	clear(p)
	return len(p), nil
}
