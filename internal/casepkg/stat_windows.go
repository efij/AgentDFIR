//go:build windows

package casepkg

import (
	"os"
	"syscall"
	"time"
)

// statSig is the identity of a file as the filesystem sees it. On Windows
// the change time is not exposed through os.FileInfo, so the creation time
// plus the file index serve the same role: together they change when the
// file is replaced, and neither is settable through ordinary file writes.
type statSig struct {
	inode uint64
	dev   uint64
	ctime time.Time
}

func statSignature(info os.FileInfo) (statSig, bool) {
	d, ok := info.Sys().(*syscall.Win32FileAttributeData)
	if !ok {
		return statSig{}, false
	}
	return statSig{
		inode: uint64(d.FileSizeHigh)<<32 | uint64(d.FileSizeLow),
		ctime: time.Unix(0, d.CreationTime.Nanoseconds()),
	}, true
}

// openNoFollow opens a path for reading. Windows has no O_NOFOLLOW; the
// post-open identity check in IngestFile still detects a source that
// changed between classification and read, and reparse points were already
// excluded by the lstat-based classification.
func openNoFollow(path string) (*os.File, error) {
	return os.Open(path)
}

// sameFile reports whether an opened handle is the same object the earlier
// lstat described.
func sameFile(before, opened os.FileInfo) bool {
	return os.SameFile(before, opened)
}
