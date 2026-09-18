//go:build windows

package casepkg

import (
	"os"
	"time"
)

// statSig is the identity of a file as the filesystem sees it.
//
// On Windows, os.FileInfo exposes creation, access and write times, but no
// change time and no file index. Creation time plus size would happily
// match a file that was modified in place, and write time is settable by
// anyone who can write the file — so there is nothing here that safely
// answers "are these still the same bytes?".
//
// Rather than guess, carry-forward is disabled on Windows: every round
// re-reads its sources. That costs read time, not storage — unchanged
// files hash to the same content address and dedupe against what the
// package already holds, and a transcript that only grew still stores just
// its new tail. Compression, deduplication, cross-case sharing, rounds and
// append-aware storage all work unchanged.
type statSig struct {
	inode uint64
	dev   uint64
	ctime time.Time
}

func statSignature(os.FileInfo) (statSig, bool) { return statSig{}, false }

// SupportsCarryForward reports whether this platform can prove a source
// file is unchanged without re-reading it.
func SupportsCarryForward() bool { return false }

// openNoFollow opens a path for reading. Windows has no O_NOFOLLOW; the
// post-open identity check in PrepareFile still detects a source that
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
