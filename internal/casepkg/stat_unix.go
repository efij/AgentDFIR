//go:build !windows

package casepkg

import (
	"os"
	"syscall"
	"time"
)

// statSig is the identity of a file as the filesystem sees it, used to
// decide whether an earlier round's evidence still describes it.
//
// ctime, not mtime: mtime is fully settable by whoever can write the file,
// so an attacker who modifies evidence can restore its mtime and make a
// naive incremental collector skip it. ctime moves on any inode change and
// cannot be set by an unprivileged writer.
type statSig struct {
	inode uint64
	dev   uint64
	ctime time.Time
}

func statSignature(info os.FileInfo) (statSig, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return statSig{}, false
	}
	ct, ok := ctimeOf(st)
	if !ok {
		return statSig{inode: uint64(st.Ino), dev: uint64(st.Dev)}, true
	}
	return statSig{
		inode: uint64(st.Ino),
		dev:   uint64(st.Dev),
		ctime: ct,
	}, true
}

// openNoFollow opens a path for reading, refusing to traverse a final
// symlink. Combined with the post-open identity check, this closes the
// window between classifying a path with lstat and reading it.
func openNoFollow(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
}

// sameFile reports whether an opened descriptor is the same object the
// earlier lstat described.
func sameFile(before, opened os.FileInfo) bool {
	a, aok := statSignature(before)
	b, bok := statSignature(opened)
	if !aok || !bok {
		return os.SameFile(before, opened)
	}
	return a.inode == b.inode && a.dev == b.dev
}
