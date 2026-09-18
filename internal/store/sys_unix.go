//go:build !windows

package store

import (
	"fmt"
	"os"
	"syscall"
)

// checkOwner refuses a directory owned by someone else: the evidence home
// holds every transcript collected on this machine.
func checkOwner(dir string, fi os.FileInfo) error {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is owned by uid %d, not the current user (uid %d)", dir, st.Uid, os.Getuid())
	}
	return nil
}

// PermissionsAreReal reports whether os.FileInfo mode bits describe the
// actual access control on this platform, and are therefore worth
// enforcing on the evidence home.
const PermissionsAreReal = true

// linkCount reports how many directory entries point at this inode. A
// shared blob with exactly one is referenced by no case.
func linkCount(fi os.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 2 // unknown: treat as referenced, never delete on a guess
}
