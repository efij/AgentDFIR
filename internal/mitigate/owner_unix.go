//go:build !windows

package mitigate

import (
	"os"
	"syscall"
)

// ownedByMe reports whether the current user owns the file. A config file
// owned by someone else (root-managed settings, another account's home) is
// never edited: that is an administrator's decision, not this tool's.
func ownedByMe(fi os.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return false
	}
	return int(st.Uid) == os.Getuid()
}
