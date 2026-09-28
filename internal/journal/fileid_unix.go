//go:build !windows

package journal

import (
	"fmt"
	"os"
	"syscall"
)

// fileID identifies a file independent of its name (device:inode), so an
// atomic-rename replacement of a transcript is visible.
func fileID(fi os.FileInfo) string {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("%d:%d", st.Dev, st.Ino)
	}
	return ""
}
