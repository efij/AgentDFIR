//go:build !windows && !plan9

package recorder

import (
	"os"
	"os/user"
	"syscall"
)

var runningAsRoot = func() bool { return os.Geteuid() == 0 }

var effectiveUID = os.Geteuid

func ownerUID(fi os.FileInfo) (int, bool) {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return int(st.Uid), true
	}
	return 0, false
}

// Home is the home directory of the effective user. A root monitor
// resolves it from the uid (the password database), never from $HOME,
// which sudo may carry over from the invoking user.
func Home() (string, error) {
	if os.Geteuid() == 0 {
		if u, err := user.LookupId("0"); err == nil && u.HomeDir != "" {
			return u.HomeDir, nil
		}
	}
	return os.UserHomeDir()
}
