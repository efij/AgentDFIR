//go:build darwin || freebsd || netbsd || openbsd || dragonfly

package casepkg

import (
	"syscall"
	"time"
)

func ctimeOf(st *syscall.Stat_t) (time.Time, bool) {
	return time.Unix(st.Ctimespec.Sec, st.Ctimespec.Nsec), true
}
