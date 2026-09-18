//go:build linux

package casepkg

import (
	"syscall"
	"time"
)

func ctimeOf(st *syscall.Stat_t) (time.Time, bool) {
	return time.Unix(st.Ctim.Sec, st.Ctim.Nsec), true
}
