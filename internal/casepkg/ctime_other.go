//go:build !windows && !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package casepkg

import (
	"syscall"
	"time"
)

// ctimeOf is unavailable on this platform. Carry-forward then declines to
// skip a re-read rather than trusting mtime, which is attacker-settable.
func ctimeOf(*syscall.Stat_t) (time.Time, bool) { return time.Time{}, false }
