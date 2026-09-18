//go:build !windows

package casepkg

import "syscall"

// processAlive reports whether a pid is still running, so a lock left by a
// crashed collection can be reclaimed while a live one is never stolen.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	return syscall.Kill(pid, 0) == nil
}
