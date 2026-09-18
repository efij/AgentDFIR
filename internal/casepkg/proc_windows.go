//go:build windows

package casepkg

import "os"

// processAlive reports whether a pid is still running. On Windows
// os.FindProcess fails for a process that does not exist.
func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = p.Release()
	return true
}
