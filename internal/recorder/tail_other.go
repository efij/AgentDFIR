//go:build !windows

package recorder

import "os"

// openTailed opens a tailed log read-only (see tail_windows.go).
func openTailed(name string) (*os.File, error) { return os.Open(name) }
