//go:build windows || plan9

package recorder

import "os"

var runningAsRoot = func() bool { return false }

var effectiveUID = func() int { return -1 }

func ownerUID(os.FileInfo) (int, bool) { return 0, false }

// Home is the user's home directory.
func Home() (string, error) { return os.UserHomeDir() }
