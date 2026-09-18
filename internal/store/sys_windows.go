//go:build windows

package store

import "os"

// checkOwner is a no-op on Windows: the per-user LOCALAPPDATA location is
// already scoped to the account, and ACL inspection would need syscalls
// this package deliberately avoids.
func checkOwner(string, os.FileInfo) error { return nil }

// linkCount is not available through os.FileInfo on Windows. Reporting 2
// means "assume referenced", so garbage collection never deletes a blob it
// cannot prove is unreferenced.
func linkCount(os.FileInfo) uint64 { return 2 }
