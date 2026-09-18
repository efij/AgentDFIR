//go:build windows

package store

import "os"

// checkOwner is a no-op on Windows: the per-user LOCALAPPDATA location is
// already scoped to the account, and ACL inspection would need syscalls
// this package deliberately avoids.
func checkOwner(string, os.FileInfo) error { return nil }

// PermissionsAreReal is false on Windows: Go synthesizes mode bits there
// from the read-only attribute alone, so every ordinary directory reports
// 0777 and a group/world-writable check would reject all of them while
// telling you nothing about the ACLs that actually govern access. The home
// lives under LOCALAPPDATA, which is already scoped to the account.
const PermissionsAreReal = false

// LinkCountsAvailable is false on Windows: os.FileInfo carries no link
// count there, so the store cannot prove a blob is unreferenced and will
// not delete one on a guess.
const LinkCountsAvailable = false

// linkCount is not available through os.FileInfo on Windows. Reporting 2
// means "assume referenced", so garbage collection never deletes a blob it
// cannot prove is unreferenced.
func linkCount(os.FileInfo) uint64 { return 2 }
