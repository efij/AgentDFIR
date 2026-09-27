//go:build windows

package mitigate

import "os"

// ownedByMe: Windows ACLs do not reduce to one owner check; files under
// the user's profile are the ones planned, and a write the user may not
// make fails at the write instead.
func ownedByMe(fi os.FileInfo) bool { return true }
