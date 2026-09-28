//go:build windows

package journal

import "os"

// fileID is not available from os.FileInfo on Windows without opening the
// file; replacement is still caught by the prefix hash.
func fileID(fi os.FileInfo) string { return "" }
