//go:build windows

package recorder

import (
	"os"
	"syscall"
)

// openTailed opens a tailed log read-only. os.Open on Windows withholds
// FILE_SHARE_DELETE, so while the monitor holds the file the writer could
// not rename it away (log rotation) or delete it. Sharing read, write and
// delete leaves the writer free; the handle keeps reading the renamed file
// to its end, as on Unix. FILE_FLAG_BACKUP_SEMANTICS lets a directory open
// so the caller's regular-file check reports it, not "access denied".
func openTailed(name string) (*os.File, error) {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	h, err := syscall.CreateFile(p, syscall.GENERIC_READ,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_ATTRIBUTE_NORMAL|syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: name, Err: err}
	}
	return os.NewFile(uintptr(h), name), nil
}
