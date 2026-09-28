//go:build !windows

package reposcan

import (
	"syscall"
	"testing"
)

func mkfifo(t *testing.T, p string) {
	if err := syscall.Mkfifo(p, 0o644); err != nil {
		t.Fatal(err)
	}
}
