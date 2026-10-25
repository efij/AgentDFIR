//go:build !windows

package extinv

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A FIFO where a manifest or entry file should be would block a naive
// read forever.
func TestFIFOsDoNotBlock(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, ".vscode", "extensions", "f.f-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "package.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(root, ".vscode", "extensions", "extensions.json"), 0o644); err != nil {
		t.Fatal(err)
	}
	skill := filepath.Join(root, ".claude", "skills", "s")
	if err := os.MkdirAll(skill, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(skill, "SKILL.md"), 0o644); err != nil {
		t.Fatal(err)
	}
	done := make(chan *Inventory, 1)
	go func() { done <- ScanHome(root) }()
	select {
	case inv := <-done:
		if x := findExt(inv, "f.f-1"); x == nil || len(inv.Unsupported) == 0 {
			t.Fatalf("FIFO manifest not reported: %+v %v", x, inv.Unsupported)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("scan blocked on a FIFO")
	}
}
