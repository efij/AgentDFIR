package recorder

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// A symlink planted in the state dir must never be written through.
func TestStatusSaveDoesNotFollowPlantedLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlinks need privileges on Windows")
	}
	dir := t.TempDir()
	victim := filepath.Join(t.TempDir(), "victim")
	_ = os.WriteFile(victim, []byte("keep"), 0o600)
	_ = os.Symlink(victim, filepath.Join(dir, "status.json.tmp"))
	_ = os.Symlink(victim, filepath.Join(dir, StatusFile))
	r := New(dir, nil)
	if err := r.Save(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(victim); string(b) != "keep" {
		t.Fatalf("planted link was written through: %q", b)
	}
	fi, err := os.Lstat(filepath.Join(dir, StatusFile))
	if err != nil || !fi.Mode().IsRegular() {
		t.Fatalf("status.json is not a regular file: %v %v", fi, err)
	}
	if m, _ := filepath.Glob(filepath.Join(dir, "status-*.tmp")); len(m) != 0 {
		t.Fatalf("temp files left: %v", m)
	}
}

func TestCheckDirAsRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX ownership")
	}
	oldRoot, oldUID := runningAsRoot, effectiveUID
	defer func() { runningAsRoot, effectiveUID = oldRoot, oldUID }()
	dir := t.TempDir()
	if err := CheckDir(dir); err != nil {
		t.Fatalf("own dir, not root: %v", err)
	}
	runningAsRoot = func() bool { return true }
	if err := CheckDir(dir); err != nil {
		t.Fatalf("dir owned by the effective uid: %v", err)
	}
	me := os.Geteuid()
	effectiveUID = func() int { return me + 1 }
	if err := CheckDir(dir); err == nil {
		t.Fatal("a root monitor accepted a state dir owned by another uid")
	}
	effectiveUID = oldUID
	link := filepath.Join(t.TempDir(), "monitor")
	_ = os.Symlink(dir, link)
	if err := CheckDir(link); err == nil {
		t.Fatal("a root monitor accepted a symlinked state dir")
	}
	if err := CheckDir(filepath.Join(t.TempDir(), "absent")); err != nil {
		t.Fatalf("absent dir: %v", err)
	}
}
