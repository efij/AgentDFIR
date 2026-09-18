package store

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func testHome(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(EnvHome, dir)
	return dir
}

// TestSharedStoreVerifiesBeforeLinking is the check that stops evidence
// substitution: anything able to write into the store could otherwise
// pre-place a file under the hash of evidence it expects to be collected,
// and have that linked into the case instead of the real bytes.
func TestSharedStoreVerifiesBeforeLinking(t *testing.T) {
	testHome(t)
	s, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	real := []byte("the real evidence")
	sum := sha256.Sum256(real)
	id := hex.EncodeToString(sum[:])

	// Plant a file under the right name with the wrong content.
	planted := s.blob(id)
	if err := os.MkdirAll(filepath.Dir(planted), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planted, []byte("attacker-supplied"), 0o600); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "blob")
	reused, err := s.Link(id, dst)
	if err != nil {
		t.Fatal(err)
	}
	if reused {
		t.Fatal("a store entry was reused on the strength of its filename alone")
	}
	if _, err := os.Stat(dst); err == nil {
		t.Fatal("planted content was placed into the package")
	}
}

// TestAdoptThenLinkReusesGenuineBytes: the optimization must still work
// for honest content.
func TestAdoptThenLinkReusesGenuineBytes(t *testing.T) {
	testHome(t)
	s, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("shared evidence bytes")
	sum := sha256.Sum256(content)
	id := hex.EncodeToString(sum[:])

	src := filepath.Join(t.TempDir(), "first")
	if err := os.WriteFile(src, content, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.Adopt(id, src); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(t.TempDir(), "second")
	reused, err := s.Link(id, dst)
	if err != nil {
		t.Fatal(err)
	}
	if !reused {
		t.Skip("hardlinks unavailable on this filesystem")
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(content) {
		t.Fatal("linked blob is not the adopted content")
	}
}

// TestGCOnlyRemovesUnreferencedBlobs: a blob a case still links to is
// live evidence and must never be collected. One whose only remaining
// link is the store's own is referenced by no case.
func TestGCOnlyRemovesUnreferencedBlobs(t *testing.T) {
	if !LinkCountsAvailable {
		t.Skip("no link counts on this platform; the store never deletes on a guess")
	}
	testHome(t)
	s, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	caseDir := t.TempDir()
	adopt := func(name, content string) (id, external string) {
		external = filepath.Join(caseDir, name)
		if err := os.WriteFile(external, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256([]byte(content))
		id = hex.EncodeToString(sum[:])
		if err := s.Adopt(id, external); err != nil {
			t.Fatal(err)
		}
		if fi, err := os.Stat(s.blob(id)); err != nil || linkCount(fi) < 2 {
			t.Skip("hardlinks unavailable on this filesystem")
		}
		return id, external
	}
	referenced, _ := adopt("live", "still in a case")
	orphan, orphanPath := adopt("dead", "no case wants this")

	// Deleting the case's copy leaves the store holding the only link.
	if err := os.Remove(orphanPath); err != nil {
		t.Fatal(err)
	}

	st, err := Status()
	if err != nil {
		t.Fatal(err)
	}
	if st.Unreferenced != 1 {
		t.Fatalf("unreferenced blobs = %d, want 1", st.Unreferenced)
	}

	dry, err := GC(true)
	if err != nil {
		t.Fatal(err)
	}
	if dry.Removed != 1 {
		t.Fatalf("dry run would remove %d, want 1", dry.Removed)
	}
	if _, err := os.Stat(s.blob(orphan)); err != nil {
		t.Fatal("dry run deleted a blob; it must only report")
	}

	got, err := GC(false)
	if err != nil {
		t.Fatal(err)
	}
	if got.Removed != 1 {
		t.Fatalf("removed %d blobs, want 1", got.Removed)
	}
	if _, err := os.Stat(s.blob(orphan)); err == nil {
		t.Fatal("unreferenced blob survived collection")
	}
	if _, err := os.Stat(s.blob(referenced)); err != nil {
		t.Fatal("collection removed a blob a case still links to")
	}
}

// TestRefusesGroupWritableHome: the home aggregates every transcript ever
// collected on the machine.
func TestRefusesGroupWritableHome(t *testing.T) {
	if !PermissionsAreReal {
		t.Skip("mode bits are synthetic on this platform; ACLs govern access")
	}
	dir := filepath.Join(t.TempDir(), "loose")
	if err := os.MkdirAll(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvHome, dir)
	if _, err := Home(); err == nil {
		t.Fatal("a world-writable directory was accepted as the evidence home")
	}
}

// TestRefusesSymlinkedHome: a pre-created symlink must not redirect where
// evidence lands.
func TestRefusesSymlinkedHome(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "elsewhere")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "home")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	t.Setenv(EnvHome, link)
	if _, err := Home(); err == nil {
		t.Fatal("a symlinked evidence home was accepted")
	}
}
