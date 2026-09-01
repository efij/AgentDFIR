package seal

import (
	"os"
	"path/filepath"
	"testing"
)

func setupPkg(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "SHA256SUMS"),
		[]byte("abc123  manifest.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestSignVerifyRoundTrip(t *testing.T) {
	pkg := setupPkg(t)
	keys := t.TempDir()
	priv := filepath.Join(keys, "k.key")
	pub := filepath.Join(keys, "k.pub")
	if err := GenerateKey(priv, pub); err != nil {
		t.Fatal(err)
	}
	if err := Sign(pkg, priv); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(pkg, "")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Present || !res.Valid {
		t.Fatalf("expected valid signature, got %+v", res)
	}
}

func TestVerifyDetectsTamperedSums(t *testing.T) {
	pkg := setupPkg(t)
	keys := t.TempDir()
	priv := filepath.Join(keys, "k.key")
	if err := GenerateKey(priv, filepath.Join(keys, "k.pub")); err != nil {
		t.Fatal(err)
	}
	if err := Sign(pkg, priv); err != nil {
		t.Fatal(err)
	}
	// Attacker edits SHA256SUMS after signing.
	if err := os.WriteFile(filepath.Join(pkg, "SHA256SUMS"),
		[]byte("evil000  manifest.json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(pkg, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("tampered SHA256SUMS accepted as validly signed")
	}
}

func TestVerifyPinnedKeyMismatch(t *testing.T) {
	pkg := setupPkg(t)
	keys := t.TempDir()
	priv := filepath.Join(keys, "k.key")
	if err := GenerateKey(priv, filepath.Join(keys, "k.pub")); err != nil {
		t.Fatal(err)
	}
	if err := Sign(pkg, priv); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(pkg, "00000000000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeef")
	if err != nil {
		t.Fatal(err)
	}
	if res.Valid {
		t.Fatal("signature from a non-pinned key accepted")
	}
}

func TestVerifyUnsignedPackage(t *testing.T) {
	pkg := setupPkg(t)
	res, err := Verify(pkg, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.Present {
		t.Fatal("unsigned package reported a signature")
	}
}
