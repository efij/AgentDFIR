package integrity

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/seal"
)

func TestVerifyPackageCleanAndSigned(t *testing.T) {
	pkg := newCase(t)
	c, err := VerifyPackage(pkg, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Package.Problems) != 0 || !c.Signature.Valid {
		t.Fatalf("clean signed case: %v %+v", c.Package.Problems, c.Signature)
	}
}

// Deleting the signature of a case whose last round was signed is a
// downgrade, not an unsigned case.
func TestVerifyPackageMissingSignatureIsAProblem(t *testing.T) {
	pkg := newCase(t)
	if err := os.Remove(filepath.Join(pkg, seal.SigFile)); err != nil {
		t.Fatal(err)
	}
	c, err := VerifyPackage(pkg, "")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(c.Package.Problems, "SEAL.sig: missing") {
		t.Fatalf("deleted signature not reported: %v", c.Package.Problems)
	}
	c, err = VerifyPackage(pkg, "ab")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(c.Package.Problems, "pinned") {
		t.Fatalf("deleted signature with a pinned key not reported: %v", c.Package.Problems)
	}
}

// A corrupt case.json must not turn the signer-downgrade check off.
func TestVerifyPackageMissingSignatureWithCorruptCaseJSON(t *testing.T) {
	pkg := newCase(t)
	if err := os.Remove(filepath.Join(pkg, seal.SigFile)); err != nil {
		t.Fatal(err)
	}
	cj := filepath.Join(pkg, "case.json")
	_ = os.Chmod(cj, 0o600)
	if err := os.WriteFile(cj, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := VerifyPackage(pkg, "")
	if err != nil {
		t.Fatal(err)
	}
	if !contains(c.Package.Problems, "case.json is unreadable") {
		t.Fatalf("missing signature with corrupt case.json not reported: %v", c.Package.Problems)
	}
}

// Re-signing with another key is legitimate (`agentdfir sign`) unless the
// caller pinned the key.
func TestVerifyPackageOtherKeyNeedsAPin(t *testing.T) {
	pkg := newCase(t)
	first, err := seal.Verify(pkg, "")
	if err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(t.TempDir(), "other.key")
	if err := seal.GenerateKey(other, other+".pub"); err != nil {
		t.Fatal(err)
	}
	if err := seal.Sign(pkg, other); err != nil {
		t.Fatal(err)
	}
	c, err := VerifyPackage(pkg, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Package.Problems) != 0 {
		t.Fatalf("re-signed package without a pin: %v", c.Package.Problems)
	}
	c, err = VerifyPackage(pkg, first.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if !contains(c.Package.Problems, "pinned key") {
		t.Fatalf("re-signed package with the original key pinned: %v", c.Package.Problems)
	}
}
