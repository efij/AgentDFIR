package export_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/export"
	"github.com/efij/AgentDFIR/v5/internal/seal"
)

func TestProductionSignatureVerifies(t *testing.T) {
	pkg := build(t, false)
	out, _ := produce(t, pkg, "", fixedTime)
	if !export.IsProduction(out) || export.IsProduction(pkg) {
		t.Fatal("IsProduction misclassifies")
	}
	// Unsigned (as v4 wrote them): verifies, with a note; a pinned key fails.
	c, err := export.VerifyProduction(out, "")
	if err != nil || len(c.Problems) > 0 || c.Signature != "none" || c.Files == 0 {
		t.Fatalf("unsigned production: %+v %v", c, err)
	}
	key := filepath.Join(t.TempDir(), "k")
	if err := seal.GenerateKey(key, key+".pub"); err != nil {
		t.Fatal(err)
	}
	pub, err := export.SignProduction(out, key)
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := export.VerifyProduction(out, pub); len(c.Problems) > 0 || c.Signature != "valid" || c.Signer != pub {
		t.Fatalf("signed production: %+v", c)
	}
	// Signing twice gives the same bytes: the production stays reproducible.
	first, _ := os.ReadFile(filepath.Join(out, export.ProductionSignature))
	if _, err := export.SignProduction(out, key); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(filepath.Join(out, export.ProductionSignature))
	if string(first) != string(second) {
		t.Fatal("signature is not deterministic")
	}
	other := filepath.Join(t.TempDir(), "o")
	_ = seal.GenerateKey(other, other+".pub")
	otherPub, _ := seal.PublicKeyHex(other)
	if c, _ := export.VerifyProduction(out, otherPub); len(c.Problems) == 0 {
		t.Fatal("a different pinned key must fail")
	}
	// Tampering: a produced file, the manifest, or a planted file.
	tamper := func(name string, f func(dir string)) {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "p")
			if err := os.CopyFS(dir, os.DirFS(out)); err != nil {
				t.Fatal(err)
			}
			f(dir)
			if c, _ := export.VerifyProduction(dir, ""); c == nil || len(c.Problems) == 0 {
				t.Fatalf("%s not detected", name)
			}
		})
	}
	tamper("file-edit", func(dir string) {
		p := filepath.Join(dir, "timeline", "findings.csv")
		if _, err := os.Stat(p); err != nil {
			t.Fatal(err)
		}
		os.Chmod(p, 0o600)
		os.WriteFile(p, []byte("rule_id\n"), 0o600)
	})
	tamper("manifest-edit", func(dir string) {
		p := filepath.Join(dir, export.ProductionManifestJSON)
		b, _ := os.ReadFile(p)
		os.Chmod(p, 0o600)
		os.WriteFile(p, append(b, ' '), 0o600)
	})
	tamper("plant", func(dir string) { os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("x"), 0o600) })
	tamper("sig-delete-pinned", func(dir string) {
		os.Remove(filepath.Join(dir, export.ProductionSignature))
		if c, _ := export.VerifyProduction(dir, pub); len(c.Problems) == 0 {
			t.Fatal("missing signature with a pinned key must fail")
		}
		os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("x"), 0o600)
	})
}
