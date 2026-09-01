package encrypt

import (
	"os"
	"path/filepath"
	"testing"
)

func makePkg(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "case.adfir")
	if err := os.MkdirAll(filepath.Join(dir, "raw"), 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"manifest.json": `{"case_id":"E-1"}`,
		"SHA256SUMS":    "abc  manifest.json\n",
		"raw/deadbeef":  "secret evidence bytes",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	src := makePkg(t)
	enc := filepath.Join(t.TempDir(), "case.adfir.enc")
	if err := Encrypt(src, enc, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}

	// The ciphertext must not contain plaintext logical paths or evidence.
	data, _ := os.ReadFile(enc)
	for _, leak := range []string{"manifest.json", "secret evidence bytes", "case_id"} {
		if containsBytes(data, leak) {
			t.Fatalf("plaintext %q leaked into encrypted file", leak)
		}
	}
	if string(data[:8]) != "ADFIRENC" {
		t.Fatal("missing envelope magic")
	}

	out := filepath.Join(t.TempDir(), "restored")
	if err := Decrypt(enc, out, "correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	restored, err := os.ReadFile(filepath.Join(out, "raw", "deadbeef"))
	if err != nil {
		t.Fatal(err)
	}
	if string(restored) != "secret evidence bytes" {
		t.Fatalf("round-trip mismatch: %q", restored)
	}
}

func TestWrongPassphraseFails(t *testing.T) {
	src := makePkg(t)
	enc := filepath.Join(t.TempDir(), "c.enc")
	if err := Encrypt(src, enc, "right"); err != nil {
		t.Fatal(err)
	}
	if err := Decrypt(enc, t.TempDir(), "wrong"); err == nil {
		t.Fatal("decryption succeeded with wrong passphrase")
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	src := makePkg(t)
	enc := filepath.Join(t.TempDir(), "c.enc")
	if err := Encrypt(src, enc, "pw"); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(enc)
	data[len(data)-1] ^= 0xFF // flip a ciphertext bit
	os.WriteFile(enc, data, 0o600)
	if err := Decrypt(enc, t.TempDir(), "pw"); err == nil {
		t.Fatal("GCM did not detect tampered ciphertext")
	}
}

func containsBytes(hay []byte, needle string) bool {
	n := []byte(needle)
	for i := 0; i+len(n) <= len(hay); i++ {
		if string(hay[i:i+len(n)]) == needle {
			return true
		}
	}
	return false
}
