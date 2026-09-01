package supportpkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/internal/casepkg"
	"github.com/efij/AgentDFIR/internal/collector"
	"github.com/efij/AgentDFIR/internal/products"
)

const syntheticKey = "AKIAIOSFODNN7EXAMPLE"

func TestSupportExportRedactsSecrets(t *testing.T) {
	root := t.TempDir()
	sess := filepath.Join(root, ".claude", "projects", "-x")
	if err := os.MkdirAll(sess, 0o755); err != nil {
		t.Fatal(err)
	}
	transcript := `{"type":"user","sessionId":"s1","message":{"role":"user","content":"deploy with ` + syntheticKey + ` and email admin@corp.example"}}`
	if err := os.WriteFile(filepath.Join(sess, "s1.jsonl"), []byte(transcript+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(t.TempDir(), "src.adfir")
	b, err := casepkg.New(src, "SUP-1", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	man, _ := products.Manifest("claude-code")
	if _, err := collector.Run(b, man, collector.Options{
		ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"),
		SystemRoot: root, Product: "claude-code",
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "support.adfir")
	rm, err := Export(src, dst)
	if err != nil {
		t.Fatal(err)
	}

	// 1. No blob in the support package contains the secret or the email.
	entries, err := os.ReadDir(filepath.Join(dst, "raw"))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, _ := os.ReadFile(filepath.Join(dst, "raw", e.Name()))
		if strings.Contains(string(data), syntheticKey) {
			t.Fatal("secret survived redaction in support package")
		}
		if strings.Contains(string(data), "admin@corp.example") {
			t.Fatal("email survived redaction in support package")
		}
	}

	// 2. Redaction manifest records categories/counts, never values.
	if len(rm.RedactedEntries) == 0 {
		t.Fatal("no redaction entries recorded")
	}
	found := false
	for _, e := range rm.RedactedEntries {
		if e.Categories["AWS_ACCESS_KEY"] > 0 {
			found = true
		}
		if e.OriginalSHA256 == "" || e.RedactedSHA256 == "" {
			t.Fatal("redaction entry missing binding hashes")
		}
	}
	if !found {
		t.Fatal("AWS_ACCESS_KEY category not recorded")
	}
	data, _ := os.ReadFile(filepath.Join(dst, "redaction-manifest.json"))
	if strings.Contains(string(data), syntheticKey) {
		t.Fatal("secret value leaked into redaction manifest")
	}

	// 3. Support package is itself sealed and verifiable.
	vres, err := casepkg.Verify(dst)
	if err != nil {
		t.Fatal(err)
	}
	if len(vres.Problems) != 0 {
		t.Fatalf("support package fails verification: %v", vres.Problems)
	}

	// 4. Original forensic package unmodified and still verifies.
	vres, err = casepkg.Verify(src)
	if err != nil {
		t.Fatal(err)
	}
	if len(vres.Problems) != 0 {
		t.Fatalf("original package was modified by export: %v", vres.Problems)
	}
	origBlob, _ := os.ReadDir(filepath.Join(src, "raw"))
	stillThere := false
	for _, e := range origBlob {
		data, _ := os.ReadFile(filepath.Join(src, "raw", e.Name()))
		if strings.Contains(string(data), syntheticKey) {
			stillThere = true
		}
	}
	if !stillThere {
		t.Fatal("forensic original no longer contains the evidence — lossless guarantee broken")
	}
}
