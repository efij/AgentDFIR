package custody

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
)

// sealedCase makes a minimal sealed package so Append has a case.json and a
// SHA256SUMS to read.
func sealedCase(t *testing.T) string {
	t.Helper()
	pkg := filepath.Join(t.TempDir(), "c.adfir")
	b, err := casepkg.New(pkg, "CUST-1", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	return pkg
}

func TestAppendChainsAndCitesSeal(t *testing.T) {
	pkg := sealedCase(t)
	digest := SealDigest(pkg)
	if digest == "" {
		t.Fatal("no seal digest")
	}
	r1, err := Append(pkg, EventAuthorized, map[string]any{"by": "Alice", "basis": "policy"})
	if err != nil {
		t.Fatal(err)
	}
	if r1.SealDigest != digest {
		t.Errorf("record seal digest %q != case seal %q", r1.SealDigest, digest)
	}
	if _, err := Append(pkg, EventReportGenerated, map[string]any{"report": "accountability"}); err != nil {
		t.Fatal(err)
	}
	recs, chainErr, err := Read(pkg)
	if err != nil || chainErr != "" {
		t.Fatalf("read: err=%v chain=%q", err, chainErr)
	}
	if len(recs) != 2 {
		t.Fatalf("want 2 records, got %d", len(recs))
	}
	if auth := Authorizations(recs); len(auth) != 1 || auth[0].FieldString("by") != "Alice" {
		t.Errorf("authorizations = %v", auth)
	}
}

func TestActivityChainBreakDetected(t *testing.T) {
	pkg := sealedCase(t)
	if _, err := Append(pkg, EventAuthorized, map[string]any{"by": "A", "basis": "b"}); err != nil {
		t.Fatal(err)
	}
	if _, err := Append(pkg, EventVerified, map[string]any{"result": "ok"}); err != nil {
		t.Fatal(err)
	}
	// Tamper the first line's content.
	p := Path(pkg)
	data, _ := os.ReadFile(p)
	tampered := []byte("{\"evil\":1}\n")
	nl := 0
	for i, c := range data {
		if c == '\n' {
			nl = i
			break
		}
	}
	out := append(tampered, data[nl+1:]...)
	if err := os.WriteFile(p, out, 0o600); err != nil {
		t.Fatal(err)
	}
	_, chainErr, _ := Read(pkg)
	if chainErr == "" {
		t.Error("tampered activity log verified clean")
	}
}

func TestReservedFieldRefused(t *testing.T) {
	pkg := sealedCase(t)
	if _, err := Append(pkg, EventVerified, map[string]any{"seal_digest": "forged"}); err == nil {
		t.Error("a caller was allowed to set the reserved seal_digest field")
	}
}
