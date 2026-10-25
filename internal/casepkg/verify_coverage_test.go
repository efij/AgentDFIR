package casepkg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The sealed zone is more than raw/: a file planted under one of its other
// names is read by every consumer exactly as if it had been sealed.

// TestVerifyDetectsPlantedManifestForm: ReadManifest prefers manifest.jsonl,
// so on a package sealed with the legacy manifest.json a planted, unlisted
// manifest.jsonl would silently replace the sealed manifest for analysis
// while verification checked only the one it covers. The reverse plant is
// the same gap.
func TestVerifyDetectsPlantedManifestForm(t *testing.T) {
	pkg := buildPackage(t, map[string]string{"a.jsonl": `{"x":1}`})
	if err := os.WriteFile(filepath.Join(pkg, manifestJSON), []byte(`{"artifacts":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !hasProblem(res.Problems, "manifest.json: present but not covered") {
		t.Fatalf("planted manifest form not reported: %v", res.Problems)
	}
}

// TestVerifyDetectsPlantedSeal: seals/ is part of the sealed zone; an
// archived seal nobody sealed must not pass as round history.
func TestVerifyDetectsPlantedSeal(t *testing.T) {
	pkg := buildPackage(t, map[string]string{"a.jsonl": `{"x":1}`})
	if err := os.MkdirAll(filepath.Join(pkg, sealsDir), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkg, sealsDir, "SHA256SUMS.7"), []byte("forged\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !hasProblem(res.Problems, "seals/SHA256SUMS.7: present but not covered") {
		t.Fatalf("planted seal not reported: %v", res.Problems)
	}
}

// TestVerifyRejectsPathsOutsideThePackage: SHA256SUMS is input. A listed
// path that climbs out of the package is a malformed seal, and verify must
// not read files outside the package on its say-so.
func TestVerifyRejectsPathsOutsideThePackage(t *testing.T) {
	pkg := buildPackage(t, map[string]string{"a.jsonl": `{"x":1}`})
	sums := filepath.Join(pkg, sumsFile)
	data, err := os.ReadFile(sums)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(sums, 0o600)
	data = append(data, []byte(strings.Repeat("0", 64)+"  ../outside.txt\n")...)
	if err := os.WriteFile(sums, data, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !hasProblem(res.Problems, "path outside the package") {
		t.Fatalf("escaping path not reported: %v", res.Problems)
	}
}

// TestVerifyRejectsDuplicateSeal: a path listed twice is a malformed seal;
// which of the two hashes a reader honours is undefined.
func TestVerifyRejectsDuplicateSeal(t *testing.T) {
	pkg := buildPackage(t, map[string]string{"a.jsonl": `{"x":1}`})
	sums := filepath.Join(pkg, sumsFile)
	data, err := os.ReadFile(sums)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(sums, 0o600)
	first := strings.SplitN(string(data), "\n", 2)[0]
	if err := os.WriteFile(sums, append(data, []byte(first+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	if !hasProblem(res.Problems, "listed twice") {
		t.Fatalf("duplicate line not reported: %v", res.Problems)
	}
}

func hasProblem(problems []string, frag string) bool {
	for _, p := range problems {
		if strings.Contains(p, frag) {
			return true
		}
	}
	return false
}
