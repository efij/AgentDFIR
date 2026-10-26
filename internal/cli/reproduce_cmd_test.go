package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/overlay"
	"github.com/efij/AgentDFIR/v5/internal/repro"
)

func analyzedAIExport(t *testing.T) string {
	t.Helper()
	zp := zipTree(t, map[string]string{"conversations.json": fixture(t, "chatgpt/conversations.json"), "user.json": fixture(t, "chatgpt/user.json")})
	pkg := filepath.Join(t.TempDir(), "r.adfir")
	if code := Main([]string{"collect", "--ai-export", zp, "--out", pkg, "--case-id", "REPRO", "--no-sign"}); code != 0 {
		t.Fatalf("collect exit %d", code)
	}
	if code, out := capture(t, "analyze", pkg, "--honeytokens", writeTemp(t, "canary-token-1\n")); code != 0 && code != 3 {
		t.Fatalf("analyze exit %d:\n%s", code, out)
	}
	return pkg
}

func writeTemp(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestVerifyReproduce(t *testing.T) {
	pkg := analyzedAIExport(t)
	// Honeytokens were used: only their count is recorded, so the list must
	// be passed again.
	if code, out := capture(t, "verify", "--reproduce", pkg); code == 0 || !strings.Contains(out, "--honeytokens") {
		t.Fatalf("reproduce without the honeytoken list: exit %d\n%s", code, out)
	}
	honey := writeTemp(t, "canary-token-1\n")
	code, out := capture(t, "verify", "--reproduce", pkg, "--honeytokens", honey)
	if code != 0 || !strings.Contains(out, "REPRODUCED") || !strings.Contains(out, "count") {
		t.Fatalf("reproduce exit %d:\n%s", code, out)
	}
	// Plain verify checks the analysis files too, and catches an edit.
	if code, out := capture(t, "verify", pkg); code != 0 || !strings.Contains(out, "Analysis overlay:   consistent") {
		t.Fatalf("verify exit %d:\n%s", code, out)
	}
	fp := filepath.Join(pkg, "detections", "findings.json")
	data, err := overlay.ReadFile(fp)
	if err != nil {
		t.Fatal(err)
	}
	var fs []map[string]any
	if err := json.Unmarshal(data, &fs); err != nil {
		t.Fatal(err)
	}
	// A planted finding (the case has few or none of its own).
	fs = append(fs, map[string]any{"rule_id": "PLANTED", "severity": "CRITICAL", "title": "t", "evidence_refs": []string{}, "status": "OBSERVED", "endpoint_corroboration": "UNKNOWN"})
	edited, _ := json.Marshal(fs)
	_ = overlay.Remove(fp)
	if err := os.WriteFile(fp, edited, 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out := capture(t, "verify", pkg); code == 0 || !strings.Contains(out, "analysis files are inconsistent") {
		t.Fatalf("an edited findings.json passed verify: exit %d\n%s", code, out)
	}
	// A reproduction still runs from the sealed zone, and says the stored
	// findings no longer match the manifest.
	if code, out := capture(t, "verify", "--reproduce", pkg, "--honeytokens", honey); code != 0 {
		t.Fatalf("reproduce after an overlay edit: exit %d\n%s", code, out)
	}
	// A different rule set is explained.
	rules := t.TempDir()
	_ = os.WriteFile(filepath.Join(rules, "x.json"), []byte(`{"pack":"x","version":"1","rules":[]}`), 0o600)
	m, err := repro.Read(repro.Path(pkg))
	if err != nil {
		t.Fatal(err)
	}
	m.FindingsFingerprint = "sha256:" + strings.Repeat("0", 64)
	m.Tool.AnalysisFingerprint = strings.Repeat("f", 64)
	alt := filepath.Join(t.TempDir(), "m.json")
	if err := writeManifestTo(alt, m); err != nil {
		t.Fatal(err)
	}
	code, out = capture(t, "verify", "--reproduce", pkg, "--manifest", alt, "--honeytokens", honey)
	if code == 0 || !strings.Contains(out, "NOT REPRODUCED") || !strings.Contains(out, "tool.analysis_fingerprint") {
		t.Fatalf("mismatch not explained: exit %d\n%s", code, out)
	}
}

func writeManifestTo(p string, m *repro.Manifest) error {
	dir := t2dir(p)
	if err := os.MkdirAll(filepath.Join(dir, "detections"), 0o700); err != nil {
		return err
	}
	if err := repro.Write(dir, m); err != nil {
		return err
	}
	return os.Rename(repro.Path(dir), p)
}

func t2dir(p string) string { return filepath.Join(filepath.Dir(p), "mdir") }

func TestPythonVerifierAgreesOnSignedProduction(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not on PATH")
	}
	pkg := analyzedAIExport(t)
	prod := filepath.Join(t.TempDir(), "prod")
	key := filepath.Join(t.TempDir(), "k")
	if code := Main([]string{"keygen", "--priv", key, "--pub", key + ".pub"}); code != 0 {
		t.Fatal("keygen")
	}
	if code, out := capture(t, "export", pkg, "--production", "--out", prod, "--sign", key, "--produced-at", "2026-10-25T00:00:00Z"); code != 0 {
		t.Fatalf("export exit %d\n%s", code, out)
	}
	if code, out := capture(t, "verify", prod); code != 0 || !strings.Contains(out, "Signature:          VALID") {
		t.Fatalf("verify production exit %d\n%s", code, out)
	}
	script, _ := filepath.Abs("../../tools/adfir-verify/adfir_verify.py")
	if out, err := exec.Command(py, "-I", script, prod).CombinedOutput(); err != nil || !strings.Contains(string(out), "VERIFIED") {
		t.Fatalf("python on production: %v\n%s", err, out)
	}
	_ = os.WriteFile(filepath.Join(prod, "planted.txt"), []byte("x"), 0o600)
	if out, err := exec.Command(py, "-I", script, prod).CombinedOutput(); err == nil {
		t.Fatalf("python accepted a planted file:\n%s", out)
	}
}
