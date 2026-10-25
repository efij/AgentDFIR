package detect

import (
	"strings"
	"testing"
)

// Synthetic credential-shaped values, assembled at run time so the source
// file itself does not hold anything a scanner would flag.
var (
	fpGitHub = "ghp_" + strings.Repeat("aB3dE5fG7h", 3) + "J9kL1m"
	fpAWS    = "AKIA" + "QW3RTY7UIOPLKJ2H"
	fpAnth   = "sk-ant-" + "api03-Zq8Xw2Vt6Rp4Nm1Lk9Jh"
)

func TestSecretFingerprintsNeverCarryTheValue(t *testing.T) {
	data := []byte("token " + fpGitHub + " again " + fpGitHub + " aws=" + fpAWS + " doc AKIAIOSFODNN7EXAMPLE key " + fpAnth)
	got := SecretFingerprints(data)
	if len(got) != 3 {
		t.Fatalf("fingerprints = %+v, want github, aws, anthropic (placeholder skipped)", got)
	}
	types := map[string]SecretFingerprint{}
	for _, f := range got {
		types[f.Type] = f
		if !strings.HasPrefix(f.Fingerprint, "sha256:") || len(f.Fingerprint) != len("sha256:")+16 {
			t.Errorf("fingerprint form: %q", f.Fingerprint)
		}
		for _, v := range []string{fpGitHub, fpAWS, fpAnth} {
			if strings.Contains(f.Fingerprint, v) || strings.Contains(f.Prefix, v) || len(f.Prefix) > 7 {
				t.Errorf("fingerprint leaks the value: %+v", f)
			}
		}
	}
	if types["GITHUB_TOKEN"].Count != 2 || types["GITHUB_TOKEN"].Prefix != "ghp_" {
		t.Errorf("github: %+v", types["GITHUB_TOKEN"])
	}
	if _, dup := types["OPENAI_API_KEY"]; dup {
		t.Error("an Anthropic key was reported twice, once as the generic sk- shape")
	}
	// Deterministic and stable across inputs: the same key elsewhere yields
	// the same fingerprint.
	again := SecretFingerprints([]byte("x " + fpAWS))
	if len(again) != 1 || again[0].Fingerprint != types["AWS_ACCESS_KEY"].Fingerprint {
		t.Errorf("same key, different fingerprint: %+v vs %+v", again, types["AWS_ACCESS_KEY"])
	}
}

func TestSecretFingerprintsPrivateKeyBody(t *testing.T) {
	body := strings.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", 3)
	key := "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----"
	escaped := "-----BEGIN PRIVATE KEY-----\\n" + body + "\\n-----END PRIVATE KEY-----"
	a, b := SecretFingerprints([]byte(key)), SecretFingerprints([]byte(`{"x":"`+escaped+`"}`))
	if len(a) != 1 || len(b) != 1 || a[0].Fingerprint != b[0].Fingerprint {
		t.Fatalf("PEM fingerprint should not depend on newline escaping: %+v %+v", a, b)
	}
	if got := SecretFingerprints([]byte("-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----")); len(got) != 0 {
		t.Errorf("elided key fingerprinted: %+v", got)
	}
	if got := SecretFingerprints([]byte("-----BEGIN PRIVATE KEY-----" + strings.Repeat("A", 100))); len(got) != 0 {
		t.Errorf("header without END fingerprinted: %+v", got)
	}
}

func TestSecretFingerprintsHostileInput(t *testing.T) {
	for _, in := range [][]byte{nil, {}, []byte("AKIA"), []byte(strings.Repeat("ghp_", 10000)), []byte("-----BEGIN PRIVATE KEY-----")} {
		_ = SecretFingerprints(in)
	}
}

func TestMaskSecrets(t *testing.T) {
	in := "curl -H 'Authorization: token " + fpGitHub + "' --aws " + fpAWS + " " + fpAnth
	out := MaskSecrets(in)
	for _, v := range []string{fpGitHub, fpAWS, fpAnth, fpAnth[7:]} {
		if strings.Contains(out, v) {
			t.Errorf("value survived masking: %s", out)
		}
	}
	if !strings.Contains(out, "ghp_…[GITHUB_TOKEN sha256:") || !strings.Contains(out, "AKIA…[AWS_ACCESS_KEY sha256:") {
		t.Errorf("masked form: %s", out)
	}
	if got := MaskSecrets("ls -la"); got != "ls -la" {
		t.Errorf("clean text changed: %q", got)
	}
}
