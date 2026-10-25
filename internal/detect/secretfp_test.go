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

// pemParts builds a key-shaped block at run time; nothing key-like is a
// literal in the source.
func pemParts() (header, body, footer string) {
	kind := "PRIV" + "ATE KEY"
	return "-----BEGIN " + kind + "-----", strings.Repeat("MIIEvQIBADANBgkqhkiG9w0BAQEFAASC", 4), "-----END " + kind + "-----"
}

func TestMaskSecretsPrivateKeyWhole(t *testing.T) {
	h, body, f := pemParts()
	half := body[:len(body)/2]
	for name, in := range map[string]string{
		"newlines":     "cat <<EOF\n" + h + "\n" + half + "\n" + body[len(half):] + "\n" + f + "\nEOF",
		"json-escaped": `{"content":"` + h + `\n` + half + `\n` + body[len(half):] + `\n` + f + `"}`,
		"no-end":       "echo '" + h + "\n" + body,
	} {
		out := MaskSecrets(in)
		if strings.Contains(out, half[:24]) || strings.Contains(out, body[len(half):len(half)+24]) {
			t.Errorf("%s: key body survived masking: %q", name, out)
		}
		if !strings.Contains(out, "-----BEGIN …[PRIVATE_KEY_BLOCK sha256:") {
			t.Errorf("%s: masked form missing: %q", name, out)
		}
		if name != "no-end" && strings.Contains(out, "-----END") {
			t.Errorf("%s: footer left behind: %q", name, out)
		}
	}
	// The masked fingerprint names the key the way SecretFingerprints does.
	in := h + "\n" + body + "\n" + f
	fp := SecretFingerprints([]byte(in))
	if len(fp) != 1 || !strings.Contains(MaskSecrets(in), fp[0].Fingerprint) {
		t.Errorf("mask %q vs fingerprint %+v", MaskSecrets(in), fp)
	}
}

func TestMaskTruncateNeverCutsAValueOpen(t *testing.T) {
	cmd := "curl -H 'Authorization: token " + fpGitHub + "' https://x.example"
	for n := 1; n < len(cmd)+5; n++ {
		out := MaskTruncate(cmd, n)
		// No run of the value's body beyond its literal prefix may appear.
		for k := 4; k+6 <= len(fpGitHub); k++ {
			if strings.Contains(out, fpGitHub[k:k+6]) {
				t.Fatalf("n=%d leaked part of the value: %q", n, out)
			}
		}
	}
	// A malformed, too-short token cut at the end is reduced to its prefix.
	if got := MaskTruncate("export T=ghp_abc123 && run", 15); got != "export T=ghp_…[cut]" {
		t.Errorf("partial token: %q", got)
	}
	// A cut inside the prefix drops the partial prefix.
	if got := MaskTruncate("x AKIAQW3", 5); got != "x …[cut]" {
		t.Errorf("cut inside prefix: %q", got)
	}
	if got := MaskTruncate("use the disk", 8); got != "use the …" {
		t.Errorf("ordinary words over-masked: %q", got)
	}
	_, body, _ := pemParts()
	if out := MaskTruncate(strings.Repeat("a", 20)+" "+"-----BEGIN PRIV"+"ATE KEY-----\n"+body, 40); strings.Contains(out, body[:10]) {
		t.Errorf("key body after cut: %q", out)
	}
}
