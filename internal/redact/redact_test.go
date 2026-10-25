package redact

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustParse(t *testing.T, spec string) *Redactor {
	t.Helper()
	r, err := Parse(spec)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestCategories(t *testing.T) {
	r := mustParse(t, "secrets,emails,paths,ips")
	key := "AKIA" + "Q3EGRZJ7LMN2PX4T"
	in := "export K=" + key + " mail ops@example.org; cat /Users/alice/.aws/credentials; curl http://10.1.2.3/x; ping fe80::1; v1.2.3.4.5 at 14:00:05 std::string src/main.go https://host/a/b"
	out := r.String(in, "event e1.summary")
	for _, leak := range []string{key, "ops@example.org", "/Users/alice", "10.1.2.3", "fe80::1"} {
		if strings.Contains(out, leak) {
			t.Errorf("value %q survived: %s", leak, out)
		}
	}
	for _, keep := range []string{"v1.2.3.4.5", "14:00:05", "std::string", "src/main.go", "https://host/a/b"} {
		if !strings.Contains(out, keep) {
			t.Errorf("non-sensitive text %q was masked: %s", keep, out)
		}
	}
	if !strings.Contains(out, Marker(Secret, key)) {
		t.Errorf("secret marker missing: %s", out)
	}
	tot := r.Totals()
	if tot[Secret] != 1 || tot[Email] != 1 || tot[Path] != 1 || tot[IP] != 2 {
		t.Errorf("totals = %v", tot)
	}
	for _, e := range r.Log() {
		if e.Location != "event e1.summary" || e.Count == 0 {
			t.Errorf("bad log entry %+v", e)
		}
		if strings.Contains(e.Kind+e.Category+e.Location, "alice") {
			t.Errorf("log leaks a value: %+v", e)
		}
	}
}

func TestIdempotentAndMarkersSafe(t *testing.T) {
	r := mustParse(t, "all")
	once := r.String("C:\\Users\\bob\\secret.txt and /home/bob/x/y", "x")
	twice := r.String(once, "x")
	if once != twice {
		t.Errorf("second pass changed output:\n%s\n%s", once, twice)
	}
	if strings.Contains(once, "bob") {
		t.Errorf("path survived: %s", once)
	}
}

func TestPrivateKeyBodyMasked(t *testing.T) {
	r := mustParse(t, "secrets")
	pem := "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAxyz0123456789abcdefABCDEF\n-----END RSA PRIVATE KEY-----"
	out := r.String("key: "+pem+" tail", "f")
	if strings.Contains(out, "MIIEow") || !strings.HasSuffix(out, " tail") {
		t.Errorf("private key not fully masked: %q", out)
	}
	// No END marker: the rest of the value is masked rather than leaked.
	out = r.String("-----BEGIN PRIVATE KEY-----\nMIIEow-truncated", "f")
	if strings.Contains(out, "MIIEow") {
		t.Errorf("unterminated key body survived: %q", out)
	}
}

func TestCustomFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "re.txt")
	os.WriteFile(p, []byte("# project codenames\nPROJECT-[A-Z]+\n\n"), 0o600)
	r := mustParse(t, "custom:"+p)
	if out := r.String("about PROJECT-ORCA today", "n"); strings.Contains(out, "ORCA") {
		t.Errorf("custom pattern not applied: %s", out)
	}
	sp := r.Spec()
	if sp.CustomPatterns != 1 || len(sp.CustomSHA256) != 64 {
		t.Errorf("spec = %+v", sp)
	}
	for name, body := range map[string]string{"empty.txt": "a*\n", "bad.txt": "([\n", "none.txt": "# only\n"} {
		q := filepath.Join(dir, name)
		os.WriteFile(q, []byte(body), 0o600)
		if _, err := Parse("custom:" + q); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	big := filepath.Join(dir, "big.txt")
	os.WriteFile(big, []byte(strings.Repeat("x", maxCustomBytes+10)), 0o600)
	if _, err := Parse("custom:" + big); err == nil {
		t.Error("oversized pattern file accepted")
	}
}

func TestParseErrors(t *testing.T) {
	if r, err := Parse(""); r != nil || err != nil {
		t.Error("empty spec should mean no redaction")
	}
	for _, bad := range []string{"secrets,bogus", ",", "custom:"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) accepted", bad)
		}
	}
	var nilR *Redactor
	if nilR.String("a@b.co", "x") != "a@b.co" || nilR.Log() != nil {
		t.Error("nil redactor must be a no-op")
	}
}

type inner struct {
	Note string            `json:"note"`
	Tags map[string]string `json:"tags"`
	Any  map[string]any    `json:"any"`
	skip string
}
type outer struct {
	Name  string   `json:"name"`
	List  []string `json:"list"`
	In    *inner   `json:"in"`
	Ignor string   `json:"-"`
}

func TestWalk(t *testing.T) {
	r := mustParse(t, "emails")
	v := &outer{Name: "a@x.io", List: []string{"ok", "b@x.io"}, Ignor: "c@x.io",
		In: &inner{Note: "d@x.io", Tags: map[string]string{"e@x.io": "f@x.io"},
			Any: map[string]any{"k": []any{"g@x.io", 3}}, skip: "h@x.io"}}
	r.Walk(v, "root")
	all := v.Name + strings.Join(v.List, "") + v.In.Note
	for k, val := range v.In.Tags {
		all += k + val
	}
	all += v.In.Any["k"].([]any)[0].(string)
	if strings.Contains(all, "@x.io") {
		t.Errorf("walk missed a value: %s", all)
	}
	if v.Ignor != "c@x.io" || v.In.skip != "h@x.io" {
		t.Error("walk touched a json:\"-\" or unexported field")
	}
	if r.Totals()[Email] != 6 {
		t.Errorf("email count = %d, want 6", r.Totals()[Email])
	}
}
