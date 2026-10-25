package analysis

import (
	"bytes"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"hash"
	"os"
	"path/filepath"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/fingerprint"
	"github.com/efij/AgentDFIR/v4/internal/overlay"
	"github.com/efij/AgentDFIR/v4/internal/repro"
	"github.com/efij/AgentDFIR/v4/internal/version"
)

// sealedOnly copies a package without its overlay.
func sealedOnly(t *testing.T, src string) string {
	t.Helper()
	dst := copyPkg(t, src)
	for _, d := range []string{"normalized", "detections", "index", "reports"} {
		if err := os.RemoveAll(filepath.Join(dst, d)); err != nil {
			t.Fatal(err)
		}
	}
	return dst
}

func TestManifestRecordsWhatDecided(t *testing.T) {
	pkg := buildPkg(t)
	audit := auditLog(t)
	rules := t.TempDir()
	if err := os.WriteFile(filepath.Join(rules, "extra.json"), []byte(`{"pack":"extra","version":"1","rules":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	sums, _ := os.ReadFile(filepath.Join(pkg, "SHA256SUMS"))
	res, err := Run(pkg, Options{EndpointLogs: []string{audit}, RulesDir: rules, Honeytokens: []string{"canary-1", "", "canary-2"}})
	if err != nil {
		t.Fatal(err)
	}
	m, err := repro.Read(repro.Path(pkg))
	if err != nil {
		t.Fatal(err)
	}
	if m.Tool.Version != version.Version || m.Tool.AnalysisFingerprint != fingerprint.Analysis() || m.Tool.GoVersion == "" || m.Tool.OS == "" {
		t.Errorf("tool identity: %+v", m.Tool)
	}
	if m.RuleSet.BuiltinFingerprint != fingerprint.Analysis() || !m.RuleSet.BuiltinPacks || len(m.RuleSet.Packs) == 0 {
		t.Errorf("rule set: %+v", m.RuleSet)
	}
	for _, p := range m.RuleSet.Packs {
		if p.Origin == "embedded" && len(p.SHA256) != 64 {
			t.Errorf("embedded pack %s has no hash", p.Pack)
		}
	}
	if len(m.RuleSet.RulesDirFiles) != 1 || len(m.RuleSet.RulesDirFiles[0].SHA256) != 64 {
		t.Errorf("rules dir files: %+v", m.RuleSet.RulesDirFiles)
	}
	if len(m.Options.EndpointLogs) != 1 || m.Options.EndpointLogs[0].Path != audit || len(m.Options.EndpointLogs[0].SHA256) != 64 {
		t.Errorf("endpoint logs: %+v", m.Options.EndpointLogs)
	}
	if m.Options.Honeytokens != 2 {
		t.Errorf("honeytokens: %d", m.Options.Honeytokens)
	}
	data, _ := os.ReadFile(repro.Path(pkg))
	if bytes.Contains(data, []byte("canary-1")) || bytes.Contains(data, []byte("honeytokens_sha256")) {
		t.Error("the manifest must not carry honeytoken values or a digest of them")
	}
	// No hash derived from the tokens, in any common framing, anywhere.
	for _, form := range []string{"canary-1\ncanary-2\n", "canary-1\ncanary-2", "canary-1", "canary-2", "canary-1canary-2", "canary-1\n\ncanary-2\n"} {
		for _, h := range []hash.Hash{sha256.New(), sha1.New(), md5.New(), sha512.New()} {
			h.Write([]byte(form))
			if d := hex.EncodeToString(h.Sum(nil)); bytes.Contains(data, []byte(d)) || bytes.Contains(data, []byte(d[:16])) {
				t.Errorf("the manifest contains a hash derived from the honeytokens (%q)", form)
			}
		}
	}
	if m.Input.SealSHA256 == "" || m.Input.InputsDigest == "" || m.Input.CaseID != "AN" || m.Input.ManifestSHA256 == "" {
		t.Errorf("input: %+v", m.Input)
	}
	if m.Findings.Count != len(res.Findings) || m.Findings.Algorithm != repro.FindingsAlgorithm {
		t.Errorf("findings summary: %+v (have %d)", m.Findings, len(res.Findings))
	}
	if m.FindingsFingerprint != repro.Fingerprint(repro.RoundTrip(res.Findings)) {
		t.Error("fingerprint does not match the findings")
	}
	// It is overlay data: the seal is untouched, and the whole overlay checks.
	after, _ := os.ReadFile(filepath.Join(pkg, "SHA256SUMS"))
	if !bytes.Equal(sums, after) {
		t.Fatal("writing the manifest changed the seal")
	}
	if c := repro.CheckOverlay(pkg); len(c.Problems) > 0 || len(c.Checked) < 2 {
		t.Fatalf("overlay check: %+v", c)
	}
}

// Determinism with a second witness: correlation, lineage and the host
// witness all run, twice, from the sealed zone alone.
func TestAnalysisWithEndpointLogIsDeterministic(t *testing.T) {
	pkg := buildPkg(t)
	audit := auditLog(t)
	var fps []string
	var files, graphs [][]byte
	for i := 0; i < 3; i++ {
		p := sealedOnly(t, pkg)
		if _, err := Run(p, Options{EndpointLogs: []string{audit}}); err != nil {
			t.Fatal(err)
		}
		m, err := repro.Read(repro.Path(p))
		if err != nil {
			t.Fatal(err)
		}
		f, _ := overlay.ReadFile(filepath.Join(p, "detections", "findings.json"))
		g, _ := overlay.ReadFile(filepath.Join(p, "normalized", "lineage.json"))
		fps, files, graphs = append(fps, m.FindingsFingerprint), append(files, f), append(graphs, g)
	}
	for i := 1; i < len(fps); i++ {
		if fps[i] != fps[0] || !bytes.Equal(files[i], files[0]) || !bytes.Equal(graphs[i], graphs[0]) {
			t.Fatalf("run %d differs from run 0: %s vs %s", i, fps[i], fps[0])
		}
	}
}

// A run that carries forward earlier correlation results says so: those
// findings depend on logs it did not read.
func TestManifestRecordsReusedCorrelation(t *testing.T) {
	pkg := buildPkg(t)
	if _, err := Run(pkg, Options{EndpointLogs: []string{auditLog(t)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := Run(pkg, Options{}); err != nil {
		t.Fatal(err)
	}
	m, err := repro.Read(repro.Path(pkg))
	if err != nil {
		t.Fatal(err)
	}
	if !m.Options.ReusedCorrelation {
		t.Fatalf("reused correlation not recorded: %+v", m.Options)
	}
}
