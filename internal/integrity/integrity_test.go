package integrity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/casepkg"
	"github.com/efij/AgentDFIR/v3/internal/seal"
	"github.com/efij/AgentDFIR/v3/internal/store"
)

func setHome(t *testing.T) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "home")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(store.EnvHome, dir)
}

// round seals one round with a file of the given content, signed with
// explicitKey (or the machine key when empty).
func round(t *testing.T, pkg, content, explicitKey string) {
	t.Helper()
	src := filepath.Join(t.TempDir(), "t.jsonl")
	if err := os.WriteFile(src, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	var b *casepkg.Builder
	var err error
	if _, statErr := os.Stat(pkg); statErr == nil {
		b, err = casepkg.Reopen(pkg, casepkg.CaseInfo{OperatorOSUser: "t"})
	} else {
		b, err = casepkg.New(pkg, "CASE-1", casepkg.CaseInfo{OperatorOSUser: "t"})
	}
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	if err := b.IngestFile(src, casepkg.ArtifactRecord{SourcePath: src, LogicalPath: "t.jsonl", ArtifactType: "transcript"}); err != nil {
		t.Fatal(err)
	}
	s := Prepare(explicitKey, false)
	if s.KeyPath == "" {
		t.Fatalf("no signing key: %s", s.Skipped)
	}
	b.Signer = s.Public
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	res, err := Finish(pkg, s, "CASE-1", b.Round(), true)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Signed || !res.Anchored {
		t.Fatalf("round not signed/anchored: %+v", res)
	}
}

func newCase(t *testing.T) string {
	setHome(t)
	pkg := filepath.Join(t.TempDir(), "c.adfir")
	round(t, pkg, "one\n", "")
	return pkg
}

func TestCleanCaseVerifies(t *testing.T) {
	pkg := newCase(t)
	p := CheckPrior(pkg, false)
	if p.Status != Verified || !p.Anchored || len(p.Problems) > 0 {
		t.Fatalf("clean signed case: %+v", p)
	}
	if full := CheckPrior(pkg, true); full.Status != Verified || full.Depth != "full" {
		t.Fatalf("full check: %+v", full)
	}
}

// Someone rewrites a sealed file and regenerates SHA256SUMS to match.
// Every hash in the package agrees again; the signature and the anchor
// do not.
func TestRewrittenSealFails(t *testing.T) {
	pkg := newCase(t)
	casePath := filepath.Join(pkg, "case.json")
	data, err := os.ReadFile(casePath)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(casePath, 0o600)
	forged := strings.Replace(string(data), `"operator_os_user": "t"`, `"operator_os_user": "someone-else"`, 1)
	if forged == string(data) {
		t.Fatal("forgery did not change case.json")
	}
	if err := os.WriteFile(casePath, []byte(forged), 0o600); err != nil {
		t.Fatal(err)
	}
	resealSums(t, pkg)
	p := CheckPrior(pkg, false)
	if p.Status != Failed {
		t.Fatalf("rewritten case passed: %+v", p)
	}
	if !contains(p.Problems, "signature") || !contains(p.Problems, "anchor") {
		t.Fatalf("want both the signature and the anchor to object: %v", p.Problems)
	}
}

// The forger also re-signs, with their own key. The case recorded which
// key its rounds were sealed for, so that fails too.
func TestResignedWithAnotherKeyFails(t *testing.T) {
	pkg := newCase(t)
	other := filepath.Join(t.TempDir(), "other.key")
	if err := seal.GenerateKey(other, other+".pub"); err != nil {
		t.Fatal(err)
	}
	if err := seal.Sign(pkg, other); err != nil {
		t.Fatal(err)
	}
	if p := CheckPrior(pkg, false); p.Status != Failed || !contains(p.Problems, "pinned key") {
		t.Fatalf("re-signed with another key: %+v", p)
	}
}

// A case restored from an older copy verifies internally — every file
// matches its own seal — but not against the anchor of the newer round.
func TestRollbackToAnEarlierRoundFails(t *testing.T) {
	pkg := newCase(t)
	backup := filepath.Join(t.TempDir(), "backup")
	if err := os.CopyFS(backup, os.DirFS(pkg)); err != nil {
		t.Fatal(err)
	}
	round(t, pkg, "one\ntwo\n", "")
	if p := CheckPrior(pkg, false); p.Status != Verified {
		t.Fatalf("after round 2: %+v", p)
	}
	chmodAll(t, pkg)
	if err := os.RemoveAll(pkg); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(pkg, os.DirFS(backup)); err != nil {
		t.Fatal(err)
	}
	if p := CheckPrior(pkg, false); p.Status != Failed || !contains(p.Problems, "anchor") {
		t.Fatalf("rolled-back case: %+v", p)
	}
}

// A blob swapped on disk is caught by the quick check's size test when
// the size changes, and by the full check always.
func TestSwappedBlobFails(t *testing.T) {
	pkg := newCase(t)
	raws, _ := filepath.Glob(filepath.Join(pkg, "raw", "*"))
	if len(raws) == 0 {
		t.Fatal("no blob")
	}
	info, _ := os.Stat(raws[0])
	_ = os.Chmod(raws[0], 0o600)
	junk := make([]byte, info.Size())
	for i := range junk {
		junk[i] = 'x'
	}
	if err := os.WriteFile(raws[0], junk, 0o600); err != nil {
		t.Fatal(err)
	}
	if p := CheckPrior(pkg, true); p.Status != Failed {
		t.Fatalf("same-size swapped blob passed the full check: %+v", p)
	}
}

// Before rounds were signed, `run --sign` signed before sealing, so its
// SEAL.sig never matched. That is reported and not trusted, but it is not
// evidence of tampering.
func TestLegacyMismatchedSignatureIsANoteNotAFailure(t *testing.T) {
	setHome(t)
	pkg := filepath.Join(t.TempDir(), "legacy.adfir")
	src := filepath.Join(t.TempDir(), "t.jsonl")
	_ = os.WriteFile(src, []byte("x\n"), 0o600)
	b, err := casepkg.New(pkg, "LEGACY", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	_ = b.IngestFile(src, casepkg.ArtifactRecord{SourcePath: src, LogicalPath: "t.jsonl"})
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(t.TempDir(), "k")
	_ = seal.GenerateKey(key, key+".pub")
	if err := seal.Sign(pkg, key); err != nil {
		t.Fatal(err)
	}
	// Rewrite SHA256SUMS after signing, as the old ordering did (the
	// round's seal was written after the signature).
	sums := filepath.Join(pkg, "SHA256SUMS")
	_ = os.Chmod(sums, 0o600)
	data, _ := os.ReadFile(sums)
	if err := os.WriteFile(sums, append([]byte("\n"), data...), 0o600); err != nil {
		t.Fatal(err)
	}
	if sig, _ := seal.Verify(pkg, ""); sig.Valid {
		t.Fatal("setup: the legacy signature still verifies")
	}
	p := CheckPrior(pkg, false)
	if p.Status == Failed || len(p.Notes) == 0 {
		t.Fatalf("legacy mismatch: %+v", p)
	}
}

// Each round archives the signature of the round before, and the new
// seal covers it: no signature is ever lost.
func TestSignaturesAreArchivedAndSealed(t *testing.T) {
	pkg := newCase(t)
	first, err := os.ReadFile(filepath.Join(pkg, seal.SigFile))
	if err != nil {
		t.Fatal(err)
	}
	round(t, pkg, "one\ntwo\n", "")
	archived, err := os.ReadFile(filepath.Join(pkg, "seals", seal.SigFile+".1"))
	if err != nil {
		t.Fatalf("round 1 signature not archived: %v", err)
	}
	if string(archived) != string(first) {
		t.Fatal("archived signature differs from round 1's")
	}
	sums, _ := os.ReadFile(filepath.Join(pkg, "SHA256SUMS"))
	if !strings.Contains(string(sums), "seals/"+seal.SigFile+".1") {
		t.Fatal("round 2's seal does not cover round 1's signature")
	}
	ci, err := casepkg.ReadCaseInfo(pkg)
	if err != nil {
		t.Fatal(err)
	}
	r2 := ci.Rounds[len(ci.Rounds)-1]
	if r2.PrevSealSHA256 == "" || r2.Signer == "" {
		t.Fatalf("round 2 record lacks its links: %+v", r2)
	}
}

// resealSums regenerates SHA256SUMS over the sealed zone — what someone
// covering their tracks would do.
func resealSums(t *testing.T, pkg string) {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(pkg, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(pkg, p)
		rel = filepath.ToSlash(rel)
		if rel == "SHA256SUMS" || rel == seal.SigFile || strings.HasPrefix(rel, "normalized/") || strings.HasPrefix(rel, ".") {
			return nil
		}
		sum, err := fileSHA(p)
		if err != nil {
			return err
		}
		lines = append(lines, sum+"  "+rel)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sums := filepath.Join(pkg, "SHA256SUMS")
	_ = os.Chmod(sums, 0o600)
	if err := os.WriteFile(sums, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func chmodAll(t *testing.T, dir string) {
	_ = filepath.WalkDir(dir, func(p string, _ os.DirEntry, _ error) error { return os.Chmod(p, 0o700) })
}

func contains(list []string, sub string) bool {
	for _, s := range list {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}
