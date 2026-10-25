package export_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"io"
	"io/fs"
	"mime"
	"mime/multipart"
	"net/mail"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/efij/AgentDFIR/v4/internal/analysis"
	"github.com/efij/AgentDFIR/v4/internal/casepkg"
	"github.com/efij/AgentDFIR/v4/internal/collector"
	"github.com/efij/AgentDFIR/v4/internal/export"
	"github.com/efij/AgentDFIR/v4/internal/notes"
	"github.com/efij/AgentDFIR/v4/internal/products"
	"github.com/efij/AgentDFIR/v4/internal/redact"
	"github.com/efij/AgentDFIR/v4/internal/report"
)

// Synthetic values that must never appear in a redacted derivative.
const (
	fakeKey   = "AKIA" + "Q3EGRZJ7LMN2PX4T"
	fakeMail  = "alice.ops@corp-example.org"
	fakePath  = "/Users/alice/secret-project/notes.txt"
	sessionID = "7e1d0c4a-4444-4b5c-8d9e-dddddddddddd"
)

// writeProfile writes one synthetic Claude Code session: a prompt with an
// email address, a tool call that reads a path, a tool result holding a
// credential-shaped value, a malformed line (a trace gap) and an answer.
func writeProfile(t *testing.T, root string, empty bool) {
	t.Helper()
	proj := filepath.Join(root, ".claude", "projects", "-Users-alice-app")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(root, ".claude.json"), []byte(`{"numStartups":1}`+"\n"), 0o644)
	if empty {
		return
	}
	s := sessionID
	lines := []string{
		`{"type":"user","uuid":"u1","sessionId":"` + s + `","timestamp":"2026-09-01T10:00:00Z","isSidechain":false,"version":"2.1.0","cwd":"/Users/alice/app","message":{"role":"user","content":"check the notes and mail ` + fakeMail + ` when done"}}`,
		`{"type":"assistant","uuid":"a1","parentUuid":"u1","sessionId":"` + s + `","timestamp":"2026-09-01T10:00:04Z","isSidechain":false,"version":"2.1.0","message":{"role":"assistant","model":"claude-sonnet-5","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"cat ` + fakePath + `"}}]}}`,
		`{"type":"user","uuid":"u2","parentUuid":"a1","sessionId":"` + s + `","timestamp":"2026-09-01T10:00:05Z","isSidechain":false,"version":"2.1.0","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_1","content":"key=` + fakeKey + `"}]}}`,
		`{"type":"assistant", this line is truncated`,
		`{"type":"assistant","uuid":"a2","parentUuid":"u2","sessionId":"` + s + `","timestamp":"2026-09-01T10:00:09Z","isSidechain":false,"version":"2.1.0","message":{"role":"assistant","model":"claude-sonnet-5","content":[{"type":"text","text":"Done. I emailed ` + fakeMail + `."}]}}`,
	}
	if err := os.WriteFile(filepath.Join(proj, s+".jsonl"), []byte(strings.Join(lines, "\n")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

// build collects the synthetic profile into a sealed, analyzed package.
func build(t *testing.T, empty bool) string {
	t.Helper()
	t.Setenv("AGENTDFIR_HOME", t.TempDir())
	t.Setenv("AGENTDFIR_MIN_FREE_GB", "1")
	root := filepath.Join(t.TempDir(), "home")
	writeProfile(t, root, empty)
	abs, _ := filepath.Abs(root)
	pkg := filepath.Join(t.TempDir(), "case.adfir")
	b, err := casepkg.New(pkg, "PROD-1", casepkg.CaseInfo{OperatorOSUser: "tester", OperatorAsserted: "Jane Examiner", Authorization: "IR-TEST"})
	if err != nil {
		t.Fatal(err)
	}
	man, err := products.ManifestAllPlatforms("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := collector.Run(b, man, collector.Options{ProfileRoot: abs, ConfigRoot: filepath.Join(abs, ".claude"), SystemRoot: abs, Product: "claude-code"}); err != nil {
		t.Fatal(err)
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	b.Close()
	if _, err := analysis.Run(pkg, analysis.Options{}); err != nil {
		t.Fatal(err)
	}
	return pkg
}

func loadCase(t *testing.T, pkg string) *report.Case {
	t.Helper()
	man, err := report.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	ci, _ := report.ReadCaseInfo(pkg)
	vres, err := casepkg.Verify(pkg)
	if err != nil {
		t.Fatal(err)
	}
	c := &report.Case{Manifest: man, CaseInfo: ci, Verify: vres,
		Events: analysis.LoadEvents(pkg), Entities: analysis.LoadEntities(pkg), Findings: analysis.LoadFindings(pkg)}
	if st, _ := notes.Open(pkg).Load(); st.Records > 0 {
		c.Notes = st
	}
	return c
}

var fixedTime = time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

func produce(t *testing.T, pkg, spec string, at time.Time) (string, *export.ProductionResult) {
	t.Helper()
	r, err := redact.Parse(spec)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "prod")
	res, err := export.Produce(pkg, loadCase(t, pkg), export.ProductionOptions{Out: out, Redactor: r,
		Examiner: "E. Xaminer", ProducedAt: at, ProducedAtSource: "--produced-at", BinarySHA256: "deadbeef"})
	if err != nil {
		t.Fatal(err)
	}
	return out, res
}

// treeHashes hashes every file under dir by relative path.
func treeHashes(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(b)
		rel, _ := filepath.Rel(dir, p)
		out[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestProductionNeverTouchesThePackage(t *testing.T) {
	pkg := build(t, false)
	before := treeHashes(t, pkg)
	out, res := produce(t, pkg, "secrets,emails,paths,ips", fixedTime)
	after := treeHashes(t, pkg)
	if len(before) != len(after) {
		t.Fatalf("package file count changed: %d -> %d", len(before), len(after))
	}
	for p, h := range before {
		if after[p] != h {
			t.Errorf("package file %s changed during a redacted production", p)
		}
	}
	if v, err := casepkg.Verify(pkg); err != nil || len(v.Problems) > 0 {
		t.Fatalf("package no longer verifies: %v %v", err, v)
	}

	// The sealed/derived package data still holds the values; the
	// production does not.
	ev, _ := os.ReadFile(filepath.Join(pkg, "normalized", "events.jsonl"))
	if !bytes.Contains(ev, []byte(fakeKey)) && !bytes.Contains(ev, []byte(fakeMail)) {
		t.Skip("parser no longer surfaces the planted values; redaction check is vacuous")
	}
	for rel := range treeHashes(t, out) {
		b, _ := os.ReadFile(filepath.Join(out, filepath.FromSlash(rel)))
		raw := string(b) + decodeRSMFZip(t, b)
		for _, leak := range []string{fakeKey, fakeMail, "/Users/alice/secret-project"} {
			if strings.Contains(raw, leak) {
				t.Errorf("%s leaks %q", rel, leak)
			}
		}
	}
	tot := res.Manifest.Redaction.Totals
	if tot["secret"] == 0 || tot["email"] == 0 || tot["path"] == 0 {
		t.Errorf("redaction totals missing categories: %v", tot)
	}
	for _, e := range res.Manifest.Redaction.Log {
		if e.Location == "" || e.Count <= 0 {
			t.Errorf("bad redaction log entry %+v", e)
		}
	}
}

func TestProductionReproducible(t *testing.T) {
	pkg := build(t, false)
	a, _ := produce(t, pkg, "secrets,emails", fixedTime)
	b, _ := produce(t, pkg, "secrets,emails", fixedTime)
	ha, hb := treeHashes(t, a), treeHashes(t, b)
	if len(ha) == 0 || len(ha) != len(hb) {
		t.Fatalf("file sets differ: %d vs %d", len(ha), len(hb))
	}
	for p, h := range ha {
		if hb[p] != h {
			t.Errorf("%s differs between identical runs", p)
		}
	}
	// A different produced_at changes only the files the manifest names.
	c, res := produce(t, pkg, "secrets,emails", fixedTime.Add(time.Hour))
	follows := map[string]bool{}
	for _, f := range res.Manifest.Reproducibility.FilesFollowing {
		follows[f] = true
	}
	for p, h := range treeHashes(t, c) {
		if !follows[p] && ha[p] != h {
			t.Errorf("%s changed with produced_at but is not listed as following it", p)
		}
	}
	var m1, m2 map[string]any
	j1, _ := os.ReadFile(filepath.Join(a, export.ProductionManifestJSON))
	j2, _ := os.ReadFile(filepath.Join(c, export.ProductionManifestJSON))
	json.Unmarshal(j1, &m1)
	json.Unmarshal(j2, &m2)
	if m1["produced_at"] == m2["produced_at"] {
		t.Error("produced_at did not change")
	}
}

func TestProductionTraceabilityAndManifest(t *testing.T) {
	pkg := build(t, false)
	out, res := produce(t, pkg, "", fixedTime)
	m := res.Manifest

	// Every listed file exists with the stated hash; nothing unlisted.
	disk := treeHashes(t, out)
	listed := map[string]bool{export.ProductionManifestJSON: true, export.ProductionManifestCSV: true}
	for _, f := range m.Files {
		listed[f.Path] = true
		if disk[f.Path] != f.SHA256 {
			t.Errorf("%s: manifest sha256 %s, disk %s", f.Path, f.SHA256, disk[f.Path])
		}
	}
	for p := range disk {
		if !listed[p] {
			t.Errorf("produced file %s is not in the manifest", p)
		}
	}

	// Every RSMF event is traced to a source artifact and line, and each
	// RSMF file validates.
	tf, err := os.Open(filepath.Join(out, "traceability.csv"))
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(tf).ReadAll()
	tf.Close()
	if err != nil {
		t.Fatal(err)
	}
	traced := map[string]bool{}
	for _, r := range rows[1:] {
		if strings.HasPrefix(r[0], "rsmf/") {
			if r[3] == "" || r[5] == "0" || r[5] == "" {
				t.Errorf("rsmf event %s has no source ref: %v", r[1], r)
			}
			traced[r[0]+"|"+r[1]] = true
		}
	}
	rsmfFiles := 0
	for _, f := range m.Files {
		if f.Kind != "rsmf" {
			continue
		}
		rsmfFiles++
		data, _ := os.ReadFile(filepath.Join(out, f.Path))
		if probs := report.ValidateRSMF(data); len(probs) > 0 {
			t.Errorf("%s invalid: %v", f.Path, probs)
		}
		if f.Items == 0 || len(f.DerivedFrom) == 0 {
			t.Errorf("%s has no derivation: %+v", f.Path, f)
		}
	}
	if rsmfFiles != 1 {
		t.Errorf("want one RSMF file for the one session, got %d", rsmfFiles)
	}
	if len(traced) != m.Traceability.EventsProduced || m.Traceability.WithoutSource != 0 {
		t.Errorf("traceability incomplete: %d traced, summary %+v", len(traced), m.Traceability)
	}

	// The malformed line is a listed limitation with its source line.
	var gap bool
	for _, l := range m.Limitations {
		if l.Code == "TRACE_GAP" && l.Count > 0 && strings.Contains(l.Refs[0], "line ") {
			gap = true
		}
	}
	if !gap {
		t.Errorf("TRACE_GAP missing from limitations: %+v", m.Limitations)
	}
	if m.Examiner.Name != "E. Xaminer" || m.Case.SealDigest == "" || m.Tool.BinarySHA256 != "deadbeef" || m.Case.Integrity != "VERIFIED" {
		t.Errorf("identity fields: examiner=%+v case=%+v tool=%+v", m.Examiner, m.Case, m.Tool)
	}
	var stages int
	for _, h := range m.History {
		if h.Source == "this_production" {
			stages++
		}
		if h.Source == "sealed_custody_log" && h.Event == "package_sealed" {
			stages += 100
		}
	}
	if stages < 105 {
		t.Errorf("processing history lacks the seal record or this run's stages: %+v", m.History)
	}
	if m.Redaction.Applied {
		t.Error("no --redact given but redaction marked applied")
	}
}

func TestProductionEmptyAndRefusals(t *testing.T) {
	pkg := build(t, true)
	out, res := produce(t, pkg, "", fixedTime)
	var noEvents bool
	for _, l := range res.Manifest.Limitations {
		noEvents = noEvents || l.Code == "NO_EVENTS"
	}
	if !noEvents {
		t.Errorf("empty case should list NO_EVENTS: %+v", res.Manifest.Limitations)
	}
	for _, f := range res.Manifest.Files {
		if f.Kind == "rsmf" {
			t.Errorf("empty case produced an RSMF file %s", f.Path)
		}
	}
	c := loadCase(t, pkg)
	if _, err := export.Produce(pkg, c, export.ProductionOptions{Out: out}); err == nil {
		t.Error("non-empty output directory accepted")
	}
	if _, err := export.Produce(pkg, c, export.ProductionOptions{Out: filepath.Join(pkg, "prod")}); err == nil {
		t.Error("output inside the package accepted")
	}
	if _, err := os.Stat(filepath.Join(pkg, "prod")); err == nil {
		t.Error("refused production still created a directory inside the package")
	}
	if _, err := export.Produce(pkg, nil, export.ProductionOptions{Out: t.TempDir()}); err == nil {
		t.Error("nil case accepted")
	}
}

// TestRedactionCoversEveryOutput plants a secret, an email, a path, an IP
// and a custom-pattern value in the integrity problems (free text the
// manifest quotes) on top of the transcript values, runs every --redact
// category, and greps every produced file for each value.
func TestRedactionCoversEveryOutput(t *testing.T) {
	pkg := build(t, false)
	before := treeHashes(t, pkg)
	c := loadCase(t, pkg)
	c.Verify.Problems = append(c.Verify.Problems,
		"raw/blob: sha256 mismatch near "+fakeKey+" mailed to "+fakeMail+" from "+fakePath+" via 10.20.30.40 tag CODENAME-ORCA")
	pat := filepath.Join(t.TempDir(), "custom.txt")
	os.WriteFile(pat, []byte("CODENAME-[A-Z]+\n"), 0o600)
	r, err := redact.Parse("secrets,emails,paths,ips,custom:" + pat)
	if err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(t.TempDir(), "prod")
	res, err := export.Produce(pkg, c, export.ProductionOptions{Out: out, Redactor: r, Examiner: "examiner@corp-example.org", ProducedAt: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	var integ bool
	for _, l := range res.Manifest.Limitations {
		integ = integ || l.Code == "INTEGRITY_FAILED"
	}
	if !integ {
		t.Fatal("INTEGRITY_FAILED not listed")
	}
	leaks := []string{fakeKey, fakeMail, "/Users/alice/secret-project", "10.20.30.40", "CODENAME-ORCA"}
	for rel := range treeHashes(t, out) {
		b, _ := os.ReadFile(filepath.Join(out, filepath.FromSlash(rel)))
		raw := string(b) + decodeRSMFZip(t, b)
		for _, leak := range leaks {
			if strings.Contains(raw, leak) {
				t.Errorf("%s leaks %q", rel, leak)
			}
		}
	}
	// The examiner is the producing party and is never redacted.
	m, _ := os.ReadFile(filepath.Join(out, export.ProductionManifestJSON))
	if !strings.Contains(string(m), `"name": "examiner@corp-example.org"`) || !strings.Contains(string(m), "examiner identity is never redacted") {
		t.Error("examiner identity was redacted or the redaction log does not say it never is")
	}
	for p, h := range treeHashes(t, pkg) {
		if before[p] != h {
			t.Errorf("package file %s changed", p)
		}
	}
}

func TestProductionSessionScope(t *testing.T) {
	pkg := build(t, false)
	r, _ := redact.Parse("")
	out := filepath.Join(t.TempDir(), "p")
	res, err := export.Produce(pkg, loadCase(t, pkg), export.ProductionOptions{Out: out, Redactor: r,
		Sessions: []string{"no-such-session"}, ProducedAt: fixedTime})
	if err != nil {
		t.Fatal(err)
	}
	if res.Manifest.Traceability.EventsInScope != 0 {
		t.Errorf("session filter ignored: %+v", res.Manifest.Traceability)
	}
	var scoped bool
	for _, l := range res.Manifest.Limitations {
		scoped = scoped || l.Code == "SCOPE_LIMITED_TO_SESSIONS"
	}
	if !scoped {
		t.Error("scope limitation not recorded")
	}
}

// decodeRSMFZip returns the text of rsmf.zip entries when b is an RSMF
// message, so leak checks see inside the attachment.
func decodeRSMFZip(t *testing.T, b []byte) string {
	t.Helper()
	if !bytes.Contains(b, []byte("X-RSMF-Version")) {
		return ""
	}
	msg, err := mail.ReadMessage(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	_, params, _ := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	mr := multipart.NewReader(msg.Body, params["boundary"])
	var all strings.Builder
	for {
		p, err := mr.NextPart()
		if err != nil {
			break
		}
		if p.FileName() != "rsmf.zip" {
			continue
		}
		z, _ := io.ReadAll(base64.NewDecoder(base64.StdEncoding, p))
		zr, err := zip.NewReader(bytes.NewReader(z), int64(len(z)))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range zr.File {
			rc, _ := f.Open()
			data, _ := io.ReadAll(rc)
			rc.Close()
			all.Write(data)
		}
	}
	return all.String()
}
