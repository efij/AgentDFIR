package cli

import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/casepkg"
)

// zipTree writes files (in-archive path → content) into a zip.
func zipTree(t *testing.T, files map[string]string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "export.zip")
	f, err := os.Create(p)
	if err != nil {
		t.Fatal(err)
	}
	zw := zip.NewWriter(f)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	f.Close()
	return p
}

func fixture(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "parsers", "aiexport", "testdata", filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func rulesByPath(t *testing.T, pkg string) map[string]string {
	t.Helper()
	man, err := casepkg.ReadManifest(pkg)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, a := range man.Current() {
		out[a.LogicalPath] = a.CollectorRule
	}
	return out
}

func TestCollectAIExportZip(t *testing.T) {
	zp := zipTree(t, map[string]string{
		"conversations.json":      fixture(t, "chatgpt/conversations.json"),
		"user.json":               fixture(t, "chatgpt/user.json"),
		"chat.html":               "<html>view</html>",
		"dalle-generations/a.png": "\x89PNG",
	})
	out := filepath.Join(t.TempDir(), "x.adfir")
	if code := Main([]string{"collect", "--ai-export", zp, "--out", out, "--case-id", "AIX", "--no-sign"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	info, err := casepkg.ReadCaseInfo(out)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(zp)
	sum := sha256.Sum256(data)
	n := info.Notes
	if n["mode"] != "ai-export" || n["ai_export_sha256"] != hex.EncodeToString(sum[:]) || n["ai_export_services"] != "chatgpt" ||
		!strings.Contains(n["ai_export_detected"], "conversations.json=chatgpt/conversations/mapping-tree") {
		t.Fatalf("notes: %+v", n)
	}
	r := rulesByPath(t, out)
	want := map[string]string{
		"conversations.json":      "aiexport.conversations",
		"user.json":               "aiexport.metadata",
		"chat.html":               "aiexport.file",
		"dalle-generations/a.png": "aiexport.file",
	}
	for k, v := range want {
		if r[k] != v {
			t.Errorf("%s: %q want %q", k, r[k], v)
		}
	}

	// A directory with no export file is refused, not sealed empty.
	empty := t.TempDir()
	_ = os.WriteFile(filepath.Join(empty, "notes.txt"), []byte("x"), 0o644)
	if code := Main([]string{"collect", "--ai-export", empty, "--out", filepath.Join(t.TempDir(), "e.adfir"), "--no-sign"}); code != 1 {
		t.Fatalf("no-export dir: exit %d", code)
	}
}

func TestCollectArchiveRecognizesExportAndUFDR(t *testing.T) {
	zp := zipTree(t, map[string]string{
		"claude-export/conversations.json": fixture(t, "claude/conversations.json"),
		"claude-export/users.json":         fixture(t, "claude/users.json"),
	})
	out := filepath.Join(t.TempDir(), "a.adfir")
	if code := Main([]string{"collect", "--archive", zp, "--out", out, "--no-sign"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	r := rulesByPath(t, out)
	if r["claude-export/conversations.json"] != "aiexport.conversations" || len(r) != 2 {
		t.Fatalf("archive export: %+v (must not also be kept as archive.sessions)", r)
	}
	info, _ := casepkg.ReadCaseInfo(out)
	if info.Notes["mode"] != "archive" || info.Notes["ai_export_services"] != "claude-ai" {
		t.Fatalf("notes: %+v", info.Notes)
	}

	ufdr := zipTree(t, map[string]string{
		"report.xml":                          `<?xml version="1.0"?><project name="x" xmlns="http://pa.cellebrite.com/report/2.0"></project>`,
		"files/Image/photo.jpg":               "\xff\xd8",
		"files/Document/chatgpt/user.json":    fixture(t, "chatgpt/user.json"),
		"files/Document/chatgpt/convers.json": fixture(t, "chatgpt/conversations-001.json"),
	})
	out2 := filepath.Join(t.TempDir(), "u.adfir")
	if code := Main([]string{"collect", "--archive", ufdr, "--out", out2, "--no-sign"}); code != 0 {
		t.Fatalf("ufdr exit %d", code)
	}
	r = rulesByPath(t, out2)
	if r["report.xml"] != "ufdr.report" || r["files/Image/photo.jpg"] != "ufdr.file" || r["files/Document/chatgpt/convers.json"] != "aiexport.conversations" {
		t.Fatalf("ufdr: %+v", r)
	}
	info, _ = casepkg.ReadCaseInfo(out2)
	if !strings.Contains(info.Notes["ufdr"], "report.xml semantics not parsed") {
		t.Fatalf("ufdr notes: %+v", info.Notes)
	}
}

func TestCollectImportFindsExport(t *testing.T) {
	tree := t.TempDir()
	p := filepath.Join(tree, "Users", "x", "Downloads", "gpt", "conversations.json")
	_ = os.MkdirAll(filepath.Dir(p), 0o755)
	if err := os.WriteFile(p, []byte(fixture(t, "chatgpt/conversations-001.json")), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.WriteFile(filepath.Join(tree, "Users", "x", "Downloads", "other.json"), []byte(`{"a":1}`), 0o644)
	out := filepath.Join(t.TempDir(), "i.adfir")
	if code := Main([]string{"collect", "--import", tree, "--out", out, "--no-sign"}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	r := rulesByPath(t, out)
	if r["Users/x/Downloads/gpt/conversations.json"] != "aiexport.conversations" || len(r) != 1 {
		t.Fatalf("import: %+v", r)
	}
	// A tree with neither profiles nor exports still fails as before.
	if code := Main([]string{"collect", "--import", t.TempDir(), "--out", filepath.Join(t.TempDir(), "n.adfir"), "--no-sign"}); code != 1 {
		t.Fatalf("empty import: exit %d", code)
	}
}
