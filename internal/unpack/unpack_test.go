package unpack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeTar(t *testing.T, gz bool, entries []tar.Header, bodies map[string]string) string {
	t.Helper()
	var buf bytes.Buffer
	var w io.WriteCloser = nopCloser{&buf}
	if gz {
		w = gzip.NewWriter(&buf)
	}
	tw := tar.NewWriter(w)
	for _, h := range entries {
		hh := h
		body := bodies[h.Name]
		if hh.Typeflag == tar.TypeReg {
			hh.Size = int64(len(body))
		}
		if hh.Mode == 0 {
			hh.Mode = 0o644
		}
		if err := tw.WriteHeader(&hh); err != nil {
			t.Fatal(err)
		}
		if hh.Typeflag == tar.TypeReg {
			tw.Write([]byte(body))
		}
	}
	tw.Close()
	w.Close()
	name := "a.tar"
	if gz {
		name = "a.tar.gz"
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

type nopCloser struct{ io.Writer }

func (nopCloser) Close() error { return nil }

func TestTarExtractionSafety(t *testing.T) {
	bodies := map[string]string{
		"root/.claude/settings.json":       `{"a":1}`,
		"root/.claude/projects/p/s1.jsonl": `{"type":"user"}` + "\n",
		"home/dev/.codex/config.toml":      `model="x"`,
		"etc/passwd":                       "root:x:0:0",
		"../../escape.txt":                 "evil",
		"/abs/path.txt":                    "abs",
		"workspaces/app/CLAUDE.md":         "# rules",
		"home/dev/big.bin":                 strings.Repeat("x", 3000),
		"home/dev/.claude/CLAUDE.md":       "# mem",
	}
	entries := []tar.Header{
		{Name: "root/", Typeflag: tar.TypeDir},
		{Name: "root/.claude/settings.json", Typeflag: tar.TypeReg},
		{Name: "root/.claude/projects/p/s1.jsonl", Typeflag: tar.TypeReg},
		{Name: "home/dev/.codex/config.toml", Typeflag: tar.TypeReg},
		{Name: "etc/passwd", Typeflag: tar.TypeReg},
		{Name: "../../escape.txt", Typeflag: tar.TypeReg},
		{Name: "/abs/path.txt", Typeflag: tar.TypeReg},
		{Name: "home/dev/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
		{Name: "dev/null", Typeflag: tar.TypeChar},
		{Name: "workspaces/app/CLAUDE.md", Typeflag: tar.TypeReg},
		{Name: "home/dev/big.bin", Typeflag: tar.TypeReg},
		{Name: "home/dev/.claude/CLAUDE.md", Typeflag: tar.TypeReg},
	}
	for _, gz := range []bool{false, true} {
		src := writeTar(t, gz, entries, bodies)
		kind, err := Kind(src)
		if err != nil || (gz && kind != "tar.gz") || (!gz && kind != "tar") {
			t.Fatalf("kind: %v %s", err, kind)
		}
		dest := t.TempDir()
		st, err := ExtractArchive(src, dest, Options{MaxEntryBytes: 2048})
		if err != nil {
			t.Fatal(err)
		}
		// escape + abs: abs is normalized (kept as abs/path.txt), escape refused.
		if st.Refused != 1 {
			t.Fatalf("refused=%d", st.Refused)
		}
		if _, err := os.Stat(filepath.Join(dest, "..", "..", "escape.txt")); err == nil {
			t.Fatal("traversal entry was written")
		}
		if _, err := os.Stat(filepath.Join(dest, "home/dev/link")); err == nil {
			t.Fatal("symlink was materialized")
		}
		if _, err := os.Stat(filepath.Join(dest, "home/dev/big.bin")); err == nil {
			t.Fatal("oversized entry was written")
		}
		if st.Skipped < 3 { // symlink, char device, oversized
			t.Fatalf("skipped=%d", st.Skipped)
		}
		if b, _ := os.ReadFile(filepath.Join(dest, "root/.claude/settings.json")); string(b) != `{"a":1}` {
			t.Fatal("content mismatch")
		}
		if st.Files != 7 || st.SHA256 == "" {
			t.Fatalf("files=%d sha=%q", st.Files, st.SHA256)
		}
	}
	// With the agent-home filter (docker mode) only agent files survive.
	src := writeTar(t, false, entries, bodies)
	dest := t.TempDir()
	st, err := ExtractArchive(src, dest, Options{Filter: AgentHomeFilter()})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"root/.claude/settings.json", "root/.claude/projects/p/s1.jsonl", "home/dev/.codex/config.toml", "workspaces/app/CLAUDE.md", "home/dev/.claude/CLAUDE.md"}
	for _, w := range want {
		if _, err := os.Stat(filepath.Join(dest, filepath.FromSlash(w))); err != nil {
			t.Fatalf("filtered out agent file %s", w)
		}
	}
	if _, err := os.Stat(filepath.Join(dest, "etc/passwd")); err == nil {
		t.Fatal("non-agent file kept by filter")
	}
	if st.Files != len(want) {
		t.Fatalf("filter kept %d", st.Files)
	}
}

func TestZipExtraction(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	add := func(name, body string) {
		w, _ := zw.Create(name)
		w.Write([]byte(body))
	}
	add("run-logs/.claude/projects/p/s1.jsonl", `{"type":"user","uuid":"u1","sessionId":"s1","message":{"role":"user","content":"hi"}}`+"\n")
	add("run-logs/notes.txt", "n")
	add("../zipslip.txt", "evil")
	add("dir/", "")
	zw.Close()
	p := filepath.Join(t.TempDir(), "artifact.zip")
	os.WriteFile(p, buf.Bytes(), 0o600)
	if k, err := Kind(p); err != nil || k != "zip" {
		t.Fatalf("kind %s %v", k, err)
	}
	dest := t.TempDir()
	st, err := ExtractArchive(p, dest, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if st.Files != 2 || st.Refused != 1 {
		t.Fatalf("zip: %+v", st)
	}
	if _, err := os.Stat(filepath.Join(dest, "run-logs/.claude/projects/p/s1.jsonl")); err != nil {
		t.Fatal("zip content missing")
	}
	if _, err := Kind(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("missing file must error")
	}
	txt := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(txt, []byte("hello"), 0o600)
	if _, err := Kind(txt); err == nil {
		t.Fatal("plain text is not an archive")
	}
}

// A stub `docker` on PATH emits a tar stream — exercises the export path
// without a container runtime. Unix only (shell script stub).
func TestDockerExportViaStub(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell stub")
	}
	tarPath := writeTar(t, false, []tar.Header{
		{Name: "root/.claude/projects/p/s1.jsonl", Typeflag: tar.TypeReg},
		{Name: "usr/bin/ls", Typeflag: tar.TypeReg},
	}, map[string]string{"root/.claude/projects/p/s1.jsonl": `{"type":"user"}` + "\n", "usr/bin/ls": "ELF"})
	bin := t.TempDir()
	stub := filepath.Join(bin, "docker")
	os.WriteFile(stub, []byte("#!/bin/sh\n[ \"$1\" = export ] || exit 2\necho \"$2\" > \""+filepath.Join(bin, "called")+"\"\ncat \""+tarPath+"\"\n"), 0o755)
	t.Setenv("AGENTDFIR_DOCKER", stub)
	rc, wait, err := DockerExport("devcontainer-3a1f")
	if err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	st, err := ExtractTarStream(rc, dest, Options{Filter: AgentHomeFilter()})
	rc.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if st.Files != 1 {
		t.Fatalf("docker filter: %+v", st)
	}
	called, _ := os.ReadFile(filepath.Join(bin, "called"))
	if strings.TrimSpace(string(called)) != "devcontainer-3a1f" {
		t.Fatalf("stub not called with container: %q", called)
	}
	if _, _, err := DockerExport("x; rm -rf /"); err == nil {
		t.Fatal("shell metacharacters in container ref must be refused")
	}
}
