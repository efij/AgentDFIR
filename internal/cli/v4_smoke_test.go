package cli

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
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

	"github.com/efij/AgentDFIR/v5/internal/analysis"
	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/collector"
	"github.com/efij/AgentDFIR/v5/internal/gaps"
	"github.com/efij/AgentDFIR/v5/internal/products"
	"github.com/efij/AgentDFIR/v5/internal/report"
	"github.com/efij/AgentDFIR/v5/internal/simulate"
)

// Cross-feature smoke tests: features built separately, run end to end.

// A synthetic ChatGPT export carrying a token → analyze → RSMF that
// validates, and a production set redacted with "all" in which the token
// appears nowhere.
func TestSmokeAIExportToRedactedProduction(t *testing.T) {
	const secret = "ghp_Zq3xY7mN2pL8kR4tV6wB9cD1fH5jS0aE2gUi"
	conv := strings.Replace(fixture(t, "chatgpt/conversations.json"), "Write me a deploy script for this diagram",
		"Write me a deploy script; the token is "+secret+" and mail ops@example.com", 1)
	if !strings.Contains(conv, secret) {
		t.Fatal("fixture text not found")
	}
	zp := zipTree(t, map[string]string{"conversations.json": conv, "user.json": fixture(t, "chatgpt/user.json")})
	pkg := filepath.Join(t.TempDir(), "aix.adfir")
	if code := Main([]string{"collect", "--ai-export", zp, "--out", pkg, "--case-id", "SMOKE-AIX", "--no-sign"}); code != 0 {
		t.Fatalf("collect --ai-export exit %d", code)
	}
	if code, out := capture(t, "analyze", pkg); code != 0 && code != 3 {
		t.Fatalf("analyze exit %d:\n%s", code, out)
	}
	// Unredacted, the token is in the derivative: the redaction checks
	// below are not vacuous.
	plain := filepath.Join(t.TempDir(), "plain")
	if code, out := capture(t, "report", pkg, "--format", "rsmf", "--out", plain); code != 0 {
		t.Fatalf("report rsmf exit %d:\n%s", code, out)
	}
	seen := false
	pents, _ := os.ReadDir(plain)
	for _, e := range pents {
		b := derivativeText(t, filepath.Join(plain, e.Name()))
		seen = seen || strings.Contains(b, secret)
	}
	if !seen {
		t.Fatal("the token never reached the unredacted RSMF; the export conversation was not parsed")
	}
	rdir := filepath.Join(t.TempDir(), "rsmf")
	if code, out := capture(t, "report", pkg, "--format", "rsmf", "--out", rdir, "--redact", "all"); code != 0 {
		t.Fatalf("report rsmf exit %d:\n%s", code, out)
	}
	ents, _ := os.ReadDir(rdir)
	if len(ents) == 0 {
		t.Fatal("no RSMF written for the AI export")
	}
	for _, e := range ents {
		b, _ := os.ReadFile(filepath.Join(rdir, e.Name()))
		if p := report.ValidateRSMF(b); len(p) > 0 {
			t.Errorf("%s: %v", e.Name(), p)
		}
		if strings.Contains(derivativeText(t, filepath.Join(rdir, e.Name())), secret) {
			t.Errorf("%s: unredacted token in RSMF", e.Name())
		}
	}
	prod := filepath.Join(t.TempDir(), "prod")
	if code, out := capture(t, "export", pkg, "--production", "--out", prod, "--redact", "all", "--produced-at", "2026-10-25T00:00:00Z"); code != 0 {
		t.Fatalf("export --production exit %d:\n%s", code, out)
	}
	mb, err := os.ReadFile(filepath.Join(prod, "production-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var man struct {
		Files     []json.RawMessage `json:"files"`
		Redaction struct {
			Spec struct {
				Categories []string `json:"categories"`
			} `json:"spec"`
		} `json:"redaction"`
	}
	if err := json.Unmarshal(mb, &man); err != nil {
		t.Fatalf("manifest: %v", err)
	}
	if len(man.Files) == 0 || len(man.Redaction.Spec.Categories) < 4 {
		t.Fatalf("manifest: %d files, redaction %+v", len(man.Files), man.Redaction)
	}
	filepath.WalkDir(prod, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b := derivativeText(t, p)
		if strings.Contains(b, secret) {
			t.Errorf("unredacted token in production file %s", p)
		}
		return nil
	})
}

// collect --image of the NTFS E01 fixture → analyze → gaps --json and
// lineage --format mermaid.
func TestSmokeImageToGapsAndLineage(t *testing.T) {
	dir := t.TempDir()
	img := imageFixture(t, dir, "disk.E01")
	pkg := filepath.Join(dir, "img.adfir")
	if code := Main([]string{"collect", "--image", img, "--out", pkg, "--no-sign", "--skip-image-verify"}); code != 0 {
		t.Fatalf("collect --image exit %d", code)
	}
	if code, out := capture(t, "analyze", pkg); code != 0 && code != 3 {
		t.Fatalf("analyze exit %d:\n%s", code, out)
	}
	code, out := capture(t, "gaps", pkg, "--json")
	if code != 0 {
		t.Fatalf("gaps exit %d:\n%s", code, out)
	}
	var rep gaps.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil || rep.Schema != gaps.Schema || rep.Summary.Sessions == 0 {
		t.Fatalf("gaps --json: %v %+v\n%s", err, rep.Summary, out)
	}
	if code, out := capture(t, "lineage", pkg, "--format", "mermaid"); code != 0 || !strings.HasPrefix(out, "flowchart LR") {
		t.Fatalf("lineage mermaid exit %d:\n%s", code, out)
	}
}

// Two different simulated incidents whose profiles configure the same
// remote MCP server: correlate-cases names the shared server URL.
func TestSmokeCorrelateCasesSharedMCPServer(t *testing.T) {
	const shared = "https://mcp.shared-relay.example/mcp"
	build := func(scenario string) string {
		root := filepath.Join(t.TempDir(), "home")
		sc, ok := simulate.ByID(scenario)
		if !ok {
			t.Fatalf("unknown scenario %s", scenario)
		}
		if err := sc.Run(root); err != nil {
			t.Fatal(err)
		}
		// Add the shared remote server beside whatever the scenario configured.
		cfgPath := filepath.Join(root, ".claude.json")
		cfg := map[string]any{}
		if b, err := os.ReadFile(cfgPath); err == nil {
			_ = json.Unmarshal(b, &cfg)
		}
		servers, _ := cfg["mcpServers"].(map[string]any)
		if servers == nil {
			servers = map[string]any{}
		}
		servers["relay"] = map[string]any{"type": "http", "url": shared}
		cfg["mcpServers"] = servers
		b, _ := json.Marshal(cfg)
		if err := os.WriteFile(cfgPath, b, 0o600); err != nil {
			t.Fatal(err)
		}
		pkg := filepath.Join(t.TempDir(), scenario+".adfir")
		bld, err := casepkg.New(pkg, "SMOKE-"+scenario, casepkg.CaseInfo{OperatorOSUser: "tester"})
		if err != nil {
			t.Fatal(err)
		}
		man, err := products.ManifestAllPlatforms("claude-code")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := collector.Run(bld, man, collector.Options{ProfileRoot: root, ConfigRoot: filepath.Join(root, ".claude"), SystemRoot: root, Product: "claude-code"}); err != nil {
			t.Fatal(err)
		}
		if err := bld.Seal(); err != nil {
			t.Fatal(err)
		}
		bld.Close()
		if _, err := analysis.Run(pkg, analysis.Options{}); err != nil {
			t.Fatal(err)
		}
		return pkg
	}
	a, b := build("toxic-chain"), build("mcpoison-rugpull")
	code, out := capture(t, "correlate-cases", a, b, "--json")
	if code != 0 {
		t.Fatalf("correlate-cases exit %d:\n%s", code, out)
	}
	var rep struct {
		Shared []struct {
			Kind    string `json:"kind"`
			Key     string `json:"key"`
			Display string `json:"display"`
		} `json:"shared"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("JSON: %v\n%s", err, out)
	}
	found := false
	for _, s := range rep.Shared {
		if s.Kind == "mcp_server" && strings.Contains(s.Display, "mcp.shared-relay.example") {
			found = true
		}
	}
	if !found {
		t.Fatalf("shared MCP server URL not reported: %+v", rep.Shared)
	}
}

// derivativeText is everything a reviewer can read in a produced file: an
// RSMF message's decoded text body and the files inside its rsmf.zip, or
// any other file as is.
func derivativeText(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, ".rsmf") {
		return string(raw)
	}
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	_, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	var out strings.Builder
	mr := multipart.NewReader(msg.Body, params["boundary"])
	for {
		p, err := mr.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		body, _ := io.ReadAll(p) // quoted-printable is decoded by the reader
		if p.Header.Get("Content-Transfer-Encoding") != "base64" {
			out.Write(body)
			continue
		}
		zb, err := base64.StdEncoding.DecodeString(strings.Join(strings.Fields(string(body)), ""))
		if err != nil {
			t.Fatalf("%s: base64: %v", path, err)
		}
		zr, err := zip.NewReader(bytes.NewReader(zb), int64(len(zb)))
		if err != nil {
			t.Fatalf("%s: zip: %v", path, err)
		}
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				t.Fatal(err)
			}
			b, _ := io.ReadAll(rc)
			rc.Close()
			out.Write(b)
		}
	}
	return out.String()
}
