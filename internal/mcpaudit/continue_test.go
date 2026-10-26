package mcpaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/casepkg"
	"github.com/efij/AgentDFIR/v5/internal/collector"
	"github.com/efij/AgentDFIR/v5/internal/products"
)

func ideProfile(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	files := map[string]string{
		// Windsurf: Claude-style map with a remote serverUrl.
		".codeium/windsurf/mcp_config.json": `{"mcpServers": {
		  "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"], "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"}},
		  "remote": {"serverUrl": "http://mcp.internal:9000/sse"}
		}}`,
		// Continue legacy JSON: experimental transport list.
		".continue/config.json": `{"models": [], "experimental": {"modelContextProtocolServers": [
		  {"transport": {"type": "stdio", "command": "uvx", "args": ["mcp-server-sqlite", "--db-path", "/tmp/x.db"]}}
		]}}`,
		// Continue YAML: block lists, flow list, flow map, comments, a hub block.
		".continue/config.yaml": `name: Local Assistant  # top
version: 1.0.0
schema: v1
models: []
mcpServers:
  - name: fetcher
    command: npx
    args:
      - "-y"
      - '@acme/fetch-mcp@latest'
    env:
      API_TOKEN: "sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
  - name: docs # remote
    type: sse
    url: https://docs.example/mcp
  - uses: anthropic/memory-mcp
rules: []
`,
		".continue/mcpServers/pinned.yaml": `name: pinned block
mcpServers:
  - name: pinned
    command: npx
    args: ["-y", "@acme/pinned-mcp@1.2.3"]
    env: {MODE: "ro"}
`,
		".continue/mcpServers/from-claude.json": `{"mcpServers": {"copied": {"command": "node", "args": ["/opt/copied/index.js"]}}}`,
		".continue/mcpServers/bad.yaml":         "mcpServers:\n  - just a scalar line\n",
	}
	for rel, content := range files {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func checkIDEInventory(t *testing.T, inv *Inventory) {
	t.Helper()
	gh := find(inv, "windsurf", "github")
	if gh == nil || gh.Package != "@modelcontextprotocol/server-github" || gh.Pinned || len(gh.SecretEnv) != 1 {
		t.Fatalf("windsurf github = %+v (servers %+v)", gh, inv.Servers)
	}
	if r := find(inv, "windsurf", "remote"); r == nil || r.Transport != "sse" || r.URL != "http://mcp.internal:9000/sse" {
		t.Fatalf("windsurf remote = %+v", r)
	}
	if s := find(inv, "continue", "server-1"); s == nil || s.Command != "uvx" || s.Package != "mcp-server-sqlite" {
		t.Fatalf("continue legacy = %+v", s)
	}
	f := find(inv, "continue", "fetcher")
	if f == nil || f.Package != "@acme/fetch-mcp@latest" || f.Pinned || len(f.Args) != 2 || len(f.SecretEnv) != 1 {
		t.Fatalf("continue fetcher = %+v", f)
	}
	if d := find(inv, "continue", "docs"); d == nil || d.Transport != "sse" || d.URL != "https://docs.example/mcp" {
		t.Fatalf("continue docs = %+v", d)
	}
	if h := find(inv, "continue", "anthropic/memory-mcp"); h == nil || h.PackageMgr != "continue-hub" || h.Pinned {
		t.Fatalf("continue hub block = %+v", h)
	}
	if p := find(inv, "continue", "pinned"); p == nil || !p.Pinned || len(p.EnvKeys) != 1 || p.EnvKeys[0] != "MODE" {
		t.Fatalf("continue pinned = %+v", p)
	}
	if c := find(inv, "continue", "copied"); c == nil || c.Command != "node" {
		t.Fatalf("continue copied json = %+v", c)
	}
	bad := false
	for _, pr := range inv.Problems {
		if strings.Contains(pr, "bad.yaml") {
			bad = true
		}
	}
	if !bad {
		t.Fatalf("unreadable server not reported: %v", inv.Problems)
	}
}

func TestContinueAndWindsurfLiveProfile(t *testing.T) {
	checkIDEInventory(t, ScanProfile(ideProfile(t)))
}

func TestContinueAndWindsurfSealedPackage(t *testing.T) {
	root := ideProfile(t)
	pkg := filepath.Join(t.TempDir(), "ide.adfir")
	b, err := casepkg.New(pkg, "MCP-IDE", casepkg.CaseInfo{OperatorOSUser: "t"})
	if err != nil {
		t.Fatal(err)
	}
	for _, pid := range []string{"continue", "windsurf"} {
		man, err := products.ManifestAllPlatforms(pid)
		if err != nil || man == nil {
			t.Fatalf("manifest %s: %v", pid, err)
		}
		prod, _ := products.ByID(pid)
		if _, err := collector.Run(b, man, collector.Options{ProfileRoot: root, ConfigRoot: filepath.Join(root, prod.ConfigDirs[0]), SystemRoot: root, Product: pid}); err != nil {
			t.Fatal(err)
		}
	}
	if err := b.Seal(); err != nil {
		t.Fatal(err)
	}
	inv, _, err := ScanPackage(pkg)
	if err != nil {
		t.Fatal(err)
	}
	checkIDEInventory(t, inv)
	fs := byRule(Evaluate(inv))
	if len(fs["INSECURE_MCP_TRANSPORT"]) != 1 || len(fs["UNPINNED_MCP_PACKAGE"]) < 2 {
		t.Fatalf("rules over IDE configs: %v", fs)
	}
}

func TestContinueYAMLHostileInput(t *testing.T) {
	for _, in := range []string{
		"", "mcpServers: []", "mcpServers: {a: b}", "mcpServers:\n", "mcpServers:\n  name: not-a-list\n",
		"mcpServers:\n  -\n  - name: x\n    args: [unterminated\n", strings.Repeat("mcpServers:\n  - name: a\n", 2000),
		"\x00\x01\x02", "mcpServers:\n  - name: \"quoted # not a comment\"\n    command: 'it''s'\n",
	} {
		servers, _, _ := parseContinueYAML([]byte(in))
		_ = servers
	}
	s, _, err := parseContinueYAML([]byte("mcpServers:\n  - name: \"quoted # not a comment\"\n    command: run\n"))
	if err != nil || len(s) != 1 || s[0].Name != "quoted # not a comment" {
		t.Fatalf("quoted comment char: %+v %v", s, err)
	}
}

func TestClassifyIDEPaths(t *testing.T) {
	for p, host := range map[string]string{
		".codeium/windsurf/mcp_config.json":        "windsurf",
		"Users/u/.continue/config.yaml":            "continue",
		"Users/u/.continue/mcpServers/sqlite.yaml": "continue",
		"Users/u/.continue/mcpServers/x.json":      "continue",
	} {
		h, _, _, ok := classify(p)
		if !ok || h != host {
			t.Errorf("%s: %s %v, want %s", p, h, ok, host)
		}
	}
	if _, _, _, ok := classify("Users/u/.continue/sessions/abc.json"); ok {
		t.Error("a Continue session classified as MCP config")
	}
}
