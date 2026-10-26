package crosscase

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/overlay"
)

func TestURLIdentityCarriesNoCredential(t *testing.T) {
	tok := "q9" + "Lm3Xv8Rt2Kp7"
	pass := "hunter" + "2pw"
	raw := "https://alice:" + pass + "@MCP.Example.com:8443/sse?api_key=" + tok + "&team=blue"
	key, disp := urlIdentity(raw)
	for _, s := range []string{key, disp} {
		for _, leak := range []string{tok, pass, "alice"} {
			if strings.Contains(s, leak) {
				t.Errorf("%q leaks %q", s, leak)
			}
		}
	}
	if !strings.HasPrefix(disp, "https://mcp.example.com:8443/sse?api_key=<sha256:") || !strings.Contains(disp, "team=<sha256:") {
		t.Errorf("display: %q", disp)
	}
	// Same server, same token, different userinfo and query order: same key.
	k2, _ := urlIdentity("https://bob:x@mcp.example.com:8443/sse?team=blue&api_key=" + tok)
	if k2 != key {
		t.Errorf("same endpoint, different keys: %s vs %s", key, k2)
	}
	// Different token: different key.
	if k3, _ := urlIdentity("https://mcp.example.com:8443/sse?api_key=other&team=blue"); k3 == key {
		t.Error("different token, same key")
	}
	// A credential-shaped value in the path is masked in the display.
	gh := "ghp_" + strings.Repeat("aB3dE5fG7h", 3) + "J9kL1m"
	if _, d := urlIdentity("https://h.example/t/" + gh + "/sse"); strings.Contains(d, gh) {
		t.Errorf("path token shown: %q", d)
	}
	if k, d := urlIdentity("git+https://u:" + pass + "@git.example/x.git"); strings.Contains(d, pass) || !strings.HasPrefix(d, "git+https://git.example/") || k == "" {
		t.Errorf("package url: %q", d)
	}
	if _, d := urlIdentity("::not a url " + tok); strings.Contains(d, tok) || !strings.HasPrefix(d, "unparseable URL sha256:") {
		t.Errorf("unparseable: %q", d)
	}
}

// The MCP inventory path end to end: nothing from the URL's userinfo or
// query reaches the keys, display or locations of the shared items.
func TestLoadMCPMasksURLs(t *testing.T) {
	tok := "q9" + "Lm3Xv8Rt2Kp7"
	pkg := t.TempDir()
	if err := os.MkdirAll(filepath.Join(pkg, "detections"), 0o700); err != nil {
		t.Fatal(err)
	}
	inv := map[string]any{"inventory": map[string]any{"servers": []any{map[string]any{
		"name": "remote", "config_path": ".claude.json", "url": "https://u:" + tok + "@mcp.example/sse?token=" + tok,
		"package": "git+https://u:" + tok + "@git.example/x.git"}}}}
	if err := overlay.WriteJSON(filepath.Join(pkg, "detections", "mcp-audit.json"), inv); err != nil {
		t.Fatal(err)
	}
	cd := &caseData{items: map[string]map[string]*occ{}, info: Case{Label: "C1"}}
	cd.loadMCP(pkg)
	if len(cd.items[KindMCP]) != 2 {
		t.Fatalf("MCP items: %+v", cd.items[KindMCP])
	}
	for k, o := range cd.items[KindMCP] {
		all := k + " " + o.display + " " + strings.Join(o.refs, " ")
		for w := range o.where {
			all += " " + w
		}
		if strings.Contains(all, tok) {
			t.Fatalf("MCP item leaks the token: %s", all)
		}
	}
}
