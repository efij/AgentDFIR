package serve

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/mitigate"
)

// postMit is what the Protect tab sends: same-origin headers plus the token.
func postMit(t *testing.T, srv *httptest.Server, action, token string, body any) (*http.Response, []byte) {
	t.Helper()
	b, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/mitigations/"+action, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	if token != "" {
		req.Header.Set("X-AgentDFIR-Mitigate", token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	out.ReadFrom(resp.Body)
	return resp, out.Bytes()
}

func TestProtectTabAppliesAndRevertsFromThePage(t *testing.T) {
	pkg := buildPkg(t)
	s, err := Load(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// The case was collected here, by this user.
	s.info.Host, _ = os.Hostname()
	if cu, err := user.Current(); err == nil {
		s.info.OperatorOSUser = cu.Username
	}
	home := t.TempDir()
	settings := filepath.Join(home, ".claude", "settings.json")
	_ = os.MkdirAll(filepath.Dir(settings), 0o755)
	_ = os.WriteFile(settings, []byte("{\n  \"model\": \"opus\"\n}\n"), 0o644)
	s.mitEnv = func() (mitigate.Env, error) {
		return mitigate.Env{Home: home, StateDir: filepath.Join(home, ".agentdfir", "mitigations"), GuardCommand: "/usr/local/bin/agentdfir guard log"}, nil
	}
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// The GET hands the page a token only because this is the same machine.
	_, body := get(t, srv, "/api/mitigations", "")
	var m struct {
		SameMachine bool   `json:"same_machine"`
		Token       string `json:"token"`
	}
	_ = json.Unmarshal(body, &m)
	if !m.SameMachine || len(m.Token) != 32 {
		t.Fatalf("mitigations: same=%v token=%q", m.SameMachine, m.Token)
	}

	// Writes without the header are read-only; with a wrong token, forbidden.
	sel := map[string]any{"packs": []string{"log-protect", "secret-paths"}, "fix": true}
	if resp, _ := postMit(t, srv, "plan", "", sel); resp.StatusCode != 405 {
		t.Fatalf("no header: %d", resp.StatusCode)
	}
	if resp, _ := postMit(t, srv, "plan", strings.Repeat("0", 32), sel); resp.StatusCode != 403 {
		t.Fatalf("wrong token: %d", resp.StatusCode)
	}
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/mitigations/plan", strings.NewReader("{}"))
	req.Header.Set("X-AgentDFIR-Mitigate", m.Token)
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	if resp, _ := http.DefaultClient.Do(req); resp.StatusCode != 405 {
		t.Fatalf("cross-site accepted: %d", resp.StatusCode)
	}
	if resp, _ := postMit(t, srv, "plan", m.Token, map[string]any{"packs": []string{"nope"}}); resp.StatusCode != 400 {
		t.Fatalf("unknown pack accepted: %d", resp.StatusCode)
	}

	// Plan: one change to settings.json, nothing written.
	resp, body := postMit(t, srv, "plan", m.Token, sel)
	var pl struct {
		Changes []struct {
			Target  string   `json:"target"`
			Summary []string `json:"summary"`
			Diff    string   `json:"diff"`
		} `json:"changes"`
	}
	_ = json.Unmarshal(body, &pl)
	if resp.StatusCode != 200 || len(pl.Changes) != 1 || pl.Changes[0].Target != settings || len(pl.Changes[0].Summary) == 0 || !strings.Contains(pl.Changes[0].Diff, "+") {
		t.Fatalf("plan: %d %s", resp.StatusCode, body)
	}
	if b, _ := os.ReadFile(settings); strings.Contains(string(b), "permissions") {
		t.Fatal("plan wrote the file")
	}

	// Apply: the file gains the guardrails, the ledger records it.
	resp, body = postMit(t, srv, "apply", m.Token, sel)
	var ap struct {
		Results []struct{ ID, Error string }
		Failed  int
	}
	_ = json.Unmarshal(body, &ap)
	if resp.StatusCode != 200 || ap.Failed != 0 || len(ap.Results) != 1 || ap.Results[0].ID == "" {
		t.Fatalf("apply: %d %s", resp.StatusCode, body)
	}
	if b, _ := os.ReadFile(settings); !strings.Contains(string(b), "permissions") || !strings.Contains(string(b), `"model": "opus"`) {
		t.Fatalf("apply did not edit in place:\n%s", b)
	}
	_, body = get(t, srv, "/api/mitigations", "")
	var after struct {
		Applied []struct{ ID, State string }
	}
	_ = json.Unmarshal(body, &after)
	if len(after.Applied) != 1 || after.Applied[0].State != "in_place" || after.Applied[0].ID != ap.Results[0].ID {
		t.Fatalf("applied rows: %s", body)
	}

	// Revert by id puts the file back byte for byte.
	resp, body = postMit(t, srv, "revert", m.Token, map[string]any{"id": ap.Results[0].ID})
	if resp.StatusCode != 200 {
		t.Fatalf("revert: %d %s", resp.StatusCode, body)
	}
	if b, _ := os.ReadFile(settings); string(b) != "{\n  \"model\": \"opus\"\n}\n" {
		t.Fatalf("revert did not restore:\n%s", b)
	}
	if resp, _ := postMit(t, srv, "revert", m.Token, map[string]any{"id": ap.Results[0].ID}); resp.StatusCode != 409 {
		t.Fatalf("second revert: %d", resp.StatusCode)
	}
	if resp, _ := postMit(t, srv, "revert", m.Token, map[string]any{}); resp.StatusCode != 400 {
		t.Fatalf("empty revert: %d", resp.StatusCode)
	}
}

func TestProtectTabRefusesAnotherMachinesCase(t *testing.T) {
	pkg := buildPkg(t)
	s, err := Load(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	s.info.Host = "elsewhere"
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()
	_, body := get(t, srv, "/api/mitigations", "")
	if strings.Contains(string(body), `"token"`) {
		t.Fatalf("token handed out for another machine's case: %s", body)
	}
	if resp, _ := postMit(t, srv, "apply", s.applyToken, map[string]any{"packs": []string{"log-protect"}}); resp.StatusCode != 403 {
		t.Fatalf("apply for another machine: %d", resp.StatusCode)
	}
}
