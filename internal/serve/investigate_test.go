package serve

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSessionsChainSearchNotes(t *testing.T) {
	pkg := buildPkg(t)
	s, err := Load(pkg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	srv := httptest.NewServer(s.Handler())
	defer srv.Close()

	// sessions: one card, risk > 0 because findings exist, counts sane.
	resp, body := get(t, srv, "/api/sessions", "127.0.0.1")
	if resp.StatusCode != 200 {
		t.Fatalf("sessions: %d %s", resp.StatusCode, body)
	}
	var cards []sessionCard
	if err := json.Unmarshal(body, &cards); err != nil || len(cards) != 1 {
		t.Fatalf("sessions body: %v %s", err, body)
	}
	c := cards[0]
	if c.ID != "s1" || c.Prompts != 1 || c.ToolCalls != 2 || c.FindTotal == 0 || c.Worst == "" || c.Risk == 0 || c.Tools["Bash"] != 2 {
		t.Fatalf("card wrong: %+v", c)
	}

	// findings carry a stable key; chain tree for the first finding has evidence children with context.
	_, fb := get(t, srv, "/api/findings", "127.0.0.1")
	var fs []map[string]any
	_ = json.Unmarshal(fb, &fs)
	if len(fs) == 0 || fs[0]["key"] == "" {
		t.Fatalf("findings: %s", fb)
	}
	var idx int
	for _, f := range fs {
		if f["rule_id"] == "DESTRUCTIVE_COMMAND" {
			idx = int(f["index"].(float64))
		}
	}
	resp, cb := get(t, srv, "/api/chain?finding="+itoa(idx), "127.0.0.1")
	if resp.StatusCode != 200 {
		t.Fatalf("chain: %d %s", resp.StatusCode, cb)
	}
	var tree struct {
		Root treeNode `json:"root"`
	}
	_ = json.Unmarshal(cb, &tree)
	if tree.Root.Kind != "finding" || len(tree.Root.Children) == 0 {
		t.Fatalf("tree: %s", cb)
	}
	ev := tree.Root.Children[0]
	if ev.EventID == "" || !strings.Contains(ev.Label, "rm -rf") {
		t.Fatalf("evidence node wrong: %+v", ev)
	}
	hasPrompt := false
	for _, ctx := range ev.Children {
		if ctx.Role == "human prompt before this" {
			hasPrompt = true
		}
	}
	if !hasPrompt {
		t.Fatalf("expected the human prompt as context: %+v", ev.Children)
	}
	// event expansion endpoint
	resp, _ = get(t, srv, "/api/chain?event="+ev.EventID, "127.0.0.1")
	if resp.StatusCode != 200 {
		t.Fatalf("chain?event: %d", resp.StatusCode)
	}
	if resp, _ := get(t, srv, "/api/chain?finding=999", "127.0.0.1"); resp.StatusCode != 400 {
		t.Fatalf("bad index should be 400, got %d", resp.StatusCode)
	}

	// search: events + findings + raw all hit "evil.example"; raw hit maps to an event; ANSI sanitized.
	resp, sb := get(t, srv, "/api/search?q=evil.example", "127.0.0.1")
	if resp.StatusCode != 200 {
		t.Fatalf("search: %d %s", resp.StatusCode, sb)
	}
	var sr struct {
		Events struct {
			Total int              `json:"total"`
			Items []map[string]any `json:"items"`
		} `json:"events"`
		Findings []map[string]any `json:"findings"`
		Raw      struct {
			Items            []rawHit `json:"items"`
			ArtifactsScanned int      `json:"artifacts_scanned"`
		} `json:"raw"`
	}
	if err := json.Unmarshal(sb, &sr); err != nil {
		t.Fatal(err)
	}
	if sr.Events.Total == 0 || len(sr.Raw.Items) == 0 || sr.Raw.ArtifactsScanned == 0 {
		t.Fatalf("search results: %s", sb)
	}
	if sr.Raw.Items[0].EventID == "" || sr.Raw.Items[0].Line != 3 {
		t.Fatalf("raw hit should map to event line 3: %+v", sr.Raw.Items[0])
	}
	_, sb = get(t, srv, "/api/search?q=red&scope=raw", "127.0.0.1")
	if bytes.Contains(sb, []byte("\x1b")) {
		t.Fatal("raw snippet leaked an escape byte")
	}
	if resp, _ := get(t, srv, "/api/search?q=%28&mode=regex", "127.0.0.1"); resp.StatusCode != 400 {
		t.Fatalf("bad regex should be 400, got %d", resp.StatusCode)
	}
	if resp, _ := get(t, srv, "/api/search?q=", "127.0.0.1"); resp.StatusCode != 400 {
		t.Fatalf("empty query should be 400, got %d", resp.StatusCode)
	}

	// notes: POST without the header is refused; with it, appended and folded; GET shows chain ok.
	post := func(hdr bool, origin string, payload string) *http.Response {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/notes", strings.NewReader(payload))
		req.Host = "127.0.0.1"
		req.Header.Set("Content-Type", "application/json")
		if hdr {
			req.Header.Set("X-AgentDFIR-Notes", "1")
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp
	}
	key := fs[0]["key"].(string)
	if r := post(false, "", `{"kind":"verdict","target":"`+key+`","value":"true_positive"}`); r.StatusCode != 405 {
		t.Fatalf("post without header: %d", r.StatusCode)
	}
	if r := post(true, "http://evil.example", `{"kind":"verdict","target":"`+key+`","value":"true_positive"}`); r.StatusCode != 405 {
		t.Fatalf("cross-origin post: %d", r.StatusCode)
	}
	if r := post(true, "http://127.0.0.1:1", `{"kind":"verdict","target":"`+key+`","value":"nonsense"}`); r.StatusCode != 400 {
		t.Fatalf("bad verdict: %d", r.StatusCode)
	}
	if r := post(true, "http://127.0.0.1:1", `{"kind":"verdict","target":"`+key+`","value":"true_positive","text":"confirmed"}`); r.StatusCode != 200 {
		t.Fatalf("verdict post: %d", r.StatusCode)
	}
	if r := post(true, "", `{"kind":"pin","target":"event:`+ev.EventID+`","value":"on"}`); r.StatusCode != 200 {
		t.Fatalf("pin post: %d", r.StatusCode)
	}
	if r := post(true, "", `{"kind":"tag","target":"session:s1","value":"add","text":"compromised"}`); r.StatusCode != 200 {
		t.Fatalf("tag post: %d", r.StatusCode)
	}
	_, nb := get(t, srv, "/api/notes", "127.0.0.1")
	var ns struct {
		State struct {
			Verdicts map[string]struct{ Verdict string } `json:"verdicts"`
			Pins     []struct{ Target string }           `json:"pins"`
			Tags     map[string][]string                 `json:"tags"`
			ChainOK  bool                                `json:"chain_ok"`
		} `json:"state"`
	}
	_ = json.Unmarshal(nb, &ns)
	if !ns.State.ChainOK || ns.State.Verdicts[key].Verdict != "true_positive" || len(ns.State.Pins) != 1 || ns.State.Tags["s1"][0] != "compromised" {
		t.Fatalf("notes state: %s", nb)
	}
	// the pin shows up on the tree node and the tag on the session card
	_, cb = get(t, srv, "/api/chain?finding="+itoa(idx), "127.0.0.1")
	if !strings.Contains(string(cb), `"pinned":true`) {
		t.Fatalf("pin not reflected in tree: %s", cb)
	}
	_, body = get(t, srv, "/api/sessions", "127.0.0.1")
	if !strings.Contains(string(body), `"compromised"`) {
		t.Fatalf("tag not reflected on card: %s", body)
	}
	// still read-only elsewhere
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/events", nil)
	req.Host = "127.0.0.1"
	req.Header.Set("X-AgentDFIR-Notes", "1")
	r, _ := http.DefaultClient.Do(req)
	r.Body.Close()
	if r.StatusCode != 405 {
		t.Fatalf("POST to a read endpoint should be 405, got %d", r.StatusCode)
	}
}

func itoa(i int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + fmtInt(i)) }

func fmtInt(i int) string {
	b, _ := json.Marshal(i)
	return string(b)
}
