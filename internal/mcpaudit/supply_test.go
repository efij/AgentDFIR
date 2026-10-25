package mcpaudit

import "testing"

func TestParseArtifactAndServerTools(t *testing.T) {
	inv, ok := ParseArtifact("Users/dev/.claude.json", []byte(`{"mcpServers":{"docs":{"command":"npx","args":["-y","docs@1"],"tools":[{"name":"search","inputSchema":{}}]}}}`))
	if !ok || len(inv.Servers) != 1 || len(inv.Servers[0].Tools) != 1 || inv.Servers[0].Tools[0].DefSHA256 == "" {
		t.Fatalf("parse: %+v %v", inv, ok)
	}
	if _, ok := ParseArtifact("Users/dev/notes.txt", []byte(`{}`)); ok {
		t.Error("non-config path accepted")
	}
	if inv, ok := ParseArtifact("Users/dev/.claude.json", []byte(`{bad`)); !ok || len(inv.Problems) == 0 {
		t.Errorf("malformed config not reported: %+v", inv)
	}
	got := ServerTools([]byte(`{"servers":{"fs":{"tools":[{"name":"read","inputSchema":{}},{"name":"write","inputSchema":{}}]},"x":{"serverName":"gh","tools":[{"name":"issue"}]}}}`))
	if len(got["fs"]) != 2 || len(got["gh"]) != 1 {
		t.Errorf("server tools: %+v", got)
	}
	for _, bad := range []string{``, `{`, `[1,2]`, `{"tools":"x"}`} {
		if r := ServerTools([]byte(bad)); len(r) != 0 {
			t.Errorf("%q yielded %+v", bad, r)
		}
	}
}
