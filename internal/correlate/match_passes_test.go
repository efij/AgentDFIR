package correlate

import (
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// Every pass that corroborates (fully or partly) records the pairing, with
// a basis that says what was compared and a confidence.
func TestEveryPassRecordsMatches(t *testing.T) {
	events := []schema.Event{
		tc("k8s", "2026-10-25T10:00:00Z", "Bash", "kubectl -n prod delete secret db"),
		tc("dns", "2026-10-25T10:01:00Z", "Bash", "curl -s https://exfil.example.net/drop"),
		tc("proxy", "2026-10-25T10:02:00Z", "Bash", "curl https://paste.example.com/raw/abc"),
		tc("path", "2026-10-25T10:03:00Z", "Bash", "curl https://api.example.io/v1/upload"),
		tc("ssh", "2026-10-25T10:04:00Z", "Bash", "ssh deploy@10.1.2.3 uptime"),
		tc("sudo", "2026-10-25T10:05:00Z", "Bash", "sudo systemctl restart nginx"),
		tc("script", "2026-10-25T10:06:00Z", "Bash", "Remove-Item -Recurse -Force build"),
		tc("image", "2026-10-25T10:07:00Z", "Bash", "git status"),
	}
	recs := []endpoint.Record{
		{Time: ts("2026-10-25T10:00:01Z"), Kind: "cloud", Provider: "k8s", Operation: "delete secrets", Resource: "prod/db", Source: "k8s-audit", Ref: "audit.jsonl:1"},
		{Time: ts("2026-10-25T10:00:59Z"), Kind: "dns", DestHost: "exfil.example.net", SourceIP: "10.0.0.5", Source: "bind", Ref: "query.log:1"},
		{Time: ts("2026-10-25T10:02:01Z"), Kind: "network", DestHost: "paste.example.com", URL: "https://paste.example.com/raw/abc", Operation: "GET", Source: "squid", Ref: "access.log:1"},
		{Time: ts("2026-10-25T10:03:01Z"), Kind: "network", DestHost: "api.example.io", URL: "/v1/other", Operation: "POST", Source: "zeek-http", Ref: "http.log:1"},
		{Time: ts("2026-10-25T10:04:02Z"), Kind: "auth", Operation: "ssh-accept publickey", User: "deploy", SourceIP: "10.0.0.5", Source: "authlog", Ref: "auth.log:1"},
		{Time: ts("2026-10-25T10:05:00Z"), Kind: "process", User: "dev", Cmdline: "systemctl restart nginx", Source: "authlog", Ref: "auth.log:2"},
		{Time: ts("2026-10-25T10:06:01Z"), Kind: "script", Exe: "powershell.exe", Cmdline: "remove-item -recurse -force build", Source: "powershell", Ref: "4104:1"},
		{Time: ts("2026-10-25T10:07:01Z"), Kind: endpoint.KindProcessImage, Exe: `C:\Git\cmd\git.exe`, Source: "security", Ref: "4688:1"},
	}
	res, _ := Endpoint(events, recs, EndpointOptions{})
	byEvent := map[string]Match{}
	for _, m := range res.Matches {
		byEvent[m.EventID] = m
	}
	want := map[string]struct{ witness, basis, conf string }{
		"k8s":    {WitnessCloud, "k8s audit verb + resource", "HIGH"},
		"dns":    {WitnessSighting, "DNS lookup of exfil.example.net within ±2m0s", "LOW"},
		"proxy":  {WitnessSighting, "proxy request host+path paste.example.com/raw/abc", "MEDIUM"},
		"path":   {WitnessSighting, "proxy request to api.example.io (another path)", "LOW"},
		"ssh":    {WitnessSighting, "sshd login accepted for deploy", "LOW"},
		"sudo":   {WitnessSighting, "authlog command line: same command line", "HIGH"},
		"script": {WitnessScript, "script block exact match", "HIGH"},
		"image":  {WitnessProcessImage, "process image basename git", "LOW"},
	}
	for id, w := range want {
		m, ok := byEvent[id]
		if !ok {
			t.Errorf("%s: no match recorded (%+v)", id, events)
			continue
		}
		if m.Witness != w.witness || !strings.Contains(m.Basis, w.basis) || m.Confidence != w.conf || m.WindowMS <= 0 {
			t.Errorf("%s: %+v, want witness %s basis ~%q conf %s", id, m, w.witness, w.basis, w.conf)
		}
	}
	if len(res.Matches) != len(want) {
		t.Errorf("matches = %d, want %d", len(res.Matches), len(want))
	}
}

// The bound applies to every pass, not only the host pass.
func TestSightingMatchesHonourBound(t *testing.T) {
	res := &EndpointResult{Matches: make([]Match, MaxMatches)}
	events := []schema.Event{tc("dns", "2026-10-25T10:01:00Z", "Bash", "curl https://a.example.net/")}
	recs := []endpoint.Record{{Time: ts("2026-10-25T10:01:01Z"), Kind: "dns", DestHost: "a.example.net", Source: "bind", Ref: "q:1"}}
	sightingPass(events, recs, EndpointOptions{Window: 3e9}, res)
	if len(res.Matches) != MaxMatches || res.MatchesOmitted != 1 || events[0].Corroboration != schema.StatePartial {
		t.Fatalf("bound: %d omitted %d state %s", len(res.Matches), res.MatchesOmitted, events[0].Corroboration)
	}
}
