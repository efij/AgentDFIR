package correlate

import (
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// Userinfo before '@' must never pose as the host: curl contacts evil.com.
func TestEventDestsUserinfoIPv6PercentEncoding(t *testing.T) {
	cases := []struct {
		cmd, netDest string
		want         []string // host|path
	}{
		{"curl https://trusted.com@evil.com/x", "trusted.com", []string{"evil.com|/x"}},
		{"curl 'https://user:pw@api.example.org:8443/v1/up?x=1'", "", []string{"api.example.org|/v1/up"}},
		{"curl http://[2001:db8::5]:8080/a", "", []string{"2001:db8::5|/a"}},
		{"curl http://[::1]:3000/health", "", nil}, // loopback
		{"curl https://ex%61mple.com/p", "", nil},  // percent-encoded host: dropped
		{"curl https://example.com/a%20b", "", []string{"example.com|/a%20b"}},
		{"curl https://[bad/x", "", nil}, // does not parse
		{"scp f.txt deploy@files.example.net:/tmp", "", []string{"files.example.net|"}},
	}
	for _, tc := range cases {
		ev := schema.Event{Command: tc.cmd, NetworkDest: tc.netDest}
		var got []string
		for _, d := range eventDests(&ev) {
			got = append(got, d.host+"|"+d.path)
		}
		if len(got) != len(tc.want) {
			t.Errorf("%q: %v, want %v", tc.cmd, got, tc.want)
			continue
		}
		for i := range got {
			if got[i] != tc.want[i] {
				t.Errorf("%q: %v, want %v", tc.cmd, got, tc.want)
			}
		}
	}
	// MCP tool: only a NetworkDest URL, with userinfo.
	ev := schema.Event{NetworkDest: "https://docs.example.com@attacker.example/page"}
	if d := eventDests(&ev); len(d) != 1 || d[0].host != "attacker.example" {
		t.Errorf("mcp url: %+v", d)
	}
}

func TestUserinfoHostNeverCorroborates(t *testing.T) {
	ev := tc("e", "2026-10-25T10:00:00Z", "Bash", "curl https://trusted.com@evil.com/x")
	ev.NetworkDest = "trusted.com" // what the regex extractor derived
	events := []schema.Event{ev}
	recs := []endpoint.Record{
		{Time: ts("2026-10-25T10:00:00Z"), Kind: "dns", DestHost: "trusted.com", Source: "bind", Ref: "q:1"},
		{Time: ts("2026-10-25T10:00:01Z"), Kind: "network", DestHost: "trusted.com", URL: "https://trusted.com/x", Source: "squid", Ref: "a:1"},
	}
	Endpoint(events, recs, EndpointOptions{})
	if events[0].Corroboration != schema.StateObserved {
		t.Fatalf("userinfo host corroborated: %s %s", events[0].Corroboration, events[0].Summary)
	}
	// The real host does.
	events = []schema.Event{ev}
	recs[1].DestHost, recs[1].URL = "evil.com", "http://evil.com/x"
	Endpoint(events, recs, EndpointOptions{})
	if events[0].Corroboration != schema.StateCorroborated {
		t.Fatalf("real host not matched: %s %s", events[0].Corroboration, events[0].Summary)
	}
}

func TestResourceMatchesSegments(t *testing.T) {
	cases := []struct {
		resource, name string
		want           bool
	}{
		{"nonprod-db", "prod", false},
		{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acctprod", "prod", false},
		{"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct1", "acct1", true},
		{"/SUBSCRIPTIONS/S/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.KEYVAULT/VAULTS/KV1", "kv1", true},
		{"projects/p/instances/db1", "db1", true},
		{"projects/p/instances/db10", "db1", false},
		{"arn:aws:lambda:eu-west-1:1:function:fn1", "fn1", true},
		{"prod-logs/app/2026/10/25.log", "s3://prod-logs/app/2026/10/25.log", true},
		{"prod-logs/app/2026/10/25.log", "prod-logs/app", true},
		{"prod-logs-old/app", "prod-logs", false},
		{"acme/api main", "acme/api", true},
		{"acme/api-v2", "acme/api", false},
		{"prod/db", "db", false}, // shorter than three: exact only
		{"db", "db", true},       // exact
		{"projects/_/buckets/b", "gs://b", false},
	}
	for _, c := range cases {
		if got := resourceMatches(c.resource, c.name); got != c.want {
			t.Errorf("resourceMatches(%q, %q) = %v, want %v", c.resource, c.name, got, c.want)
		}
	}
}

// The existing cloud pass had the same substring defect.
func TestCloudScoreNoSubstringMatch(t *testing.T) {
	events := []schema.Event{
		tc("az", "2026-06-10T10:00:00Z", "Bash", "az storage account delete -n prod -g rg --yes"),
		tc("aws", "2026-06-10T10:00:10Z", "Bash", "aws rds delete-db-instance --db-instance-identifier prod"),
		tc("noname", "2026-06-10T10:00:20Z", "Bash", "aws s3api list-buckets"), // no resource: still corroborated by operation
	}
	recs := []endpoint.Record{
		cloudRec("2026-06-10T10:00:01Z", "azure", "microsoft.storage/storageaccounts/delete", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/nonprod", "u", ""),
		cloudRec("2026-06-10T10:00:11Z", "aws", "rds:DeleteDBInstance", "nonprod-db", "u", ""),
		cloudRec("2026-06-10T10:00:21Z", "aws", "s3:ListBuckets", "", "u", ""),
	}
	Endpoint(events, recs, EndpointOptions{})
	want := map[string]string{"az": schema.StateObserved, "aws": schema.StateObserved, "noname": schema.StateCorroborated}
	for _, e := range events {
		if e.Corroboration != want[e.EventID] {
			t.Errorf("%s: %s, want %s (%s)", e.EventID, e.Corroboration, want[e.EventID], e.Summary)
		}
	}
}

func TestWitnessCloudNoSubstringAndNoNamePartial(t *testing.T) {
	events := []schema.Event{
		tc("k8s", "2026-10-25T10:00:00Z", "Bash", "kubectl delete deployment prod"),
		tc("s3", "2026-10-25T10:00:10Z", "Bash", "aws s3 rb s3://logs"),
		tc("ls", "2026-10-25T10:00:20Z", "Bash", "aws s3 ls"),
	}
	recs := []endpoint.Record{
		{Time: ts("2026-10-25T10:00:01Z"), Kind: "cloud", Provider: "k8s", Operation: "delete deployments", Resource: "default/nonprod", Source: "k8s-audit", Ref: "k:1"},
		{Time: ts("2026-10-25T10:00:11Z"), Kind: "cloud", Provider: "s3", Operation: "REST.DELETE.BUCKET", Resource: "applogs", Source: "s3-access", Ref: "s:1"},
		{Time: ts("2026-10-25T10:00:21Z"), Kind: "cloud", Provider: "s3", Operation: "REST.GET.SERVICE", Resource: "", Source: "s3-access", Ref: "s:2"},
	}
	res, _ := Endpoint(events, recs, EndpointOptions{})
	want := map[string]string{"k8s": schema.StateObserved, "s3": schema.StateObserved, "ls": schema.StatePartial}
	for _, e := range events {
		if e.Corroboration != want[e.EventID] {
			t.Errorf("%s: %s, want %s (%s)", e.EventID, e.Corroboration, want[e.EventID], e.Summary)
		}
	}
	if res.CloudCorroborated != 0 || res.CloudPartial != 1 {
		t.Errorf("result %+v", res)
	}
}
