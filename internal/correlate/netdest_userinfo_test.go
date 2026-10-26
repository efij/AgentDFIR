package correlate

import (
	"testing"

	"github.com/efij/AgentDFIR/v5/internal/endpoint"
	"github.com/efij/AgentDFIR/v5/internal/netdest"
	"github.com/efij/AgentDFIR/v5/internal/schema"
)

// normalize fills NetworkDest from netdest.Extract; the host pass matches
// network records against it. A connection to the userinfo "host" must
// not corroborate a command whose real destination is evil.com.
func TestHostNetworkPassIgnoresURLUserinfo(t *testing.T) {
	cmd := "curl https://trusted.com@evil.com/x"
	dests := netdest.Extract(cmd)
	if len(dests) != 1 || dests[0] != "evil.com" {
		t.Fatalf("Extract: %v", dests)
	}
	for _, src := range []string{"auditd", "sysmon"} {
		mk := func() []schema.Event {
			return []schema.Event{{EventID: "e", EventType: schema.EventToolCall, Tool: "Bash", Command: cmd, NetworkDest: dests[0],
				Timestamp: "2026-10-25T10:00:00Z", Corroboration: schema.StateObserved}}
		}
		rec := func(host string) []endpoint.Record {
			return []endpoint.Record{{Time: ts("2026-10-25T10:00:01Z"), Kind: "network", PID: 7, Exe: "/usr/bin/curl", DestHost: host, DestPort: 443, Source: src, Ref: src + ":1"}}
		}
		events := mk()
		Endpoint(events, rec("trusted.com"), EndpointOptions{})
		if events[0].Corroboration != schema.StateObserved {
			t.Errorf("%s: connection to the userinfo host corroborated: %s", src, events[0].Summary)
		}
		events = mk()
		Endpoint(events, rec("evil.com"), EndpointOptions{})
		if events[0].Corroboration != schema.StateCorroborated {
			t.Errorf("%s: connection to the real host not matched: %s", src, events[0].Summary)
		}
	}
}
