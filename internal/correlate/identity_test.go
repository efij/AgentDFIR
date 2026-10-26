package correlate

import (
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

func TestSetCloudIdentity(t *testing.T) {
	cases := []struct {
		rec            endpoint.Record
		principal, res string
	}{
		{endpoint.Record{Provider: "aws", User: "arn:aws:iam::111122223333:user/dev", Resource: "my-bucket arn:aws:s3:::my-bucket"},
			"arn:aws:iam::111122223333:user/dev", "arn:aws:s3:::my-bucket"},
		{endpoint.Record{Provider: "gcp", User: "sa@proj.iam.gserviceaccount.com", Resource: "projects/_/buckets/b1"},
			"sa@proj.iam.gserviceaccount.com", "projects/_/buckets/b1"},
		{endpoint.Record{Provider: "azure", User: "dev@contoso.com", Resource: "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa"},
			"dev@contoso.com", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/sa"},
		{endpoint.Record{Provider: "aws"}, "", ""},
	}
	for i, c := range cases {
		var ev schema.Event
		setCloudIdentity(&ev, c.rec)
		if ev.Principal != c.principal || ev.ResourceID != c.res {
			t.Errorf("case %d: principal %q resource %q", i, ev.Principal, ev.ResourceID)
		}
	}
	// A value already on the event is kept.
	ev := schema.Event{Principal: "keep", ResourceID: "keep"}
	setCloudIdentity(&ev, cases[0].rec)
	if ev.Principal != "keep" || ev.ResourceID != "keep" {
		t.Error("existing identity overwritten")
	}
	// Hostile: overlong, invalid UTF-8, a credential in the principal.
	key := "AKIA" + strings.Repeat("W", 16)
	ev = schema.Event{}
	setCloudIdentity(&ev, endpoint.Record{User: key + "\xff" + strings.Repeat("u", 1000), Resource: strings.Repeat("r", 1000)})
	if len(ev.Principal) > maxIdentity || len(ev.ResourceID) > maxIdentity || strings.Contains(ev.Principal, key) {
		t.Errorf("hostile identity not bounded/masked: %d/%d bytes", len(ev.Principal), len(ev.ResourceID))
	}
}

func TestSetExecEnv(t *testing.T) {
	var ev schema.Event
	setExecEnv(&ev, endpoint.Record{ContainerID: "abc123", Pod: "p"})
	if ev.ExecEnv != "container:abc123" {
		t.Errorf("container: %q", ev.ExecEnv)
	}
	ev = schema.Event{}
	setExecEnv(&ev, endpoint.Record{Pod: "web-1", K8sNamespace: "prod"})
	if ev.ExecEnv != "pod:prod/web-1" {
		t.Errorf("pod: %q", ev.ExecEnv)
	}
	ev = schema.Event{}
	setExecEnv(&ev, endpoint.Record{Exe: "/bin/ls"})
	if ev.ExecEnv != "" {
		t.Errorf("host process given an environment: %q", ev.ExecEnv)
	}
}
