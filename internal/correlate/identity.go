package correlate

import (
	"strings"
	"unicode/utf8"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
	"github.com/efij/AgentDFIR/v4/internal/toolargs"
)

// maxIdentity bounds a principal, resource or environment value copied
// from a witness record onto an event.
const maxIdentity = 256

// setCloudIdentity records, on a tool call a cloud audit record
// corroborated, who the cloud says made the call and on what: the
// CloudTrail userIdentity.arn (or principalId / userName), GCP
// authenticationInfo.principalEmail, Azure caller; and the first resource
// the record names, preferring an ARN or an Azure/GCP resource path. Values
// the event already carries are kept.
func setCloudIdentity(ev *schema.Event, r endpoint.Record) {
	if ev.Principal == "" {
		ev.Principal = boundIdentity(r.User)
	}
	if ev.ResourceID == "" {
		ev.ResourceID = boundIdentity(primaryResource(r.Resource))
	}
}

// primaryResource picks one identifier from a record's space-separated
// resource list.
func primaryResource(list string) string {
	fields := strings.Fields(list)
	for _, f := range fields {
		if strings.HasPrefix(f, "arn:") || strings.HasPrefix(f, "/subscriptions/") || strings.HasPrefix(f, "projects/") || strings.HasPrefix(f, "//") {
			return f
		}
	}
	if len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// setExecEnv records the container a corroborating process record ran in,
// when the telemetry attributes it to one.
func setExecEnv(ev *schema.Event, r endpoint.Record) {
	if ev.ExecEnv != "" {
		return
	}
	switch {
	case r.ContainerID != "":
		ev.ExecEnv = boundIdentity("container:" + r.ContainerID)
	case r.Pod != "":
		ev.ExecEnv = boundIdentity("pod:" + r.K8sNamespace + "/" + r.Pod)
	}
}

// boundIdentity bounds a value and masks credential formats in it.
func boundIdentity(s string) string {
	s = toolargs.Scrub(strings.TrimSpace(strings.ToValidUTF8(s, "\uFFFD")))
	if len(s) <= maxIdentity {
		return s
	}
	cut := maxIdentity
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
