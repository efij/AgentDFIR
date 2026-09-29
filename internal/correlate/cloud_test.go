package correlate

import (
	"fmt"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/endpoint"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

func cloudRec(when, provider, op, resource, user, failed string) endpoint.Record {
	return endpoint.Record{Time: ts(when), Kind: "cloud", Provider: provider, Operation: op, Resource: resource, User: user, Failed: failed, Source: provider + "-audit", Ref: "audit.json record " + when}
}

func TestCloudAuditCorroboratesAgentCommands(t *testing.T) {
	events := []schema.Event{
		tc("aws", "2026-06-10T10:00:00Z", "Bash", "aws --profile prod s3 rb s3://prod-logs --force"),
		tc("lambda", "2026-06-10T10:00:10Z", "Bash", "aws lambda delete-function --function-name fn1"),
		tc("az", "2026-06-10T10:00:20Z", "Bash", `az storage account delete -n acct1 -g rg --yes`),
		tc("lock", "2026-06-10T10:00:30Z", "Bash", "az group lock delete --name keep -g rg"),
		tc("gcp", "2026-06-10T10:00:40Z", "Bash", "gcloud sql instances delete db1 --quiet"),
		tc("denied", "2026-06-10T10:00:50Z", "Bash", "cd infra && aws rds delete-db-instance --db-instance-identifier db9"),
		tc("other", "2026-06-10T10:01:00Z", "Bash", "az keyvault delete -n kv-other"), // log has a different vault
		tc("none", "2026-06-10T10:01:10Z", "Bash", "gcloud projects delete gone"),     // not in the log at all
		tc("ls", "2026-06-10T10:01:20Z", "Bash", "ls -la"),
	}
	recs := []endpoint.Record{
		cloudRec("2026-06-10T10:00:01Z", "aws", "s3:DeleteBucket", "prod-logs", "arn:aws:iam::1:user/dev", ""),
		cloudRec("2026-06-10T10:00:11Z", "aws", "lambda:DeleteFunction20150331", "fn1", "arn:aws:iam::1:user/dev", ""),
		cloudRec("2026-06-10T10:00:22Z", "azure", "microsoft.storage/storageaccounts/delete", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct1", "dev@example.com", ""),
		cloudRec("2026-06-10T10:00:31Z", "azure", "microsoft.authorization/locks/delete", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.Authorization/locks/keep", "dev@example.com", ""),
		cloudRec("2026-06-10T10:00:45Z", "gcp", "cloudsql.googleapis.com cloudsql.instances.delete", "projects/p/instances/db1", "dev@example.com", ""),
		cloudRec("2026-06-10T10:00:51Z", "aws", "rds:DeleteDBInstance", "db9", "arn:aws:iam::1:user/dev", "AccessDenied"),
		cloudRec("2026-06-10T10:01:01Z", "azure", "microsoft.keyvault/vaults/delete", "/subscriptions/s/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv-prod", "dev@example.com", ""),
	}
	res, findings := Endpoint(events, recs, EndpointOptions{})
	want := map[string]string{"aws": schema.StateCorroborated, "lambda": schema.StateCorroborated, "az": schema.StateCorroborated, "lock": schema.StateCorroborated,
		"gcp": schema.StateCorroborated, "denied": schema.StateCorroborated, "other": schema.StateObserved, "none": schema.StateObserved, "ls": schema.StateObserved}
	for _, e := range events {
		if e.Corroboration != want[e.EventID] {
			t.Errorf("%s: %s, want %s (%s)", e.EventID, e.Corroboration, want[e.EventID], e.Summary)
		}
	}
	if !strings.Contains(events[5].Summary, "the cloud refused it: AccessDenied") {
		t.Errorf("refused call not noted: %q", events[5].Summary)
	}
	if res.CloudCorroborated != 6 || res.CloudRefused != 1 || res.Contradicted != 0 || len(findings) != 0 {
		t.Errorf("result %+v findings %v", res, findings)
	}
}

func TestCloudDestructiveBurst(t *testing.T) {
	var recs []endpoint.Record
	for i := 0; i < 12; i++ { // 12 storage accounts in 6 minutes, each logged twice (Started, Succeeded)
		when := fmt.Sprintf("2026-06-10T11:%02d:%02dZ", i/2, (i%2)*30)
		res := fmt.Sprintf("/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct%d", i)
		recs = append(recs, cloudRec(when, "azure", "microsoft.storage/storageaccounts/delete", res, "sp-leaked", ""), cloudRec(when, "azure", "microsoft.storage/storageaccounts/delete", res, "sp-leaked", ""))
	}
	// Refused deletes and reads never count; another identity's 3 deletes neither.
	for i := 0; i < 20; i++ {
		recs = append(recs, cloudRec("2026-06-10T11:02:00Z", "azure", "microsoft.sql/servers/databases/delete", fmt.Sprintf("db%d", i), "sp-leaked", "Failed"))
		recs = append(recs, cloudRec("2026-06-10T11:02:00Z", "azure", "microsoft.storage/storageaccounts/read", fmt.Sprintf("r%d", i), "sp-leaked", ""))
	}
	for i := 0; i < 3; i++ {
		recs = append(recs, cloudRec("2026-06-10T11:03:00Z", "azure", "microsoft.web/sites/delete", fmt.Sprintf("app%d", i), "dev@example.com", ""))
	}
	res, findings := Endpoint(nil, recs, EndpointOptions{})
	if len(findings) != 1 || res.CloudBursts != 1 {
		t.Fatalf("want one burst, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.RuleID != "CLOUD_DESTRUCTIVE_BURST" || !strings.Contains(f.Description, "sp-leaked deleting 12 distinct resources") || !strings.Contains(f.Description, "None of them match") {
		t.Errorf("finding: %s", f.Description)
	}
	// Nine deletes stay under the threshold.
	if _, fs := Endpoint(nil, recs[:18], EndpointOptions{}); len(fs) != 0 {
		t.Errorf("nine deletes reported as a burst: %v", fs)
	}
}

// Cloud records must not act as host telemetry: a cloud-only export gives
// no process coverage, so nothing is contradicted or reported unlogged.
func TestCloudOnlyNeverContradicts(t *testing.T) {
	events := []schema.Event{tc("e1", "2026-06-10T10:00:00Z", "Bash", "pytest -q")}
	recs := []endpoint.Record{cloudRec("2026-06-10T10:00:01Z", "aws", "s3:ListBuckets", "", "u", "")}
	res, findings := Endpoint(events, recs, EndpointOptions{})
	if events[0].Corroboration != schema.StateObserved || res.Contradicted != 0 || res.OutsideCover != 0 || len(findings) != 0 {
		t.Fatalf("%+v %+v %v", events[0], res, findings)
	}
}

func TestParseCloudCalls(t *testing.T) {
	for cmd, want := range map[string]string{
		"AWS_PROFILE=x aws --region eu-west-1 ec2 terminate-instances --instance-ids i-1": "aws [ec2] terminate-instances [i-1]",
		"sudo az keyvault secret show --vault-name kv -n s":                               "azure [keyvault secret] show [kv s]",
		"gcloud beta storage buckets delete gs://b":                                       "gcp [storage buckets] delete [gs://b]",
		"echo aws s3 rb": "",
	} {
		got := ""
		if cs := parseCloudCalls(cmd); len(cs) > 0 {
			got = fmt.Sprintf("%s %v %s %v", cs[0].provider, cs[0].groups, cs[0].verb, cs[0].names)
		}
		if got != want {
			t.Errorf("%q: %q, want %q", cmd, got, want)
		}
	}
}

// Re-analysing the same overlay with the same log keeps one note.
func TestCloudNoteIsIdempotent(t *testing.T) {
	events := []schema.Event{tc("e", "2026-06-10T10:00:00Z", "Bash", "aws s3 rb s3://b")}
	recs := []endpoint.Record{cloudRec("2026-06-10T10:00:01Z", "aws", "s3:DeleteBucket", "b", "u", "")}
	Endpoint(events, recs, EndpointOptions{})
	once := events[0].Summary
	Endpoint(events, recs, EndpointOptions{})
	if events[0].Summary != once || strings.Count(once, "corroborated by") != 1 {
		t.Fatalf("note stacked: %q", events[0].Summary)
	}
}
