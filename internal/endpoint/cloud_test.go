package endpoint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCloudAuditFormatsSniffAndParse(t *testing.T) {
	cases := []struct {
		name, body          string
		provider, op, user  string
		resourceHas, failed string
	}{
		{"cloudtrail.json", `{"Records":[{"eventTime":"2026-06-10T10:00:01Z","eventSource":"s3.amazonaws.com","eventName":"DeleteBucket","userIdentity":{"arn":"arn:aws:iam::1:user/dev"},"sourceIPAddress":"198.51.100.7","requestParameters":{"bucketName":"prod-logs"}}]}`,
			"aws", "s3:DeleteBucket", "arn:aws:iam::1:user/dev", "prod-logs", ""},
		{"trail.jsonl", `{"eventTime":"2026-06-10T10:00:02Z","eventSource":"rds.amazonaws.com","eventName":"DeleteDBInstance","errorCode":"AccessDenied","userIdentity":{"principalId":"AID1"},"requestParameters":{"dBInstanceIdentifier":"db1"}}` + "\n",
			"aws", "rds:DeleteDBInstance", "AID1", "db1", "AccessDenied"},
		{"activity.json", `[{"eventTimestamp":"2026-06-10T10:00:03Z","operationName":{"value":"Microsoft.Storage/storageAccounts/delete"},"status":{"value":"Succeeded"},"caller":"sp-app","resourceId":"/subscriptions/s/resourceGroups/rg/providers/Microsoft.Storage/storageAccounts/acct1","httpRequest":{"clientIpAddress":"203.0.113.9"}}]`,
			"azure", "microsoft.storage/storageaccounts/delete", "sp-app", "acct1", ""},
		{"diag.json", `{"records":[{"time":"2026-06-10T10:00:04Z","operationName":"MICROSOFT.KEYVAULT/VAULTS/DELETE","resultType":"Failed","resourceId":"/SUBSCRIPTIONS/S/RESOURCEGROUPS/RG/PROVIDERS/MICROSOFT.KEYVAULT/VAULTS/KV1","callerIpAddress":"203.0.113.9"}]}`,
			"azure", "microsoft.keyvault/vaults/delete", "", "KV1", "Failed"},
		{"gcp.json", `[{"timestamp":"2026-06-10T10:00:05Z","protoPayload":{"serviceName":"cloudsql.googleapis.com","methodName":"cloudsql.instances.delete","resourceName":"projects/p/instances/db1","authenticationInfo":{"principalEmail":"dev@example.com"},"requestMetadata":{"callerIp":"192.0.2.4"}}}]`,
			"gcp", "cloudsql.googleapis.com cloudsql.instances.delete", "dev@example.com", "instances/db1", ""},
	}
	for _, tc := range cases {
		p := writeFile(t, tc.name, tc.body)
		f, err := Sniff(p)
		if err != nil || f != FormatCloud {
			t.Fatalf("%s: sniffed %q %v", tc.name, f, err)
		}
		lr, err := Load(p, FormatAuto)
		if err != nil || len(lr.Records) != 1 {
			t.Fatalf("%s: %v records=%d problems=%v", tc.name, err, len(lr.Records), lr.Problems)
		}
		r := lr.Records[0]
		if r.Kind != "cloud" || r.Provider != tc.provider || r.Operation != tc.op || r.User != tc.user || r.Failed != tc.failed ||
			!strings.Contains(r.Resource, tc.resourceHas) || r.Ref == "" || r.Time.IsZero() {
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
	// A generic process export must still be read as JSONL, not cloud.
	p := writeFile(t, "proc.jsonl", `{"time":"2026-06-10T10:00:00Z","kind":"process","cmdline":"ls"}`+"\n")
	if f, _ := Sniff(p); f != FormatJSONL {
		t.Fatalf("generic export sniffed as %q", f)
	}
}
