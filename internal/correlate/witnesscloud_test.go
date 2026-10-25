package correlate

import (
	"fmt"
	"strings"
	"testing"

	"github.com/efij/AgentDFIR/v3/internal/endpoint"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

func TestK8sAuditCorroboratesKubectl(t *testing.T) {
	events := []schema.Event{
		tc("del", "2026-10-25T10:00:00Z", "Bash", "kubectl -n prod delete secret db"),
		tc("exec", "2026-10-25T10:00:10Z", "Bash", "kubectl exec -it api-0 -n prod -- sh"),
		tc("apply", "2026-10-25T10:00:20Z", "Bash", "kubectl apply -f deploy.yaml"),
		tc("slash", "2026-10-25T10:00:30Z", "Bash", "kubectl rollout restart deploy/web -n prod"),
		tc("other", "2026-10-25T10:00:40Z", "Bash", "kubectl delete pod web-1"), // log deleted web-2
		tc("get", "2026-10-25T10:00:50Z", "Bash", "kubectl get pods -A"),        // not in the log
	}
	k := func(when, op, res, failed string) endpoint.Record {
		return endpoint.Record{Time: ts(when), Kind: "cloud", Provider: "k8s", Operation: op, Resource: res, User: "dev@example.com", Failed: failed, Source: "k8s-audit", Ref: "audit.jsonl " + when}
	}
	recs := []endpoint.Record{
		k("2026-10-25T10:00:01Z", "delete secrets", "prod/db", ""),
		k("2026-10-25T10:00:11Z", "create pods/exec", "prod/api-0", "HTTP 403 Forbidden"),
		k("2026-10-25T10:00:21Z", "patch deployments", "prod/api", ""),
		k("2026-10-25T10:00:31Z", "patch deployments", "prod/web", ""),
		k("2026-10-25T10:00:41Z", "delete pods", "default/web-2", ""),
	}
	res, findings := Endpoint(events, recs, EndpointOptions{})
	want := map[string]string{"del": schema.StateCorroborated, "exec": schema.StateCorroborated, "apply": schema.StatePartial, // -f manifest: no resource to compare
		"slash": schema.StateCorroborated, "other": schema.StateObserved, "get": schema.StateObserved}
	for _, e := range events {
		if e.Corroboration != want[e.EventID] {
			t.Errorf("%s: %s, want %s (%s)", e.EventID, e.Corroboration, want[e.EventID], e.Summary)
		}
	}
	if !strings.Contains(events[1].Summary, "the service refused it: HTTP 403 Forbidden") {
		t.Errorf("refusal not noted: %q", events[1].Summary)
	}
	if res.CloudCorroborated != 3 || res.CloudPartial != 1 || res.CloudRefused != 1 || res.CloudRecords != 5 || res.Contradicted != 0 || len(findings) != 0 {
		t.Errorf("result %+v findings %v", res, findings)
	}
}

func TestGitAuditCorroboratesGhAndPush(t *testing.T) {
	events := []schema.Event{
		tc("create", "2026-10-25T10:00:00Z", "Bash", "gh repo create acme/new-tool --private"),
		tc("push", "2026-10-25T10:00:10Z", "Bash", "git add -A && git commit -m wip && git push origin main"),
		tc("api", "2026-10-25T10:00:20Z", "Bash", "gh api -X DELETE repos/acme/api/branches/main/protection"),
		tc("read", "2026-10-25T10:00:30Z", "Bash", "gh api repos/acme/api"), // reads are not audited
		tc("gl", "2026-10-25T10:00:40Z", "Bash", "glab repo delete acme/old"),
	}
	g := func(when, prov, op, res string) endpoint.Record {
		return endpoint.Record{Time: ts(when), Kind: "cloud", Provider: prov, Operation: op, Resource: res, User: "dev", Source: prov + "-audit", Ref: prov + ".json " + when}
	}
	recs := []endpoint.Record{
		g("2026-10-25T10:00:02Z", "github", "repo.create", "acme/new-tool"),
		g("2026-10-25T10:00:12Z", "github", "git.push", "acme/api"),
		g("2026-10-25T10:00:21Z", "github", "protected_branch.destroy", "acme/api main"),
		g("2026-10-25T10:00:31Z", "github", "repo.access", "acme/api"),
		g("2026-10-25T10:00:41Z", "gitlab", "project_destroyed", "acme/old"),
	}
	res, _ := Endpoint(events, recs, EndpointOptions{})
	want := map[string]string{"create": schema.StateCorroborated, "push": schema.StatePartial /* a remote name, not a repository */, "api": schema.StateCorroborated, "read": schema.StateObserved, "gl": schema.StateCorroborated}
	for _, e := range events {
		if e.Corroboration != want[e.EventID] {
			t.Errorf("%s: %s, want %s (%s)", e.EventID, e.Corroboration, want[e.EventID], e.Summary)
		}
	}
	if res.CloudCorroborated != 3 || res.CloudPartial != 1 {
		t.Errorf("result %+v", res)
	}
	// `git commit -m push` is not a push.
	if c := parseWitnessCalls("git commit -m push"); len(c) != 0 {
		t.Errorf("commit parsed as push: %d calls", len(c))
	}
}

func TestGitDestructiveBurst(t *testing.T) {
	var recs []endpoint.Record
	for i := 0; i < 11; i++ {
		recs = append(recs, endpoint.Record{Time: ts(fmt.Sprintf("2026-10-25T10:%02d:00Z", i/2)), Kind: "cloud", Provider: "github", Operation: "repo.destroy",
			Resource: fmt.Sprintf("acme/r%d", i), User: "leaked-token", Source: "github-audit", Ref: fmt.Sprintf("gh %d", i)})
	}
	// Kubernetes deletes never feed the burst rule.
	for i := 0; i < 30; i++ {
		recs = append(recs, endpoint.Record{Time: ts("2026-10-25T10:01:00Z"), Kind: "cloud", Provider: "k8s", Operation: "delete pods", Resource: fmt.Sprintf("ns/p%d", i), User: "system:serviceaccount:kube-system:replicaset-controller", Source: "k8s-audit", Ref: "k"})
	}
	res, findings := Endpoint(nil, recs, EndpointOptions{})
	if len(findings) != 1 || res.CloudBursts != 1 || !strings.Contains(findings[0].Description, "leaked-token deleting 11 distinct resources") {
		t.Fatalf("burst: %+v %+v", res, findings)
	}
}

func TestStorageLogsCorroborate(t *testing.T) {
	events := []schema.Event{
		tc("s3rm", "2026-10-25T10:00:00Z", "Bash", "aws s3 rm s3://prod-logs/app/2026/10/25.log"),
		tc("s3api", "2026-10-25T10:00:10Z", "Bash", "aws s3api delete-bucket --bucket prod-logs"),
		tc("up", "2026-10-25T10:00:20Z", "Bash", "aws s3 cp ./dump.sql s3://drop-zone/dump.sql"),
		tc("gs", "2026-10-25T10:00:30Z", "Bash", "gsutil rm gs://media/a/b.png"),
		tc("gcloud", "2026-10-25T10:00:40Z", "Bash", "gcloud storage cp gs://media/c.txt ."),
		tc("az", "2026-10-25T10:00:50Z", "Bash", "az storage blob delete --account-name acct1 -c backups -n db.bak"),
		tc("miss", "2026-10-25T10:01:00Z", "Bash", "aws s3 rm s3://other/x"),
	}
	s := func(when, prov, op, res, failed string) endpoint.Record {
		return endpoint.Record{Time: ts(when), Kind: "cloud", Provider: prov, Operation: op, Resource: res, Failed: failed, Source: prov, Ref: prov + " " + when}
	}
	recs := []endpoint.Record{
		s("2026-10-25T10:00:01Z", "s3", "REST.DELETE.OBJECT", "prod-logs/app/2026/10/25.log", ""),
		s("2026-10-25T10:00:11Z", "s3", "REST.DELETE.BUCKET", "prod-logs", "AccessDenied"),
		s("2026-10-25T10:00:22Z", "s3", "REST.PUT.OBJECT", "drop-zone/dump.sql", ""),
		s("2026-10-25T10:00:31Z", "gcs", "DELETE DELETE_Object", "media/a/b.png", ""),
		s("2026-10-25T10:00:41Z", "gcs", "GET GET_Object", "media/c.txt", ""),
		s("2026-10-25T10:00:51Z", "azure-storage", "DeleteBlob", "/acct1/backups/db.bak", ""),
		s("2026-10-25T10:01:01Z", "s3", "REST.DELETE.OBJECT", "prod-logs/other", ""),
	}
	res, findings := Endpoint(events, recs, EndpointOptions{})
	for _, e := range events {
		want := schema.StateCorroborated
		if e.EventID == "miss" {
			want = schema.StateObserved
		}
		if e.Corroboration != want {
			t.Errorf("%s: %s, want %s (%s)", e.EventID, e.Corroboration, want, e.Summary)
		}
	}
	if res.CloudCorroborated != 6 || res.CloudRefused != 1 || len(findings) != 0 {
		t.Errorf("result %+v %v", res, findings)
	}
}
