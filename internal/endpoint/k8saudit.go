package endpoint

import (
	"fmt"
	"strconv"
	"strings"
)

// Kubernetes API-server audit log (audit.k8s.io/v1 Event, one per line,
// or an EventList {"items":[…]}). Each event is the control plane's record
// of one API request: the second witness for an agent's kubectl commands.
//
// Record: Provider k8s, Operation "<verb> <resource>[/<subresource>]"
// (e.g. "delete pods", "create pods/exec"), Resource "<namespace>/<name>"
// (or the name alone for cluster-scoped objects), User user.username,
// SourceIP the first of sourceIPs, Failed the HTTP status when >= 400.
//
// The API server logs a request once per stage it reaches; only the final
// stage (ResponseComplete or Panic, or an event without a stage) becomes a
// record, the earlier stages are counted as skipped.

func loadK8sAudit(path string) (*LoadResult, error) {
	res := &LoadResult{}
	staged := 0
	err := forEachJSONDoc(path, res, []string{"items"}, func(doc map[string]any, ref string) {
		if leaf(doc, "verb") == "" || leaf(doc, "auditID") == "" {
			res.problem(ref + ": not a Kubernetes audit event")
			return
		}
		switch leaf(doc, "stage") {
		case "", "ResponseComplete", "Panic":
		default:
			staged++
			res.ignore()
			return
		}
		t, ok := parseTime(firstNonEmpty(leaf(doc, "requestReceivedTimestamp"), leaf(doc, "stageTimestamp"), leaf(doc, "metadata.creationTimestamp")))
		if !ok {
			res.problem(ref + ": no recognizable timestamp")
			return
		}
		resource := leaf(doc, "objectRef.resource")
		if sub := leaf(doc, "objectRef.subresource"); sub != "" {
			resource += "/" + sub
		}
		op := leaf(doc, "verb")
		if resource != "" {
			op += " " + resource
		} else if u := leaf(doc, "requestURI"); u != "" {
			op += " " + u // non-resource URL such as /healthz
		}
		name := leaf(doc, "objectRef.name")
		if ns := leaf(doc, "objectRef.namespace"); ns != "" {
			name = strings.TrimSuffix(ns+"/"+name, "/")
		}
		r := Record{Time: t, Kind: "cloud", Provider: "k8s", Source: "k8s-audit", Ref: ref,
			Operation: op, Resource: name, User: leaf(doc, "user.username")}
		if ips, ok := doc["sourceIPs"].([]any); ok && len(ips) > 0 {
			r.SourceIP = anyStr(ips[0])
		}
		if c, _ := strconv.Atoi(leaf(doc, "responseStatus.code")); c >= 400 {
			r.Failed = fmt.Sprintf("HTTP %d", c)
			if reason := leaf(doc, "responseStatus.reason"); reason != "" {
				r.Failed += " " + reason
			}
		}
		res.Records = append(res.Records, r)
	})
	if staged > 0 && len(res.Problems) < 5 {
		res.Problems = append(res.Problems, fmt.Sprintf("%d earlier-stage event(s) (RequestReceived/ResponseStarted) folded into their final stage", staged))
	}
	return res, err
}
