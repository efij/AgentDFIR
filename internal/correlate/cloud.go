package correlate

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/efij/AgentDFIR/v3/internal/endpoint"
	"github.com/efij/AgentDFIR/v3/internal/schema"
)

// Cloud audit correlation. An agent's az, aws or gcloud command is
// CORROBORATED when the provider's control plane recorded the same
// operation within cloudWindow, on the same resource when the command
// names one. A miss changes nothing: the export may be for a different
// account, subscription or project, so absence is never a contradiction.
//
// From the audit log alone, CLOUD_DESTRUCTIVE_BURST reports one identity
// deleting many resources in a short time. This is where tempo means
// something: every coding agent retries in seconds, but a person tearing
// down ten storage accounts in ten minutes is rare.

const (
	cloudWindow     = 2 * time.Minute
	burstWindow     = 10 * time.Minute
	burstMinDeletes = 10
)

// cloudCall is what a CLI command asks the control plane to do.
type cloudCall struct {
	provider string   // aws | azure | gcp
	groups   []string // command groups: [storage account], [s3api], [sql instances]
	verb     string   // delete, delete-bucket, list …
	names    []string // resource names given on the command line
}

func cloudPass(events []schema.Event, records []endpoint.Record, res *EndpointResult) []schema.Finding {
	res.CloudRecords = len(records)
	if len(records) == 0 {
		return nil
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].Time.Before(records[j].Time) })
	start, end := records[0].Time, records[len(records)-1].Time
	matched := make([]bool, len(records))
	matchedBy := map[int]*schema.Event{}

	for i := range events {
		ev := &events[i]
		if ev.EventType != schema.EventToolCall || ev.Command == "" {
			continue
		}
		calls := parseCloudCalls(ev.Command)
		if len(calls) == 0 {
			continue
		}
		t, ok := parseEventTime(ev.Timestamp)
		if !ok || t.Before(start.Add(-cloudWindow)) || t.After(end.Add(cloudWindow)) {
			continue
		}
		res.CloudCommands++
		best, bestScore := -1, 0
		for j := lowerBound(records, t.Add(-cloudWindow)); j < len(records) && !records[j].Time.After(t.Add(cloudWindow)); j++ {
			if matched[j] {
				continue
			}
			for _, c := range calls {
				if s := cloudScore(c, records[j]); s > bestScore {
					best, bestScore = j, s
				}
			}
		}
		if best < 0 {
			continue
		}
		matched[best] = true
		matchedBy[best] = ev
		r := records[best]
		if ev.Corroboration == schema.StateObserved || ev.Corroboration == schema.StateReported || ev.Corroboration == schema.StateUnknown {
			ev.Corroboration = schema.StateCorroborated
		}
		note := fmt.Sprintf("corroborated by %s: %s by %s (%s)", r.Source, r.Operation, orUnknown(r.User), r.Ref)
		if r.Failed != "" {
			note += "; the cloud refused it: " + r.Failed
			res.CloudRefused++
		}
		ev.Summary = appendNote(ev.Summary, note)
		res.CloudCorroborated++
	}
	return burstFindings(records, matchedBy, res)
}

// burstFindings: one finding per identity whose successful deletes reach
// burstMinDeletes distinct resources inside burstWindow.
func burstFindings(records []endpoint.Record, matchedBy map[int]*schema.Event, res *EndpointResult) []schema.Finding {
	byUser := map[string][]int{}
	var users []string
	for i, r := range records {
		if r.Failed != "" || !isDeleteOp(r) {
			continue
		}
		u := orUnknown(r.User)
		if _, ok := byUser[u]; !ok {
			users = append(users, u)
		}
		byUser[u] = append(byUser[u], i)
	}
	sort.Strings(users)
	var out []schema.Finding
	for _, u := range users {
		idx := byUser[u]
		at := func(k int) time.Time { return records[idx[k]].Time }
		for i := 0; i < len(idx); {
			j := i
			for j+1 < len(idx) && at(j+1).Sub(at(i)) <= burstWindow {
				j++
			}
			if distinctOps(records, idx[i:j+1]) < burstMinDeletes {
				i++
				continue
			}
			// A burst: keep going while the deletes keep coming.
			for j+1 < len(idx) && at(j+1).Sub(at(j)) <= burstWindow {
				j++
			}
			out = append(out, burstFinding(records, idx[i:j+1], u, matchedBy))
			res.CloudBursts++
			i = j + 1
		}
	}
	return out
}

func distinctOps(records []endpoint.Record, win []int) int {
	d := map[string]bool{}
	for _, j := range win {
		d[records[j].Operation+"|"+records[j].Resource] = true
	}
	return len(d)
}

func burstFinding(records []endpoint.Record, win []int, u string, matchedBy map[int]*schema.Event) schema.Finding {
	var refs, lines []string
	agentMatched := 0
	var sessionID, agentID string
	for _, j := range win {
		r := records[j]
		if len(refs) < 5 {
			refs = append(refs, r.Ref)
			lines = append(lines, trim(r.Operation+" "+r.Resource, 160))
		}
		if ev := matchedBy[j]; ev != nil {
			agentMatched++
			if sessionID == "" {
				sessionID, agentID = ev.SessionID, ev.AgentID
			}
		}
	}
	first, last := records[win[0]].Time, records[win[len(win)-1]].Time
	link := "None of them match a command in the collected transcripts: they came from a script, another tool or another machine."
	if agentMatched > 0 {
		link = fmt.Sprintf("%d of them match commands in the collected agent transcripts.", agentMatched)
	}
	return schema.Finding{
		RuleID: "CLOUD_DESTRUCTIVE_BURST", Severity: "HIGH", Title: "Many Cloud Resources Deleted by One Identity in Minutes",
		Description: fmt.Sprintf("The %s audit log shows %s deleting %d distinct resources between %s and %s (%s). %s",
			records[win[0]].Provider, u, distinctOps(records, win), first.Format(time.RFC3339), last.Format(time.RFC3339), last.Sub(first).Round(time.Second), link),
		SessionID: sessionID, AgentID: agentID,
		Related: lines, EvidenceRefs: refs,
		Status: schema.StateObserved, Endpoint: schema.StateObserved,
		MitreATTACK: "T1485", MitreATLAS: "AML.T0101",
		FalsePositive: "Planned teardown of a test environment, or infrastructure-as-code destroying a stack. Check the identity and whether the teardown was scheduled.",
	}
}

func isDeleteOp(r endpoint.Record) bool {
	op := strings.ToLower(r.Operation)
	if r.Provider == "azure" {
		return strings.HasSuffix(op, "/delete")
	}
	for _, w := range []string{"delete", "terminate", "destroy", "purge", "schedulekeydeletion"} {
		if strings.Contains(op, w) {
			return true
		}
	}
	return false
}

func orUnknown(s string) string {
	if s == "" {
		return "an unrecorded identity"
	}
	return s
}

// ---- command parsing ----

// parseCloudCalls finds az, aws and gcloud invocations in a command line,
// including each part of a compound command.
func parseCloudCalls(cmd string) []cloudCall {
	var out []cloudCall
	for _, seg := range splitCompound(cmd) {
		toks := strings.Fields(seg)
		for len(toks) > 0 && (strings.Contains(toks[0], "=") && !strings.HasPrefix(toks[0], "-") || toks[0] == "sudo" || toks[0] == "command" || toks[0] == "exec") {
			toks = toks[1:]
		}
		for i := range toks {
			toks[i] = strings.Trim(toks[i], `"'`)
		}
		if len(toks) < 3 {
			continue
		}
		switch exeName(toks[0]) {
		case "aws":
			if c, ok := parseAWS(toks[1:]); ok {
				out = append(out, c)
			}
		case "az":
			if c, ok := parseAz(toks[1:]); ok {
				out = append(out, c)
			}
		case "gcloud":
			if c, ok := parseGcloud(toks[1:]); ok {
				out = append(out, c)
			}
		}
	}
	return out
}

// awsValueFlags are global flags that take a value before the service.
var awsValueFlags = map[string]bool{"--profile": true, "--region": true, "--output": true, "--endpoint-url": true, "--query": true, "--color": true, "--cli-read-timeout": true, "--cli-connect-timeout": true}

func parseAWS(t []string) (cloudCall, bool) {
	var pos []string
	names := []string{}
	for i := 0; i < len(t); i++ {
		a := t[i]
		if strings.HasPrefix(a, "--") {
			flag, val, hasEq := strings.Cut(a, "=")
			if !hasEq && i+1 < len(t) && !strings.HasPrefix(t[i+1], "--") && (awsValueFlags[flag] || len(pos) >= 2) {
				val = t[i+1]
				i++
			}
			if len(pos) >= 2 && isNameFlag(flag) && val != "" {
				names = append(names, val)
			}
			continue
		}
		pos = append(pos, a)
	}
	if len(pos) < 2 {
		return cloudCall{}, false
	}
	for _, p := range pos[2:] {
		if strings.HasPrefix(p, "s3://") {
			names = append(names, strings.SplitN(strings.TrimPrefix(p, "s3://"), "/", 2)[0])
		}
	}
	return cloudCall{provider: "aws", groups: []string{pos[0]}, verb: pos[1], names: names}, true
}

func parseAz(t []string) (cloudCall, bool) {
	var pos, names []string
	for i := 0; i < len(t); i++ {
		a := t[i]
		if strings.HasPrefix(a, "-") {
			flag, val, hasEq := strings.Cut(a, "=")
			if !hasEq && i+1 < len(t) && !strings.HasPrefix(t[i+1], "-") {
				val = t[i+1]
				i++
			}
			if flag == "-n" || flag == "--name" || flag == "--account-name" || flag == "--vault-name" || flag == "--ids" {
				names = append(names, val)
			}
			continue
		}
		if !hasFlagBefore(t, i) {
			pos = append(pos, a)
		}
	}
	if len(pos) < 2 {
		return cloudCall{}, false
	}
	return cloudCall{provider: "azure", groups: pos[:len(pos)-1], verb: pos[len(pos)-1], names: names}, true
}

func hasFlagBefore(t []string, i int) bool {
	for _, a := range t[:i] {
		if strings.HasPrefix(a, "-") {
			return true
		}
	}
	return false
}

var gcloudVerbs = map[string]bool{"delete": true, "create": true, "update": true, "patch": true, "list": true, "describe": true, "destroy": true, "disable": true, "enable": true, "add-iam-policy-binding": true, "remove-iam-policy-binding": true, "set-iam-policy": true, "rm": true, "cp": true}

func parseGcloud(t []string) (cloudCall, bool) {
	var groups, names []string
	verb := ""
	for i := 0; i < len(t); i++ {
		a := t[i]
		if strings.HasPrefix(a, "-") {
			if !strings.Contains(a, "=") && i+1 < len(t) && !strings.HasPrefix(t[i+1], "-") && verb == "" {
				i++
			}
			continue
		}
		switch {
		case verb == "" && (a == "alpha" || a == "beta") && len(groups) == 0:
		case verb == "" && gcloudVerbs[a]:
			verb = a
		case verb == "":
			groups = append(groups, a)
		default:
			names = append(names, a)
		}
	}
	if verb == "" || len(groups) == 0 {
		return cloudCall{}, false
	}
	return cloudCall{provider: "gcp", groups: groups, verb: verb, names: names}, true
}

func isNameFlag(f string) bool {
	f = strings.TrimPrefix(f, "--")
	return f == "bucket" || f == "name" || f == "key-id" || f == "secret-id" || f == "instance-ids" || f == "stack-name" ||
		strings.HasSuffix(f, "-name") || strings.HasSuffix(f, "-identifier") || strings.HasSuffix(f, "-arn")
}

// ---- matching ----

// cloudScore: 0 = not this record. 95 = operation and resource name agree;
// 75 = operation agrees and the command named no resource; 70 = operation
// agrees and the record names none.
func cloudScore(c cloudCall, r endpoint.Record) int {
	if c.provider != r.Provider || !opMatches(c, r) {
		return 0
	}
	if len(c.names) == 0 {
		return 75
	}
	if r.Resource == "" {
		return 70
	}
	res := strings.ToLower(r.Resource)
	for _, n := range c.names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" && strings.Contains(res, n) {
			return 95
		}
	}
	return 0 // same operation on a different resource
}

func opMatches(c cloudCall, r endpoint.Record) bool {
	op := strings.ToLower(r.Operation)
	switch c.provider {
	case "aws":
		svc, name, _ := strings.Cut(op, ":")
		want := strings.ToLower(c.groups[0])
		if want == "s3api" {
			want = "s3"
		}
		if svc != want {
			return false
		}
		verb := strings.ReplaceAll(strings.ToLower(c.verb), "-", "")
		if want == "s3" {
			if alias, ok := s3Aliases[c.verb]; ok {
				verb = alias
			}
		}
		return strings.HasPrefix(name, verb) // lambda appends an API date: deletefunction20150331
	case "azure":
		if !azureVerbMatches(c.verb, op) {
			return false
		}
		key := strings.Join(c.groups, " ")
		for _, k := range azureTypeKeys { // longest first: "group lock" before "group"
			if key == k || strings.HasPrefix(key, k+" ") {
				return strings.Contains(op, azureTypes[k])
			}
		}
		// Unlisted group: the provider namespace and the resource noun.
		if !strings.Contains(op, "microsoft."+c.groups[0]) {
			return false
		}
		return len(c.groups) < 2 || strings.Contains(op, c.groups[1])
	case "gcp":
		svcs := gcpServices[c.groups[0]]
		if len(svcs) == 0 {
			svcs = []string{c.groups[0]}
		}
		ok := false
		for _, s := range svcs {
			if strings.Contains(op, s) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
		verb := c.verb
		switch verb {
		case "rm":
			verb = "delete"
		case "describe":
			verb = "get"
		}
		if !strings.Contains(op, verb) {
			return false
		}
		noun := strings.TrimSuffix(c.groups[len(c.groups)-1], "s")
		return strings.Contains(op, noun)
	}
	return false
}

var s3Aliases = map[string]string{"rb": "deletebucket", "mb": "createbucket", "rm": "deleteobject", "ls": "list"}

func azureVerbMatches(verb, op string) bool {
	switch verb {
	case "delete":
		return strings.HasSuffix(op, "/delete")
	case "purge":
		return strings.Contains(op, "purge")
	case "create", "update", "set", "add":
		return strings.HasSuffix(op, "/write")
	case "list", "show":
		return strings.HasSuffix(op, "/read") || strings.Contains(op, "listkeys")
	case "show-connection-string", "renew":
		return strings.Contains(op, "listkeys") || strings.Contains(op, "regeneratekey")
	case "disable":
		return strings.HasSuffix(op, "/delete") || strings.HasSuffix(op, "/write")
	}
	return strings.Contains(op, strings.ReplaceAll(verb, "-", ""))
}

// azureTypes maps az command groups to Resource Manager resource types.
var azureTypes = map[string]string{
	"storage account":             "microsoft.storage/storageaccounts",
	"keyvault":                    "microsoft.keyvault/",
	"group":                       "microsoft.resources/subscriptions/resourcegroups",
	"functionapp":                 "microsoft.web/sites",
	"webapp":                      "microsoft.web/sites",
	"appservice plan":             "microsoft.web/serverfarms",
	"vm":                          "microsoft.compute/virtualmachines",
	"aks":                         "microsoft.containerservice/managedclusters",
	"sql db":                      "microsoft.sql/servers/databases",
	"sql server":                  "microsoft.sql/servers",
	"cosmosdb":                    "microsoft.documentdb/databaseaccounts",
	"lock":                        "microsoft.authorization/locks",
	"resource lock":               "microsoft.authorization/locks",
	"group lock":                  "microsoft.authorization/locks",
	"role assignment":             "microsoft.authorization/roleassignments",
	"backup protection":           "microsoft.recoveryservices/vaults",
	"backup vault":                "microsoft.recoveryservices/vaults",
	"monitor diagnostic-settings": "microsoft.insights/diagnosticsettings",
}

var azureTypeKeys = func() []string {
	keys := make([]string, 0, len(azureTypes))
	for k := range azureTypes {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if len(keys[i]) != len(keys[j]) {
			return len(keys[i]) > len(keys[j])
		}
		return keys[i] < keys[j]
	})
	return keys
}()

// gcpServices maps gcloud command groups to audit-log service names.
var gcpServices = map[string][]string{
	"sql":       {"cloudsql", "sqladmin"},
	"storage":   {"storage"},
	"compute":   {"compute"},
	"secrets":   {"secretmanager"},
	"projects":  {"cloudresourcemanager"},
	"container": {"container"},
	"functions": {"cloudfunctions"},
	"run":       {"run.googleapis"},
	"kms":       {"cloudkms"},
	"iam":       {"iam"},
	"logging":   {"logging"},
}
