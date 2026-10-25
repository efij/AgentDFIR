package correlate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/efij/AgentDFIR/v4/internal/endpoint"
	"github.com/efij/AgentDFIR/v4/internal/schema"
)

// Cloud-like audit sources beside CloudTrail/Azure/GCP, with the cloud
// audit semantics: a command is CORROBORATED when the service recorded
// the same operation within cloudWindow, on the same resource when the
// command names one; a miss changes nothing (the export may be for
// another cluster, organization or bucket), and nothing is contradicted.
//
//   - k8s: kubectl get/delete/apply/exec … ↔ audit verb + resource
//   - github/gitlab: gh repo create/delete, gh api -X …, git push, glab
//     repo … ↔ the audit action
//   - s3/gcs/azure-storage: aws s3 / s3api, gsutil / gcloud storage, az
//     storage blob|container ↔ the storage operation on bucket/key
//
// CLOUD_DESTRUCTIVE_BURST also runs over the GitHub and GitLab records
// (one identity destroying many repositories is rare); Kubernetes
// controllers and object churn make deletes routine there, so k8s and
// storage records do not feed it.

// witnessCall is one operation a command asks a service for.
type witnessCall struct {
	providers []string
	op        func(op string) bool // on the lower-cased record Operation
	names     []string
}

func witnessCloudPass(events []schema.Event, records []endpoint.Record, res *EndpointResult) []schema.Finding {
	res.CloudRecords += len(records)
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
		calls := parseWitnessCalls(ev.Command)
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
				if s := witnessScore(c, records[j]); s > bestScore {
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
		// Only an operation on the named resource corroborates. When the
		// command names no resource (or the record names none) the match
		// is by operation alone: PARTLY CONFIRMED.
		verb := "corroborated"
		if bestScore >= 95 {
			switch ev.Corroboration {
			case schema.StateObserved, schema.StateReported, schema.StateUnknown, schema.StatePartial:
				ev.Corroboration = schema.StateCorroborated
			}
			res.CloudCorroborated++
		} else {
			verb = "partly corroborated (operation only, no resource to compare)"
			switch ev.Corroboration {
			case schema.StateObserved, schema.StateReported, schema.StateUnknown:
				ev.Corroboration = schema.StatePartial
			}
			res.CloudPartial++
		}
		note := fmt.Sprintf("%s by %s: %s by %s (%s)", verb, r.Source, r.Operation, orUnknown(r.User), r.Ref)
		if r.Resource != "" {
			note = fmt.Sprintf("%s by %s: %s on %s by %s (%s)", verb, r.Source, r.Operation, trim(r.Resource, 80), orUnknown(r.User), r.Ref)
		}
		if r.Failed != "" {
			note += "; the service refused it: " + r.Failed
			res.CloudRefused++
		}
		ev.Summary = appendNote(ev.Summary, note)
		basis, conf := witnessCloudBasis(r.Provider, bestScore)
		addMatchBasis(res, WitnessCloud, ev, r, bestScore, basis, conf, cloudWindow, nil)
	}
	// Bursts over the Git hosting records only, indexed as burstFindings expects.
	var git []endpoint.Record
	gitBy := map[int]*schema.Event{}
	for j, r := range records {
		if r.Provider == "github" || r.Provider == "gitlab" {
			if ev := matchedBy[j]; ev != nil {
				gitBy[len(git)] = ev
			}
			git = append(git, r)
		}
	}
	return burstFindings(git, gitBy, res)
}

// witnessCloudBasis names what a Kubernetes, Git hosting or storage
// match compared, with the confidence of the cloud rung its score is on.
func witnessCloudBasis(provider string, score int) (string, string) {
	what := strings.TrimSuffix(provider, "-storage") + " storage operation"
	switch provider {
	case "k8s":
		what = "k8s audit verb"
	case "github", "gitlab":
		what = provider + " audit action"
	}
	_, conf := MatchBasis("cloud", score)
	switch {
	case score >= 95:
		return what + " + resource", conf
	case score >= 75:
		return what + "; the command named no resource", conf
	}
	return what + "; the record names no resource", conf
}

// witnessScore mirrors cloudScore: 95 operation and resource agree, 75
// the command named no resource, 70 the record names none, 0 otherwise.
func witnessScore(c witnessCall, r endpoint.Record) int {
	okProv := false
	for _, p := range c.providers {
		if p == r.Provider {
			okProv = true
		}
	}
	if !okProv || !c.op(strings.ToLower(r.Operation)) {
		return 0
	}
	if len(c.names) == 0 {
		return 75
	}
	if r.Resource == "" {
		return 70
	}
	for _, n := range c.names {
		if resourceMatches(r.Resource, n) {
			return 95
		}
	}
	return 0
}

// minNameLen: shorter names only match a resource exactly, never as a
// segment of a longer path.
const minNameLen = 3

// resourceMatches reports whether a name from a command line identifies
// the record's resource: the whole resource (one of its space-separated
// ids) equals the name, or the name's '/'-separated segments appear as
// whole, consecutive segments of it ("prod" matches ".../prod/..." and
// "prod/db", never "nonprod-db"). ARN colons count as separators; a
// URL scheme on the name (s3://, gs://) is ignored.
func resourceMatches(resource, name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if i := strings.Index(name, "://"); i >= 0 {
		name = name[i+3:]
	}
	name = strings.Trim(name, "/")
	if name == "" {
		return false
	}
	split := func(s string) []string {
		return strings.FieldsFunc(s, func(r rune) bool { return r == '/' || r == ':' })
	}
	want := split(name)
	for _, id := range strings.Fields(strings.ToLower(resource)) {
		if strings.Trim(id, "/") == name {
			return true
		}
		if len(name) < minNameLen || len(want) == 0 {
			continue
		}
		segs := split(id)
		for i := 0; i+len(want) <= len(segs); i++ {
			ok := true
			for k := range want {
				if segs[i+k] != want[k] {
					ok = false
					break
				}
			}
			if ok {
				return true
			}
		}
	}
	return false
}

// parseWitnessCalls finds kubectl, gh, glab, git push, aws s3, gsutil,
// gcloud storage and az storage invocations in each part of a command.
func parseWitnessCalls(cmd string) []witnessCall {
	var out []witnessCall
	for _, seg := range splitCompound(cmd) {
		toks := strings.Fields(seg)
		for len(toks) > 0 && (strings.Contains(toks[0], "=") && !strings.HasPrefix(toks[0], "-") || toks[0] == "sudo" || toks[0] == "command" || toks[0] == "exec") {
			toks = toks[1:]
		}
		for i := range toks {
			toks[i] = strings.Trim(toks[i], `"'`)
		}
		if len(toks) < 2 {
			continue
		}
		var c []witnessCall
		switch exeName(toks[0]) {
		case "kubectl", "oc":
			c = parseKubectl(toks[1:])
		case "gh":
			c = parseGh(toks[1:])
		case "glab":
			c = parseGlab(toks[1:])
		case "git":
			c = parseGitPush(toks[1:])
		case "aws":
			c = parseAWSStorage(toks[1:])
		case "gsutil":
			c = parseGCSCommand(toks[1:])
		case "gcloud":
			if len(toks) > 2 && toks[1] == "storage" {
				c = parseGCSCommand(toks[2:])
			}
		case "az":
			c = parseAzStorage(toks[1:])
		}
		out = append(out, c...)
	}
	return out
}

// positionals splits arguments into positionals and flag values; flags in
// valued take the next token as their value.
func positionals(t []string, valued map[string]bool) (pos []string, flags map[string]string) {
	flags = map[string]string{}
	for i := 0; i < len(t); i++ {
		a := t[i]
		if strings.HasPrefix(a, "-") && len(a) > 1 {
			k, v, eq := strings.Cut(a, "=")
			if !eq && valued[k] && i+1 < len(t) {
				v = t[i+1]
				i++
			}
			flags[k] = v
			continue
		}
		pos = append(pos, a)
	}
	return pos, flags
}

func anyOf(words ...string) func(string) bool {
	return func(op string) bool {
		for _, w := range words {
			if strings.Contains(op, w) {
				return true
			}
		}
		return false
	}
}

// ---- Kubernetes ----

var kubectlValued = map[string]bool{"-n": true, "--namespace": true, "--context": true, "--kubeconfig": true, "--cluster": true, "--user": true,
	"-o": true, "--output": true, "-l": true, "--selector": true, "-f": true, "--filename": true, "-c": true, "--container": true,
	"--type": true, "-p": true, "--patch": true, "--replicas": true, "--image": true, "--field-selector": true, "-k": true, "--server": true, "-s": true, "--as": true, "--token": true}

// kubectl verb → audit verbs; the resource comes from the arguments.
var kubectlVerbs = map[string][]string{
	"get": {"get", "list", "watch"}, "describe": {"get", "list"}, "delete": {"delete", "deletecollection"},
	"create": {"create"}, "apply": {"create", "patch", "update"}, "replace": {"update", "create"},
	"edit": {"patch", "update"}, "patch": {"patch"}, "label": {"patch"}, "annotate": {"patch"}, "set": {"patch", "update"},
	"scale": {"patch", "update"}, "rollout": {"patch", "update", "create"}, "expose": {"create"}, "run": {"create"},
	"exec": {"create", "get"}, "attach": {"create", "get"}, "cp": {"create", "get"}, "port-forward": {"create", "get"}, "logs": {"get"},
	"cordon": {"patch"}, "uncordon": {"patch"}, "drain": {"patch", "create", "delete"}, "taint": {"patch"},
}

var kubeShort = map[string]string{"po": "pods", "svc": "services", "deploy": "deployments", "ns": "namespaces", "cm": "configmaps",
	"sa": "serviceaccounts", "rs": "replicasets", "ds": "daemonsets", "sts": "statefulsets", "ing": "ingresses", "pv": "persistentvolumes",
	"pvc": "persistentvolumeclaims", "no": "nodes", "cj": "cronjobs", "crd": "customresourcedefinitions", "hpa": "horizontalpodautoscalers",
	"netpol": "networkpolicies", "ep": "endpoints", "ev": "events", "pdb": "poddisruptionbudgets", "sc": "storageclasses", "quota": "resourcequotas",
	"ingress": "ingresses", "networkpolicy": "networkpolicies", "endpoints": "endpoints", "secret": "secrets"}

func kubeResource(s string) string {
	s = strings.ToLower(s)
	s, _, _ = strings.Cut(s, ".") // deployments.apps
	if r, ok := kubeShort[s]; ok {
		return r
	}
	switch {
	case strings.HasSuffix(s, "s"):
		return s
	case strings.HasSuffix(s, "y"):
		return s[:len(s)-1] + "ies"
	}
	return s + "s"
}

func parseKubectl(t []string) []witnessCall {
	pos, flags := positionals(t, kubectlValued)
	if len(pos) == 0 {
		return nil
	}
	verb := pos[0]
	verbs, ok := kubectlVerbs[verb]
	if !ok {
		return nil
	}
	args := pos[1:]
	if verb == "rollout" || verb == "set" { // rollout restart deployment/x
		if len(args) > 0 {
			args = args[1:]
		}
	}
	resource, name := "", ""
	switch verb {
	case "exec", "attach", "cp", "port-forward", "logs":
		resource = "pods"
		if len(args) > 0 {
			name = args[0]
			if r, n, ok := strings.Cut(name, "/"); ok {
				resource, name = kubeResource(r), n
			}
			if verb == "cp" { // kubectl cp ns/pod:/path local
				name, _, _ = strings.Cut(name, ":")
				if _, n, ok := strings.Cut(name, "/"); ok {
					name = n
				}
			}
		}
	case "run":
		resource = "pods"
		if len(args) > 0 {
			name = args[0]
		}
	case "expose":
		resource = "services"
	default:
		if _, file := flags["-f"]; file || flags["--filename"] != "" || flags["-k"] != "" {
			break // resources come from a manifest the command line does not show
		}
		if len(args) > 0 {
			first := args[0]
			if r, n, ok := strings.Cut(first, "/"); ok {
				resource, name = kubeResource(r), n
			} else {
				resource = kubeResource(strings.Split(first, ",")[0])
				if len(args) > 1 {
					name = args[1]
				}
			}
		}
	}
	vs := map[string]bool{}
	for _, v := range verbs {
		vs[v] = true
	}
	c := witnessCall{providers: []string{"k8s"}, op: func(op string) bool {
		v, res, _ := strings.Cut(op, " ")
		if !vs[v] {
			return false
		}
		if resource == "" {
			return true
		}
		base, _, _ := strings.Cut(res, "/")
		return base == resource
	}}
	if name != "" {
		// The audit resource is namespace/name: with -n the full path is
		// compared, so even a short object name matches on segments.
		if ns := firstNonBlank(flags["-n"], flags["--namespace"]); ns != "" && !strings.Contains(name, "/") {
			name = ns + "/" + name
		}
		c.names = []string{name}
	}
	return []witnessCall{c}
}

// ---- GitHub / GitLab ----

var ghValued = map[string]bool{"-R": true, "--repo": true, "-X": true, "--method": true, "-f": true, "-F": true, "--field": true, "--raw-field": true,
	"-H": true, "--header": true, "-b": true, "--body": true, "-t": true, "--title": true, "--jq": true, "-q": true, "--hostname": true,
	"-d": true, "--description": true, "--visibility": true, "--org": true, "--env": true, "-e": true, "--team": true, "-B": true, "--base": true}

// gh command group → the action prefix the audit log uses.
var ghGroups = map[string]string{"repo": "repo.", "pr": "pull_request", "release": "release", "secret": "secret", "variable": "variable",
	"workflow": "workflow", "ruleset": "ruleset", "issue": "issue", "gist": "gist", "codespace": "codespace", "label": "label", "deploy-key": "deploy_key", "ssh-key": "public_key"}

func ghVerbWords(verb string) []string {
	switch verb {
	case "create", "fork":
		return []string{"create", "add"}
	case "delete", "remove":
		return []string{"destroy", "delete", "remove"}
	case "set", "edit":
		return []string{"create", "update", "change", "add"}
	case "rename":
		return []string{"rename"}
	case "archive", "unarchive":
		return []string{"archive"}
	case "merge":
		return []string{"merge"}
	case "close":
		return []string{"close"}
	case "enable", "disable":
		return []string{verb}
	}
	return nil
}

func parseGh(t []string) []witnessCall {
	pos, flags := positionals(t, ghValued)
	if len(pos) < 2 {
		return nil
	}
	repo := firstNonBlank(flags["-R"], flags["--repo"])
	if pos[0] == "api" {
		method := strings.ToUpper(firstNonBlank(flags["-X"], flags["--method"]))
		if method == "" {
			method = "GET"
			for _, k := range []string{"-f", "-F", "--field", "--raw-field"} {
				if _, ok := flags[k]; ok {
					method = "POST"
				}
			}
		}
		var words []string
		switch method {
		case "DELETE":
			words = []string{"destroy", "delete", "remove"}
		case "POST":
			words = []string{"create", "add"}
		case "PUT", "PATCH":
			words = []string{"update", "create", "change", "add"}
		default:
			return nil // reads are not in the audit log
		}
		p := strings.TrimPrefix(pos[1], "/")
		var names []string
		if parts := strings.Split(p, "/"); len(parts) >= 3 && (parts[0] == "repos" || parts[0] == "orgs") {
			if parts[0] == "repos" {
				names = []string{parts[1] + "/" + parts[2]}
			} else {
				names = []string{parts[1]}
			}
		}
		return []witnessCall{{providers: []string{"github"}, op: anyOf(words...), names: names}}
	}
	prefix, ok := ghGroups[pos[0]]
	words := ghVerbWords(pos[1])
	if !ok || words == nil {
		return nil
	}
	var names []string
	if len(pos) > 2 {
		names = append(names, pos[2])
	}
	if repo != "" {
		names = append(names, repo)
	}
	op := func(op string) bool { return strings.Contains(op, prefix) && anyOf(words...)(op) }
	return []witnessCall{{providers: []string{"github"}, op: op, names: names}}
}

func parseGlab(t []string) []witnessCall {
	pos, _ := positionals(t, ghValued)
	if len(pos) < 2 || pos[0] != "repo" {
		return nil
	}
	words := ghVerbWords(pos[1])
	if words == nil {
		return nil
	}
	var names []string
	if len(pos) > 2 {
		names = []string{pos[2]}
	}
	op := func(op string) bool { return strings.Contains(op, "project") && anyOf(words...)(op) }
	return []witnessCall{{providers: []string{"gitlab"}, op: op, names: names}}
}

// parseGitPush: `git push [remote|url] [refspec]`. The repository is only
// known when a URL is given; a remote name says nothing about it.
func parseGitPush(t []string) []witnessCall {
	pos, _ := positionals(t, map[string]bool{"-C": true, "-c": true, "--repo": true, "-o": true, "--push-option": true})
	if len(pos) == 0 || pos[0] != "push" {
		return nil
	}
	var names []string
	if len(pos) > 1 && (strings.Contains(pos[1], "://") || strings.Contains(pos[1], "@")) {
		u := pos[1]
		if i := strings.Index(u, "://"); i >= 0 {
			u = u[i+3:]
			if j := strings.IndexByte(u, '/'); j >= 0 {
				u = u[j+1:]
			}
		} else if _, after, ok := strings.Cut(u, ":"); ok { // git@github.com:o/r.git
			u = after
		}
		names = []string{strings.TrimSuffix(u, ".git")}
	}
	op := func(op string) bool {
		return op == "git.push" || strings.Contains(op, "git_push") || strings.Contains(op, "repository_git_operation") || strings.HasPrefix(op, "push")
	}
	return []witnessCall{{providers: []string{"github", "gitlab"}, op: op, names: names}}
}

// ---- object storage ----

func s3Path(u string) string { return strings.TrimSuffix(strings.TrimPrefix(u, "s3://"), "/") }

func parseAWSStorage(t []string) []witnessCall {
	pos, flags := positionals(t, map[string]bool{"--profile": true, "--region": true, "--output": true, "--endpoint-url": true, "--query": true,
		"--bucket": true, "--key": true, "--exclude": true, "--include": true, "--acl": true, "--storage-class": true, "--sse": true, "--copy-source": true})
	if len(pos) < 2 {
		return nil
	}
	call := func(names []string, ops ...string) []witnessCall {
		return []witnessCall{{providers: []string{"s3"}, op: anyOf(ops...), names: names}}
	}
	var s3args []string
	for _, p := range pos[2:] {
		if strings.HasPrefix(p, "s3://") {
			s3args = append(s3args, s3Path(p))
		}
	}
	switch pos[0] {
	case "s3":
		switch pos[1] {
		case "rm":
			return call(s3args, "delete.object", "multi_object_delete")
		case "rb":
			return call(s3args, "delete.bucket")
		case "mb":
			return call(s3args, "put.bucket")
		case "ls":
			if len(s3args) == 0 {
				return call(nil, "get.service")
			}
			return call(s3args, "get.bucket")
		case "cp", "mv", "sync":
			if len(s3args) == 0 {
				return nil
			}
			dstS3 := strings.HasPrefix(pos[len(pos)-1], "s3://")
			srcS3 := strings.HasPrefix(pos[2], "s3://")
			switch {
			case dstS3 && srcS3:
				return call(s3args, "copy.object", "put.object", "get.object")
			case dstS3:
				return call(s3args[len(s3args)-1:], "put.object", "post.upload", "put.part")
			default:
				return call(s3args[:1], "get.object", "get.bucket")
			}
		}
	case "s3api":
		bucket, key := flags["--bucket"], flags["--key"]
		name := strings.TrimSuffix(bucket+"/"+key, "/")
		var names []string
		if name != "" {
			names = []string{name}
		}
		ops := map[string][]string{
			"delete-object": {"delete.object"}, "delete-objects": {"multi_object_delete"}, "put-object": {"put.object"},
			"get-object": {"get.object"}, "head-object": {"head.object"}, "copy-object": {"copy.object", "put.object"},
			"delete-bucket": {"delete.bucket"}, "create-bucket": {"put.bucket"}, "list-objects": {"get.bucket"}, "list-objects-v2": {"get.bucket"},
			"put-bucket-policy": {"put.bucketpolicy"}, "delete-bucket-policy": {"delete.bucketpolicy"}, "put-bucket-acl": {"put.acl"}, "put-object-acl": {"put.acl"},
		}[pos[1]]
		if ops == nil {
			return nil
		}
		return call(names, ops...)
	}
	return nil
}

func parseGCSCommand(t []string) []witnessCall {
	pos, _ := positionals(t, map[string]bool{"-h": true, "-o": true, "-p": true, "-u": true})
	for len(pos) > 0 && strings.HasPrefix(pos[0], "-") {
		pos = pos[1:]
	}
	if len(pos) == 0 {
		return nil
	}
	if pos[0] == "buckets" || pos[0] == "objects" { // gcloud storage buckets delete gs://b
		if len(pos) < 2 {
			return nil
		}
		pos = append([]string{map[string]string{"delete": "rm", "create": "mb", "list": "ls", "describe": "ls"}[pos[1]]}, pos[2:]...)
	}
	var gs []string
	for _, p := range pos[1:] {
		if strings.HasPrefix(p, "gs://") {
			gs = append(gs, strings.TrimSuffix(strings.TrimPrefix(p, "gs://"), "/"))
		}
	}
	method := func(ms ...string) func(string) bool {
		return func(op string) bool {
			for _, m := range ms {
				if strings.HasPrefix(op, m) {
					return true
				}
			}
			return false
		}
	}
	call := func(names []string, ms ...string) []witnessCall {
		return []witnessCall{{providers: []string{"gcs"}, op: method(ms...), names: names}}
	}
	switch pos[0] {
	case "rm", "rb":
		return call(gs, "delete")
	case "mb":
		return call(gs, "post", "put")
	case "ls", "cat", "du", "stat":
		return call(gs, "get")
	case "cp", "mv", "rsync":
		if len(gs) == 0 {
			return nil
		}
		if strings.HasPrefix(pos[len(pos)-1], "gs://") {
			return call(gs[len(gs)-1:], "put", "post")
		}
		return call(gs[:1], "get")
	}
	return nil
}

func parseAzStorage(t []string) []witnessCall {
	pos, flags := positionals(t, map[string]bool{"--account-name": true, "-c": true, "--container-name": true, "-n": true, "--name": true,
		"-f": true, "--file": true, "-g": true, "--resource-group": true, "--auth-mode": true, "--account-key": true, "--connection-string": true,
		"--sas-token": true, "-d": true, "--destination": true, "-s": true, "--source": true, "--pattern": true, "--subscription": true})
	if len(pos) < 3 || pos[0] != "storage" {
		return nil
	}
	container := firstNonBlank(flags["-c"], flags["--container-name"])
	name := firstNonBlank(flags["-n"], flags["--name"])
	var ops []string
	switch pos[1] + " " + pos[2] {
	case "blob delete":
		ops = []string{"deleteblob"}
	case "blob delete-batch":
		ops = []string{"deleteblob"}
		container = firstNonBlank(flags["-s"], flags["--source"])
	case "blob upload", "blob upload-batch":
		ops = []string{"putblob", "putblock", "putblocklist"}
	case "blob download", "blob download-batch":
		ops = []string{"getblob"}
	case "blob list":
		ops = []string{"listblobs"}
	case "container delete":
		ops = []string{"deletecontainer"}
		container = firstNonBlank(container, name)
		name = ""
	case "container create":
		ops = []string{"createcontainer"}
		container = firstNonBlank(container, name)
		name = ""
	case "container list":
		ops = []string{"listcontainers"}
	default:
		return nil
	}
	var names []string
	switch {
	case container != "" && name != "":
		names = []string{container + "/" + name}
	case container != "":
		names = []string{container}
	}
	want := map[string]bool{}
	for _, o := range ops {
		want[o] = true
	}
	return []witnessCall{{providers: []string{"azure-storage"}, op: func(op string) bool { return want[op] }, names: names}}
}
