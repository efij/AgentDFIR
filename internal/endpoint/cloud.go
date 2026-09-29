package endpoint

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
)

// Cloud audit logs are the control plane's own record of an API call: the
// second witness for an agent's az, aws and gcloud commands, the way auditd
// is for its shell commands. Three exports are read, as JSON, a JSON array
// or JSON Lines:
//
//   - AWS CloudTrail: {"Records":[…]} files, or events one per line
//   - Azure Activity Log: `az monitor activity-log list` output, the REST
//     {"value":[…]} shape, or diagnostic-settings {"records":[…]} blobs
//   - GCP Cloud Audit Logs: `gcloud logging read --format=json` output
//
// Files only. Nothing here calls a cloud API.

// looksLikeCloudAudit sniffs the first bytes of a JSON export.
func looksLikeCloudAudit(head []byte) bool {
	has := func(k string) bool { return bytes.Contains(head, []byte(`"`+k+`"`)) }
	switch {
	case has("eventSource") && has("eventName"):
		return true
	case has("protoPayload") && has("methodName"):
		return true
	case has("operationName") && (has("resourceId") || has("caller") || has("eventTimestamp")):
		return true
	}
	return false
}

func loadCloud(path string) (*LoadResult, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	res := &LoadResult{}
	base := baseName(path)
	n := 0
	emit := func(raw json.RawMessage) {
		n++
		var doc map[string]any
		if err := json.Unmarshal(raw, &doc); err != nil {
			res.problem(fmt.Sprintf("record %d: %v", n, err))
			return
		}
		if r, ok := cloudRecord(doc); ok {
			r.Ref = fmt.Sprintf("%s record %d", base, n)
			res.Records = append(res.Records, r)
		} else {
			res.Skipped++
		}
	}
	var visit func(raw json.RawMessage)
	visit = func(raw json.RawMessage) {
		raw = bytes.TrimSpace(raw)
		if len(raw) == 0 {
			return
		}
		if raw[0] == '[' {
			var arr []json.RawMessage
			if err := json.Unmarshal(raw, &arr); err != nil {
				res.problem("json array: " + err.Error())
				return
			}
			for _, e := range arr {
				visit(e)
			}
			return
		}
		var wrap map[string]json.RawMessage
		if err := json.Unmarshal(raw, &wrap); err != nil {
			res.problem("json: " + err.Error())
			return
		}
		for _, k := range []string{"Records", "value", "records", "entries"} {
			if inner, ok := wrap[k]; ok && len(bytes.TrimSpace(inner)) > 0 && bytes.TrimSpace(inner)[0] == '[' {
				visit(inner)
				return
			}
		}
		emit(raw)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			if !errors.Is(err, io.EOF) {
				res.problem("json: " + err.Error())
			}
			break
		}
		visit(raw)
	}
	sort.SliceStable(res.Records, func(i, j int) bool { return res.Records[i].Time.Before(res.Records[j].Time) })
	return res, nil
}

// cloudRecord maps one audit event of any of the three providers.
func cloudRecord(doc map[string]any) (Record, bool) {
	switch {
	case str(doc, "eventSource") != "" && str(doc, "eventName") != "":
		return cloudTrail(doc)
	case doc["protoPayload"] != nil:
		return gcpAudit(doc)
	case doc["operationName"] != nil:
		return azureActivity(doc)
	}
	return Record{}, false
}

func cloudTrail(doc map[string]any) (Record, bool) {
	t, ok := parseTime(str(doc, "eventTime"))
	if !ok {
		return Record{}, false
	}
	svc := strings.TrimSuffix(str(doc, "eventSource"), ".amazonaws.com")
	r := Record{
		Time: t, Kind: "cloud", Provider: "aws", Source: "cloudtrail",
		Operation: svc + ":" + str(doc, "eventName"),
		User:      firstNonEmpty(str(doc, "userIdentity.arn"), str(doc, "userIdentity.principalId"), str(doc, "userIdentity.userName")),
		SourceIP:  str(doc, "sourceIPAddress"),
		Failed:    str(doc, "errorCode"),
	}
	var names []string
	if rp, ok := doc["requestParameters"].(map[string]any); ok {
		names = append(names, resourceNames(rp)...)
	}
	if rs, ok := doc["resources"].([]any); ok {
		for _, x := range rs {
			if m, ok := x.(map[string]any); ok {
				names = append(names, str(m, "ARN"))
			}
		}
	}
	r.Resource = strings.Join(dedupe(names), " ")
	return r, true
}

func azureActivity(doc map[string]any) (Record, bool) {
	t, ok := parseTime(firstNonEmpty(str(doc, "eventTimestamp"), str(doc, "time"), str(doc, "submissionTimestamp")))
	if !ok {
		return Record{}, false
	}
	op := firstNonEmpty(str(doc, "operationName.value"), str(doc, "operationName"))
	status := firstNonEmpty(str(doc, "status.value"), str(doc, "resultType"), str(doc, "status"))
	r := Record{
		Time: t, Kind: "cloud", Provider: "azure", Source: "azure-activity",
		Operation: strings.ToLower(op),
		Resource:  firstNonEmpty(str(doc, "resourceId"), str(doc, "resourceUri")),
		User:      firstNonEmpty(str(doc, "caller"), str(doc, "identity.claims.name"), str(doc, "identity.claims.appid")),
		SourceIP:  firstNonEmpty(str(doc, "httpRequest.clientIpAddress"), str(doc, "callerIpAddress")),
	}
	if strings.EqualFold(status, "Failed") {
		r.Failed = firstNonEmpty(str(doc, "subStatus.value"), str(doc, "properties.statusCode"), "Failed")
	}
	return r, op != ""
}

func gcpAudit(doc map[string]any) (Record, bool) {
	t, ok := parseTime(firstNonEmpty(str(doc, "timestamp"), str(doc, "receiveTimestamp")))
	if !ok {
		return Record{}, false
	}
	method := str(doc, "protoPayload.methodName")
	r := Record{
		Time: t, Kind: "cloud", Provider: "gcp", Source: "gcp-audit",
		Operation: strings.TrimSpace(str(doc, "protoPayload.serviceName") + " " + method),
		Resource:  str(doc, "protoPayload.resourceName"),
		User:      str(doc, "protoPayload.authenticationInfo.principalEmail"),
		SourceIP:  str(doc, "protoPayload.requestMetadata.callerIp"),
	}
	if c, ok := dig(doc, "protoPayload.status.code").(float64); ok && c != 0 {
		r.Failed = fmt.Sprintf("status %d", int(c))
	}
	return r, method != ""
}

// resourceNames pulls resource identifiers out of CloudTrail
// requestParameters: the values of keys that name or identify something.
func resourceNames(m map[string]any) []string {
	var out []string
	for k, v := range m {
		lk := strings.ToLower(k)
		if !(strings.Contains(lk, "name") || strings.HasSuffix(lk, "id") || strings.Contains(lk, "identifier") || strings.Contains(lk, "arn") || lk == "bucket") {
			continue
		}
		switch x := v.(type) {
		case string:
			out = append(out, x)
		case map[string]any: // instancesSet {items:[{instanceId}]}
			for _, it := range asList(x["items"]) {
				if im, ok := it.(map[string]any); ok {
					out = append(out, resourceNames(im)...)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

func asList(v any) []any {
	l, _ := v.([]any)
	return l
}

// dig walks a dotted path through nested JSON objects.
func dig(doc map[string]any, path string) any {
	var cur any = doc
	for _, k := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[k]
	}
	return cur
}

func str(doc map[string]any, path string) string {
	s, _ := dig(doc, path).(string)
	return s
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}

func dedupe(l []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range l {
		if s != "" && !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
