package endpoint

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strings"
)

// Git hosting audit exports: the provider's own record of repository and
// organization changes, the second witness for an agent's `gh repo
// create`, `git push` or `gh api -X DELETE …`.
//
//   - GitHub audit log export, JSON (array or lines) or CSV: action
//     (repo.create, git.push, protected_branch.destroy …), actor,
//     repo, @timestamp or created_at (epoch milliseconds or RFC 3339),
//     actor_ip
//   - GitLab audit events JSON (the /audit_events API or the UI export):
//     event_name or details.custom_message/add/remove/change, details.author_name,
//     details.entity_path or target_details, details.ip_address, created_at

func isGitHubCSVHeader(l string) bool {
	cols := map[string]bool{}
	for _, c := range strings.Split(strings.ToLower(l), ",") {
		cols[strings.Trim(strings.TrimSpace(c), `"`)] = true
	}
	return cols["action"] && cols["actor"] && (cols["@timestamp"] || cols["created_at"])
}

func loadGitAudit(path string) (*LoadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	head := make([]byte, 512)
	n, _ := io.ReadFull(f, head)
	f.Close()
	head = bytes.TrimLeft(head[:n], "\xef\xbb\xbf \t\r\n")
	res := &LoadResult{}
	if len(head) > 0 && head[0] != '{' && head[0] != '[' {
		return loadGitHubCSV(path, res)
	}
	err = forEachJSONDoc(path, res, []string{"items", "events", "data"}, func(doc map[string]any, ref string) {
		var r Record
		var ok bool
		switch {
		case leaf(doc, "action") != "":
			r, ok = githubRecord(func(k string) string { return leaf(doc, k) })
		case leaf(doc, "entity_type") != "" || doc["details"] != nil:
			r, ok = gitlabRecord(doc)
		}
		if !ok {
			res.problem(ref + ": not a GitHub or GitLab audit event (or no timestamp)")
			return
		}
		r.Ref = ref
		res.Records = append(res.Records, r)
	})
	return res, err
}

func loadGitHubCSV(path string, res *LoadResult) (*LoadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cr := csv.NewReader(f)
	cr.FieldsPerRecord = -1
	cr.LazyQuotes = true
	header, err := cr.Read()
	if err != nil {
		return nil, fmt.Errorf("csv header: %w", err)
	}
	for i := range header {
		header[i] = strings.TrimSpace(strings.TrimPrefix(header[i], "\xef\xbb\xbf"))
	}
	base := baseName(path)
	n := 1
	for {
		row, err := cr.Read()
		if err == io.EOF {
			break
		}
		n++
		ref := fmt.Sprintf("%s:%d", base, n)
		if err != nil {
			res.problem(fmt.Sprintf("row %d: %v", n, err))
			continue
		}
		vals := map[string]string{}
		for i, v := range row {
			if i < len(header) {
				vals[header[i]] = v
			}
		}
		r, ok := githubRecord(func(k string) string { return vals[k] })
		if !ok {
			res.problem(ref + ": no action or timestamp")
			continue
		}
		r.Ref = ref
		res.Records = append(res.Records, r)
	}
	return res, nil
}

func githubRecord(get func(string) string) (Record, bool) {
	t, ok := parseTime(firstNonEmpty(get("@timestamp"), get("created_at"), get("timestamp")))
	action := get("action")
	if !ok || action == "" {
		return Record{}, false
	}
	var names []string
	names = append(names, firstNonEmpty(get("repo"), get("repository")))
	for _, k := range []string{"branch", "ref", "name", "team", "user", "org"} {
		if v := get(k); v != "" && len(names) < 4 {
			names = append(names, v)
		}
	}
	return Record{Time: t, Kind: "cloud", Provider: "github", Source: "github-audit",
		Operation: action, Resource: strings.Join(dedupe(names), " "),
		User: get("actor"), SourceIP: get("actor_ip")}, true
}

func gitlabRecord(doc map[string]any) (Record, bool) {
	t, ok := parseTime(firstNonEmpty(leaf(doc, "created_at"), leaf(doc, "time")))
	if !ok {
		return Record{}, false
	}
	op := firstNonEmpty(leaf(doc, "event_name"), leaf(doc, "details.event_name"), leaf(doc, "details.custom_message"))
	if op == "" {
		for _, k := range []string{"add", "remove", "change"} {
			if v := leaf(doc, "details."+k); v != "" {
				op = k + " " + v
				break
			}
		}
	}
	if op == "" {
		return Record{}, false
	}
	return Record{Time: t, Kind: "cloud", Provider: "gitlab", Source: "gitlab-audit",
		Operation: op,
		Resource:  firstNonEmpty(leaf(doc, "details.entity_path"), leaf(doc, "entity_path"), leaf(doc, "details.target_details")),
		User:      firstNonEmpty(leaf(doc, "details.author_name"), leaf(doc, "author_name"), leaf(doc, "author.name")),
		SourceIP:  firstNonEmpty(leaf(doc, "details.ip_address"), leaf(doc, "ip_address"))}, true
}
