package endpoint

import (
	"os"
	"strings"
	"testing"
	"time"
)

// load writes body, checks the sniffed format and loads it.
func load(t *testing.T, name, body string, want Format) *LoadResult {
	t.Helper()
	p := write(t, name, body)
	// Year-less syslog lines take their year from the file's mtime.
	mt := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	_ = os.Chtimes(p, mt, mt)
	f, err := Sniff(p)
	if err != nil || f != want {
		t.Fatalf("%s: sniffed %q (%v), want %q", name, f, err, want)
	}
	res, err := Load(p, FormatAuto)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	if res.Format != want {
		t.Fatalf("%s: format %q", name, res.Format)
	}
	return res
}

func TestZeekDNSHTTPSSL(t *testing.T) {
	tsv := "#separator \\x09\n#set_separator\t,\n#empty_field\t(empty)\n#unset_field\t-\n#path\tdns\n" +
		"#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\tquery\tqtype_name\tanswers\n" +
		"#types\ttime\tstring\taddr\tport\taddr\tport\tenum\tstring\tstring\tvector[string]\n" +
		"1792922400.120000\tCx1\t10.0.0.5\t50000\t10.0.0.1\t53\tudp\texfil.example.net\tA\t203.0.113.9,203.0.113.10\n" +
		"1792922401.000000\tCx2\t10.0.0.5\t50001\t10.0.0.1\t53\tudp\t-\t-\t-\n" + // no query: skipped
		"1792922402.000000\tCx3\ttoo\tfew\n" // malformed
	res := load(t, "dns.log", tsv, FormatZeek)
	if len(res.Records) != 1 || res.Skipped != 2 || len(res.Problems) != 1 {
		t.Fatalf("records=%d skipped=%d problems=%v", len(res.Records), res.Skipped, res.Problems)
	}
	r := res.Records[0]
	if r.Kind != "dns" || r.DestHost != "exfil.example.net" || r.SourceIP != "10.0.0.5" || r.Answers != "203.0.113.9 203.0.113.10" || r.Source != "zeek-dns" || r.Time.Unix() != 1792922400 {
		t.Fatalf("dns: %+v", r)
	}

	js := `{"ts":1792922400.5,"uid":"C1","id.orig_h":"10.0.0.5","id.resp_h":"93.184.216.34","id.resp_p":80,"method":"POST","host":"upload.example.org","uri":"/drop?x=1","status_code":200}
{"ts":"2026-10-25T10:00:01.000Z","uid":"C2","id.orig_h":"10.0.0.5","id.resp_h":"140.82.112.3","id.resp_p":443,"server_name":"api.github.com","version":"TLSv13"}
{"ts":1792922402,"uid":"C3","id.orig_h":"10.0.0.5","query":"pypi.org","qtype_name":"AAAA","answers":["2a04::1"]}
{"ts":1792922403,"uid":
`
	res = load(t, "zeek.json", js, FormatZeek)
	if len(res.Records) != 3 || res.Skipped != 1 {
		t.Fatalf("json: records=%d skipped=%d %v", len(res.Records), res.Skipped, res.Problems)
	}
	h := res.Records[0]
	if h.Kind != "network" || h.DestHost != "upload.example.org" || h.URL != "/drop?x=1" || h.DestPort != 80 || h.Operation != "POST" || h.Source != "zeek-http" {
		t.Fatalf("http: %+v", h)
	}
	if s := res.Records[1]; s.DestHost != "api.github.com" || s.Source != "zeek-ssl" || s.DestPort != 443 {
		t.Fatalf("ssl: %+v", s)
	}
	if d := res.Records[2]; d.Kind != "dns" || d.DestHost != "pypi.org" || d.Answers != "2a04::1" {
		t.Fatalf("json dns: %+v", d)
	}
	// Unsupported Zeek log: reported, not guessed at.
	res = load(t, "conn.log", "#separator \\x09\n#path\tconn\n#fields\tts\tuid\n1792922400.0\tC1\n", FormatZeek)
	if len(res.Records) != 0 || len(res.Problems) == 0 || !strings.Contains(res.Problems[0], "UNSUPPORTED") {
		t.Fatalf("conn.log: %+v", res)
	}
}

func TestDNSQueryLogs(t *testing.T) {
	log := `25-Oct-2026 10:00:00.123 queries: info: client @0x7f8b1c0 10.0.0.5#53514 (exfil.example.net): query: exfil.example.net IN A +E(0)K (10.0.0.1)
Oct 25 10:00:01 gw dnsmasq[811]: query[A] Paste.Example.com from 10.0.0.6
Oct 25 10:00:01 gw dnsmasq[811]: forwarded paste.example.com to 1.1.1.1
Oct 25 10:00:01 gw dnsmasq[811]: reply paste.example.com is 198.51.100.4
Oct 25 10:00:02 pihole-FTL[900]: query[AAAA] ads.example from 10.0.0.7
Oct 25 10:00:02 pihole-FTL[900]: gravity blocked ads.example is ::
[1792922403] unbound[1234:0] info: 10.0.0.8 registry.npmjs.org. A IN
10/25/2026 10:00:04 AM 0E5C PACKET  000000D2B1E3A170 UDP Rcv 10.0.0.9      0002   Q [0001   D   NOERROR] A      (7)example(3)com(0)
10/25/2026 10:00:04 AM 0E5C PACKET  000000D2B1E3A170 UDP Snd 10.0.0.9      0002 R Q [8081   DR  NOERROR] A      (7)example(3)com(0)
this line has no timestamp
`
	res := load(t, "query.log", log, FormatDNSLog)
	if len(res.Records) != 5 || res.Skipped != 3 || len(res.Problems) != 1 {
		t.Fatalf("records=%d skipped=%d problems=%v %+v", len(res.Records), res.Skipped, res.Problems, res.Records)
	}
	want := []struct{ src, host, client, answers string }{
		{"bind", "exfil.example.net", "10.0.0.5", ""},
		{"dnsmasq", "paste.example.com", "10.0.0.6", "198.51.100.4"},
		{"pihole", "ads.example", "10.0.0.7", "::"},
		{"unbound", "registry.npmjs.org", "10.0.0.8", ""},
		{"windows-dns", "example.com", "10.0.0.9", ""},
	}
	for i, w := range want {
		r := res.Records[i]
		if r.Kind != "dns" || r.Source != w.src || r.DestHost != w.host || r.SourceIP != w.client || r.Answers != w.answers || r.Time.IsZero() {
			t.Errorf("%d: %+v", i, r)
		}
	}
	if got := res.Records[1].Time.Format(time.RFC3339); got != "2026-10-25T10:00:01Z" {
		t.Errorf("syslog year/zone: %s", got)
	}
}

func TestSquidAccessLog(t *testing.T) {
	log := `1792922400.123    180 10.0.0.5 TCP_MISS/200 411 GET http://example.com/a/b?q=1 - HIER_DIRECT/93.184.216.34 text/html
1792922401.000      5 10.0.0.5 TCP_DENIED/403 0 CONNECT webhook.site:443 dev HIER_NONE/- -
10.0.0.6 - alice [25/Oct/2026:10:00:02 +0000] "CONNECT api.github.com:443 HTTP/1.1" 200 5120 TCP_TUNNEL:HIER_DIRECT
1792922403.000 garbage
`
	res := load(t, "access.log", log, FormatSquid)
	if len(res.Records) != 3 || res.Skipped != 1 {
		t.Fatalf("records=%d skipped=%d %v", len(res.Records), res.Skipped, res.Problems)
	}
	a, d, c := res.Records[0], res.Records[1], res.Records[2]
	if a.Kind != "network" || a.DestHost != "example.com" || a.URL != "http://example.com/a/b?q=1" || a.DestIP != "93.184.216.34" || a.Failed != "" {
		t.Fatalf("native: %+v", a)
	}
	if d.DestHost != "webhook.site" || d.DestPort != 443 || d.Failed != "TCP_DENIED" || d.User != "dev" {
		t.Fatalf("denied: %+v", d)
	}
	if c.DestHost != "api.github.com" || c.User != "alice" || c.Operation != "CONNECT" || c.Time.Format(time.RFC3339) != "2026-10-25T10:00:02Z" {
		t.Fatalf("common: %+v", c)
	}
}

func TestProxyGenericExport(t *testing.T) {
	jsonl := `{"timestamp":"2026-10-25T10:00:00Z","user":"dev","url":"https://paste.example.com/raw/abc","action":"allowed"}
{"timestamp":"2026-10-25T10:00:01Z","user":"dev","url":"not a url"}
`
	res := load(t, "swg.jsonl", jsonl, FormatJSONL)
	if len(res.Records) != 1 || res.Skipped != 1 {
		t.Fatalf("records=%d skipped=%d %v", len(res.Records), res.Skipped, res.Problems)
	}
	r := res.Records[0]
	if r.Kind != "network" || r.Source != "proxy-export" || r.DestHost != "paste.example.com" || r.URL != "https://paste.example.com/raw/abc" || !IsSighting(r) {
		t.Fatalf("%+v", r)
	}
	csvDoc := "time,user,url,dest_host\n2026-10-25 10:00:00,dev,https://a.example/x,a.example\n"
	res = load(t, "swg.csv", csvDoc, FormatCSV)
	if len(res.Records) != 1 || res.Records[0].URL != "https://a.example/x" || res.Records[0].Source != "export" {
		t.Fatalf("csv with dest_host stays a host network record carrying the URL: %+v", res.Records)
	}
}

func TestAuthLogAndJournal(t *testing.T) {
	log := `Oct 25 10:00:00 host sudo:      dev : TTY=pts/0 ; PWD=/home/dev/proj ; USER=root ; COMMAND=/usr/bin/rm -rf /var/www/old
Oct 25 10:00:01 host sudo:      dev : command not allowed ; TTY=pts/0 ; PWD=/home/dev ; USER=root ; COMMAND=/bin/sh
Oct 25 10:00:02 host sshd[2201]: Accepted publickey for deploy from 10.0.0.5 port 50522 ssh2: ED25519 SHA256:abc
Oct 25 10:00:03 host sshd[2202]: Failed password for invalid user admin from 198.51.100.7 port 4242 ssh2
Oct 25 10:00:04 host su[2300]: pam_unix(su:session): session opened for user root(uid=0) by dev(uid=1000)
Oct 25 10:00:05 host CRON[2400]: pam_unix(cron:session): session closed for user root
2026-10-25T10:00:06.123456+00:00 host sudo[2500]:      dev : TTY=pts/1 ; PWD=/tmp ; USER=root ; ENV=A=1 ; COMMAND=/usr/bin/apt install -y jq
not syslog at all
`
	res := load(t, "auth.log", log, FormatAuthLog)
	// Each sudo line yields its process record plus a kind auth privilege-change record.
	if len(res.Records) != 9 || res.Skipped != 2 || len(res.Problems) != 1 {
		t.Fatalf("records=%d skipped=%d problems=%v %+v", len(res.Records), res.Skipped, res.Problems, res.Records)
	}
	s := res.Records[0]
	if s.Kind != "process" || s.Cmdline != "/usr/bin/rm -rf /var/www/old" || s.Exe != "/usr/bin/rm" || s.User != "dev" || s.Source != "authlog" || !IsSighting(s) {
		t.Fatalf("sudo: %+v", s)
	}
	if a := res.Records[1]; a.Kind != "auth" || a.Operation != "sudo" || a.PrivFrom != "dev" || a.PrivTo != "root" {
		t.Fatalf("sudo privilege change: %+v", a)
	}
	if f := res.Records[2]; f.Failed != "command not allowed" || f.Cmdline != "/bin/sh" {
		t.Fatalf("refused sudo: %+v", f)
	}
	if a := res.Records[4]; a.Kind != "auth" || a.Operation != "ssh-accept publickey" || a.User != "deploy" || a.SourceIP != "10.0.0.5" {
		t.Fatalf("sshd: %+v", a)
	}
	if f := res.Records[5]; f.Operation != "ssh-fail password" || f.User != "admin" || f.Failed == "" {
		t.Fatalf("sshd fail: %+v", f)
	}
	if su := res.Records[6]; su.Operation != "su" || su.Resource != "root" || su.User != "dev" {
		t.Fatalf("su: %+v", su)
	}
	if r := res.Records[7]; r.Cmdline != "/usr/bin/apt install -y jq" || r.PID != 2500 || r.Time.Nanosecond() == 0 {
		t.Fatalf("iso sudo: %+v", r)
	}

	journal := `{"__REALTIME_TIMESTAMP":"1792922400000000","_PID":"3100","_COMM":"sudo","SYSLOG_IDENTIFIER":"sudo","_EXE":"/usr/bin/sudo","_CMDLINE":"sudo rm -rf /var/www/old","_UID":"1000","MESSAGE":"     dev : TTY=pts/0 ; PWD=/home/dev ; USER=root ; COMMAND=/usr/bin/rm -rf /var/www/old"}
{"__REALTIME_TIMESTAMP":"1792922401000000","_PID":"3100","_COMM":"sudo","_CMDLINE":"sudo rm -rf /var/www/old","MESSAGE":"pam_unix(sudo:session): session closed"}
{"__REALTIME_TIMESTAMP":"1792922402000000","_PID":"3200","SYSLOG_IDENTIFIER":"sshd","MESSAGE":[65,99,99,101,112,116,101,100,32,112,97,115,115,119,111,114,100,32,102,111,114,32,100,101,118,32,102,114,111,109,32,49,48,46,48,46,48,46,53,32,112,111,114,116,32,50,50,32,115,115,104,50]}
{"MESSAGE":"no timestamp"}
{broken
`
	res = load(t, "journal.json", journal, FormatJournal)
	// sudo entry → sudo COMMAND record + _CMDLINE record; second line is the
	// same pid+cmdline (skipped); sshd byte-array MESSAGE → auth record;
	// the sudo line also yields its privilege-change auth record.
	if len(res.Records) != 4 || res.Skipped != 3 || len(res.Problems) != 2 {
		t.Fatalf("records=%d skipped=%d problems=%v %+v", len(res.Records), res.Skipped, res.Problems, res.Records)
	}
	var sawCmd, sawCmdline, sawSSH bool
	for _, r := range res.Records {
		switch {
		case r.Kind == "process" && r.Cmdline == "/usr/bin/rm -rf /var/www/old":
			sawCmd = true
		case r.Kind == "process" && r.Cmdline == "sudo rm -rf /var/www/old" && r.Exe == "/usr/bin/sudo" && r.PID == 3100:
			sawCmdline = true
		case r.Kind == "auth" && r.User == "dev" && r.SourceIP == "10.0.0.5":
			sawSSH = true
		case r.Kind == "auth" && r.Operation == "sudo" && r.PrivTo == "root":
		}
		if r.Source != "journald" {
			t.Errorf("source: %+v", r)
		}
	}
	if !sawCmd || !sawCmdline || !sawSSH {
		t.Fatalf("journal records: %+v", res.Records)
	}
}

func TestK8sAudit(t *testing.T) {
	log := `{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"a1","stage":"RequestReceived","requestURI":"/api/v1/namespaces/prod/secrets/db","verb":"delete","user":{"username":"dev@example.com"},"sourceIPs":["10.0.0.5"],"objectRef":{"resource":"secrets","namespace":"prod","name":"db","apiVersion":"v1"},"requestReceivedTimestamp":"2026-10-25T10:00:00.100000Z"}
{"kind":"Event","apiVersion":"audit.k8s.io/v1","level":"Metadata","auditID":"a1","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/prod/secrets/db","verb":"delete","user":{"username":"dev@example.com"},"sourceIPs":["10.0.0.5"],"objectRef":{"resource":"secrets","namespace":"prod","name":"db","apiVersion":"v1"},"responseStatus":{"code":200},"requestReceivedTimestamp":"2026-10-25T10:00:00.100000Z"}
{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"a2","stage":"ResponseComplete","verb":"create","user":{"username":"dev@example.com"},"objectRef":{"resource":"pods","subresource":"exec","namespace":"prod","name":"api-0"},"responseStatus":{"code":403,"reason":"Forbidden"},"requestReceivedTimestamp":"2026-10-25T10:00:01Z"}
{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"a3","stage":"ResponseComplete","verb":"list","user":{"username":"system:kube-scheduler"},"objectRef":{"resource":"nodes"},"requestReceivedTimestamp":"2026-10-25T10:00:02Z"}
{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"a4","stage":"ResponseComplete","verb":"get","requestReceivedTimestamp":"yesterday"}
{"not":"an audit event"}
`
	res := load(t, "audit.jsonl", log, FormatK8s)
	if len(res.Records) != 3 || res.Skipped != 3 {
		t.Fatalf("records=%d skipped=%d problems=%v", len(res.Records), res.Skipped, res.Problems)
	}
	d := res.Records[0]
	if d.Kind != "cloud" || d.Provider != "k8s" || d.Operation != "delete secrets" || d.Resource != "prod/db" || d.User != "dev@example.com" || d.SourceIP != "10.0.0.5" || d.Failed != "" || !IsWitnessCloud(d) {
		t.Fatalf("delete: %+v", d)
	}
	if e := res.Records[1]; e.Operation != "create pods/exec" || e.Failed != "HTTP 403 Forbidden" {
		t.Fatalf("exec: %+v", e)
	}
	if n := res.Records[2]; n.Operation != "list nodes" || n.Resource != "" {
		t.Fatalf("cluster-scoped: %+v", n)
	}
	// EventList wrapper.
	list := `{"kind":"EventList","apiVersion":"audit.k8s.io/v1","items":[{"auditID":"b1","verb":"get","objectRef":{"resource":"pods","namespace":"x","name":"p"},"requestReceivedTimestamp":"2026-10-25T10:00:00Z"}]}`
	if res := load(t, "list.json", list, FormatK8s); len(res.Records) != 1 || res.Records[0].Resource != "x/p" {
		t.Fatalf("eventlist: %+v", res)
	}
}

func TestGitAuditExports(t *testing.T) {
	gh := `[{"@timestamp":1792922400000,"action":"repo.create","actor":"dev","repo":"acme/new-tool","actor_ip":"203.0.113.5","org":"acme"},
{"created_at":"2026-10-25T10:00:05Z","action":"protected_branch.destroy","actor":"dev","repo":"acme/api","branch":"main"},
{"action":"git.push","actor":"dev"}]`
	res := load(t, "github.json", gh, FormatGitAud)
	if len(res.Records) != 2 || res.Skipped != 1 {
		t.Fatalf("records=%d skipped=%d %v", len(res.Records), res.Skipped, res.Problems)
	}
	if r := res.Records[0]; r.Provider != "github" || r.Operation != "repo.create" || !strings.Contains(r.Resource, "acme/new-tool") || r.User != "dev" || r.SourceIP != "203.0.113.5" || r.Time.Unix() != 1792922400 {
		t.Fatalf("repo.create: %+v", r)
	}
	if r := res.Records[1]; r.Operation != "protected_branch.destroy" || !strings.Contains(r.Resource, "main") {
		t.Fatalf("branch: %+v", r)
	}
	csvDoc := "@timestamp,action,actor,repo,actor_ip\n1792922400000,git.push,dev,acme/api,203.0.113.5\nnot-a-time,repo.destroy,dev,acme/x,\n"
	res = load(t, "github.csv", csvDoc, FormatGitAud)
	if len(res.Records) != 1 || res.Skipped != 1 || res.Records[0].Operation != "git.push" || res.Records[0].Resource != "acme/api" {
		t.Fatalf("csv: %+v", res)
	}
	gl := `{"id":1,"author_id":7,"entity_id":6,"entity_type":"Project","details":{"author_name":"Dev","event_name":"project_destroyed","entity_path":"acme/api","ip_address":"203.0.113.5"},"created_at":"2026-10-25T10:00:00.000Z"}
{"id":2,"author_id":7,"entity_type":"Group","details":{"author_name":"Dev","add":"user_access","target_details":"acme"},"created_at":"2026-10-25T10:00:01.000Z"}
`
	res = load(t, "gitlab.jsonl", gl, FormatGitAud)
	if len(res.Records) != 2 {
		t.Fatalf("gitlab: %+v", res)
	}
	if r := res.Records[0]; r.Provider != "gitlab" || r.Operation != "project_destroyed" || r.Resource != "acme/api" || r.User != "Dev" {
		t.Fatalf("gitlab 1: %+v", r)
	}
	if r := res.Records[1]; r.Operation != "add user_access" || r.Resource != "acme" {
		t.Fatalf("gitlab 2: %+v", r)
	}
}

func TestStorageAccessLogs(t *testing.T) {
	s3 := `79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be prod-logs [25/Oct/2026:10:00:00 +0000] 192.0.2.3 arn:aws:iam::1:user/dev 3E57427F3EXAMPLE REST.DELETE.OBJECT app/2026/10/25.log%20old "DELETE /prod-logs/app/2026/10/25.log%20old HTTP/1.1" 204 - - - 7 - "-" "aws-cli/2.15" - s9lzHYrFp76ZVxRcpX9+5cjAnEH2ROuNkd2BHfIa6UkFVdtjf5mKR3/eTPFvsiP/XV/VLi31234= SigV4 ECDHE-RSA-AES128-GCM-SHA256 AuthHeader prod-logs.s3.us-west-1.amazonaws.com TLSV1.2 - -
79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be prod-logs [25/Oct/2026:10:00:01 +0000] 192.0.2.3 arn:aws:iam::1:user/dev 3E57427F3EXAMPLF REST.DELETE.BUCKET - "DELETE /prod-logs HTTP/1.1" 403 AccessDenied 243 - 7 - "-" "aws-cli/2.15" -
garbage
`
	res := load(t, "s3.log", s3, FormatStorage)
	if len(res.Records) != 2 || res.Skipped != 1 {
		t.Fatalf("s3: records=%d skipped=%d %v", len(res.Records), res.Skipped, res.Problems)
	}
	if r := res.Records[0]; r.Provider != "s3" || r.Operation != "REST.DELETE.OBJECT" || r.Resource != "prod-logs/app/2026/10/25.log old" || r.User != "arn:aws:iam::1:user/dev" || r.SourceIP != "192.0.2.3" || r.Failed != "" {
		t.Fatalf("s3 object: %+v", r)
	}
	if r := res.Records[1]; r.Operation != "REST.DELETE.BUCKET" || r.Resource != "prod-logs" || r.Failed != "AccessDenied" {
		t.Fatalf("s3 bucket: %+v", r)
	}

	gcs := `"time_micros","c_ip","c_ip_type","c_ip_region","cs_method","cs_uri","sc_status","cs_bytes","sc_bytes","time_taken_micros","cs_host","cs_referer","cs_user_agent","s_request_id","cs_operation","cs_bucket","cs_object"
"1792922400000000","192.0.2.4","1","","DELETE","/storage/v1/b/media/o/a%2Fb.png","204","0","0","1000","storage.googleapis.com","","gsutil","id1","DELETE_Object","media","a%2Fb.png"
"bad","192.0.2.4","1","","GET","/","200","0","0","1","","","","id2","","media",""
`
	res = load(t, "usage.csv", gcs, FormatStorage)
	if len(res.Records) != 1 || res.Skipped != 1 {
		t.Fatalf("gcs: records=%d skipped=%d %v", len(res.Records), res.Skipped, res.Problems)
	}
	if r := res.Records[0]; r.Provider != "gcs" || r.Operation != "DELETE DELETE_Object" || r.Resource != "media/a/b.png" || r.SourceIP != "192.0.2.4" {
		t.Fatalf("gcs: %+v", r)
	}

	az := `1.0;2026-10-25T10:00:00.1234567Z;DeleteBlob;Success;202;10;10;authenticated;acct1;acct1;blob;"https://acct1.blob.core.windows.net/backups/db.bak";"/acct1/backups/db.bak";e1a2;0;192.0.2.5:51234;2019-02-02;512;0;0;0;0;;;"md5";"Mon, 25 Oct 2026 10:00:00 GMT";;"az-cli";;"id"
2.0;2026-10-25T10:00:01.0000000Z;GetBlob;AuthorizationFailure;403;1;1;sas;;acct1;blob;"https://acct1.blob.core.windows.net/backups/x";"/acct1/backups/x";e1a3;0;192.0.2.6:1;2019-02-02;1;0;0;0;0;;;;;;;;
2.0;short
`
	res = load(t, "storage.log", az, FormatStorage)
	if len(res.Records) != 2 || res.Skipped != 1 {
		t.Fatalf("azure: records=%d skipped=%d %v", len(res.Records), res.Skipped, res.Problems)
	}
	if r := res.Records[0]; r.Provider != "azure-storage" || r.Operation != "DeleteBlob" || r.Resource != "/acct1/backups/db.bak" || r.SourceIP != "192.0.2.5" || r.User != "acct1" {
		t.Fatalf("azure: %+v", r)
	}
	if r := res.Records[1]; r.Failed != "AuthorizationFailure" {
		t.Fatalf("azure failed: %+v", r)
	}
}

// Every format must sniff as itself and nothing else, including the
// pre-existing auditd, Sysmon, cloud-audit, JSONL and CSV inputs.
func TestCrossSniff(t *testing.T) {
	cases := []struct {
		name, body string
		want       Format
	}{
		{"auditd", "type=SYSCALL msg=audit(1788084007.123:101): arch=c000003e syscall=59 pid=1 exe=\"/bin/ls\"\n", FormatAuditd},
		{"sysmon", `<Events><Event><System><EventID>1</EventID></System></Event></Events>`, FormatSysmon},
		{"cloudtrail", `{"Records":[{"eventTime":"2026-06-10T10:00:01Z","eventSource":"s3.amazonaws.com","eventName":"DeleteBucket"}]}`, FormatCloud},
		{"gcp", `[{"timestamp":"2026-06-10T10:00:05Z","protoPayload":{"methodName":"x"}}]`, FormatCloud},
		{"jsonl-proc", `{"time":"2026-06-10T10:00:00Z","kind":"process","cmdline":"ls"}` + "\n", FormatJSONL},
		{"jsonl-action", `{"time":"2026-06-10T10:00:00Z","action":"connect","actor":"x","dest_ip":"1.2.3.4"}` + "\n", FormatJSONL},
		{"csv", "EventTime,Pid,Exe,CommandLine\n2026-08-30 10:00:07,1,/bin/ls,ls\n", FormatCSV},
		{"csv-host", "time,user,url,host\n2026-10-25 10:00:00,dev,https://a/x,a\n", FormatCSV},
		{"zeek-tsv", "#separator \\x09\n#path\tdns\n#fields\tts\tquery\n", FormatZeek},
		{"zeek-json", `{"ts":1,"uid":"C","id.orig_h":"10.0.0.1","query":"a.example"}` + "\n", FormatZeek},
		{"bind", "25-Oct-2026 10:00:00.123 queries: info: client @0x1 10.0.0.5#1 (a.example): query: a.example IN A +\n", FormatDNSLog},
		{"dnsmasq", "Oct 25 10:00:01 gw dnsmasq[811]: query[A] a.example from 10.0.0.6\n", FormatDNSLog},
		{"pihole", "Oct 25 10:00:01 dnsmasq[811]: query[A] a.example from 10.0.0.6\n", FormatDNSLog},
		{"unbound", "[1792922403] unbound[1234:0] info: 10.0.0.8 a.example. A IN\n", FormatDNSLog},
		{"windns", "10/25/2026 10:00:04 AM 0E5C PACKET  000000D2B1E3A170 UDP Rcv 10.0.0.9      0002   Q [0001   D   NOERROR] A      (1)a(7)example(0)\n", FormatDNSLog},
		{"squid", "1792922400.123    180 10.0.0.5 TCP_MISS/200 411 GET http://a.example/ - HIER_DIRECT/1.2.3.4 text/html\n", FormatSquid},
		{"squid-common", `10.0.0.6 - - [25/Oct/2026:10:00:02 +0000] "CONNECT a.example:443 HTTP/1.1" 200 5 TCP_TUNNEL:HIER_DIRECT` + "\n", FormatSquid},
		{"authlog", "Oct 25 10:00:02 host sshd[2201]: Accepted publickey for deploy from 10.0.0.5 port 1 ssh2\n", FormatAuthLog},
		{"secure", "Oct 25 10:00:00 host sudo:      dev : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls\n", FormatAuthLog},
		{"journald", `{"__REALTIME_TIMESTAMP":"1792922400000000","_PID":"1","MESSAGE":"x"}` + "\n", FormatJournal},
		{"k8s", `{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"a","verb":"get","objectRef":{"resource":"pods"}}` + "\n", FormatK8s},
		{"github-json", `[{"@timestamp":1792922400000,"action":"repo.create","actor":"dev"}]`, FormatGitAud},
		{"github-csv", "@timestamp,action,actor,repo\n1792922400000,git.push,dev,a/b\n", FormatGitAud},
		{"gitlab", `[{"id":1,"author_id":7,"entity_type":"Project","details":{"author_name":"x"},"created_at":"2026-10-25T10:00:00Z"}]`, FormatGitAud},
		{"s3", "79a59df900b949e55d96a1e698fbacedfd6e09d98eacf8f8d5218e7cd47ef2be b [25/Oct/2026:10:00:00 +0000] 192.0.2.3 - X REST.GET.OBJECT k \"GET /b/k HTTP/1.1\" 200 - 1 1 1 1 \"-\" \"-\" -\n", FormatStorage},
		{"gcs", "\"time_micros\",\"c_ip\",\"cs_method\",\"cs_bucket\"\n\"1\",\"1.1.1.1\",\"GET\",\"b\"\n", FormatStorage},
		{"azure", "1.0;2026-10-25T10:00:00.1234567Z;GetBlob;Success;200;1;1;anonymous;;a;blob;\"u\";\"/a/c/b\";i;0;1.2.3.4:5;v\n", FormatStorage},
	}
	for _, tc := range cases {
		p := write(t, tc.name+".log", tc.body)
		if got, err := Sniff(p); got != tc.want {
			t.Errorf("%s: sniffed %q (%v), want %q", tc.name, got, err, tc.want)
		}
	}
	// A web server's own access log is not a proxy log.
	p := write(t, "nginx.log", `10.0.0.6 - - [25/Oct/2026:10:00:02 +0000] "GET /index.html HTTP/1.1" 200 5 "-" "curl/8"`+"\n")
	if got, _ := Sniff(p); got == FormatSquid {
		t.Errorf("nginx access log sniffed as squid")
	}
}

func TestTelemetryHostileInput(t *testing.T) {
	// Huge line, binary junk and unterminated quotes: problems, no panic.
	long := strings.Repeat("A", 1<<20)
	for _, f := range []Format{FormatZeek, FormatDNSLog, FormatSquid, FormatAuthLog, FormatJournal, FormatK8s, FormatGitAud, FormatStorage} {
		p := write(t, "hostile-"+string(f), long+"\n\x00\xff\xfe\"[unterminated\n{\"a\":\n")
		res, err := Load(p, f)
		if err != nil {
			continue // e.g. a CSV header that is not a header: an error, not a panic
		}
		if len(res.Records) != 0 {
			t.Errorf("%s: invented records from junk: %+v", f, res.Records)
		}
	}
	if _, err := Load(write(t, "x", "y"), Format("nope")); err == nil {
		t.Fatal("unknown format accepted")
	}
}
