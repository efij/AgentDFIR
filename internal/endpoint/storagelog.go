package endpoint

import (
	"encoding/csv"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

// Cloud object-storage access logs: the storage service's own record of
// each object request, the second witness for `aws s3 rm`, `gsutil cp`
// or `az storage blob delete`.
//
//   - S3 server access log: space-delimited, [bracketed time], "quoted
//     request"; Operation is the S3 operation (REST.DELETE.OBJECT …),
//     Resource is bucket/key, User the requester ARN
//   - GCS usage logs: CSV with a header (time_micros, c_ip, cs_method,
//     cs_bucket, cs_object, sc_status, cs_operation …); usage logs name no
//     principal
//   - Azure Storage Analytics logging (classic $logs, format 1.0 and 2.0):
//     semicolon-delimited; Operation is the operation type (DeleteBlob …),
//     Resource the requested object key (/account/container/blob)
//
// Lines of the three formats may not be mixed in one file; each line is
// checked against the format of the first.

func loadStorageLog(path string) (*LoadResult, error) {
	lines := []string{}
	if f, err := os.Open(path); err == nil {
		head := make([]byte, 8<<10)
		n, _ := io.ReadFull(f, head)
		f.Close()
		lines = headLines([]byte(strings.TrimPrefix(string(head[:n]), "\xef\xbb\xbf")), 1)
	}
	if len(lines) == 0 {
		return &LoadResult{}, nil
	}
	first := lines[0]
	if strings.Contains(first, "time_micros") && strings.Contains(first, "cs_method") {
		return loadGCSUsage(path)
	}
	res := &LoadResult{}
	base := baseName(path)
	azure := azureStorRe.MatchString(first)
	err := scanLines(path, func(line string, n int) {
		if strings.TrimSpace(line) == "" {
			return
		}
		at := fmt.Sprintf("%s:%d", base, n)
		var r Record
		var ok bool
		if azure {
			r, ok = azureStorageRecord(line)
		} else {
			r, ok = s3AccessRecord(line)
		}
		if !ok {
			res.problem(at + ": not a storage access log line")
			return
		}
		r.Ref = at
		res.Records = append(res.Records, r)
	})
	return res, err
}

// s3AccessRecord: bucket_owner bucket [time] remote_ip requester
// request_id operation key "request_uri" http_status error_code …
func s3AccessRecord(line string) (Record, bool) {
	if !s3AccessRe.MatchString(line) {
		return Record{}, false
	}
	f := splitQuoted(line, ' ', true)
	if len(f) < 10 {
		return Record{}, false
	}
	t, err := time.Parse("02/Jan/2006:15:04:05 -0700", f[2])
	if err != nil {
		return Record{}, false
	}
	resource := f[1]
	if f[7] != "-" && f[7] != "" {
		key := f[7]
		if k, err := url.PathUnescape(key); err == nil {
			key = k
		}
		resource += "/" + key
	}
	r := Record{Time: t.UTC(), Kind: "cloud", Provider: "s3", Source: "s3-access", Operation: f[6], Resource: resource, SourceIP: f[3]}
	if f[4] != "-" {
		r.User = f[4]
	}
	if len(f) > 10 && f[10] != "-" {
		r.Failed = f[10]
	} else if s, _ := strconv.Atoi(f[9]); s >= 400 {
		r.Failed = "HTTP " + f[9]
	}
	return r, f[6] != ""
}

// azureStorageRecord reads the fixed leading fields shared by formats 1.0
// and 2.0: version;request-start-time;operation-type;request-status;
// http-status-code;e2e-latency;server-latency;authentication-type;
// requester-account-name;owner-account-name;service-type;request-url;
// requested-object-key;request-id;operation-count;requester-ip-address;…
func azureStorageRecord(line string) (Record, bool) {
	if !azureStorRe.MatchString(line) {
		return Record{}, false
	}
	f := splitQuoted(line, ';', false)
	if len(f) < 16 {
		return Record{}, false
	}
	t, ok := parseTime(f[1])
	if !ok {
		return Record{}, false
	}
	ip := f[15]
	if h, _, _ := hostOfURL(ip); h != "" {
		ip = h
	}
	r := Record{Time: t, Kind: "cloud", Provider: "azure-storage", Source: "azure-storage", Operation: f[2],
		Resource: f[12], User: firstNonEmpty(f[8], f[7]), SourceIP: ip}
	if s, _ := strconv.Atoi(f[4]); s >= 400 {
		r.Failed = f[3]
	}
	return r, true
}

func loadGCSUsage(path string) (*LoadResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	res := &LoadResult{}
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
		at := fmt.Sprintf("%s:%d", base, n)
		if err != nil {
			res.problem(fmt.Sprintf("row %d: %v", n, err))
			continue
		}
		v := map[string]string{}
		for i, x := range row {
			if i < len(header) {
				v[header[i]] = x
			}
		}
		us, err := strconv.ParseInt(v["time_micros"], 10, 64)
		if err != nil || us <= 0 || v["cs_method"] == "" {
			res.problem(at + ": no time_micros or cs_method")
			continue
		}
		resource := v["cs_bucket"]
		if obj := v["cs_object"]; obj != "" {
			if o, err := url.PathUnescape(obj); err == nil {
				obj = o
			}
			resource += "/" + obj
		}
		r := Record{Time: time.UnixMicro(us).UTC(), Kind: "cloud", Provider: "gcs", Source: "gcs-usage", Ref: at,
			Operation: strings.TrimSpace(v["cs_method"] + " " + v["cs_operation"]), Resource: resource, SourceIP: v["c_ip"]}
		if s, _ := strconv.Atoi(v["sc_status"]); s >= 400 {
			r.Failed = "HTTP " + v["sc_status"]
		}
		res.Records = append(res.Records, r)
	}
	return res, nil
}
